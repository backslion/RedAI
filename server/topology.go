package server

// 内网拓扑的 HTTP 装配。
//
// 数据库给出「库存层」（网段/主机/端口/是否已测），这里补「实测层」——
// 隧道连接日志里成功拨通过的目标。两层分开是有意的：
//   - 库存只说明「我知道这个地址存在」（来自入库）；
//   - 可达只说明「我确实打通过」（来自真实 TCP 连接）。
// 把两者混成一个「边」，图上就分不清哪条是猜的、哪条是打出来的，而这恰好是
// 复盘时最需要分清的一件事。
//
// 隧道是进程内状态，服务重启即失。所以拓扑里的 Reachable 边只代表**当前进程
// 生命周期内**的实测结果，前端标注「本次会话」——不要把它当成长期资产。

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// topologyRecentConns 取每条隧道的连接记录条数。与 pivot.maxConnLog（200）对齐：
// 取多了拿不到（内存里只留这么多），取少了会漏掉早期的成功连接。
const topologyRecentConns = 200

// connSample 是两种隧道（pivot / webshell）连接日志的公共投影。
// 两个包各自定义了未导出的 connLog，字段同名但类型不同，这里统一成一份。
type connSample struct {
	Target string
	OK     bool
	At     time.Time
}

// taskTopology 返回任务的网段拓扑。
// GET /api/tasks/{id}/topology
func (s *Server) taskTopology(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	topo, err := as.BuildTopology(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.enrichTopology(topo, taskID)
	writeJSON(w, 200, topo)
}

// enrichTopology 把运行中的隧道投影成「立足点 + 实测可达边」。
func (s *Server) enrichTopology(topo *db.Topology, taskID int64) {
	edgeSeen := map[string]bool{}

	addLanding := func(kind, id, label string, alive bool, hops []string, socksURL string, samples []connSample) {
		l := db.TopologyLanding{
			Kind: kind, ID: id, Label: label, Alive: alive,
			Hops: hops, SocksURL: socksURL,
		}
		seenTarget := map[string]bool{}
		for _, c := range samples {
			// 失败的尝试不构成拓扑边：那是「试过但不通」，画上去会让人以为打得通。
			if !c.OK {
				continue
			}
			ip, port := splitTarget(c.Target)
			if ip == "" {
				continue
			}
			if !seenTarget[ip] {
				seenTarget[ip] = true
				l.Targets = append(l.Targets, ip)
			}
			seg := db.CSegmentOf(ip)
			key := id + "|" + ip + "|" + strconv.Itoa(port)
			if edgeSeen[key] {
				continue
			}
			edgeSeen[key] = true
			topo.Edges = append(topo.Edges, db.TopologyEdge{
				From: id, To: ip, Port: port, At: c.At, Segment: seg,
			})
		}
		topo.Landings = append(topo.Landings, l)
	}

	if s.pivots != nil {
		for _, tun := range s.pivots.List(taskID) {
			v := tun.View(topologyRecentConns)
			hops := make([]string, 0, len(v.Hops))
			for _, h := range v.Hops {
				if a := strings.TrimSpace(h.Addr); a != "" {
					hops = append(hops, a)
				}
			}
			samples := make([]connSample, 0, len(v.Recent))
			for _, c := range v.Recent {
				samples = append(samples, connSample{Target: c.Target, OK: c.OK, At: c.At})
			}
			addLanding("pivot", v.ID, v.Label, v.Alive, hops, v.SocksURL, samples)
		}
	}
	if s.wsTunnels != nil {
		for _, tun := range s.wsTunnels.List(taskID) {
			v := tun.View(topologyRecentConns)
			samples := make([]connSample, 0, len(v.Recent))
			for _, c := range v.Recent {
				samples = append(samples, connSample{Target: c.Target, OK: c.OK, At: c.At})
			}
			// WebShell 隧道没有 SSH 那种跳板链，入口就是 webshell 会话本身。
			hops := []string{}
			if v.Session != "" {
				hops = append(hops, v.Session)
			}
			addLanding("webshell", v.ID, v.Label, v.Alive, hops, v.SocksURL, samples)
		}
	}

	// 把实测边折进网段计数，前端不必自己再数一遍。
	for i := range topo.Segments {
		seg := &topo.Segments[i]
		for _, e := range topo.Edges {
			if e.Segment != "" && e.Segment == seg.CIDR {
				seg.Verified++
			}
		}
	}
}

// splitTarget 把隧道连接日志里的 target（"host:port"）拆成 IP 与端口。
// 域名目标返回空 IP——拓扑只画 IP：域名到 IP 的映射会变，画上去第二天就错了。
func splitTarget(target string) (string, int) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", 0
	}
	if host, portText, err := net.SplitHostPort(t); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			p, _ := strconv.Atoi(portText)
			return ip.String(), p
		}
		return "", 0
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String(), 0
	}
	return "", 0
}
