package db

// 内网拓扑。
//
// ## 为什么单独做一个聚合，而不是让前端去拼资产列表
// 拓扑需要的不是「资产清单」，而是「网段 → 主机 → 端口」这一层结构。资产表里
// 有 c_segment（入库时自动算好的 /24），但前端要自己再归并一遍，还得处理同一个
// IP 出现在多条 service 资产里的重复。把归并放在 SQL 后面这一层，前端只画图。
//
// ## 数据来源与证据等级
// 这里只做**库存层**：任务范围内有哪些 IP、落在哪个网段、开了哪些端口、是否已测过。
// 运行时的「哪条隧道真的拨通了哪个目标」由 server 层用隧道连接日志补上——
// 那才是「已验证可达」的边。两者刻意分开：库存来自入库，可达来自实测，
// 混在一起就分不清「我看到过」和「我打通过」。

import (
	"bytes"
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"time"
)

// TopologyHost 是任务范围内一个有 IP 的主机（同一 IP 的多条服务资产已归并）。
type TopologyHost struct {
	IP     string   `json:"ip"`
	Ports  []int    `json:"ports,omitempty"`
	URLs   []string `json:"urls,omitempty"`
	Tested bool     `json:"tested"`
}

// TopologySegment 是一个 /24（IPv6 为 /48）网段及其中的主机。
type TopologySegment struct {
	CIDR string `json:"cidr"`
	// Authorized 表示该网段落在任务的显式授权网段内（task_scope 的 ip/cidr 行，
	// 或任务声明了 company 范围）。入库来的 c_segment 不会自己变成授权——
	// 否则「看到过」就等于「被授权」，范围就没有意义了。
	Authorized bool `json:"authorized"`
	HostCount  int  `json:"host_count"`
	Tested     int  `json:"tested"`
	// Verified 是经隧道**实测拨通**过的主机数（来自连接日志，不是入库）。
	// 由 server 层补：数据库不知道运行时隧道状态。
	Verified int            `json:"verified"`
	Hosts    []TopologyHost `json:"hosts"`
}

// Topology 是一次拓扑快照。Segments 来自数据库；Landings/Edges 由 server 层用
// 运行中的隧道补上（隧道是进程内状态，数据库里没有）。
type Topology struct {
	TaskID      int64             `json:"task_id"`
	ScopeNets   []string          `json:"scope_nets"` // 任务显式授权的网段
	Segments    []TopologySegment `json:"segments"`
	Landings    []TopologyLanding `json:"landings"` // 由 server 填
	Edges       []TopologyEdge    `json:"edges"`    // 由 server 填：实测可达
	GeneratedAt time.Time         `json:"generated_at"`
}

// TopologyLanding 是一个内网立足点（隧道/跳板）。由 server 填。
type TopologyLanding struct {
	Kind     string   `json:"kind"` // pivot | webshell
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Alive    bool     `json:"alive"`
	Hops     []string `json:"hops,omitempty"`    // 跳板地址链
	Targets  []string `json:"targets,omitempty"` // 经它拨通过的目标 IP
	SocksURL string   `json:"socks_url,omitempty"`
}

// TopologyEdge 是一条**实测**可达边：某条立足点成功拨通过某个目标。
// 只记录 OK=true 的连接——失败的尝试不算拓扑边，那是「试过但不通」。
type TopologyEdge struct {
	From    string    `json:"from"` // 立足点 id
	To      string    `json:"to"`   // 目标 IP
	Port    int       `json:"port,omitempty"`
	At      time.Time `json:"at"`
	Segment string    `json:"segment,omitempty"`
}

// BuildTopology 聚合任务范围内的 IP 资产为网段 → 主机结构。
//
// 范围判定复用 contextCoverageCTE 的 target 子集：它不仅包含 task_scope 直接
// 命中的资产，也包含经探索图 anchor 关联进来的资产——那些往往正是横向过程中
// 发现的内网主机，漏掉它们拓扑就只剩入口那一段。
func (s *AssetStore) BuildTopology(taskID int64) (*Topology, error) {
	t := &Topology{
		TaskID:      taskID,
		ScopeNets:   []string{},
		Segments:    []TopologySegment{},
		Landings:    []TopologyLanding{},
		Edges:       []TopologyEdge{},
		GeneratedAt: time.Now(),
	}
	if taskID <= 0 {
		return t, nil
	}

	// 显式授权网段 + 是否声明了 company 范围。
	var hasCompany bool
	nets := []*net.IPNet{}
	scopeRows, err := s.db.Query(`SELECT kind, COALESCE(net::text,'') FROM task_scope WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	for scopeRows.Next() {
		var kind, netText string
		if err := scopeRows.Scan(&kind, &netText); err != nil {
			continue
		}
		switch kind {
		case "company":
			hasCompany = true
		case "ip", "cidr":
			if _, n, err := net.ParseCIDR(netText); err == nil {
				nets = append(nets, n)
				t.ScopeNets = append(t.ScopeNets, n.String())
			}
		}
	}
	if err := scopeRows.Err(); err != nil {
		scopeRows.Close()
		return nil, err
	}
	scopeRows.Close()
	sort.Strings(t.ScopeNets)

	rows, err := s.db.Query(`WITH `+contextCoverageCTE+`
SELECT COALESCE(a.c_segment::text,''), a.ip, COALESCE(a.url,''), COALESCE(a.port,0),
       COALESCE(array_to_json(a.open_ports)::text,'[]'),
       (a.id IN (SELECT asset_id FROM tested)) AS tested
FROM assets a JOIN target t ON t.id = a.id
WHERE COALESCE(a.ip,'') <> ''
ORDER BY a.ip`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 先建「指针图」再摊平成切片：直接对 t.Segments / seg.Hosts 反复 append 会触发
	// 扩容，之前存进 map 的指针会指向被丢弃的旧数组，后续写入全部丢失（而且不报错）。
	segMap := map[string]*TopologySegment{}
	var segOrder []string
	hostMap := map[string]*TopologyHost{}    // key = cidr|ip
	segHosts := map[string][]*TopologyHost{} // cidr → 按发现顺序的主机指针
	for rows.Next() {
		var cidr, ip, rawURL, portsJSON string
		var port int
		var tested bool
		if err := rows.Scan(&cidr, &ip, &rawURL, &port, &portsJSON, &tested); err != nil {
			return nil, err
		}
		if cidr == "" {
			// c_segment 是入库时按 IP 算出来的；为空说明 IP 形态异常。归到
			// 「未归段」而不是丢掉——丢掉会让「资产数对不上」变成永久的疑问。
			cidr = "未归段"
		}
		seg, ok := segMap[cidr]
		if !ok {
			seg = &TopologySegment{CIDR: cidr}
			segMap[cidr] = seg
			segOrder = append(segOrder, cidr)
		}
		key := cidr + "|" + ip
		host, ok := hostMap[key]
		if !ok {
			host = &TopologyHost{IP: ip}
			hostMap[key] = host
			segHosts[cidr] = append(segHosts[cidr], host)
		}
		if tested {
			host.Tested = true
		}
		if port > 0 {
			host.Ports = appendUniquePort(host.Ports, port)
		}
		for _, p := range portsFromJSON(portsJSON) {
			host.Ports = appendUniquePort(host.Ports, p)
		}
		if rawURL != "" {
			host.URLs = appendUniqueString(host.URLs, rawURL)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 摊平 + 授权标记 + 计数 + 稳定排序。
	for _, cidr := range segOrder {
		seg := segMap[cidr]
		seg.Authorized = hasCompany || segmentAuthorized(seg.CIDR, nets)
		ptrs := segHosts[cidr]
		seg.Hosts = make([]TopologyHost, 0, len(ptrs))
		for _, p := range ptrs {
			seg.Hosts = append(seg.Hosts, *p)
		}
		seg.HostCount = len(seg.Hosts)
		seg.Tested = 0
		for j := range seg.Hosts {
			sort.Ints(seg.Hosts[j].Ports)
			sort.Strings(seg.Hosts[j].URLs)
			if seg.Hosts[j].Tested {
				seg.Tested++
			}
		}
		sort.SliceStable(seg.Hosts, func(a, b int) bool {
			return ipLess(seg.Hosts[a].IP, seg.Hosts[b].IP)
		})
		t.Segments = append(t.Segments, *seg)
	}
	sort.SliceStable(t.Segments, func(a, b int) bool {
		return t.Segments[a].CIDR < t.Segments[b].CIDR
	})
	return t, nil
}

// segmentAuthorized 判断一个网段是否落在任一授权网段内。
// 按网段的网络地址判定：一个 /24 被 /16 授权覆盖即算授权，这是操作上真正关心的粒度。
func segmentAuthorized(cidr string, nets []*net.IPNet) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// portsFromJSON 解析 open_ports（[{"port":22,"service":"ssh"}]）里的端口号。
func portsFromJSON(raw string) []int {
	if raw == "" || raw == "[]" || raw == "null" {
		return nil
	}
	var entries []map[string]any
	if json.Unmarshal([]byte(raw), &entries) != nil {
		return nil
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		switch v := e["port"].(type) {
		case float64:
			if v > 0 && v < 65536 {
				out = append(out, int(v))
			}
		case int:
			if v > 0 && v < 65536 {
				out = append(out, v)
			}
		case string:
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
				out = append(out, n)
			}
		}
	}
	return out
}

func appendUniquePort(in []int, p int) []int {
	for _, v := range in {
		if v == p {
			return in
		}
	}
	return append(in, p)
}

func appendUniqueString(in []string, s string) []string {
	for _, v := range in {
		if v == s {
			return in
		}
	}
	return append(in, s)
}

// ipLess 按地址数值排序（字符串排序会把 10.0.0.10 排在 10.0.0.9 前面）。
func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	return bytes.Compare(ia.To16(), ib.To16()) < 0
}
