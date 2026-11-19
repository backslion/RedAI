package pivot

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// 经隧道探测内网端口。
//
// 为什么不用现成的 tcp_probe：tcp_probe 是平台本机直接 Dial，打不到目标内网。
// nmap 也不走 SOCKS5（除非装 proxychains）。而 SSH 的 direct-tcpip 通道本身就
// 是一次「由跳板机代拨」的 TCP 连接——通道打开成功即证明该端口接受连接，
// 不需要等应用层数据，也不受本机网络位置限制。这是本功能最实用的一环。
//
// 语义边界：只做 TCP 连接判定，不爆破、不发应用层 payload（banner 是被动读）。
// 「连接被拒」与「超时」分开返回——前者说明主机活着但端口关闭，后者说明
// 过滤或主机不存在，两者对下一步动作的含义完全不同。

// ProbeResult 是单个 host:port 的结论。
type ProbeResult struct {
	Target    string `json:"target"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
	Banner    string `json:"banner,omitempty"`
}

// ProbeOptions 是批量探测输入。
type ProbeOptions struct {
	Hosts       []string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	// GrabBanner 对开放端口被动读最多 256 字节（800ms）。会拖慢整体，
	// 大范围扫段时关掉。
	GrabBanner bool
}

// Probe 经指定隧道批量探测。返回按 host 排序、同 host 内按端口排序的结果。
func (m *Manager) Probe(ctx context.Context, id string, opts ProbeOptions) ([]ProbeResult, error) {
	m.mu.RLock()
	t, ok := m.tunnels[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("隧道 %s 不存在", id)
	}
	if !t.Alive {
		return nil, fmt.Errorf("隧道 %s 已断开（%s）", id, t.LastError)
	}
	if t.Mode != ModeSocks && t.Mode != ModePortFwd {
		return nil, fmt.Errorf("隧道模式 %q 不支持探测", t.Mode)
	}
	if len(opts.Hosts) == 0 {
		return nil, fmt.Errorf("hosts 不能为空")
	}
	if len(opts.Ports) == 0 {
		return nil, fmt.Errorf("ports 不能为空")
	}
	if len(opts.Hosts) > 256 {
		return nil, fmt.Errorf("hosts 一次最多 256 个")
	}
	if len(opts.Ports) > 1024 {
		return nil, fmt.Errorf("ports 一次最多 1024 个")
	}
	if len(opts.Hosts)*len(opts.Ports) > 65536 {
		return nil, fmt.Errorf("探测组合过多（%d host × %d port），请分批", len(opts.Hosts), len(opts.Ports))
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 32
	}
	if conc > 128 {
		conc = 128
	}

	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	out := make([]ProbeResult, 0, len(opts.Hosts)*4)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				r := t.probeOne(j.host, j.port, timeout, opts.GrabBanner)
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
			}
		}()
	}
	for _, h := range opts.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		for _, p := range opts.Ports {
			if ctx.Err() != nil {
				break
			}
			jobs <- job{host: h, port: p}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

// probeOne 经最后一跳拨一次。dialVia 成功即端口开放（sshd 已代为完成 TCP 握手）。
func (t *Tunnel) probeOne(host string, port int, timeout time.Duration, grab bool) ProbeResult {
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := ProbeResult{Target: target, Host: host, Port: port}
	start := time.Now()

	// ssh.Client.Dial 没有 context 版本，用 goroutine + 超时兜住：
	// 目标侧黑洞（DROP 而非 REJECT）时底层 TCP 会挂很久，不设上限会把并发槽占满。
	type dialRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialRes, 1)
	go func() {
		c, err := t.dialVia(target)
		ch <- dialRes{conn: c, err: err}
	}()

	select {
	case <-time.After(timeout):
		res.LatencyMs = time.Since(start).Milliseconds()
		res.Error = "timeout（目标无响应，可能被过滤或主机不存在）"
		return res
	case d := <-ch:
		res.LatencyMs = time.Since(start).Milliseconds()
		if d.err != nil {
			res.Error = classifySSHDialErr(d.err)
			return res
		}
		res.Open = true
		if grab {
			res.Banner = readBanner(d.conn, 800*time.Millisecond)
		}
		_ = d.conn.Close()
		return res
	}
}

// classifySSHDialErr 把 sshd 的 direct-tcpip 失败原因分类。sshd 会把底层
// connect 的错误放进 "connect failed (...)" 里，据此区分「端口关闭」与「不可达」。
func classifySSHDialErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connection refused（主机可达，端口关闭）"
	case strings.Contains(s, "no route to host"):
		return "no route to host（跳板机到目标网段无路由）"
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "timed out"):
		return "timeout（跳板机侧连接超时，可能被防火墙丢包）"
	case strings.Contains(s, "administratively prohibited"):
		return "administratively prohibited（跳板机 sshd 禁止转发，需 AllowTcpForwarding yes）"
	case strings.Contains(s, "unknown channel type"):
		return "unknown channel type（跳板机 sshd 未开启 direct-tcpip）"
	}
	return s
}

// readBanner 被动读一小段服务横幅。不复用 waitConn：probe 需要的是「能读到就
// 返回，读不到也不算失败」，而 waitConn 会把超时当成功。
func readBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	s := strings.TrimSpace(string(buf[:n]))
	// 二进制服务（SMB/RDP）的首包不可打印，别把乱码写进报告。
	printable := 0
	for _, r := range s {
		if r >= 0x20 && r < 0x7f || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	if printable*10 < len([]rune(s))*7 {
		return ""
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
