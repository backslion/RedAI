package agent

// 内网纵深工具（YCode 二开）：给执行侧 agent 提供不依赖外部二进制的网络侧基础
// 能力——网段展开与 TCP 存活/端口探测。两者都【不触碰双图】，用 readTool 构造
// （并发安全、无 store 依赖），因此 worker（任务内）与 pentest/auto（经
// buildDomainReg 的服务级 ToolSet 注入）都能用。真正的内网方法论与配套脚本在
// skills/intranet-pivot，这里只提供原子操作。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// --- expand_cidr ---

func (t *ToolSet) expandCIDR() actool.CoreTool {
	return readTool("expand_cidr",
		"(内网纵深)把 CIDR 网段(如 10.0.1.0/24)、IP 范围(如 10.0.1.10-10.0.1.20)或单个 IP 展开成 IP 列表。用于内网网段摸底后确定要探测的地址；输出可直接喂给 tcp_probe，发现的存活 IP 应登记 insert_assets(type=ip)。",
		obj(map[string]any{
			"cidrs": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "CIDR / IP 范围 / 单 IP 的列表，如 [\"10.0.1.0/24\",\"192.168.30.10-192.168.30.20\",\"172.16.0.5\"]。同时支持 IPv4 与 IPv6 CIDR。",
			},
			"limit": map[string]any{
				"type": "integer", "default": 256,
				"description": "最多返回多少个 IP(1..8192)，超出则截断并置 truncated=true，可分段再展开。",
			},
		}, "cidrs"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Cidrs []string `json:"cidrs"`
				Limit int      `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(p.Cidrs) == 0 {
				return actool.Errorf("cidrs 不能为空"), nil
			}
			if p.Limit <= 0 {
				p.Limit = 256
			}
			if p.Limit > 8192 {
				p.Limit = 8192
			}
			seen := map[string]bool{}
			var ips []string
			truncated := false
			for _, c := range p.Cidrs {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				got, err := expandOne(c, p.Limit-len(ips), func(ip string) {
					if !seen[ip] {
						seen[ip] = true
						ips = append(ips, ip)
					}
				})
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if got {
					truncated = true
				}
				if len(ips) >= p.Limit {
					truncated = true
					break
				}
			}
			return jsonResult(map[string]any{
				"count":     len(ips),
				"ips":       ips,
				"truncated": truncated,
			})
		})
}

// expandOne expands a single CIDR / range / IP, emitting via emit. Returns true
// when the budget (cap) was hit before the input was exhausted.
func expandOne(s string, cap int, emit func(string)) (bool, error) {
	if cap <= 0 {
		return true, nil
	}
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		// "a.b.c.d-a.b.c.d" (IPv4 only)
		lo, hi := strings.SplitN(s, "-", 2)[0], strings.SplitN(s, "-", 2)[1]
		loIP := net.ParseIP(strings.TrimSpace(lo)).To4()
		hiIP := net.ParseIP(strings.TrimSpace(hi)).To4()
		if loIP == nil || hiIP == nil {
			return false, fmt.Errorf("无法解析 IP 范围 %q", s)
		}
		loN, hiN := ipToUint32(loIP), ipToUint32(hiIP)
		if hiN < loN {
			loN, hiN = hiN, loN
		}
		n := 0
		for v := loN; v <= hiN; v++ {
			if n >= cap {
				return true, nil
			}
			emit(uint32ToIP(v).String())
			n++
		}
		return false, nil
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return false, fmt.Errorf("无法解析 IP %q", s)
		}
		emit(ip.String())
		return false, nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false, fmt.Errorf("无法解析 CIDR %q: %v", s, err)
	}
	n := 0
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		if n >= cap {
			return true, nil
		}
		emit(ip.String())
		n++
	}
	return false, nil
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// --- tcp_probe ---

// portPresets are curated common intranet service ports. "all" unions every
// preset; explicit ports always add on top.
var portPresets = map[string][]int{
	"top100": {21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 500, 512, 513, 514, 548, 554, 587, 623, 636, 873, 990, 993, 995, 1080, 1099, 1194, 1433, 1521, 1604, 1723, 1883, 2049, 2181, 2375, 2376, 2379, 2638, 3000, 3128, 3260, 3306, 3389, 4444, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6379, 6443, 6666, 7001, 7002, 7077, 7100, 7547, 7777, 8000, 8008, 8009, 8010, 8020, 8025, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8098, 8161, 8180, 8200, 8443, 8500, 8649, 8686, 8786, 8800, 8848, 8849, 8888, 8983, 9000, 9001, 9002, 9042, 9043, 9080, 9090, 9091, 9092, 9100, 9200, 9300, 9418, 9443, 9527, 9800, 9876, 9999, 10000, 10001, 10050, 10051, 11211, 15672, 18080, 18083, 19000, 20880, 27017, 28015, 32400, 33060, 50000, 50070, 61616, 63791},
	"web":    {80, 81, 88, 443, 444, 555, 591, 1080, 2082, 2083, 2087, 2095, 3000, 4848, 5000, 5601, 6080, 7001, 7002, 7070, 7080, 7777, 8000, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8161, 8180, 8443, 8786, 8800, 8848, 8899, 8983, 9000, 9080, 9090, 9100, 9443, 9527, 9999, 10000, 18080, 18083},
	"db":     {1433, 1521, 2638, 3306, 5432, 5984, 6379, 7199, 8086, 8649, 9042, 9200, 9300, 11211, 2049, 23023, 27017, 27018, 28015, 28017, 33060, 50000, 61616},
	"win":    {88, 135, 139, 389, 445, 464, 593, 636, 1099, 3268, 3269, 3389, 5985, 5986, 9389, 47001, 49665, 49667},
	"nix":    {22, 111, 513, 514, 873, 1080, 2049, 6000, 7777},
}

func (t *ToolSet) tcpProbe() actool.CoreTool {
	return readTool("tcp_probe",
		"(内网纵深)并发 TCP 连接探测：对一批 host×port 做连通性测试并抓取服务 banner(对 HTTP 端口在无回显时发 HEAD 探测)。用于内网存活发现、端口开放确认与服务初判。只做单次连接探测，不爆破、不利用；端口全部关闭/拒绝属正常结论。存活主机与开放端口应登记 insert_assets(type=ip/service)。",
		obj(map[string]any{
			"hosts": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "目标主机列表(IP 或域名)，如 [\"10.0.1.5\",\"10.0.1.6\"]。",
			},
			"ports": map[string]any{
				"type": "array", "items": map[string]any{"type": "integer"},
				"description": "显式端口列表(与 preset 叠加)，如 [22,445,3389]。",
			},
			"preset": map[string]any{
				"type": "string", "default": "top100",
				"description": "端口预设：top100(默认,常用全量) / web / db / win(Windows 域与管理) / nix / none(只用显式 ports)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 1500,
				"description": "单次连接超时毫秒(500..10000)。内网一般 1000-2000 足够。",
			},
			"grab_banner": map[string]any{
				"type": "boolean", "default": true,
				"description": "是否在连接后抓取服务 banner。",
			},
		}, "hosts"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Hosts     []string `json:"hosts"`
				Ports     []int    `json:"ports"`
				Preset    string   `json:"preset"`
				TimeoutMs int      `json:"timeout_ms"`
				Grab      *bool    `json:"grab_banner"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(p.Hosts) == 0 {
				return actool.Errorf("hosts 不能为空"), nil
			}
			if len(p.Hosts) > 512 {
				return actool.Errorf("hosts 一次最多 512 个，请分批"), nil
			}
			if p.Preset == "" {
				p.Preset = "top100"
			}
			portSet := map[int]bool{}
			if p.Preset != "none" {
				preset, ok := portPresets[p.Preset]
				if !ok {
					return actool.Errorf(fmt.Sprintf("未知 preset %q，可选 top100/web/db/win/nix/none", p.Preset)), nil
				}
				for _, pt := range preset {
					portSet[pt] = true
				}
			}
			for _, pt := range p.Ports {
				if pt < 1 || pt > 65535 {
					return actool.Errorf(fmt.Sprintf("非法端口 %d", pt)), nil
				}
				portSet[pt] = true
			}
			if len(portSet) == 0 {
				return actool.Errorf("未指定任何端口(preset=none 且 ports 为空)"), nil
			}
			if len(p.Hosts)*len(portSet) > 65536 {
				return actool.Errorf(fmt.Sprintf("探测组合过多(%d host × %d port)，请缩小范围或分批", len(p.Hosts), len(portSet))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 1500 * time.Millisecond
			}
			if timeout > 10*time.Second {
				timeout = 10 * time.Second
			}
			grab := p.Grab == nil || *p.Grab

			ports := make([]int, 0, len(portSet))
			for pt := range portSet {
				ports = append(ports, pt)
			}
			sort.Ints(ports)

			start := time.Now()
			type job struct {
				host string
				port int
			}
			jobs := make(chan job)
			results := make([]tcpProbeResult, 0, len(p.Hosts)*8)
			var mu sync.Mutex
			var wg sync.WaitGroup
			const workers = 300
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := range jobs {
						if ctx.Err() != nil {
							return
						}
						r := probeOne(ctx, j.host, j.port, timeout, grab)
						mu.Lock()
						results = append(results, r)
						mu.Unlock()
					}
				}()
			}
		produce:
			for _, h := range p.Hosts {
				for _, pt := range ports {
					select {
					case jobs <- job{host: strings.TrimSpace(h), port: pt}:
					case <-ctx.Done():
						break produce
					}
				}
			}
			close(jobs)
			wg.Wait()

			// 只回开放端口 + 汇总，闭合端口不逐条占上下文。
			open := make([]tcpProbeResult, 0, len(results)/10+1)
			closed := 0
			for _, r := range results {
				if r.Open {
					open = append(open, r)
				} else {
					closed++
				}
			}
			return jsonResult(map[string]any{
				"open_count":      len(open),
				"closed_filtered": closed,
				"hosts":           len(p.Hosts),
				"ports_per_host":  len(ports),
				"elapsed_ms":      time.Since(start).Milliseconds(),
				"open":            open,
			})
		})
}

// tcpProbeResult is one host×port probe outcome; only open hits carry banner.
type tcpProbeResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Banner  string `json:"banner,omitempty"`
	Service string `json:"service,omitempty"`
	Err     string `json:"error,omitempty"`
}

// httpLikePorts gates the follow-up HEAD probe: silent non-HTTP services (SMB,
// RDP, DB…) must not receive HTTP noise — only HTTP-family ports get probed.
var httpLikePorts = map[int]bool{80: true, 81: true, 88: true, 443: true, 591: true, 1080: true, 2082: true, 2083: true, 2087: true, 2095: true, 3000: true, 444: true, 4848: true, 5000: true, 5601: true, 6080: true, 7001: true, 7002: true, 7070: true, 7080: true, 7777: true, 8000: true, 8008: true, 8009: true, 8010: true, 8020: true, 8042: true, 8060: true, 8069: true, 8080: true, 8081: true, 8088: true, 8089: true, 8090: true, 8091: true, 8161: true, 8180: true, 8443: true, 8786: true, 8800: true, 8848: true, 8899: true, 8983: true, 9000: true, 9080: true, 9090: true, 9100: true, 9443: true, 9527: true, 9999: true, 10000: true, 15672: true, 18080: true, 18083: true}

// probeOne dials one host:port, optionally grabs a banner, and tags a coarse
// service guess from the port number.
func probeOne(ctx context.Context, host string, port int, timeout time.Duration, grab bool) tcpProbeResult {
	var r tcpProbeResult
	r.Host, r.Port = host, port
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		r.Err = "closed"
		return r
	}
	defer conn.Close()
	r.Open = true
	r.Service = guessService(port)
	if !grab {
		return r
	}
	_ = conn.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 && httpLikePorts[port] {
		// 无主动回显的【HTTP 类】端口才补一个最小 HEAD 再试读一次；
		// 非 HTTP 服务(SMB/RDP/DB…)不发协议噪音，只记开放。
		_ = conn.SetWriteDeadline(time.Now().Add(900 * time.Millisecond))
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		n, _ = conn.Read(buf)
	}
	if n > 0 {
		b := strings.TrimSpace(string(buf[:n]))
		if len(b) > 200 {
			b = b[:200]
		}
		b = strings.ReplaceAll(b, "\r", " ")
		b = strings.ReplaceAll(b, "\n", " ⏎ ")
		r.Banner = b
	}
	return r
}

// guessService maps well-known ports to a coarse service label.
func guessService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80, 81, 88, 443, 8000, 8008, 8009, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9080, 9090, 18080:
		return "http"
	case 110:
		return "pop3"
	case 135, 139, 445:
		return "smb/rpc"
	case 143:
		return "imap"
	case 389, 636:
		return "ldap"
	case 4444:
		return "metasploit?"
	case 5432:
		return "postgresql"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2049:
		return "nfs"
	case 2375, 2376, 2377:
		return "docker-api"
	case 3306, 33060:
		return "mysql"
	case 3389:
		return "rdp"
	case 5984:
		return "couchdb"
	case 6379:
		return "redis"
	case 7001, 7002, 4848:
		return "weblogic"
	case 8161:
		return "activemq"
	case 9200, 9300:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 27017, 27018:
		return "mongodb"
	case 5601:
		return "kibana"
	case 5672, 15672:
		return "rabbitmq/amqp"
	case 2181:
		return "zookeeper"
	case 1099:
		return "java-rmi"
	case 5900, 5901:
		return "vnc"
	case 1723:
		return "pptp-vpn"
	case 1194:
		return "openvpn"
	case 500, 4500:
		return "ipsec-vpn"
	}
	return ""
}
