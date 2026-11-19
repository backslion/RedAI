package agent

// NBNS 主机名发现（YCode 二开 · 内网纵深）：nbns_probe 向 Windows 主机的 UDP 137
// (NetBIOS Name Service) 发 Node Status Request，取回其 NetBIOS 名称表——主机名、
// 登录用户名(<03> Messenger)、域/工作组(<00> DOMAIN)、文件服务(<20>) 等标识。
// 这是 Windows 网段「IP→主机名/当前登录用户」最便宜的一跳：无需凭据、单 UDP 包。
// 前置：tcp_probe 摸出 137 开放的 Windows 主机。协议按 RFC 1002 手写，零依赖。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// nbnsDecodeName 解码第一级编码名（32 字节 → 15 字节名字 + 后缀）。
func nbnsDecodeName(enc []byte) (name string, suffix byte) {
	if len(enc) < 32 {
		return "", 0
	}
	out := make([]byte, 0, 15)
	for i := 0; i+1 < 32; i += 2 {
		a, b := enc[i], enc[i+1]
		// 'A'..'P' 编码：每两个字符还原 1 字节
		if a < 'A' || a > 'P' || b < 'A' || b > 'P' {
			continue
		}
		out = append(out, ((a-'A')<<4)|(b-'A'))
	}
	// 名称补齐空格
	for len(out) > 0 && out[len(out)-1] == 0x20 {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "", 0
	}
	name = string(out[:len(out)-1])
	return strings.TrimSpace(name), out[len(out)-1]
}

var nbnsSuffixNames = map[byte]string{
	0x00: "工作站/重定向器",
	0x03: "Messenger(当前登录用户)",
	0x06: "RAS 服务",
	0x1B: "域主浏览器(DC)",
	0x1C: "域控制器组",
	0x1D: "主浏览器",
	0x1E: "浏览器选举",
	0x20: "文件服务器",
	0x21: "RAS 客户端",
}

// nbnsNodeStatus 向 target:137 发 Node Status Request 并解析名称表。
func nbnsNodeStatus(target string, timeout time.Duration) (ip string, entries []map[string]any, err error) {
	// Transaction ID + Flags(0x0000) + QDCOUNT=1 + ANCOUNT/NSCOUNT/ARCOUNT=0
	var q [50]byte
	_, _ = rand.Read(q[:2]) // 事务 ID 随机
	q[2], q[3] = 0x00, 0x00
	binary.BigEndian.PutUint16(q[4:], 1) // QDCOUNT
	// QNAME：* 编码（RFC 1002 node status 用 * 作为名字）
	name := "*"
	enc := make([]byte, 32)
	for i := range enc {
		enc[i] = 'A'
	}
	pay := []byte(name)
	for i := 0; i < len(pay); i++ {
		enc[i*2] = 'A' + (pay[i] >> 4)
		enc[i*2+1] = 'A' + (pay[i] & 0x0F)
	}
	copy(q[12:], enc)
	q[44], q[45] = 0x00, 0x20 // QTYPE = NBSTAT(0x0021)
	q[46], q[47] = 0x00, 0x01 // QCLASS = IN

	conn, err := net.DialTimeout("udp", net.JoinHostPort(target, "137"), timeout)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q[:]); err != nil {
		return "", nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", nil, err
	}
	if n < 57 {
		return "", nil, fmt.Errorf("NBNS 应答过短(%d 字节)", n)
	}
	// 应答：header 12 + name(34) + RR fields(10) + RDLENGTH(2) + rdata
	off := 56
	rdLen := int(binary.BigEndian.Uint16(buf[54:56]))
	if off+rdLen > n {
		rdLen = n - off
	}
	if rdLen < 1 {
		return "", nil, fmt.Errorf("NBNS 应答无数据")
	}
	numNames := int(buf[off])
	rdata := buf[off+1 : off+rdLen]
	pos := 0
	entries = []map[string]any{}
	for i := 0; i < numNames && pos+18 <= len(rdata); i++ {
		enc2 := rdata[pos : pos+16] // 实际 15 名称 + 1 后缀（未二次编码）
		pos += 16
		flags := binary.BigEndian.Uint16(rdata[pos : pos+2])
		pos += 2
		name := strings.TrimRight(string(enc2[:15]), " ")
		suffix := enc2[15]
		if name == "" {
			continue
		}
		entry := map[string]any{
			"name":    name,
			"type":    fmt.Sprintf("0x%02X", suffix),
			"type_zh": nbnsSuffixNames[suffix],
			"unique":  flags&0x8000 == 0, // G 位：0=UNIQUE
		}
		entries = append(entries, entry)
	}
	// MAC 地址在名称表后 6 字节
	if pos+6 <= len(rdata) {
		mac := rdata[pos : pos+6]
		entries = append(entries, map[string]any{
			"name": fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
			"type": "mac",
		})
	}
	return target, entries, nil
}

func (t *ToolSet) nbnsProbe() actool.CoreTool {
	return readTool("nbns_probe",
		"(内网纵深)NBNS 主机名发现：对 Windows 主机(UDP 137)发 NetBIOS Node Status Request，取回名称表——计算机名、当前登录用户名(<03> Messenger 记录，无凭据拿到谁在用这台机器！)、域/工作组名、文件服务角色、MAC 地址。这是「IP→主机名+在线用户」最便宜的一跳：单 UDP 包、无凭据。前置：tcp_probe 摸到 137/UDP 开放(或 445 开放的 Windows)。产出直接进域内地图：登录用户→凭据复用候选，域记录→域控定位(配合 asrep_roast/ldap_enum)。只读探测。",
		obj(map[string]any{
			"hosts": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "目标 IP 列表(≤32)，如 [\"10.0.0.5\",\"10.0.0.8\"]。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 3000, "description": "单请求超时毫秒(1000..8000)。UDP 无响应=不开 NBNS。",
			},
		}, "hosts"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Hosts     []string `json:"hosts"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			var hosts []string
			for _, h := range p.Hosts {
				if h = strings.TrimSpace(h); h != "" {
					hosts = append(hosts, h)
				}
			}
			if len(hosts) == 0 {
				return actool.Errorf("hosts 不能为空"), nil
			}
			if len(hosts) > 32 {
				return actool.Errorf("主机过多(>32)，请分批"), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 3 * time.Second
			}
			if timeout > 8*time.Second {
				timeout = 8 * time.Second
			}

			type hostResult struct {
				IP      string           `json:"ip"`
				Entries []map[string]any `json:"entries,omitempty"`
				Error   string           `json:"error,omitempty"`
				Summary string           `json:"summary,omitempty"`
			}
			results := make([]hostResult, 0, len(hosts))
			hitCount := 0
			for _, h := range hosts {
				if ctx.Err() != nil {
					break
				}
				r := hostResult{IP: h}
				_, entries, err := nbnsNodeStatus(h, timeout)
				if err != nil {
					r.Error = "无 NBNS 应答(非 Windows 或 137 被过滤)"
					results = append(results, r)
					continue
				}
				r.Entries = entries
				var parts []string
				loginUser, computer, domain := "", "", ""
				for _, e := range entries {
					if e["type"] == "mac" {
						parts = append(parts, "MAC "+e["name"].(string))
						continue
					}
					switch e["type"] {
					case "0x03":
						loginUser = e["name"].(string)
					case "0x00":
						if e["unique"].(bool) {
							computer = e["name"].(string)
						} else {
							domain = e["name"].(string)
						}
					case "0x1B", "0x1C":
						domain = e["name"].(string) + "(DC)"
					case "0x20":
						parts = append(parts, "文件服务:"+e["name"].(string))
					}
				}
				if loginUser != "" {
					parts = append(parts, "登录用户:"+loginUser+"——凭据复用候选")
				}
				if computer != "" {
					parts = append(parts, "主机名:"+computer)
				}
				if domain != "" {
					parts = append(parts, "域/组:"+domain)
				}
				r.Summary = strings.Join(parts, "；")
				hitCount++
				results = append(results, r)
			}
			out := map[string]any{"results": results, "responded": hitCount}
			if hitCount > 0 {
				out["verdict"] = fmt.Sprintf("%d/%d 台主机返回 NBNS 名称表——登录用户/域名已入地图，凭据复用矩阵候选+1", hitCount, len(hosts))
			} else {
				out["verdict"] = "无主机响应 NBNS(非 Windows 网段或 UDP 137 被过滤)——改用 tcp_probe 445/88 特征判断"
			}
			return jsonResult(out)
		})
}
