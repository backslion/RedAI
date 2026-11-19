package agent

// SMB 枚举与凭据验证工具（YCode 二开 · Windows 域纵深）：smb_check 对 host:445 做
// ① SMB2 协商（dialect/签名/GUID 指纹）②匿名/空会话尝试 ③【凭据验证】NTLMv2 逐组合
// 登录（每组合一次，≤5 组合）④会话成功后 TREE_CONNECT 探测常见共享存在性。
// 与 ssh_check/http_login_check 同一定位：验证器不是爆破器。协议按 MS-SMB2/MS-NLMP
// 手写（SMB2 直连 0xFE'SMB' 头 + NTLM type1/2/3 + MD4/HMAC-MD5，x/crypto/md4）。
// 副产品 oracle：NO_SUCH_USER / WRONG_PASSWORD / ACCOUNT_DISABLED / LOCKED_OUT 的
// 状态码差异即用户名与账号状态枚举。

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLM 协议规定 MD5
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/md4" //nolint:gosec // NTLM 协议规定 MD4

	actool "github.com/Autumn-27/norma/tool"
)

// ---------- SMB2 常量 ----------

const (
	smb2Negotiate    = 0x0000
	smb2SessionSetup = 0x0001
	smb2TreeConnect  = 0x0003
	smb2Logoff       = 0x0002

	smbStatusSuccess                = 0x00000000
	smbStatusMoreProcessingRequired = 0xC0000016
	smbStatusAccessDenied           = 0xC0000022
	smbStatusNoSuchUser             = 0xC0000064
	smbStatusWrongPassword          = 0xC000006A
	smbStatusAccountDisabled        = 0xC0000072
	smbStatusAccountLockedOut       = 0xC0000234
	smbStatusLogonFailure           = 0xC000006D
	smbStatusBadNetworkName         = 0xC00000CC
	smbStatusNotSupported           = 0xC00000BB
)

var smbStatusText = map[uint32]string{
	smbStatusSuccess:                "成功",
	smbStatusMoreProcessingRequired: "需要更多处理(challenge)",
	smbStatusAccessDenied:           "拒绝访问",
	smbStatusNoSuchUser:             "用户不存在",
	smbStatusWrongPassword:          "口令错误",
	smbStatusAccountDisabled:        "账号已禁用",
	smbStatusAccountLockedOut:       "账号已锁定",
	smbStatusLogonFailure:           "登录失败(用户或口令不符)",
	smbStatusBadNetworkName:         "共享不存在",
	smbStatusNotSupported:           "服务器不支持该操作",
}

// defaultShares 探测存在性的常见共享（只做存在性判定，不读写内容）。
var defaultShares = []string{"IPC$", "ADMIN$", "C$", "SYSVOL", "NETLOGON", "print$", "public", "shared", "share"}

// ---------- NTLM（MS-NLMP） ----------

const ntlmSignature = "NTLMSSP\x00"

func ntlmType1(domain string) []byte {
	flags := uint32(0x00000201 | 0x00000900) // NEGOTIATE_NTLM | OEM/UNICODE | REQUEST_TARGET + NTLM v? ; 0x200=NTLM2 session…
	flags = 0x88201 | 0x800000 | 0x00200000  // UNICODE|OEM|REQUEST_TARGET|NTLM|ALWAYS_SIGN|NTLM2_KEY 简化集
	var b []byte
	b = append(b, ntlmSignature...)
	b = binary.LittleEndian.AppendUint32(b, 1) // type 1
	b = binary.LittleEndian.AppendUint32(b, flags)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(domain))) // domain len/alloc
	b = binary.LittleEndian.AppendUint16(b, uint16(len(domain)))
	b = binary.LittleEndian.AppendUint32(b, 32+uint32(len(domain))) // offset
	b = binary.LittleEndian.AppendUint32(b, 0)                      // workstation len/alloc
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = append(b, []byte(domain)...)
	return b
}

// ntlmType2 解析 type2 挑战：challenge + targetInfo（NTLMv2 blob 需要）。
func ntlmType2(msg []byte) (challenge []byte, targetInfo []byte, flags uint32, err error) {
	if len(msg) < 32 || string(msg[:7]) != "NTLMSSP" {
		return nil, nil, 0, fmt.Errorf("不是 NTLMSSP 消息")
	}
	typ := binary.LittleEndian.Uint32(msg[8:12])
	if typ != 2 {
		return nil, nil, 0, fmt.Errorf("期望 type2，得到 type %d", typ)
	}
	flags = binary.LittleEndian.Uint32(msg[20:24])
	challenge = msg[24:32]
	// MS-NLMP CHALLENGE_MESSAGE：targetInfoFields 在偏移 40（len2/alloc2/offset4）
	tiLen, tiOff := uint16(0), uint32(0)
	if len(msg) >= 48 {
		tiLen = binary.LittleEndian.Uint16(msg[40:42])
		tiOff = binary.LittleEndian.Uint32(msg[44:48])
		if int(tiOff)+int(tiLen) <= len(msg) && tiLen > 0 {
			targetInfo = msg[tiOff : tiOff+uint32(tiLen)]
		}
	}
	return challenge, targetInfo, flags, nil
}

func ntHash(password string) []byte {
	h := md4.New() //nolint:gosec // NTLM 规定
	h.Write([]byte(utf16LE(password)))
	return h.Sum(nil)
}

func utf16LE(s string) []byte {
	runes := []rune(s)
	u := make([]uint16, len(runes))
	for i, r := range runes {
		u[i] = uint16(r)
	}
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key) //nolint:gosec // NTLM 规定
	m.Write(data)
	return m.Sum(nil)
}

// computeNTLMv2 是 NTLMv2 响应的纯函数核心（可测试）：返回 (ntResp, lmResp)。
// blob: 0x01010000 + reserved(4) + filetime(8) + clientChallenge(8) + 0 + targetInfo + 0；
// ntResp = HMAC-MD5(ntlmv2Hash, serverChallenge||blob) || blob；
// lmResp = HMAC-MD5(ntlmv2Hash, serverChallenge||clientChallenge) || clientChallenge。
func computeNTLMv2(user, password, domain string, serverChallenge, clientChallenge, targetInfo []byte, filetime uint64) (ntResp, lmResp []byte) {
	nt := ntHash(password)
	ntlmv2 := hmacMD5(nt, utf16LE(strings.ToUpper(user)+strings.ToUpper(domain)))
	var blob []byte
	blob = append(blob, 0x01, 0x01, 0x00, 0x00)
	blob = binary.LittleEndian.AppendUint32(blob, 0)
	blob = binary.LittleEndian.AppendUint64(blob, filetime)
	blob = append(blob, clientChallenge...)
	blob = binary.LittleEndian.AppendUint32(blob, 0)
	blob = append(blob, targetInfo...)
	blob = binary.LittleEndian.AppendUint32(blob, 0)
	ntResp = append(hmacMD5(ntlmv2, append(append([]byte{}, serverChallenge...), blob...)), blob...)
	lmResp = append(hmacMD5(ntlmv2, append(append([]byte{}, serverChallenge...), clientChallenge...)), clientChallenge...)
	return ntResp, lmResp
}

// ntlmType3 按 NTLMv2 构造认证消息。
func ntlmType3(user, password, domain string, challenge, targetInfo []byte) []byte {
	cc := make([]byte, 8)
	_, _ = rand.Read(cc)
	// FILETIME since 1601-01-01 in 100ns
	ts := uint64(time.Now().UnixNano()/100) + 116444736000000000
	ntResp, lmResp := computeNTLMv2(user, password, domain, challenge, cc, targetInfo, ts)

	flags := uint32(0x88201 | 0x800000 | 0x00200000) // UNICODE|OEM|REQUEST_TARGET|NTLM|ALWAYS_SIGN|NTLM2_KEY
	enc := func(s string) (uint16, uint16, uint32, []byte) {
		b := utf16LE(s)
		return uint16(len(b)), uint16(len(b)), 0, b
	}
	dl, da, _, db := enc(domain)
	ul, ua, _, ub := enc(user)
	wl, wa, _, wb := enc("YCODE")
	l1, l2 := uint16(len(lmResp)), uint16(len(ntResp))
	// 计算 buffer 起始 offset：header 64(type3 基础头)
	off := uint32(64)
	dOff := off
	uOff := dOff + uint32(da)
	wOff := uOff + uint32(ua)
	lOff := wOff + uint32(wa)
	nOff := lOff + uint32(l1)
	var b []byte
	b = append(b, ntlmSignature...)
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint16(b, l1) // LM
	b = binary.LittleEndian.AppendUint16(b, l1)
	b = binary.LittleEndian.AppendUint32(b, lOff)
	b = binary.LittleEndian.AppendUint16(b, l2) // NT
	b = binary.LittleEndian.AppendUint16(b, l2)
	b = binary.LittleEndian.AppendUint32(b, nOff)
	b = binary.LittleEndian.AppendUint16(b, dl)
	b = binary.LittleEndian.AppendUint16(b, da)
	b = binary.LittleEndian.AppendUint32(b, dOff)
	b = binary.LittleEndian.AppendUint16(b, ul)
	b = binary.LittleEndian.AppendUint16(b, ua)
	b = binary.LittleEndian.AppendUint32(b, uOff)
	b = binary.LittleEndian.AppendUint16(b, wl)
	b = binary.LittleEndian.AppendUint16(b, wa)
	b = binary.LittleEndian.AppendUint32(b, wOff)
	b = binary.LittleEndian.AppendUint32(b, flags)
	b = binary.LittleEndian.AppendUint32(b, 0) // end of header fields
	// payload 顺序：domain,user,workstation,lm,nt
	b = append(b, db...)
	b = append(b, ub...)
	b = append(b, wb...)
	b = append(b, lmResp...)
	b = append(b, ntResp...)
	return b
}

// 从 SPNEGO/应答安全缓冲里定位 NTLM type2（Windows 将其明文内嵌）。
func extractNTLMType2(buf []byte) []byte {
	for i := 0; i+12 <= len(buf); i++ {
		if string(buf[i:i+7]) == "NTLMSSP" && buf[i+7] == 0 && binary.LittleEndian.Uint32(buf[i+8:i+12]) == 2 {
			return buf[i:]
		}
	}
	return nil
}

// ---------- SMB2 帧 ----------

type smbFrame struct {
	command   uint16
	status    uint32
	sessionID uint64
	treeID    uint32
	body      []byte
}

func smbHeader(cmd uint16, sessionID uint64, treeID uint32, bodyLen int) []byte {
	// MS-SMB2 2.2.1：SMB2 header 共 64 字节（含 magic），数组下标即 header 偏移。
	h := make([]byte, 64)
	copy(h, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)   // StructureSize
	binary.LittleEndian.PutUint16(h[6:], 1)    // CreditCharge
	binary.LittleEndian.PutUint32(h[8:], 0)    // Status
	binary.LittleEndian.PutUint16(h[12:], cmd) // Command
	binary.LittleEndian.PutUint16(h[14:], 1)   // Credits requested
	binary.LittleEndian.PutUint32(h[16:], 0)   // Flags
	binary.LittleEndian.PutUint32(h[20:], 0)   // NextCommand
	binary.LittleEndian.PutUint64(h[24:], 0)   // MessageId
	binary.LittleEndian.PutUint32(h[32:], 0)   // Reserved/ProcessId
	binary.LittleEndian.PutUint32(h[36:], treeID)
	binary.LittleEndian.PutUint64(h[40:], sessionID)
	// signature 16 字节零（不启用签名）
	h = append(h, make([]byte, bodyLen)...)
	return h
}

func smbNetBios(frame []byte) []byte {
	n := len(frame)
	return append([]byte{0, byte(n >> 16), byte(n >> 8), byte(n)}, frame...)
}

func parseSMB2(reply []byte) (*smbFrame, error) {
	if len(reply) < 72 || reply[0] != 0 || reply[4] != 0xFE || reply[5] != 'S' || reply[6] != 'M' || reply[7] != 'B' {
		return nil, fmt.Errorf("不是合法 SMB2 应答(%d 字节)", len(reply))
	}
	h := reply[4:] // 去掉 NetBIOS 前缀，此后 h[0]=magic，下标与 SMB2 header 相对偏移一致
	return &smbFrame{
		status:    binary.LittleEndian.Uint32(h[8:12]),
		command:   binary.LittleEndian.Uint16(h[12:14]),
		sessionID: binary.LittleEndian.Uint64(h[40:48]),
		treeID:    binary.LittleEndian.Uint32(h[36:40]),
		body:      h[64:],
	}, nil
}

// smbNegotiate 发送 SMB2 NEGOTIATE，返回 dialect/签名/安全缓冲（含 type2? negotiate 不含 NTLM）。
func smbNegotiate(conn net.Conn) (*smbFrame, error) {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	body := make([]byte, 0)
	body = binary.LittleEndian.AppendUint16(body, 36) // StructureSize
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects)))
	body = binary.LittleEndian.AppendUint16(body, 1) // signing enabled
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 1) // DFS capabilities
	guid := make([]byte, 16)
	_, _ = rand.Read(guid)
	body = append(body, guid...)
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	frame := smbHeader(smb2Negotiate, 0, 0, len(body))
	copy(frame[64:], body)
	if _, err := conn.Write(smbNetBios(frame)); err != nil {
		return nil, err
	}
	reply, err := smbRead(conn, 8*time.Second)
	if err != nil {
		return nil, err
	}
	return parseSMB2(reply)
}

// smbSessionSetup 发送 session setup：ntlmMsg 为 nil 时发 type1（取 challenge）。
func smbSessionSetup(conn net.Conn, sessionID uint64, ntlmMsg []byte) (*smbFrame, []byte, error) {
	if ntlmMsg == nil {
		ntlmMsg = ntlmType1("")
	}
	body := make([]byte, 0)
	body = binary.LittleEndian.AppendUint16(body, 25) // StructureSize
	body = append(body, 0)                            // Flags (1 字节)
	body = append(body, 1)                            // SecurityMode: signing enabled (1 字节)
	body = binary.LittleEndian.AppendUint32(body, 0)  // Capabilities
	body = binary.LittleEndian.AppendUint32(body, 0)  // Channel
	body = binary.LittleEndian.AppendUint16(body, 80) // SecurityBufferOffset (64 header + 16)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(ntlmMsg)))
	frame := smbHeader(smb2SessionSetup, sessionID, 0, 16+len(ntlmMsg))
	copy(frame[64:], body)
	copy(frame[80:], ntlmMsg)
	if _, err := conn.Write(smbNetBios(frame)); err != nil {
		return nil, nil, err
	}
	reply, err := smbRead(conn, 8*time.Second)
	if err != nil {
		return nil, nil, err
	}
	f, err := parseSMB2(reply)
	if err != nil {
		return nil, nil, err
	}
	var secBuf []byte
	if len(f.body) >= 16 {
		// SecurityBufferOffset 从 SMB2 header 起算（MS-SMB2 2.2.6）
		off := binary.LittleEndian.Uint16(f.body[12:14])
		ln := binary.LittleEndian.Uint16(f.body[14:16])
		if int(off)+int(ln) <= len(reply) && ln > 0 {
			secBuf = reply[off : int(off)+int(ln)]
		}
	}
	return f, secBuf, nil
}

// smbTreeConnect 探测共享存在性。
func smbTreeConnect(conn net.Conn, sessionID uint64, host, share string) (*smbFrame, error) {
	path := utf16LE(`\\` + host + `\` + share)
	body := make([]byte, 0)
	body = binary.LittleEndian.AppendUint16(body, 9)  // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 0)  // Flags
	body = binary.LittleEndian.AppendUint16(body, 72) // PathOffset (64 header + 8)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(path)))
	frame := smbHeader(smb2TreeConnect, sessionID, 0, 8+len(path))
	copy(frame[64:], body)
	copy(frame[72:], path)
	if _, err := conn.Write(smbNetBios(frame)); err != nil {
		return nil, err
	}
	reply, err := smbRead(conn, 8*time.Second)
	if err != nil {
		return nil, err
	}
	return parseSMB2(reply)
}

// smbRead 按 NetBIOS 长度前缀读一帧。
func smbRead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var nb [4]byte
	if _, err := ioReadFull(conn, nb[:]); err != nil {
		return nil, err
	}
	n := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if n <= 0 || n > 1<<20 {
		return nil, fmt.Errorf("SMB 帧长度异常 %d", n)
	}
	buf := make([]byte, n)
	if _, err := ioReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---------- 工具 ----------

func (t *ToolSet) smbCheck() actool.CoreTool {
	return readTool("smb_check",
		"(域纵深)SMB 枚举与凭据验证：对 host:445 做 ①SMB2 协商(dialect/签名指纹) ②匿名会话尝试 ③逐个验证【domain\\user+password】组合(NTLMv2，每组合一次，≤5) ④会话成功则 TREE_CONNECT 探测常见共享(ADMIN$/C$/SYSVOL/NETLOGON/IPC$…)存在性。状态码 oracle：NO_SUCH_USER=用户不存在 / WRONG_PASSWORD=用户有效口令错 / ACCOUNT_DISABLED / ACCOUNT_LOCKED_OUT / ACCESS_DENIED。用于：①拿到内网 Windows 主机后摸底 SMB ②验证凭据(尤其凭据复用矩阵的 SMB 入口) ③SYSVOL/NETLOGON 可读=域成员信号，SYSVOL 里的 GPP(cpassword) 是经典凭据源。验证器不是爆破器，遵守防锁定纪律。",
		obj(map[string]any{
			"host": map[string]any{
				"type": "string", "description": "目标主机(IP 或域名)。",
			},
			"credentials": map[string]any{
				"type":        "array",
				"description": "凭据组合(≤5)：[{\"domain\":\"CORP\",\"username\":\"admin\",\"password\":\"...\"}]。domain 可空(默认按 host/workgroup)。留空=只做匿名探测。",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"domain":   map[string]any{"type": "string", "description": "域名/NETBIOS 域，可空"},
						"username": map[string]any{"type": "string"},
						"password": map[string]any{"type": "string"},
					},
					"required": []string{"username"},
				},
			},
			"port": map[string]any{
				"type": "integer", "default": 445, "description": "SMB 端口(默认 445)。",
			},
			"shares": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "额外要探测的共享名(与默认 9 个叠加)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 6000, "description": "单请求超时毫秒(2000..15000)。",
			},
		}, "host"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Host        string `json:"host"`
				Credentials []struct {
					Domain   string `json:"domain"`
					Username string `json:"username"`
					Password string `json:"password"`
				} `json:"credentials"`
				Port      int      `json:"port"`
				Shares    []string `json:"shares"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			host := strings.TrimSpace(p.Host)
			if host == "" {
				return actool.Errorf("host 不能为空"), nil
			}
			if p.Port <= 0 {
				p.Port = 445
			}
			if len(p.Credentials) > 5 {
				return actool.Errorf(fmt.Sprintf("凭据组合过多(%d>5)：验证器不是爆破器，请分批", len(p.Credentials))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 6 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.Port))

			out := map[string]any{"host": host, "port": p.Port}

			// ---- ① 协商 ----
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return actool.Errorf("SMB 端口不可达: " + err.Error()), nil
			}
			defer func() { _ = conn.Close() }()
			neg, err := smbNegotiate(conn)
			if err != nil {
				return actool.Errorf("SMB2 协商失败(可能不是 SMB 或协议异常): " + err.Error()), nil
			}
			dialect := uint32(0)
			if len(neg.body) >= 8 {
				dialect = uint32(binary.LittleEndian.Uint16(neg.body[4:6]))
			}
			out["negotiate"] = map[string]any{
				"status":  smbStatusText[neg.status],
				"dialect": fmt.Sprintf("0x%04x", dialect),
				"signing": neg.status == smbStatusSuccess,
			}
			if neg.status != smbStatusSuccess {
				out["verdict"] = "SMB2 协商未成功(状态 " + smbStatusText[neg.status] + ")，终止"
				return jsonResult(out)
			}

			// ---- ② 匿名尝试 ----
			anon := map[string]any{}
			f, secBuf, err := smbSessionSetup(conn, 0, nil)
			if err != nil {
				anon["error"] = err.Error()
			} else {
				anon["status"] = smbStatusText[f.status]
				anon["status_code"] = fmt.Sprintf("0x%08X", f.status)
				if f.status == smbStatusMoreProcessingRequired {
					anon["note"] = "服务器要求 challenge 流程(正常)，匿名成败取决于 type3 应答"
					type2 := extractNTLMType2(secBuf)
					if type2 != nil {
						chal, ti, _, terr := ntlmType2(type2)
						if terr == nil {
							_ = chal
							f3, _, err3 := smbSessionSetup(conn, f.sessionID, ntlmType3("guest", "", "", chal, ti))
							if err3 != nil {
								anon["anon_result"] = "error: " + err3.Error()
							} else {
								anon["anon_result"] = smbStatusText[f3.status]
								anon["anon_status_code"] = fmt.Sprintf("0x%08X", f3.status)
								anon["anon_ok"] = f3.status == smbStatusSuccess
								if f3.status == smbStatusAccessDenied {
									anon["note"] = anon["note"]
								}
							}
						} else {
							anon["type2_error"] = terr.Error()
						}
					}
				}
			}
			out["anonymous"] = anon

			// ---- ③ 凭据验证（每组合独立连接，避免会话状态串扰）----
			type credResult struct {
				Username string           `json:"username"`
				Domain   string           `json:"domain,omitempty"`
				Verdict  string           `json:"verdict"` // ok / wrong_password / no_such_user / disabled / locked_out / denied / error
				Detail   string           `json:"detail,omitempty"`
				Shares   []map[string]any `json:"shares,omitempty"`
			}
			verdictFromStatus := func(st uint32) (string, string) {
				switch st {
				case smbStatusSuccess:
					return "ok", "认证成功"
				case smbStatusWrongPassword:
					return "wrong_password", "用户有效、口令错误"
				case smbStatusNoSuchUser:
					return "no_such_user", "用户不存在"
				case smbStatusAccountDisabled:
					return "disabled", "账号已禁用(但用户名有效)"
				case smbStatusAccountLockedOut:
					return "locked_out", "账号已锁定——立即停止该账号的一切尝试"
				case smbStatusLogonFailure:
					return "wrong_password", "登录失败(用户或口令不符)"
				case smbStatusAccessDenied:
					return "denied", "认证被拒(匿名映射禁用或权限不足)"
				default:
					return "error", smbStatusText[st]
				}
			}
			results := make([]credResult, 0, len(p.Credentials))
			for i, c := range p.Credentials {
				u := strings.TrimSpace(c.Username)
				if u == "" {
					continue
				}
				res := credResult{Username: u, Domain: strings.TrimSpace(c.Domain)}
				if i > 0 {
					select {
					case <-time.After(300 * time.Millisecond):
					case <-ctx.Done():
						return actool.Errorf("已取消"), nil
					}
				}
				c2, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					res.Verdict, res.Detail = "error", "连接失败: "+err.Error()
					results = append(results, res)
					continue
				}
				defer func() { _ = c2.Close() }()
				if _, err := smbNegotiate(c2); err != nil {
					res.Verdict, res.Detail = "error", "协商失败: "+err.Error()
					results = append(results, res)
					continue
				}
				f1, sec, err := smbSessionSetup(c2, 0, nil)
				if err != nil || f1.status != smbStatusMoreProcessingRequired {
					res.Verdict, res.Detail = "error", "未获得 challenge: "+err.Error()
					results = append(results, res)
					continue
				}
				type2 := extractNTLMType2(sec)
				if type2 == nil {
					res.Verdict, res.Detail = "error", "应答中无 NTLM type2"
					results = append(results, res)
					continue
				}
				chal, ti, _, terr := ntlmType2(type2)
				if terr != nil {
					res.Verdict, res.Detail = "error", terr.Error()
					results = append(results, res)
					continue
				}
				dom := res.Domain
				if dom == "" {
					dom = host
				}
				f3, _, err := smbSessionSetup(c2, f1.sessionID, ntlmType3(u, c.Password, dom, chal, ti))
				if err != nil {
					res.Verdict, res.Detail = "error", err.Error()
					results = append(results, res)
					continue
				}
				res.Verdict, res.Detail = verdictFromStatus(f3.status)
				if f3.status == smbStatusSuccess {
					// ---- ④ 共享探测 ----
					shareList := append([]string{}, defaultShares...)
					shareList = append(shareList, p.Shares...)
					seen := map[string]bool{}
					found := []map[string]any{}
					for _, sh := range shareList {
						if sh = strings.TrimSpace(sh); sh == "" || seen[strings.ToUpper(sh)] {
							continue
						}
						seen[strings.ToUpper(sh)] = true
						tf, terr := smbTreeConnect(c2, f3.sessionID, host, sh)
						if terr != nil {
							continue
						}
						entry := map[string]any{"share": sh}
						switch tf.status {
						case smbStatusSuccess:
							entry["exists"], entry["readable"] = true, true
						case smbStatusAccessDenied:
							entry["exists"], entry["readable"] = true, false
						case smbStatusBadNetworkName:
							entry["exists"] = false
						default:
							entry["exists"] = nil
							entry["status"] = smbStatusText[tf.status]
						}
						found = append(found, entry)
					}
					res.Shares = found
					_, _ = smbRead(c2, time.Second) // 尽力吸收 LOGOFF 应答（不发也行）
				}
				results = append(results, res)
			}
			if len(results) > 0 {
				out["credentials"] = results
				okCount := 0
				for _, r := range results {
					if r.Verdict == "ok" {
						okCount++
					}
				}
				if okCount > 0 {
					out["verdict"] = fmt.Sprintf("%d 个凭据组合认证成功——SMB 入口实证横向，立即 record_intelligence + 试共享面", okCount)
				} else {
					out["verdict"] = "无成功凭据；按状态码 oracle 记录用户名/账号状态结论"
				}
			} else {
				out["verdict"] = "仅完成协商与匿名探测；传 credentials 可做凭据验证与共享探测"
			}
			return jsonResult(out)
		})
}
