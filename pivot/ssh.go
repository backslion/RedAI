package pivot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialChain 逐跳建立 SSH 连接并返回最后一跳的 client。
//
// 多跳怎么实现：第 1 跳用本机 TCP 直连；第 2 跳起的 TCP 连接建在上一跳的
// direct-tcpip 通道上（prev.Dial），所以中间主机不需要装客户端、不需要出网、
// 也不会落任何文件——这是 SSH 协议本身的能力，不是我们自己搭的代理。
//
// 返回值 fp 是最后一跳的主机密钥指纹。取最后一跳是因为：前面的跳板机凭据
// 通常已验证过，而最后一跳往往是最新接触的机器，指纹更值得人工核对。
func dialChain(ctx context.Context, dial func(context.Context, string) (net.Conn, error), hops []Hop) (*ssh.Client, string, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: dialTimeout}
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}

	var prev *ssh.Client
	var lastFP string

	for i, h := range hops {
		addr := strings.TrimSpace(h.Addr)
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "22")
		}

		var conn net.Conn
		var err error
		if prev == nil {
			conn, err = dial(ctx, addr)
			if err != nil {
				return nil, "", fmt.Errorf("第 %d 跳 %s 连接失败: %w", i+1, addr, wrapDialErr(err))
			}
		} else {
			// 经上一跳开通道。这里没有独立超时：ssh.Client.Dial 会受底层
			// TCP 与 SSH 层的超时约束，外面再套一层容易误杀慢链路。
			conn, err = prev.Dial("tcp", addr)
			if err != nil {
				prev.Close()
				return nil, "", fmt.Errorf("第 %d 跳 %s 无法经上一跳到达: %w", i+1, addr, err)
			}
		}

		fp := ""
		cfg := &ssh.ClientConfig{
			User: h.User,
			Auth: authMethods(h),
			// 渗透现场拿不到 known_hosts，硬校验会让工具在真实目标上完全不可用。
			// 取舍：接受任意主机密钥，但把指纹回传给调用方核对（见 Tunnel.HostKey）。
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				fp = ssh.FingerprintSHA256(key)
				return nil
			},
			Timeout: dialTimeout,
		}
		if len(cfg.Auth) == 0 {
			conn.Close()
			return nil, "", fmt.Errorf("第 %d 跳 %s 没有可用认证方式", i+1, addr)
		}

		c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			conn.Close()
			return nil, "", fmt.Errorf("第 %d 跳 %s SSH 握手失败: %w", i+1, addr, wrapAuthErr(err))
		}
		if fp != "" {
			lastFP = fp
		}
		prev = ssh.NewClient(c, chans, reqs)
	}
	return prev, lastFP, nil
}

// authMethods 按凭据类型组装认证方式。顺序：私钥优先（更常见于运维跳板），
// 其次口令，最后 keyboard-interactive（不少 sshd 只开这个给口令用户）。
func authMethods(h Hop) []ssh.AuthMethod {
	var out []ssh.AuthMethod
	if len(h.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if len(h.Passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(h.PrivateKey, h.Passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(h.PrivateKey)
		}
		if err == nil {
			out = append(out, ssh.PublicKeys(signer))
		}
	}
	if h.Password != "" {
		out = append(out, ssh.Password(h.Password))
		out = append(out, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = h.Password
			}
			return answers, nil
		}))
	}
	return out
}

// wrapDialErr 把常见网络错误翻成「下一步该做什么」，避免 agent 在
// connection refused 上空转（通常是端口不对，而不是凭据问题）。
func wrapDialErr(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("超时（网络不可达或被过滤）：%w", err)
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return fmt.Errorf("端口拒绝连接（服务未监听或端口写错）：%w", err)
	case strings.Contains(s, "no route to host"):
		return fmt.Errorf("无路由（当前网络到不了这个地址，先确认是否需要经已有隧道）：%w", err)
	case strings.Contains(s, "i/o timeout"):
		return fmt.Errorf("连接超时（可能被防火墙丢包）：%w", err)
	}
	return err
}

// wrapAuthErr 区分「认证失败」与「协议/算法不兼容」，这两种的处置完全不同。
func wrapAuthErr(err error) error {
	if err == nil {
		return nil
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "unable to authenticate") || strings.Contains(s, "no supported methods") {
		return fmt.Errorf("认证失败（口令/私钥不被接受，或该用户禁止登录）：%w", err)
	}
	if strings.Contains(s, "handshake failed") {
		return fmt.Errorf("握手失败（可能是非 SSH 服务、或算法过旧被拒）：%w", err)
	}
	return err
}

// waitConn 等待连接可读（probe 用）：给一个字节的读超时，能读到或超时都算通。
// 单独抽出来是因为 probe 的语义是「TCP 层是否可达」，不该等应用层数据。
func waitConn(conn net.Conn, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var b [1]byte
	n, err := conn.Read(b[:])
	if n > 0 {
		return true, nil
	}
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// 连上了但没数据：端口开放且服务静默（SSH/SMB 常见），算可达。
			return true, nil
		}
		// 对端立刻关闭：端口开放但服务拒绝握手（例如只接受 TLS 的端口收到明文）。
		if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "EOF") {
			return true, nil
		}
		return false, err
	}
	return true, nil
}
