package pivot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ─────────────────────────────────────────────────────────────
// 测试用 SSH 服务端：只实现 direct-tcpip，够验证整条链路。
// 用真实 sshd 协议而不是 mock，是因为本功能的关键假设就是
// 「客户端 Dial 经过 SSH 通道拨号」——mock 掉就什么都没验证。
// ─────────────────────────────────────────────────────────────

type testSSHD struct {
	addr string
	ln   net.Listener
	cfg  *ssh.ServerConfig
}

func newTestSSHD(t *testing.T, user, pass string) *testSSHD {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("构造 signer 失败: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshd 监听失败: %v", err)
	}
	s := &testSSHD{addr: ln.Addr().String(), ln: ln, cfg: cfg}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *testSSHD) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *testSSHD) handle(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			_ = nc.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		var p struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			_ = nc.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		target := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
		up, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			_ = nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			_ = up.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			_, _ = io.Copy(ch, up)
			_ = ch.Close()
		}()
		go func() {
			_, _ = io.Copy(up, ch)
			_ = up.Close()
		}()
	}
}

// echoServer 起一个把收到的内容原样回写的 TCP 服务（模拟内网目标）。
func echoServer(t *testing.T) (addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo 监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return ln.Addr().String(), n
}

// socksRoundTrip 经 SOCKS5 连到 target 并发一次数据，返回回显。
func socksRoundTrip(t *testing.T, socksAddr, user, pass, target string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("连 socks 入口失败: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02}
	}
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("握手写失败: %v", err)
	}
	var mr [2]byte
	if _, err := io.ReadFull(c, mr[:]); err != nil {
		t.Fatalf("握手读失败: %v", err)
	}
	if mr[1] == 0xff {
		t.Fatalf("服务端拒绝全部认证方式")
	}
	if mr[1] == 0x02 {
		ub := []byte(user)
		pb := []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("认证写失败: %v", err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			t.Fatalf("认证读失败: %v", err)
		}
		if ar[1] != 0x00 {
			t.Fatalf("认证被拒: %v", ar)
		}
	}

	host, portStr, _ := net.SplitHostPort(target)
	pn, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb2 [2]byte
	binary.BigEndian.PutUint16(pb2[:], uint16(pn))
	req = append(req, pb2[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("请求写失败: %v", err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("应答读失败: %v", err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("CONNECT 失败 rep=0x%02x", rep[1])
	}
	// 吃掉 BND.ADDR
	switch rep[3] {
	case 0x01:
		var b [6]byte
		_, _ = io.ReadFull(c, b[:])
	case 0x04:
		var b [18]byte
		_, _ = io.ReadFull(c, b[:])
	case 0x03:
		var l [1]byte
		_, _ = io.ReadFull(c, l[:])
		b := make([]byte, int(l[0])+2)
		_, _ = io.ReadFull(c, b)
	}

	payload := []byte("hello-through-pivot")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("回显读取失败: %v", err)
	}
	return string(got)
}

func TestSocks5ThroughSSH(t *testing.T) {
	sshd := newTestSSHD(t, "ops", "S3cret!")
	echo, echoPort := echoServer(t)
	_ = echo

	m := NewManager()
	defer m.CloseAll()

	tun, err := m.Open(context.Background(), OpenOptions{
		TaskID: 7, Label: "jump-1", Mode: ModeSocks,
		Hops: []Hop{{Addr: sshd.addr, User: "ops", Password: "S3cret!"}},
		TTL:  time.Minute,
	})
	if err != nil {
		t.Fatalf("开隧道失败: %v", err)
	}
	if !tun.Alive {
		t.Fatal("隧道应立即可用")
	}
	if !strings.HasPrefix(tun.Listen, "127.0.0.1:") {
		t.Fatalf("默认应只绑回环，实际 %s", tun.Listen)
	}
	if tun.HostKey == "" {
		t.Fatal("应记录主机密钥指纹")
	}

	got := socksRoundTrip(t, tun.Listen, "", "", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if got != "hello-through-pivot" {
		t.Fatalf("回显不一致: %q", got)
	}

	// 记账：一次成功连接、字节数非零。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tun.conns.Load() > 0 && tun.up.Load() > 0 && tun.down.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tun.conns.Load() != 1 {
		t.Fatalf("成功连接数应为 1，实际 %d", tun.conns.Load())
	}
	if tun.up.Load() == 0 || tun.down.Load() == 0 {
		t.Fatalf("上下行字节应记账，实际 up=%d down=%d", tun.up.Load(), tun.down.Load())
	}

	v := tun.View(5)
	if len(v.Recent) != 1 || !v.Recent[0].OK {
		t.Fatalf("连接记录应有一条成功项: %+v", v.Recent)
	}
}

func TestPortForwardThroughSSH(t *testing.T) {
	sshd := newTestSSHD(t, "ops", "pw")
	_, echoPort := echoServer(t)

	m := NewManager()
	defer m.CloseAll()
	tun, err := m.Open(context.Background(), OpenOptions{
		TaskID: 7, Mode: ModePortFwd,
		Hops:   []Hop{{Addr: sshd.addr, User: "ops", Password: "pw"}},
		Target: fmt.Sprintf("127.0.0.1:%d", echoPort),
		TTL:    time.Minute,
	})
	if err != nil {
		t.Fatalf("开 portfwd 失败: %v", err)
	}

	c, err := net.DialTimeout("tcp", tun.Listen, 3*time.Second)
	if err != nil {
		t.Fatalf("连转发口失败: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("via-forward")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	buf := make([]byte, 11)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("读失败: %v", err)
	}
	if string(buf) != "via-forward" {
		t.Fatalf("回显不一致: %q", buf)
	}
}

func TestMultiHopChain(t *testing.T) {
	// A 是入口跳板，B 是经 A 才能到的第二跳。echo 在 B 后面。
	a := newTestSSHD(t, "u1", "p1")
	b := newTestSSHD(t, "u2", "p2")
	_, echoPort := echoServer(t)

	m := NewManager()
	defer m.CloseAll()
	tun, err := m.Open(context.Background(), OpenOptions{
		TaskID: 1, Mode: ModeSocks,
		Hops: []Hop{
			{Addr: a.addr, User: "u1", Password: "p1"},
			{Addr: b.addr, User: "u2", Password: "p2"},
		},
		TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("两跳隧道失败: %v", err)
	}
	if len(tun.View(0).Hops) != 2 {
		t.Fatalf("应记录两跳，实际 %d", len(tun.View(0).Hops))
	}
	got := socksRoundTrip(t, tun.Listen, "", "", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if got != "hello-through-pivot" {
		t.Fatalf("两跳回显不一致: %q", got)
	}
}

func TestOpenRejectsBadInput(t *testing.T) {
	sshd := newTestSSHD(t, "u", "p")
	m := NewManager()
	defer m.CloseAll()

	cases := []struct {
		name string
		opts OpenOptions
		want string
	}{
		{"无跳板", OpenOptions{Mode: ModeSocks}, "至少要有一跳"},
		{"缺端口", OpenOptions{Mode: ModeSocks, Hops: []Hop{{Addr: "10.0.0.1", User: "u", Password: "p"}}}, "需带端口"},
		{"缺凭据", OpenOptions{Mode: ModeSocks, Hops: []Hop{{Addr: sshd.addr, User: "u"}}}, "缺少凭据"},
		{"非法模式", OpenOptions{Mode: "reverseshell", Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}}}, "mode 只能是"},
		{"portfwd 无目标", OpenOptions{Mode: ModePortFwd, Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}}}, "必须给 target"},
		{"公网绑定无认证", OpenOptions{Mode: ModeSocks, BindHost: "0.0.0.0", Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}}}, "必须同时设置 socks_user"},
	}
	for _, c := range cases {
		_, err := m.Open(context.Background(), c.opts)
		if err == nil {
			t.Errorf("%s: 应报错", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: 错误文案应含 %q，实际 %v", c.name, c.want, err)
		}
	}
}

func TestOpenRejectsWrongPassword(t *testing.T) {
	sshd := newTestSSHD(t, "u", "right")
	m := NewManager()
	defer m.CloseAll()
	_, err := m.Open(context.Background(), OpenOptions{
		Mode: ModeSocks,
		Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "wrong"}},
	})
	if err == nil {
		t.Fatal("错口令应失败")
	}
	if !strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("应明确说认证失败，实际 %v", err)
	}
}

func TestSocksAuth(t *testing.T) {
	sshd := newTestSSHD(t, "u", "p")
	_, echoPort := echoServer(t)
	m := NewManager()
	defer m.CloseAll()
	tun, err := m.Open(context.Background(), OpenOptions{
		Mode: ModeSocks, Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}},
		SocksUser: "sock", SocksPass: "sockpw", TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("开隧道失败: %v", err)
	}
	if !tun.HasAuth {
		t.Fatal("应标记需要认证")
	}
	if !strings.Contains(tun.SocksURL, "sock:sockpw@") {
		t.Fatalf("SocksURL 应含凭据，实际 %s", tun.SocksURL)
	}

	// 正确凭据能通
	got := socksRoundTrip(t, tun.Listen, "sock", "sockpw", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if got != "hello-through-pivot" {
		t.Fatalf("认证后回显不一致: %q", got)
	}

	// 错误凭据被拒：CONNECT 前就失败，round-trip 会 Fatal，所以单独写一段。
	c, err := net.DialTimeout("tcp", tun.Listen, 2*time.Second)
	if err != nil {
		t.Fatalf("连入口失败: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	var mr [2]byte
	if _, err := io.ReadFull(c, mr[:]); err != nil {
		t.Fatalf("读方法选择失败: %v", err)
	}
	msg := append([]byte{0x01, 0x03}, []byte("bad")...)
	msg = append(msg, 0x03)
	msg = append(msg, []byte("bad")...)
	_, _ = c.Write(msg)
	var ar [2]byte
	if _, err := io.ReadFull(c, ar[:]); err != nil {
		t.Fatalf("读认证结果失败: %v", err)
	}
	if ar[1] == 0x00 {
		t.Fatal("错误凭据不应通过认证")
	}
}

func TestProbeThroughTunnel(t *testing.T) {
	sshd := newTestSSHD(t, "u", "p")
	_, echoPort := echoServer(t)
	// 找一个确定关闭的端口：起一个 listener 再关掉。
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := tmp.Addr().String()
	_ = tmp.Close()
	_, closedPortStr, _ := net.SplitHostPort(closedAddr)
	closedPort, _ := strconv.Atoi(closedPortStr)

	m := NewManager()
	defer m.CloseAll()
	tun, err := m.Open(context.Background(), OpenOptions{
		Mode: ModeSocks, Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}}, TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("开隧道失败: %v", err)
	}

	res, err := m.Probe(context.Background(), tun.ID, ProbeOptions{
		Hosts: []string{"127.0.0.1"}, Ports: []int{echoPort, closedPort},
		Timeout: 2 * time.Second, Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("应有两条结果，实际 %d", len(res))
	}
	byPort := map[int]ProbeResult{}
	for _, r := range res {
		byPort[r.Port] = r
	}
	if !byPort[echoPort].Open {
		t.Fatalf("echo 端口应开放，实际 %+v", byPort[echoPort])
	}
	if byPort[closedPort].Open {
		t.Fatalf("关闭端口不应判开放，实际 %+v", byPort[closedPort])
	}
	if !strings.Contains(byPort[closedPort].Error, "refused") {
		t.Fatalf("关闭端口应归类为 refused，实际 %q", byPort[closedPort].Error)
	}
}

func TestTTLExpires(t *testing.T) {
	sshd := newTestSSHD(t, "u", "p")
	m := NewManager()
	defer m.CloseAll()
	tun, err := m.Open(context.Background(), OpenOptions{
		Mode: ModeSocks, Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}},
		TTL: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("开隧道失败: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !tun.Alive {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tun.Alive {
		t.Fatal("TTL 到期后应自动关闭")
	}
	// 入口应已释放
	if _, err := net.DialTimeout("tcp", tun.Listen, 200*time.Millisecond); err == nil {
		t.Fatal("TTL 到期后入口仍可连")
	}
}

func TestCloseAndQuota(t *testing.T) {
	sshd := newTestSSHD(t, "u", "p")
	m := NewManager()
	defer m.CloseAll()
	opts := OpenOptions{
		TaskID: 42, Mode: ModeSocks,
		Hops: []Hop{{Addr: sshd.addr, User: "u", Password: "p"}}, TTL: time.Minute,
	}
	made := make([]*Tunnel, 0, MaxPerTask)
	for i := 0; i < MaxPerTask; i++ {
		tu, err := m.Open(context.Background(), opts)
		if err != nil {
			t.Fatalf("第 %d 条应能开: %v", i+1, err)
		}
		made = append(made, tu)
	}
	if _, err := m.Open(context.Background(), opts); err == nil {
		t.Fatal("超过单任务上限应拒绝")
	}
	if got := len(m.List(42)); got != MaxPerTask {
		t.Fatalf("按任务过滤应得 %d 条，实际 %d", MaxPerTask, got)
	}
	if err := m.Close(made[0].ID); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if _, ok := m.Get(made[0].ID); ok {
		t.Fatal("关闭后不应再查到")
	}
	if n := m.CloseTask(42); n != MaxPerTask-1 {
		t.Fatalf("CloseTask 应关 %d 条，实际 %d", MaxPerTask-1, n)
	}
}
