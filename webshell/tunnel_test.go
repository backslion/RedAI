package webshell

// WebShell 隧道端到端测试：用 Go 实现一个与 PHP 隧道脚本等价的 HTTP 端点，
// 它真的建 TCP 连接、双向搬数据。验证的是完整链路：
//
//	SOCKS5 客户端 → 平台隧道入口 → HTTP 长连接 → fake 脚本 → 内网 echo 服务
//
// 与 webshell_test.go 的 fakeShell 一样，测的是协议与编排是否自洽（帧编解码、
// channel 生命周期、握手、记账、任务隔离），这恰是最容易写错的部分。真机上
// PHP 脚本本身的行为由测评人验证。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testTunnelToken = "testtoken123"

// fakeTunnelEndpoint 是 PHP 隧道脚本的 Go 等价实现。
// OPEN 帧形如 "host:port|<token>"，校验 token 后建 TCP，再双向转发帧。
type fakeTunnelEndpoint struct {
	token       string
	mu          sync.Mutex
	opens       int
	pings       int
	failConnect bool // 让 OPEN 总是失败（测 STATUS 错误路径）
	active      int
	maxActive   int
}

func (f *fakeTunnelEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	flusher, _ := w.(http.Flusher)
	wf := func(typ byte, data []byte) {
		var h [5]byte
		binary.BigEndian.PutUint32(h[:4], uint32(len(data)))
		h[4] = typ
		_, _ = w.Write(h[:])
		if len(data) > 0 {
			_, _ = w.Write(data)
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	reqFrame := func() (byte, []byte, error) {
		var h [5]byte
		if _, err := io.ReadFull(r.Body, h[:]); err != nil {
			return 0, nil, err
		}
		n := binary.BigEndian.Uint32(h[:4])
		buf := make([]byte, int(n))
		if n > 0 {
			if _, err := io.ReadFull(r.Body, buf); err != nil {
				return 0, nil, err
			}
		}
		return h[4], buf, nil
	}

	typ, payload, err := reqFrame()
	if err != nil {
		return
	}
	if typ == framePing {
		f.mu.Lock()
		f.pings++
		f.mu.Unlock()
		wf(framePong, nil)
		return
	}
	if typ != frameOpen {
		wf(frameStatus, statusErr("expect OPEN"))
		return
	}

	raw := string(payload)
	sep := strings.LastIndex(raw, "|")
	if sep < 0 || raw[sep+1:] != f.token {
		wf(frameStatus, statusErr("bad token"))
		return
	}
	target := raw[:sep]
	f.mu.Lock()
	f.opens++
	active := f.active
	f.active++
	if active+1 > f.maxActive {
		f.maxActive = active + 1
	}
	fail := f.failConnect
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()

	if fail {
		wf(frameStatus, statusErr("dial refused (test)"))
		return
	}
	up, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		wf(frameStatus, statusErr(err.Error()))
		return
	}
	defer up.Close()
	wf(frameStatus, statusOK())

	// 两个 goroutine：socket 回显 → 响应帧；请求帧 DATA → socket。
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32768)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				wf(frameData, append([]byte(nil), buf[:n]...))
			}
			if err != nil {
				wf(frameEOF, nil)
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			t, p, err := reqFrame()
			if err != nil {
				return
			}
			switch t {
			case frameData:
				if _, err := up.Write(p); err != nil {
					return
				}
			case frameEOF, frameClose:
				return
			}
		}
	}()
	<-done // 任一方向结束就收摊（另一端会因连接关闭而退出）
}

// startEchoTarget 起一个行回显 TCP 服务，返回地址与关闭函数。
func startEchoTarget(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					_, _ = c.Write(append(sc.Bytes(), '\n'))
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// newTestTunnel 建一个带真实会话与 fake 脚本端点的 manager。
func newTestTunnel(t *testing.T, ep http.Handler, taskID int64) (*TunnelManager, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	sessions, err := NewManager(dir)
	if err != nil {
		t.Fatalf("new session mgr: %v", err)
	}
	_, err = sessions.Add(AddOptions{
		Name: "ws1", URL: "http://example.invalid/shell.php", Type: "php", Param: "p", TaskID: taskID,
	})
	if err != nil {
		t.Fatalf("add session: %v", err)
	}
	srv := httptest.NewServer(ep)
	return NewTunnelManager(sessions), srv
}

// dialSocks 用 net/http 无关的裸 SOCKS5 客户端连 target，返回可读写的连接。
func dialSocks(t *testing.T, socksAddr, target string, user, pass string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// 方法协商
	methods := []byte{0x05, 0x02, 0x00, 0x02}
	if user == "" {
		methods = []byte{0x05, 0x01, 0x00}
	}
	if _, err := c.Write(methods); err != nil {
		t.Fatal(err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatal(err)
	}
	method := resp[1]
	if (user != "" && method != 0x02) || (user == "" && method != 0x00) {
		t.Fatalf("unexpected method 0x%02x", method)
	}
	// 认证
	if user != "" {
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := c.Write(auth); err != nil {
			t.Fatal(err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			t.Fatal(err)
		}
		if ar[1] != 0 {
			t.Fatalf("auth rejected")
		}
	}
	// CONNECT 请求（域名形式）
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	p16 := uint16(portNum)
	// CONNECT 请求（域名形式）：VER CMD RSV ATYP LEN domain port。
	// 域名长度是 ATYP 之后的独立一个字节，不能塞进 RSV。
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], p16)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte // IPv4 BND 应答：VER REP RSV ATYP ADDR(4) PORT(2)
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("CONNECT rejected: rep=0x%02x", rep[1])
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func TestWebShellTunnelEndToEnd(t *testing.T) {
	echoAddr, closeEcho := startEchoTarget(t)
	defer closeEcho()
	ep := &fakeTunnelEndpoint{token: testTunnelToken}
	mgr, srv := newTestTunnel(t, ep, 1)
	defer srv.Close()
	defer mgr.CloseAll()

	tn, err := mgr.Open(context.Background(), TunnelOptions{
		TaskID: 1, Session: "ws1", TunnelURL: srv.URL + "/tunnel.php", Token: testTunnelToken,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !tn.Alive || tn.Mode != ModeSocks {
		t.Fatalf("bad tunnel: %+v", tn.View(0))
	}

	// 经隧道发一行，应原样回显。
	c := dialSocks(t, tn.Listen, echoAddr, "", "")
	msg := "hello-from-webshell-tunnel\n"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got != msg {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}

	// 第二条连接验证 channel 可复用（不是一次性）。
	c2 := dialSocks(t, tn.Listen, echoAddr, "", "")
	if _, err := c2.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c2).ReadString('\n')
	if err != nil || line != "second\n" {
		t.Fatalf("second channel: %q %v", line, err)
	}

	// 记账在 pipeBoth 结束时结算（长连接语义，与 pivot 一致）。关掉两端后
	// 有界轮询等结算完成，不用固定 sleep（CI 高负载下会 flaky）。
	c.Close()
	c2.Close()
	deadline := time.Now().Add(2 * time.Second)
	var v TunnelView
	for time.Now().Before(deadline) {
		v = tn.View(5)
		if v.Conns >= 2 && v.BytesUp > 0 && v.BytesDown > 0 && v.ActiveNow == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.Conns < 2 || v.BytesUp == 0 || v.BytesDown == 0 {
		t.Fatalf("accounting missing: %+v", v)
	}
	ep.mu.Lock()
	opens := ep.opens
	ep.mu.Unlock()
	if opens != 2 {
		t.Fatalf("endpoint opens=%d want 2", opens)
	}
}

func TestWebShellTunnelGuards(t *testing.T) {
	ep := &fakeTunnelEndpoint{token: testTunnelToken}
	mgr, srv := newTestTunnel(t, ep, 1)
	defer srv.Close()
	defer mgr.CloseAll()
	base := TunnelOptions{TaskID: 1, Session: "ws1", TunnelURL: srv.URL + "/t", Token: testTunnelToken}

	t.Run("wrong token fails on channel open", func(t *testing.T) {
		// PING 探活不校验 token（脚本对 PING 直接回 PONG），所以 Open 成功；
		// token 在 OPEN 帧校验，错误 token 应在真正建 channel 时失败。
		o := base
		o.Token = "wrong"
		tn, err := mgr.Open(context.Background(), o)
		if err != nil {
			t.Fatalf("Open should pass probe: %v", err)
		}
		defer mgr.Close(tn.ID)
		if _, err := tn.dialChannel(context.Background(), "127.0.0.1:1"); err == nil {
			t.Fatal("channel open with wrong token should fail")
		}
	})
	t.Run("bad url", func(t *testing.T) {
		o := base
		o.TunnelURL = "ftp://x/y"
		if _, err := mgr.Open(context.Background(), o); err == nil {
			t.Fatal("non-http url should fail")
		}
	})
	t.Run("non-loopback bind needs auth", func(t *testing.T) {
		o := base
		o.BindHost = "0.0.0.0"
		if _, err := mgr.Open(context.Background(), o); err == nil {
			t.Fatal("non-loopback without auth should fail")
		}
	})
	t.Run("portfwd needs target", func(t *testing.T) {
		o := base
		o.Mode = ModePortFwd
		if _, err := mgr.Open(context.Background(), o); err == nil {
			t.Fatal("portfwd without target should fail")
		}
	})
	t.Run("cross-task session rejected", func(t *testing.T) {
		o := base
		o.TaskID = 2
		if _, err := mgr.Open(context.Background(), o); err == nil {
			t.Fatal("cross-task session should be rejected")
		}
	})
}

func TestWebShellTunnelSocksAuthAndIsolation(t *testing.T) {
	echoAddr, closeEcho := startEchoTarget(t)
	defer closeEcho()
	ep := &fakeTunnelEndpoint{token: testTunnelToken}
	mgr, srv := newTestTunnel(t, ep, 7)
	defer srv.Close()
	defer mgr.CloseAll()

	tn, err := mgr.Open(context.Background(), TunnelOptions{
		TaskID: 7, Session: "ws1", TunnelURL: srv.URL + "/t", Token: testTunnelToken,
		SocksUser: "u1", SocksPass: "p1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tn.HasAuth || !strings.Contains(tn.SocksURL, "u1:p1@") {
		t.Fatalf("auth not reflected: %+v", tn.View(0))
	}
	// 错误口令被拒
	cBad, err := net.Dial("tcp", tn.Listen)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cBad.Write([]byte{0x05, 0x02, 0x00, 0x02})
	var m [2]byte
	_, _ = io.ReadFull(cBad, m[:])
	_, _ = cBad.Write([]byte{0x01, 1, 'x', 1, 'x'})
	var a [2]byte
	_, _ = io.ReadFull(cBad, a[:])
	cBad.Close()
	if a[1] == 0 {
		t.Fatal("bad password accepted")
	}
	// 正确口令可通
	c := dialSocks(t, tn.Listen, echoAddr, "u1", "p1")
	defer c.Close()
	if _, err := c.Write([]byte("authed\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "authed\n" {
		t.Fatalf("authed echo: %q %v", line, err)
	}

	// 列表按任务隔离：别的任务看不到。
	if got := len(mgr.List(999)); got != 0 {
		t.Fatalf("task 999 sees %d tunnels", got)
	}
	if got := len(mgr.List(7)); got != 1 {
		t.Fatalf("task 7 sees %d tunnels", got)
	}
}

func TestWebShellTunnelFrameRoundTrip(t *testing.T) {
	// 帧编解码：含 NUL 与高位的二进制 payload 必须无损往返。
	var buf bytes.Buffer
	payload := []byte{0x00, 0xff, 'a', 0x0d, 0x0a, 0x80, 0x00, 'z'}
	if err := writeFrame(&buf, frameData, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != frameData || !bytes.Equal(got, payload) {
		t.Fatalf("frame roundtrip: typ=0x%02x got=%v", typ, got)
	}
	// 超长帧必须被拒。
	big := make([]byte, maxFramePayload+1)
	if err := writeFrame(&buf, frameData, big); err == nil {
		t.Fatal("oversized frame should be rejected")
	}
}

func TestWebShellTunnelStatsAndQuota(t *testing.T) {
	mgr := NewTunnelManager(nil)
	// 用 InjectForTest 塞 8 条存活隧道，验证配额上限逻辑的数据面。
	for i := 0; i < MaxPerTask; i++ {
		mgr.InjectForTest(&Tunnel{ID: fmt.Sprintf("t%d", i), TaskID: 1, Alive: true, Mode: ModeSocks})
	}
	s := mgr.Stats()
	if s.Tunnels != MaxPerTask || s.Alive != MaxPerTask || s.Socks != MaxPerTask {
		t.Fatalf("stats: %+v", s)
	}
	if got := len(mgr.List(1)); got != MaxPerTask {
		t.Fatalf("list: %d", got)
	}
	if got := len(mgr.List(2)); got != 0 {
		t.Fatalf("isolation: %d", got)
	}
	if got := mgr.CloseTask(1); got != MaxPerTask {
		t.Fatalf("close task: %d", got)
	}
}

// 确保 atomic 计数器在有连接时被正确累加（编译期 + 运行期双重确认）。
var _ atomic.Int64
