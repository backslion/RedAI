package agent

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSocks5 是最小 SOCKS5 服务端：只实现协商 + CONNECT，用于验证探测逻辑。
// reply 控制 CONNECT 的应答码（0x00 成功 / 0x05 连接被拒）。
type fakeSocks5 struct {
	ln      net.Listener
	user    string
	pass    string
	reply   byte
	reached chan string
}

func newFakeSocks5(t *testing.T, user, pass string, reply byte) *fakeSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks5{ln: ln, user: user, pass: pass, reply: reply, reached: make(chan string, 8)}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeSocks5) addr() string { return f.ln.Addr().String() }

func (f *fakeSocks5) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSocks5) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	if f.user != "" {
		// 只接受用户名口令认证。
		accepted := false
		for _, m := range methods {
			if m == 0x02 {
				accepted = true
			}
		}
		if !accepted {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		_, _ = c.Write([]byte{0x05, 0x02})
		ver := make([]byte, 2)
		if _, err := io.ReadFull(c, ver); err != nil || ver[0] != 0x01 {
			return
		}
		ul := make([]byte, int(ver[1]))
		if _, err := io.ReadFull(c, ul); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(c, pl); err != nil {
			return
		}
		pb := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(c, pb); err != nil {
			return
		}
		if string(ul) != f.user || string(pb) != f.pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	f.reached <- net.JoinHostPort(host, strconv.Itoa(int(port)))

	if f.reply != 0x00 {
		_, _ = c.Write([]byte{0x05, f.reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// 免认证入口：CONNECT 成功即证明「入口可达 + 目标被正确转交」。
func TestSocks5ConnectProbeNoAuth(t *testing.T) {
	s := newFakeSocks5(t, "", "", 0x00)
	if err := socks5ConnectProbe(context.Background(), s.addr(), "", "", "10.0.0.9", 445, 3*time.Second); err != nil {
		t.Fatalf("探测应成功: %v", err)
	}
	select {
	case got := <-s.reached:
		if got != "10.0.0.9:445" {
			t.Errorf("转交目标 = %s, want 10.0.0.9:445", got)
		}
	case <-time.After(time.Second):
		t.Error("服务端未收到 CONNECT")
	}
}

// 域名要按 ATYP=3 发送，不能被误当 IP。
func TestSocks5ConnectProbeDomain(t *testing.T) {
	s := newFakeSocks5(t, "", "", 0x00)
	if err := socks5ConnectProbe(context.Background(), s.addr(), "", "", "intranet.local", 80, 3*time.Second); err != nil {
		t.Fatalf("探测应成功: %v", err)
	}
	if got := <-s.reached; got != "intranet.local:80" {
		t.Errorf("转交目标 = %s", got)
	}
}

// 入口要求认证时必须带上，否则探测要明确失败而不是挂住。
func TestSocks5ConnectProbeAuth(t *testing.T) {
	s := newFakeSocks5(t, "u", "p", 0x00)
	if err := socks5ConnectProbe(context.Background(), s.addr(), "u", "p", "10.0.0.1", 22, 3*time.Second); err != nil {
		t.Fatalf("带对认证应成功: %v", err)
	}
	err := socks5ConnectProbe(context.Background(), s.addr(), "u", "wrong", "10.0.0.1", 22, 3*time.Second)
	if err == nil {
		t.Fatal("错认证必须失败")
	}
	err = socks5ConnectProbe(context.Background(), s.addr(), "", "", "10.0.0.1", 22, 3*time.Second)
	if err == nil {
		t.Fatal("未给认证必须失败")
	}
}

// CONNECT 被拒要翻译成「主机活着但端口关闭」这类可执行结论，而不是裸错误码。
func TestSocks5ConnectProbeRefused(t *testing.T) {
	s := newFakeSocks5(t, "", "", 0x05)
	err := socks5ConnectProbe(context.Background(), s.addr(), "", "", "10.0.0.1", 8080, 3*time.Second)
	if err == nil {
		t.Fatal("应失败")
	}
	if !strings.Contains(err.Error(), "连接被拒") {
		t.Errorf("错误应可读，实际: %v", err)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"10.0.0.1", "10.0.0.1", 80},
		{"10.0.0.1:445", "10.0.0.1", 445},
		{"intranet.local:8080", "intranet.local", 8080},
		{" 10.0.0.2:22 ", "10.0.0.2", 22},
	}
	for _, c := range cases {
		h, p, err := splitHostPort(c.in, 80)
		if err != nil {
			t.Errorf("%q 解析失败: %v", c.in, err)
			continue
		}
		if h != c.host || p != c.port {
			t.Errorf("%q → %s:%d, want %s:%d", c.in, h, p, c.host, c.port)
		}
	}
	if _, _, err := splitHostPort("10.0.0.1:99999", 80); err == nil {
		t.Error("非法端口应报错")
	}
	if _, _, err := splitHostPort("", 80); err == nil {
		t.Error("空目标应报错")
	}
}

// 选型优先级：复用 > SSH > WebShell > 反弹；全阻断时要诚实说 none。
func TestRecommendPivotPath(t *testing.T) {
	all := []pivotPath{
		{Kind: "reuse", Feasible: "yes"},
		{Kind: "ssh", Feasible: "unknown"},
		{Kind: "webshell", Feasible: "unknown"},
		{Kind: "reverse", Feasible: "unknown"},
	}
	if got := recommendPivotPath(all)["kind"]; got != "reuse" {
		t.Errorf("有存活隧道时推荐 %v, want reuse", got)
	}

	noReuse := []pivotPath{
		{Kind: "reuse", Feasible: "no"},
		{Kind: "ssh", Feasible: "unknown"},
		{Kind: "webshell", Feasible: "yes"},
	}
	if got := recommendPivotPath(noReuse)["kind"]; got != "ssh" {
		t.Errorf("无隧道时推荐 %v, want ssh（稳定性优先）", got)
	}

	onlyWS := []pivotPath{
		{Kind: "reuse", Feasible: "no"},
		{Kind: "ssh", Feasible: "no"},
		{Kind: "webshell", Feasible: "unknown"},
	}
	if got := recommendPivotPath(onlyWS)["kind"]; got != "webshell" {
		t.Errorf("推荐 %v, want webshell", got)
	}

	blocked := []pivotPath{
		{Kind: "reuse", Feasible: "no"},
		{Kind: "ssh", Feasible: "no"},
		{Kind: "webshell", Feasible: "no"},
		{Kind: "reverse", Feasible: "no"},
	}
	if got := recommendPivotPath(blocked)["kind"]; got != "none" {
		t.Errorf("全阻断时推荐 %v, want none", got)
	}
}

// pivot_plan 必须在不连任何目标的情况下也能给出结论（只读聚合）。
func TestPivotPlanNoRuntime(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	tool := ts.pivotPlan()
	if tool.Name() != "pivot_plan" {
		t.Fatalf("工具名 = %q", tool.Name())
	}
	res, err := tool.Call(context.Background(), []byte(`{"hint_target":"10.0.0.1"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	body := toolResultText(t, res)
	if body == "" {
		t.Fatal("应有输出")
	}
	for _, want := range []string{`"paths"`, `"recommended"`, "ssh", "webshell"} {
		if !strings.Contains(body, want) {
			t.Errorf("输出缺少 %q", want)
		}
	}
}
