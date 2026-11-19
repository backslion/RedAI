// Package pivot 把「已控主机」变成平台的内网出口（内网横向穿透）。
//
// 定位：RedAI 原有的横向能力是「验证一跳」——ssh_check 确认凭据能登录、
// tcp_probe 确认端口开放，但验证完就断了，agent 拿不到一个可复用的出口去打
// 更深的网段。本包补的就是这一环：建一条长寿命的 SSH 通道，在平台回环上开
// SOCKS5 或端口转发，之后 curl / 工具链打内网都走它。
//
// 为什么用 SSH 而不是 chisel/suo5（上游 artex-ymh 的 tunnel 方案）：
//   - chisel/suo5 要在目标机落二进制（suo5 还要 webshell），落不下去就等于没有；
//     SSH 是目标机本来就开着的服务，通道纯内存，不写任何文件。
//   - RedAI 的原则是纯 Go、零外部二进制；x/crypto/ssh 已在依赖里。
//   - SSH 的 direct-tcpip 通道天然支持「多跳」：第 N+1 跳的 TCP 连接直接建在
//     第 N 跳的通道上，不需要在中间主机落任何东西。
//
// 不做什么：
//   - 不做交互式 shell（那是 C2 的事，见 listener 包的设计边界）。
//   - 不做凭据爆破：hops 里的凭据必须来自 asset_credentials 或人工显式提供。
//   - 「目标无出网 + 只有 WebShell」的场景不由本包负责：那是 webshell 包的
//     SOCKS5 隧道（webshell_pivot_*，正向 HTTP 长连接），不是 SSH 反向隧道，
//     也不需要交互式 shell。两者并列：有 22 且有凭据走本包（快、稳、多跳），
//     只有一句话马走 webshell 隧道（不落二进制、但要吃 HTTP 延迟）。
//
// 安全取舍（都在返回值里显式告知，不静默）：
//   - SOCKS5 默认只绑 127.0.0.1。绑 0.0.0.0 等于把内网入口开放给同网段任何人，
//     必须显式设置 BindHost 并自带认证。
//   - 目标主机密钥默认不校验（渗透现场拿不到 known_hosts），但会记录 SHA256
//     指纹并回传，供人工核对；同一隧道重连时不做 TOFU 升级。
//   - 每条经隧道的连接都记账（目标、字节、成败），供活动流与报告引用。
package pivot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// 模式。
const (
	ModeSocks   = "socks"   // 平台回环上开 SOCKS5，任意内网目标
	ModePortFwd = "portfwd" // 平台回环上开固定端口，转发到单个内网目标
)

// 硬限制。全部按「一次渗透任务可能同时开几条」来定，不做无限。
const (
	// MaxHops 是跳板链长度上限。四跳已经够覆盖「入口 → DMZ → 办公 → 核心」，
	// 再长说明路径没设计好，也不利于排障（出错时不知道断在哪一跳）。
	MaxHops = 4
	// DefaultTTL / MaxTTL 是隧道寿命。默认 2 小时覆盖一次完整横向；上限 8 小时
	// 防止「开了忘记关」——隧道留着就是对内网的长期开放入口。
	DefaultTTL = 2 * time.Hour
	MaxTTL     = 8 * time.Hour
	// MaxPerTask 是单任务同时存活的隧道数。
	MaxPerTask = 8
	// dialTimeout 是单跳 TCP 连接 + SSH 握手的总超时。
	dialTimeout = 20 * time.Second
	// keepaliveInterval / keepaliveMaxFail 是心跳。三次失败视为链路已死：
	// 目标侧 sshd 可能已被杀、网络可能已断，此时隧道静默留着比报错更危险。
	keepaliveInterval = 30 * time.Second
	keepaliveMaxFail  = 3
	// socksHandshakeTimeout 是单个 SOCKS5 客户端完成协商的上限，防半开连接堆积。
	socksHandshakeTimeout = 30 * time.Second
)

// Hop 是一跳跳板机。凭据由调用方注入——agent 侧只传 credential_id，
// 由工具层从 asset_credentials 取 secret，secret 不出现在任何返回值里。
type Hop struct {
	Addr       string `json:"addr"` // host:port
	User       string `json:"user"`
	Password   string `json:"-"` // 永不序列化：不进工具返回值、不进 API 响应
	PrivateKey []byte `json:"-"`
	Passphrase []byte `json:"-"`
	// Label 是给人看的标识（资产名/IP），默认同 Addr。
	Label string `json:"label,omitempty"`
}

// OpenOptions 是一次建隧道的输入。
type OpenOptions struct {
	TaskID int64
	Label  string
	Mode   string
	Hops   []Hop
	// Target 仅 portfwd 用：最终要访问的内网 host:port（经最后一跳拨）。
	Target string
	TTL    time.Duration
	// BindHost 默认 127.0.0.1。填非回环地址时调用方必须同时给 SocksUser/Pass。
	BindHost  string
	SocksUser string
	SocksPass string
}

// hopView 是 Hop 的可回传投影（不含任何凭据）。
type hopView struct {
	Addr  string `json:"addr"`
	User  string `json:"user"`
	Label string `json:"label,omitempty"`
}

// connLog 是一条经隧道连接的记录。只保留最近 N 条：隧道可能被打成代理池，
// 全量保留会把内存吃满。
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
	Hops      []hopView `json:"hops"`
	Listen    string    `json:"listen"` // 127.0.0.1:port
	Target    string    `json:"target,omitempty"`
	SocksURL  string    `json:"socks_url,omitempty"`
	HasAuth   bool      `json:"has_auth"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	HostKey   string    `json:"host_key"` // 最后一跳的 SHA256 指纹
	Alive     bool      `json:"alive"`
	LastError string    `json:"last_error,omitempty"`

	Conns     int64 `json:"conns"`
	Fails     int64 `json:"fails"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	ActiveNow int64 `json:"active_now"`

	// 内部状态
	client   *ssh.Client
	listener net.Listener
	closeOne sync.Once
	closed   chan struct{}
	auth     *socksAuth

	mu  sync.Mutex
	log []connLog

	conns     atomic.Int64
	fails     atomic.Int64
	up        atomic.Int64
	down      atomic.Int64
	activeNow atomic.Int64
}

// SOCKSAddr 返回可直接使用的 socks5 地址（不含认证，认证信息单独给）。
func (t *Tunnel) SOCKSAddr() string {
	if t == nil || t.Mode != ModeSocks {
		return ""
	}
	return t.Listen
}

func (t *Tunnel) recordConn(e connLog) {
	t.mu.Lock()
	t.log = append(t.log, e)
	if len(t.log) > maxConnLog {
		t.log = t.log[len(t.log)-maxConnLog:]
	}
	t.mu.Unlock()
}

// RecentConns 返回最近的连接记录（新的在后）。
func (t *Tunnel) RecentConns(limit int) []connLog {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit <= 0 || limit > len(t.log) {
		limit = len(t.log)
	}
	out := make([]connLog, limit)
	copy(out, t.log[len(t.log)-limit:])
	return out
}

// Manager 是进程级隧道台账。与 listener.Manager 同一形态：只活在内存里，
// 进程重启后残留的连接由 OS 回收，不做磁盘持久化（持久化等于给重启后的
// 平台一个「指向已不存在通道」的假条目）。
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
	closed  bool
	// dial 可注入，供测试用内存管道替换真实 TCP/SSH 握手之外的部分。
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

// NewManager 建一个空台账。
func NewManager() *Manager {
	return &Manager{tunnels: map[string]*Tunnel{}}
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pv-%d", time.Now().UnixNano())
	}
	return "pv-" + hex.EncodeToString(b[:])
}

func normalizeTTL(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTTL
	}
	if d > MaxTTL {
		return MaxTTL
	}
	return d
}

// Open 建隧道并开始服务。返回时 SOCKS5/转发入口已可连（listener 已 Listen）。
func (m *Manager) Open(ctx context.Context, opts OpenOptions) (*Tunnel, error) {
	if m == nil {
		return nil, fmt.Errorf("pivot manager 未初始化")
	}
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return nil, fmt.Errorf("pivot manager 已关闭")
	}

	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = ModeSocks
	}
	if mode != ModeSocks && mode != ModePortFwd {
		return nil, fmt.Errorf("mode 只能是 %s 或 %s", ModeSocks, ModePortFwd)
	}
	if len(opts.Hops) == 0 {
		return nil, fmt.Errorf("至少要有一跳跳板机")
	}
	if len(opts.Hops) > MaxHops {
		return nil, fmt.Errorf("跳板链最多 %d 跳（当前 %d）", MaxHops, len(opts.Hops))
	}
	for i, h := range opts.Hops {
		if strings.TrimSpace(h.Addr) == "" {
			return nil, fmt.Errorf("第 %d 跳缺少 addr", i+1)
		}
		if !strings.Contains(h.Addr, ":") {
			return nil, fmt.Errorf("第 %d 跳 addr 需带端口（如 10.0.0.5:22），实际 %q", i+1, h.Addr)
		}
		if strings.TrimSpace(h.User) == "" {
			return nil, fmt.Errorf("第 %d 跳缺少 user", i+1)
		}
		if len(h.Password) == 0 && len(h.PrivateKey) == 0 {
			return nil, fmt.Errorf("第 %d 跳缺少凭据（口令或私钥）", i+1)
		}
	}
	if mode == ModePortFwd {
		if strings.TrimSpace(opts.Target) == "" || !strings.Contains(opts.Target, ":") {
			return nil, fmt.Errorf("portfwd 模式必须给 target（内网 host:port）")
		}
	}

	// 同任务配额。
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

	client, fp, err := dialChain(ctx, m.dial, opts.Hops)
	if err != nil {
		return nil, err
	}

	// 入口绑定。非回环必须带认证——这一点在 API 层也会校验，这里再兜一次，
	// 因为工具直接调用 Manager，不能只靠 HTTP 层的检查。
	bind := strings.TrimSpace(opts.BindHost)
	hasAuth := opts.SocksUser != "" || opts.SocksPass != ""
	if bind == "" {
		bind = "127.0.0.1"
	}
	if !isLoopbackHost(bind) && !hasAuth {
		client.Close()
		return nil, fmt.Errorf("绑定 %s 必须同时设置 socks_user/socks_pass：否则等于把内网入口开放给同网段任何人", bind)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("监听入口失败: %w", err)
	}

	t := &Tunnel{
		ID:        newID(),
		TaskID:    opts.TaskID,
		Label:     strings.TrimSpace(opts.Label),
		Mode:      mode,
		Listen:    ln.Addr().String(),
		Target:    strings.TrimSpace(opts.Target),
		HasAuth:   hasAuth,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(normalizeTTL(opts.TTL)),
		HostKey:   fp,
		Alive:     true,
		client:    client,
		listener:  ln,
		closed:    make(chan struct{}),
	}
	for _, h := range opts.Hops {
		lbl := h.Label
		if lbl == "" {
			lbl = h.Addr
		}
		t.Hops = append(t.Hops, hopView{Addr: h.Addr, User: h.User, Label: lbl})
	}
	if t.Label == "" {
		t.Label = t.Hops[len(t.Hops)-1].Label
	}
	if hasAuth {
		t.auth = &socksAuth{user: opts.SocksUser, pass: opts.SocksPass}
	}
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
		client.Close()
		return nil, fmt.Errorf("pivot manager 已关闭")
	}
	m.tunnels[t.ID] = t
	m.mu.Unlock()

	go t.serve()
	go t.keepalive(keepaliveInterval, keepaliveMaxFail)
	time.AfterFunc(time.Until(t.ExpiresAt), func() {
		t.LastError = "TTL 到期自动关闭"
		t.close()
	})
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
			// 单次 accept 失败（EMFILE 等）不终止隧道，退避后继续。
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

// keepalive 定期探活。连续失败即判定链路死亡并关闭隧道（Alive=false 保留
// 台账条目，供列表页显示「已断开」而不是让条目凭空消失）。
func (t *Tunnel) keepalive(every time.Duration, maxFail int) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	fails := 0
	for {
		select {
		case <-t.closed:
			return
		case <-tk.C:
			if _, _, err := t.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				fails++
				if fails >= maxFail {
					t.LastError = "心跳连续失败，链路已断: " + err.Error()
					t.close()
					return
				}
				continue
			}
			fails = 0
		}
	}
}

func (t *Tunnel) close() {
	t.closeOne.Do(func() {
		t.Alive = false
		close(t.closed)
		if t.listener != nil {
			_ = t.listener.Close()
		}
		if t.client != nil {
			_ = t.client.Close()
		}
	})
}

// Close 关闭隧道（幂等）。
func (m *Manager) Close(id string) error {
	m.mu.RLock()
	t, ok := m.tunnels[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	t.close()
	m.mu.Lock()
	delete(m.tunnels, id)
	m.mu.Unlock()
	return nil
}

// CloseTask 关闭某任务的全部隧道，返回关闭数量。
func (m *Manager) CloseTask(taskID int64) int {
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

// Get 取一条隧道（不复制，调用方只读）。
func (m *Manager) Get(id string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// List 列出隧道。taskID>0 时只返回该任务的；taskID<=0 返回全部。
func (m *Manager) List(taskID int64) []*Tunnel {
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

// Stats 是概览。
type Stats struct {
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

// InjectForTest 把一条「没有真实链路」的隧道塞进台账。
//
// 只用于测试不依赖连接的逻辑（归属判断、列表过滤、配额统计）。生产代码不得
// 调用：这样注入的隧道没有 client/listener，真去 serve 会立刻失败。
func (m *Manager) InjectForTest(t *Tunnel) {
	if t.closed == nil {
		t.closed = make(chan struct{})
	}
	m.mu.Lock()
	m.tunnels[t.ID] = t
	m.mu.Unlock()
}

// Stats 汇总当前台账。
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var s Stats
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

// CloseAll 关闭全部隧道（进程退出时调用）。
func (m *Manager) CloseAll() {
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

// isLoopbackHost 判断绑定地址是否只在本机。空串按回环处理（默认值）。
func isLoopbackHost(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// dialVia 经最后一跳建立到 target 的连接（SSH direct-tcpip 通道）。
func (t *Tunnel) dialVia(target string) (net.Conn, error) {
	if t.client == nil {
		return nil, fmt.Errorf("隧道已关闭")
	}
	return t.client.Dial("tcp", target)
}

// view 生成可安全回传的快照。刻意不暴露 client/listener/auth。
type TunnelView struct {
	ID        string    `json:"id"`
	TaskID    int64     `json:"task_id"`
	Label     string    `json:"label"`
	Mode      string    `json:"mode"`
	Hops      []hopView `json:"hops"`
	Listen    string    `json:"listen"`
	Target    string    `json:"target,omitempty"`
	SocksURL  string    `json:"socks_url,omitempty"`
	HasAuth   bool      `json:"has_auth"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TTLSec    int64     `json:"ttl_sec"`
	HostKey   string    `json:"host_key"`
	Alive     bool      `json:"alive"`
	LastError string    `json:"last_error,omitempty"`
	Conns     int64     `json:"conns"`
	Fails     int64     `json:"fails"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	ActiveNow int64     `json:"active_now"`
	Recent    []connLog `json:"recent,omitempty"`
}

// View 生成快照（含最近若干条连接记录，供页面与工具展示）。
func (t *Tunnel) View(recent int) TunnelView {
	ttl := int64(time.Until(t.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	v := TunnelView{
		ID: t.ID, TaskID: t.TaskID, Label: t.Label, Mode: t.Mode, Hops: t.Hops,
		Listen: t.Listen, Target: t.Target, SocksURL: t.SocksURL, HasAuth: t.HasAuth,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, TTLSec: ttl, HostKey: t.HostKey,
		Alive: t.Alive, LastError: t.LastError,
		Conns: t.conns.Load(), Fails: t.fails.Load(), BytesUp: t.up.Load(),
		BytesDown: t.down.Load(), ActiveNow: t.activeNow.Load(),
	}
	if recent > 0 {
		v.Recent = t.RecentConns(recent)
	}
	return v
}
