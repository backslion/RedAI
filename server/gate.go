package server

// 访问门控（伪装门控）。
//
// 解决的问题：平台默认把登录页直接摊在 8787 上。任何扫描器/测绘引擎 GET 一次
// 就能从 HTML 里认出这是「AI 渗透平台」，登录页也成了明确的爆破入口。
//
// 门控做两件事：
//  1. 未通过门控的请求不返回任何平台内容——非浏览器请求直接给逐字节固定的
//     nginx 404 页；浏览器请求给 401 让浏览器弹 Basic Auth 框，但 realm 写成
//     nginx，不暴露产品名。
//  2. 通过后种一个 HMAC cookie，后续请求（含 _next/static 资源）凭 cookie 放行，
//     不再重复要求认证。
//
// 刻意的取舍：
//   - **不做随机入口路径**。随机路径隐蔽性更强，但用户会找不到入口，且丢失路径
//     只能改库恢复。固定路径 + 门控已经能挡住绝大多数自动化测绘。
//   - **错误凭据返回 404 而不是再弹 401**。弹框会让爆破者知道「这里要密码、刚才
//     错了」，24 小时就能把弱口令试完；返回 404 让错误与「路径不存在」不可区分。
//   - **默认关闭**。老部署升级后行为不变，必须显式开启——否则一次误配置就把
//     所有人挡在门外。
//
// 救急通道：环境变量 POJUN_GATE_USER / POJUN_GATE_PASS 优先于数据库设置。
// 忘了门户密码时，设这两个变量重启即可进入，再在界面里改回来。

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	gateEnabledKey  = "gate_enabled"
	gateUserKey     = "gate_user"
	gatePassHashKey = "gate_pass_hash"
	gateCookieName  = "pojun_gate"
	// gateRealm 刻意写成 nginx：浏览器弹框里显示「服务器 nginx 要求用户名和密码」，
	// 与 404 页的品牌一致，不泄露这是渗透平台。
	gateRealm = "nginx"
	// gateConfigTTL 是配置缓存时长。设置页保存后会主动 Invalidate，TTL 只是
	// 兜底（例如直接改了数据库）。
	gateConfigTTL = 30 * time.Second
)

// decoyNotFound 是逐字节固定的 nginx 404 页。
//
// 不要在这里加变量、时间戳或请求信息：一旦响应随请求变化，扫描器就能靠
// 差分把它和真实 nginx 区分开，伪装即失效。
const decoyNotFound = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`

// gateConfig 是门控的生效配置。
type gateConfig struct {
	enabled  bool
	user     string
	passHash string // bcrypt；环境变量兜底通道下为空，改比明文
	envPass  string // 仅环境变量通道使用
}

type accessGate struct {
	mu       sync.RWMutex
	cfg      gateConfig
	loadedAt time.Time
}

// gateAction 是一次请求的门控裁决。
type gateAction int

const (
	gatePass      gateAction = iota // 放行
	gateChallenge                   // 401 + WWW-Authenticate（浏览器弹框）
	gateDecoy                       // 伪造 404
)

// decideGate 是纯函数：不读库、不写响应，便于单测覆盖全部分支。
//
// setCookie=true 表示本次请求刚通过 Basic 认证，需要下发记忆 cookie。
func decideGate(cfg gateConfig, r *http.Request, key []byte) (action gateAction, setCookie bool) {
	if !cfg.enabled {
		return gatePass, false
	}
	// 1. 已有有效 cookie：直接放行（静态资源靠它，不然页面加载会碎）。
	if c, err := r.Cookie(gateCookieName); err == nil && c.Value != "" {
		if hmac.Equal([]byte(c.Value), []byte(gateCookieValue(cfg, key))) {
			return gatePass, false
		}
	}
	// 2. Basic 凭据。
	if u, p, ok := r.BasicAuth(); ok {
		if verifyGateCredential(cfg, u, p) {
			return gatePass, true
		}
		// 凭据错误：不弹框、不再给机会，直接当路径不存在。
		return gateDecoy, false
	}
	// 3. 无凭据：浏览器给挑战，其余一律伪造页。
	if wantsHTML(r) {
		return gateChallenge, false
	}
	return gateDecoy, false
}

// verifyGateCredential 校验用户名口令。两条通道：
//   - 环境变量（救急）：明文常量时间比较；
//   - 数据库：bcrypt 哈希比较。
//
// 用户名也必须常量时间比较，否则可以靠响应时间差枚举用户名。
func verifyGateCredential(cfg gateConfig, user, pass string) bool {
	if subtle.ConstantTimeCompare([]byte(user), []byte(cfg.user)) != 1 {
		// 仍然跑一次 bcrypt，避免「用户名错」比「密码错」返回更快。
		if cfg.passHash != "" {
			_ = bcrypt.CompareHashAndPassword([]byte(cfg.passHash), []byte(pass))
		}
		return false
	}
	if cfg.envPass != "" {
		return subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.envPass)) == 1
	}
	if cfg.passHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(cfg.passHash), []byte(pass)) == nil
}

// gateCookieValue 由用户与口令哈希派生，改密码后旧 cookie 自动失效。
// key 用进程的 JWT 密钥：重启不变，且不额外引入一个需要备份的秘密。
func gateCookieValue(cfg gateConfig, key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("gate|" + cfg.user + "|" + cfg.passHash + "|" + cfg.envPass))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// wantsHTML 判断这是不是浏览器在要页面。只有这种请求才值得给 401 弹框；
// 给脚本 401 等于告诉它「这里有 Basic 认证」。
func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// load 读配置（带 TTL 缓存）。环境变量优先。
func (g *accessGate) load(pg settingReader) gateConfig {
	g.mu.RLock()
	if time.Since(g.loadedAt) < gateConfigTTL {
		cfg := g.cfg
		g.mu.RUnlock()
		return cfg
	}
	g.mu.RUnlock()

	cfg := gateConfig{}
	if pg != nil {
		if v, ok, err := pg.GetSetting(gateEnabledKey); err == nil && ok {
			cfg.enabled = v == "1" || strings.EqualFold(v, "true")
		}
		if v, ok, err := pg.GetSetting(gateUserKey); err == nil && ok {
			cfg.user = v
		}
		if v, ok, err := pg.GetSetting(gatePassHashKey); err == nil && ok {
			cfg.passHash = v
		}
	}
	// 环境变量优先：忘密码时的救急通道。
	if u := strings.TrimSpace(os.Getenv("POJUN_GATE_USER")); u != "" {
		if p := os.Getenv("POJUN_GATE_PASS"); p != "" {
			cfg.enabled = true
			cfg.user = u
			cfg.envPass = p
			cfg.passHash = ""
		}
	}

	g.mu.Lock()
	g.cfg = cfg
	g.loadedAt = time.Now()
	g.mu.Unlock()
	return cfg
}

// invalidate 让下一次请求重新读库（设置保存后调用）。
func (g *accessGate) invalidate() {
	g.mu.Lock()
	g.loadedAt = time.Time{}
	g.mu.Unlock()
}

// settingReader 是门控需要的最小存储面，便于单测注入。
type settingReader interface {
	GetSetting(key string) (string, bool, error)
}

// gateMiddleware 包在前端 handler 外层。
//
// 只包前端：/api 与 /s（暂存下载）走各自的鉴权/capability URL，不受门控影响。
// 这一点很关键——API 客户端用 Bearer，不该被 Basic 弹框打断。
func (s *Server) gateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pg settingReader
		if s.m != nil && s.m.pg != nil {
			pg = s.m.pg
		}
		cfg := s.gate.load(pg)
		action, setCookie := decideGate(cfg, r, s.gateKey())

		switch action {
		case gatePass:
			if setCookie {
				http.SetCookie(w, &http.Cookie{
					Name:     gateCookieName,
					Value:    gateCookieValue(cfg, s.gateKey()),
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Secure:   r.TLS != nil,
					MaxAge:   int((12 * time.Hour).Seconds()),
				})
			}
			next.ServeHTTP(w, r)
		case gateChallenge:
			// realm 写 nginx：弹框文案不出现产品名。
			w.Header().Set("WWW-Authenticate", `Basic realm="`+gateRealm+`"`)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Authorization Required\n"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "nginx")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(decoyNotFound))
		}
	})
}

// gateKey 取 JWT 密钥作 HMAC key。
func (s *Server) gateKey() []byte {
	if v := s.jwtKey.Load(); v != nil {
		if b, ok := v.([]byte); ok && len(b) > 0 {
			return b
		}
	}
	// 未初始化（开发模式）：用固定串保证行为可预期，不 panic。
	return []byte("pojun-gate-dev-key")
}
