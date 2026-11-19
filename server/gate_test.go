package server

// 访问门控的行为守卫（不需要数据库）。
//
// 门控是安全边界，但它**默认关闭**——所以「以为自己开了其实没开」和
// 「开了却把自己锁在外面」两种错误都只能在运行时发现。这里把裁决逻辑
// 拆成纯函数后逐分支钉死。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func mustHash(t *testing.T, pass string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func reqWith(accept, user, pass string, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	if user != "" || pass != "" {
		r.SetBasicAuth(user, pass)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: gateCookieName, Value: cookie})
	}
	return r
}

// 默认关闭：老部署升级后行为必须完全不变。
func TestGateDisabledPassesEverything(t *testing.T) {
	cfg := gateConfig{enabled: false, user: "u", passHash: mustHash(t, "p")}
	action, setCookie := decideGate(cfg, reqWith("text/html", "", "", ""), []byte("k"))
	if action != gatePass || setCookie {
		t.Errorf("未启用时应无条件放行，得到 action=%v setCookie=%v", action, setCookie)
	}
}

// 浏览器（Accept: text/html）才给 401 弹框；脚本拿到 401 等于被告知「要密码」。
func TestGateChallengesOnlyBrowsers(t *testing.T) {
	cfg := gateConfig{enabled: true, user: "u", passHash: mustHash(t, "p")}

	if a, _ := decideGate(cfg, reqWith("text/html,application/xhtml+xml", "", "", ""), []byte("k")); a != gateChallenge {
		t.Errorf("浏览器应得 401 挑战，得到 %v", a)
	}
	if a, _ := decideGate(cfg, reqWith("application/json", "", "", ""), []byte("k")); a != gateDecoy {
		t.Errorf("非 HTML 应得伪造 404，得到 %v", a)
	}
	// POST 即使声明 text/html 也不弹框：表单提交不该触发认证框。
	post := httptest.NewRequest(http.MethodPost, "/", nil)
	post.Header.Set("Accept", "text/html")
	if a, _ := decideGate(cfg, post, []byte("k")); a != gateDecoy {
		t.Errorf("POST 应得伪造 404，得到 %v", a)
	}
}

// 正确凭据放行并下发记忆 cookie。
func TestGateAcceptsCorrectBasic(t *testing.T) {
	cfg := gateConfig{enabled: true, user: "u", passHash: mustHash(t, "p")}
	action, setCookie := decideGate(cfg, reqWith("text/html", "u", "p", ""), []byte("k"))
	if action != gatePass || !setCookie {
		t.Fatalf("正确凭据应放行并种 cookie，得到 action=%v setCookie=%v", action, setCookie)
	}

	// cookie 有效后，连 Basic 都不带也应放行（静态资源靠这条路径）。
	value := gateCookieValue(cfg, []byte("k"))
	if a, sc := decideGate(cfg, reqWith("text/html", "", "", value), []byte("k")); a != gatePass || sc {
		t.Errorf("有效 cookie 应放行且不重复种，得到 %v %v", a, sc)
	}
}

// 错误凭据一律伪造 404：弹框会让爆破者知道「刚才错了」。
func TestGateRejectsWrongCredentialAsDecoy(t *testing.T) {
	cfg := gateConfig{enabled: true, user: "u", passHash: mustHash(t, "p")}
	if a, _ := decideGate(cfg, reqWith("text/html", "u", "wrong", ""), []byte("k")); a != gateDecoy {
		t.Errorf("错密码应得伪造 404，得到 %v", a)
	}
	if a, _ := decideGate(cfg, reqWith("text/html", "other", "p", ""), []byte("k")); a != gateDecoy {
		t.Errorf("错用户名应得伪造 404，得到 %v", a)
	}
	// 无效 cookie 等同于无 cookie。
	if a, _ := decideGate(cfg, reqWith("text/html", "", "", "deadbeef"), []byte("k")); a != gateChallenge {
		t.Errorf("无效 cookie 应按无凭据处理，得到 %v", a)
	}
}

// 环境变量救急通道：忘密码时靠它进来。
func TestGateEnvCredentialChannel(t *testing.T) {
	cfg := gateConfig{enabled: true, user: "rescue", envPass: "rescue-pass"}
	if a, sc := decideGate(cfg, reqWith("text/html", "rescue", "rescue-pass", ""), []byte("k")); a != gatePass || !sc {
		t.Errorf("环境变量凭据应放行，得到 %v %v", a, sc)
	}
	if a, _ := decideGate(cfg, reqWith("text/html", "rescue", "nope", ""), []byte("k")); a != gateDecoy {
		t.Errorf("环境变量错密码应得伪造 404，得到 %v", a)
	}
}

// cookie 由凭据派生：改密码后旧 cookie 必须立刻失效，否则改密码等于没改。
func TestGateCookieRotatesWithPassword(t *testing.T) {
	a := gateConfig{enabled: true, user: "u", passHash: mustHash(t, "old")}
	b := gateConfig{enabled: true, user: "u", passHash: mustHash(t, "new")}
	if gateCookieValue(a, []byte("k")) == gateCookieValue(b, []byte("k")) {
		t.Error("改密码后 cookie 值必须变化")
	}
	// 换密钥（重启换了 jwt.key）也要失效。
	if gateCookieValue(a, []byte("k")) == gateCookieValue(a, []byte("k2")) {
		t.Error("换密钥后 cookie 值必须变化")
	}
}

// 伪造页必须逐字节固定：随请求变化的响应等于自曝。
func TestDecoyPageIsStatic(t *testing.T) {
	if len(decoyNotFound) == 0 {
		t.Fatal("伪页为空")
	}
	low := strings.ToLower(decoyNotFound)
	for _, bad := range []string{"pojun", "REDAI", "%s", "%d"} {
		if strings.Contains(low, bad) {
			t.Errorf("伪页不应包含 %q（会泄露产品身份或引入格式化）", bad)
		}
	}
}

// 配置缓存过期后应重新读库；invalidate 应立即失效。
func TestGateConfigInvalidate(t *testing.T) {
	g := &accessGate{}
	first := g.load(nil)
	if first.enabled {
		t.Fatal("空配置默认必须关闭")
	}
	g.mu.Lock()
	g.cfg = gateConfig{enabled: true, user: "x"}
	g.loadedAt = time.Now()
	g.mu.Unlock()

	if got := g.load(nil); !got.enabled {
		t.Error("TTL 内应命中缓存")
	}
	g.invalidate()
	if got := g.load(nil); got.enabled {
		t.Error("invalidate 后应重新读库（nil 源 → 关闭）")
	}
}
