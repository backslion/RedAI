package agent

// Web 登录凭据验证器（YCode 二开）：http_login_check 是 ssh_check 的 Web 对应物——
// 对一个登录表单/登录接口逐个验证【用户名+口令】组合，自动判定成败（跳转/状态码/
// 长度/失败关键词差异），返回可登录组合。定位与 ssh_check 一致：验证器而非爆破器——
// 每组合一次尝试、单次调用 ≤10 组合、防锁定兜底（出现锁定关键词/429 立即中止）。
// 表单字段可自动识别（GET 登录页解析 <form>/<input>），JSON 接口显式指定字段即可。
// 请求经 t.probeHTTPClient（默认录制代理）→ 流量入库存证。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

var (
	formRe      = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	inputRe     = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe      = regexp.MustCompile(`(?is)([a-zA-Z-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	formAttrRe  = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	userNameTyp = regexp.MustCompile(`(?i)^(user|username|user_name|account|loginname|login_name|email|mail|name|phone|mobile|acct)$`)
	passNameTyp = regexp.MustCompile(`(?i)^(password|passwd|pwd|pass|userpass|loginpass)$`)
)

// parseLoginHTML 从登录页 HTML 里识别第一个带 password input 的表单：
// 返回 action(完整 URL，相对路径按 base 解析)、method、用户名字段、口令字段。
func parseLoginHTML(pageURL, body string) (action, method, userField, passField string) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return "", "", "", ""
	}
	for _, form := range formRe.FindAllString(body, 4) {
		// 表单属性
		method, action = "POST", ""
		if m := formAttrRe.FindString(form); m != "" {
			attrs := parseHTMLAttrs(m)
			if v := strings.ToUpper(attrs["method"]); v == "GET" || v == "POST" {
				method = v
			}
			action = strings.TrimSpace(attrs["action"])
		}
		for _, in := range inputRe.FindAllString(form, -1) {
			attrs := parseHTMLAttrs(in)
			name := strings.TrimSpace(attrs["name"])
			if name == "" {
				continue
			}
			typ := strings.ToLower(strings.TrimSpace(attrs["type"]))
			switch {
			case (typ == "password" || passNameTyp.MatchString(name)) && passField == "":
				passField = name
			case typ == "" || typ == "text" || typ == "email" || typ == "tel":
				// 第一个 text 类输入先占位；出现更像用户名的字段则升级
				if userField == "" || userNameTyp.MatchString(name) {
					userField = name
				}
			}
		}
		if passField != "" && userField != "" {
			if action == "" {
				action = pageURL
			} else if u, err := base.Parse(action); err == nil {
				action = u.String()
			}
			return action, method, userField, passField
		}
	}
	return "", "", "", ""
}

// parseHTMLAttrs 解析一个标签字符串里的属性 map。
func parseHTMLAttrs(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
		v := m[3]
		if v == "" {
			v = m[4]
		}
		if v == "" {
			v = m[5]
		}
		out[strings.ToLower(m[1])] = v
	}
	return out
}

// loginFailKeywords 常见登录失败指示词（响应体命中其一且与基线一致 → 认证拒绝）。
var loginFailKeywords = []string{
	"密码错误", "用户名或密码", "账户或密码", "账号或密码", "登录失败", "登陆失败",
	"无效", "不正确", "已被锁定", "尝试次数", "locked", "invalid", "incorrect",
	"wrong password", "failed to login", "login failed", "bad credentials",
	"authentication failed", "unauthorized",
}

// lockoutKeywords 出现即认定触发防锁定/限流，立即中止。
var lockoutKeywords = []string{"已被锁定", "账户锁定", "尝试次数过多", "稍后再试", "locked", "lockout", "too many attempts", "too many failed"}

type loginAttempt struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Status   int    `json:"status"`
	Len      int    `json:"len"`
	Loc      string `json:"location,omitempty"`
	Ms       int64  `json:"ms"`
	Verdict  string `json:"verdict"` // success / failed / error / skipped
	Evidence string `json:"evidence,omitempty"`
}

func (t *ToolSet) httpLoginCheck() actool.CoreTool {
	return readTool("http_login_check",
		"(凭据复用)验证 Web 登录凭据：对登录表单/登录接口逐个尝试【用户名+口令】组合(每组合一次)，自动判定成败(跳转/状态码/长度/失败关键词差异，或显式 success_contains)。表单字段可自动识别(GET 登录页解析 form)，JSON 接口请显式传 username_field/password_field/content_type。用于：①登录页弱口令验证(先小字典)②拿到凭据后在 Web 控制台上验证复用——一次成功登录即实证。验证器不是爆破器：单次 ≤10 组合、串行+间隔、出现锁定关键词/429 立即中止。组合默认按序配对(users[i]+passwords[i]，验证已有情报)，mode=cross 才做笛卡尔积。",
		obj(map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "登录页或登录接口 URL。HTML 表单页直接给页面地址(自动解析 form 提交地址与字段)；JSON/API 接口直接给接口地址并显式传字段。",
			},
			"users": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "用户名候选列表。",
			},
			"passwords": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "口令候选列表。默认与 users 按序配对(验证已有凭据情报)；mode=cross 时做笛卡尔积(截断到 10)。",
			},
			"mode": map[string]any{
				"type": "string", "default": "pairs",
				"description": "pairs(默认)=users[i]+passwords[i] 按序配对；cross=笛卡尔积(取前 10)。",
			},
			"username_field": map[string]any{
				"type": "string", "description": "用户名字段名(JSON/API 必传；HTML 表单可自动识别)。",
			},
			"password_field": map[string]any{
				"type": "string", "description": "口令字段名(JSON/API 必传；HTML 表单可自动识别)。",
			},
			"content_type": map[string]any{
				"type": "string", "default": "form",
				"description": "form=application/x-www-form-urlencoded(默认)；json=application/json。",
			},
			"extra_params": map[string]any{
				"type":        "string",
				"description": "登录所需的其它固定参数，k=v&k=v 形式(如 csrf token、captcha 占位)，会原样并入请求体。",
			},
			"success_contains": map[string]any{
				"type":        "string",
				"description": "显式成功指示：响应体包含该串即 success(比自动判定可靠；已知成功页特征时优先用)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 6000, "description": "单请求超时毫秒(2000..15000)。",
			},
			"proxy": map[string]any{
				"type": "string", "description": "HTTP 代理地址(可选)；留空默认走本任务录制代理(若有)。",
			},
		}, "url", "users", "passwords"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				URL             string   `json:"url"`
				Users           []string `json:"users"`
				Passwords       []string `json:"passwords"`
				Mode            string   `json:"mode"`
				UsernameField   string   `json:"username_field"`
				PasswordField   string   `json:"password_field"`
				ContentType     string   `json:"content_type"`
				ExtraParams     string   `json:"extra_params"`
				SuccessContains string   `json:"success_contains"`
				TimeoutMs       int      `json:"timeout_ms"`
				Proxy           string   `json:"proxy"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			target := strings.TrimSpace(p.URL)
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				return actool.Errorf("url 必须以 http:// 或 https:// 开头"), nil
			}
			if len(p.Users) == 0 || len(p.Passwords) == 0 {
				return actool.Errorf("users 与 passwords 都不能为空"), nil
			}
			if p.Mode == "" {
				p.Mode = "pairs"
			}
			// 组合生成：pairs 语义——单用户×全口令 / 全用户×单口令 / 等长按序配对；cross 笛卡尔积
			type combo struct{ u, pw string }
			var combos []combo
			switch p.Mode {
			case "pairs":
				switch {
				case len(p.Users) == 1:
					for _, pw := range p.Passwords {
						if pw != "" {
							combos = append(combos, combo{strings.TrimSpace(p.Users[0]), pw})
						}
					}
				case len(p.Passwords) == 1:
					for _, u := range p.Users {
						if u = strings.TrimSpace(u); u != "" {
							combos = append(combos, combo{u, p.Passwords[0]})
						}
					}
				default:
					n := len(p.Users)
					if len(p.Passwords) < n {
						n = len(p.Passwords)
					}
					for i := 0; i < n; i++ {
						if u := strings.TrimSpace(p.Users[i]); u != "" && p.Passwords[i] != "" {
							combos = append(combos, combo{u, p.Passwords[i]})
						}
					}
				}
			case "cross":
				for _, u := range p.Users {
					for _, pw := range p.Passwords {
						if u = strings.TrimSpace(u); u != "" && pw != "" {
							combos = append(combos, combo{u, pw})
						}
					}
				}
			default:
				return actool.Errorf(fmt.Sprintf("未知 mode %q，可选 pairs/cross", p.Mode)), nil
			}
			if len(combos) == 0 {
				return actool.Errorf("没有生成任何有效组合(检查 users/passwords)"), nil
			}
			truncated := false
			if len(combos) > 10 {
				combos = combos[:10]
				truncated = true
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 6 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}
			client, err := t.probeHTTPClient(p.Proxy, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			// ---- 字段识别：显式优先，否则 GET 登录页解析 form ----
			uf, pf := strings.TrimSpace(p.UsernameField), strings.TrimSpace(p.PasswordField)
			action, method := target, http.MethodPost
			autodetected := false
			if uf == "" || pf == "" {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				req.Header.Set("User-Agent", "YCode-recon/0.3")
				resp, err := client.Do(req)
				if err != nil {
					return actool.Errorf("登录页不可达: " + err.Error()), nil
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				a, m, u2, p2 := parseLoginHTML(target, string(body))
				if u2 == "" || p2 == "" {
					return actool.Errorf("未能自动识别登录表单字段(页面可能无 <form> 或为 JSON 接口)：请显式传 username_field / password_field"), nil
				}
				if uf == "" {
					uf = u2
				}
				if pf == "" {
					pf = p2
				}
				action, method = a, m
				autodetected = true
			}
			if p.ContentType == "" {
				p.ContentType = "form"
			}
			if p.ContentType != "form" && p.ContentType != "json" {
				return actool.Errorf("content_type 仅支持 form/json"), nil
			}

			// ---- 请求构造 ----
			buildBody := func(u, pw string) (string, string) {
				if p.ContentType == "json" {
					m := map[string]any{uf: u, pf: pw}
					if extra := strings.TrimSpace(p.ExtraParams); extra != "" {
						for _, kv := range strings.Split(extra, "&") {
							k, v, ok := strings.Cut(kv, "=")
							if ok {
								m[strings.TrimSpace(k)], _ = url.QueryUnescape(v)
							}
						}
					}
					b, _ := json.Marshal(m)
					return string(b), "application/json"
				}
				vals := url.Values{}
				vals.Set(uf, u)
				vals.Set(pf, pw)
				if extra := strings.TrimSpace(p.ExtraParams); extra != "" {
					for _, kv := range strings.Split(extra, "&") {
						k, v, ok := strings.Cut(kv, "=")
						if ok {
							vals.Set(strings.TrimSpace(k), v)
						}
					}
				}
				return vals.Encode(), "application/x-www-form-urlencoded"
			}
			type respFP struct {
				status int
				len    int
				loc    string
				body   string
				ms     int64
			}
			do := func(u, pw string) (respFP, error) {
				body, ctype := buildBody(u, pw)
				var req *http.Request
				if method == http.MethodGet {
					qs, _ := url.ParseQuery(body)
					req, _ = http.NewRequestWithContext(ctx, http.MethodGet, action+"?"+qs.Encode(), nil)
					req.Header.Set("Content-Type", ctype)
				} else {
					req, _ = http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(body))
					req.Header.Set("Content-Type", ctype)
				}
				req.Header.Set("User-Agent", "YCode-recon/0.3")
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					return respFP{ms: time.Since(start).Milliseconds()}, err
				}
				rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return respFP{
					status: resp.StatusCode,
					len:    len(rb),
					loc:    resp.Header.Get("Location"),
					body:   string(rb),
					ms:     time.Since(start).Milliseconds(),
				}, nil
			}
			bodyHasAny := func(body string, kws []string) string {
				lb := strings.ToLower(body)
				for _, k := range kws {
					if strings.Contains(lb, strings.ToLower(k)) {
						return k
					}
				}
				return ""
			}

			// ---- 基线：一次必错随机组合，采集失败指纹 ----
			randUser := fmt.Sprintf("ycbk%d", 1000+rand.Intn(9000))
			base, err := do(randUser, "Yc-NotAReal-Pass-000")
			if err != nil {
				return actool.Errorf("基线请求失败(目标不可达或代理失败): " + err.Error()), nil
			}
			if kw := bodyHasAny(base.body, lockoutKeywords); kw != "" || base.status == http.StatusTooManyRequests {
				return actool.Errorf("目标登录已触发锁定/限流(基线即被拒)，本次放弃——请等冷却或换入口"), nil
			}
			baseFailKw := bodyHasAny(base.body, loginFailKeywords)

			results := make([]loginAttempt, 0, len(combos))
			found := make([]loginAttempt, 0, 2)
			locked := false
			for i, c := range combos {
				if i > 0 {
					select {
					case <-time.After(300 * time.Millisecond): // 温和间隔，降低限流/锁定概率
					case <-ctx.Done():
						return actool.Errorf("已取消"), nil
					}
				}
				fp, err := do(c.u, c.pw)
				r := loginAttempt{Username: c.u, Password: c.pw, Status: fp.status, Len: fp.len, Loc: fp.loc, Ms: fp.ms}
				if err != nil {
					r.Verdict, r.Evidence = "error", "请求失败: "+err.Error()
					results = append(results, r)
					continue
				}
				if kw := bodyHasAny(fp.body, lockoutKeywords); kw != "" || fp.status == http.StatusTooManyRequests {
					r.Verdict, r.Evidence = "skipped", "触发锁定/限流(关键词 "+kw+")，后续组合全部跳过"
					results = append(results, r)
					locked = true
					// 中止：把剩余组合标为 skipped 但不再发请求
					for _, rest := range combos[i+1:] {
						results = append(results, loginAttempt{Username: rest.u, Password: rest.pw, Verdict: "skipped", Evidence: "防锁定兜底"})
					}
					break
				}
				// ---- 成败判定 ----
				if sc := strings.TrimSpace(p.SuccessContains); sc != "" && strings.Contains(fp.body, sc) {
					r.Verdict, r.Evidence = "success", "命中显式 success_contains"
				} else if fp.status != base.status {
					r.Verdict = "success"
					r.Evidence = fmt.Sprintf("状态码与失败基线不同(%d vs %d)——需人工确认", fp.status, base.status)
				} else if fp.loc != "" && fp.loc != base.loc {
					r.Verdict = "success"
					r.Evidence = "跳转目标与失败基线不同: " + fp.loc
				} else if base.len > 0 && abs(fp.len-base.len)*100/max(base.len, 1) > 25 {
					r.Verdict = "possible"
					r.Evidence = fmt.Sprintf("响应长度与失败基线差异显著(%d vs %d)——疑似，需确认", fp.len, base.len)
				} else if baseFailKw != "" && bodyHasAny(fp.body, loginFailKeywords) == "" {
					r.Verdict = "possible"
					r.Evidence = "基线含失败提示词而本次没有——疑似，需确认"
				} else {
					r.Verdict = "failed"
					if baseFailKw != "" {
						r.Evidence = "与失败基线一致(含失败提示词)"
					}
				}
				if r.Verdict == "success" {
					found = append(found, r)
				}
				results = append(results, r)
			}

			out := map[string]any{
				"url":          action,
				"method":       method,
				"fields":       map[string]string{"username": uf, "password": pf},
				"autodetected": autodetected,
				"baseline":     map[string]any{"status": base.status, "len": base.len, "location": base.loc, "fail_keyword": baseFailKw},
				"truncated":    truncated,
				"locked":       locked,
				"any_success":  len(found) > 0,
				"results":      results,
			}
			if len(found) > 0 {
				out["found"] = found
				out["note"] = "success=可登录凭据(实证，立刻 record_intelligence + insert_assets auth)；possible=疑似需人工复核；locked=触发防护已中止"
			} else {
				out["note"] = "本次组合均未成功；possible=疑似需复核；如需更大字典请分批多次调用(遵守防锁定纪律)"
			}
			return jsonResult(out)
		})
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
