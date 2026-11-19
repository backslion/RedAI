package agent

// web_fingerprint：Web 指纹识别（组件 + 版本），输出可直接喂给 search_vulns。
//
// 为什么需要它：RedAI 的攻击链在「信息收集 → 查 CVE」之间一直断着——http_probe
// 只回 server/title/content_type，dir_probe 只回路径状态码，两者都不产出
// 「组件名 + 版本」，而 search_vulns 恰恰要求这两个参数。结果就是 worker 看到
// nginx 首页、却不知道该查什么，最后只能凭印象试几个 CVE。
//
// 设计边界（有意为之）：
//   - 只做只读 GET，不爆破、不爬站、不解析 JS 运行时；一次调用确定「这是什么」。
//   - 目录发现不是它的职责（那是 dir_probe）。deep 模式的路径探测只覆盖 8 条
//     「能确认产品身份」的固定路径，且明确标注为身份确认而非资产发现。
//     路径结果带随机路径基线 + 响应体特征词双重校验，软 404 / SPA 兜底不会
//     被误判成「同时装了八个中间件」。
//   - 不做「多票加权」：多条弱证据加起来还是弱证据。同一 product 只保留最强证据。
//   - 版本拿不到就说拿不到。绝不用「看起来像 2.4.x」去凑一个版本号——把错误版本
//     喂给 search_vulns 会得到 version_in_range=false 的假安全结论。

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	fpMaxBody     = 512 << 10 // 首页只读前 512KB：指纹全在头部与资源引用里
	fpMaxEvidence = 3         // 单组件最多留 3 条证据
	fpEvidenceLen = 160       // 单条证据截断长度
)

// fpPathProbe 一条「路径 → 产品」的确认探针。
//
// 只在 deep=true 时跑。401/403 也算命中：控制台存在但需要认证，产品身份已经确定了。
//
// BodyRe 是必须项，不能省。原因：只看状态码会把「SPA 兜底 / 软 404 / WAF 友好
// 错误页」这类对任意路径都返 200 的站点判成同时装了 WordPress+Joomla+Nacos+
// Jenkins+Solr…，进而拼出一堆假的 search_vulns 查询。所以 2xx 响应必须在正文里
// 命中产品特征词才算数；401/403 只在「基线路径正确返 404」时才可单独作数。
var fpPathProbes = []struct {
	Path                  string
	Product, Vendor, Name string
	Category              string
	Conf                  float64
	BodyRe                *regexp.Regexp
}{
	{"/wp-login.php", "wordpress", "wordpress", "WordPress", "cms", 0.9,
		regexp.MustCompile(`(?i)wp-login|wordpress|wp-submit|lostpassword`)},
	{"/administrator/", "joomla", "joomla", "Joomla", "cms", 0.9,
		regexp.MustCompile(`(?i)joomla|com_login|com_users`)},
	{"/nacos/", "nacos", "alibaba", "Alibaba Nacos", "platform", 0.9,
		regexp.MustCompile(`(?i)nacos`)},
	{"/druid/index.html", "druid", "apache", "Apache Druid", "platform", 0.9,
		regexp.MustCompile(`(?i)druid|statview|Stat View`)},
	{"/actuator/env", "spring_boot", "vmware", "Spring Boot", "framework", 0.85,
		regexp.MustCompile(`(?i)propertySources|activeProfiles|"profiles"|spring\.boot|"property"`)},
	{"/jenkins/", "jenkins", "jenkins", "Jenkins", "platform", 0.9,
		regexp.MustCompile(`(?i)jenkins|hudson`)},
	{"/phpmyadmin/", "phpmyadmin", "phpmyadmin", "phpMyAdmin", "platform", 0.9,
		regexp.MustCompile(`(?i)phpmyadmin|pma_|"token"`)},
	{"/solr/", "solr", "apache", "Apache Solr", "platform", 0.9,
		regexp.MustCompile(`(?i)solr|lucene|Solr Admin`)},
}

var fpLinkRe = regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["']([^"']{1,512})["']`)

// fpPage 是一次 GET 采到的全部语料。
type fpPage struct {
	FinalURL string
	Status   int
	Server   string
	Headers  http.Header
	Cookie   string
	Title    string
	Body     string
	Links    string
	BodyLen  int
	Trunc    bool
}

// fpHit 是一个已识别的组件。
type fpHit struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor,omitempty"`
	Version     string   `json:"version,omitempty"`
	VersionFrom string   `json:"version_source,omitempty"`
	Confidence  float64  `json:"confidence"`
	Evidence    []string `json:"evidence"`
}

func (t *ToolSet) webFingerprint() actool.CoreTool {
	return readTool("web_fingerprint",
		"(指纹识别)识别 Web 目标的技术栈并给出【组件名 + 版本】，直接产出可用的 search_vulns 查询。\n"+
			"采集：响应头（Server/X-Powered-By/X-AspNet-Version/X-Jenkins/Kbn-Version…）、Set-Cookie 名"+
			"（rememberMe→Shiro、laravel_session→Laravel、zbx_session→Zabbix…）、meta generator、"+
			"静态资源路径（/wp-content/、jquery-3.4.1.min.js）、默认错误页（Whitelabel→Spring Boot）。\n"+
			"deep=true 时先探一条随机路径做基线，再探 8 条【能确认产品身份】的固定路径"+
			"（/nacos/ /druid/ /actuator/env /wp-login.php…）：2xx 必须命中响应体特征词、且与基线不是"+
			"同一张兜底页才算数（防 SPA/软 404 全站误报）；基线正确返 404 时 401/403 也算命中。"+
			"目录发现请用 dir_probe，本工具不干这个。\n"+
			"返回 components 数组（含 product/vendor/version/confidence/evidence）与 next_queries："+
			"后者是拼好的 search_vulns 调用，直接照抄即可。\n"+
			"拿不到版本的组件会在 warnings 里单列——**不要猜版本**，错误版本会让 search_vulns "+
			"返回 version_in_range=false 的假安全结论；无版本时按组件名查、再逐个 get_vuln 核对 CPE 区间。",
		obj(map[string]any{
			"url":        str("目标 URL（http:// 或 https:// 开头，可带路径；一般给站点根）"),
			"deep":       map[string]any{"type": "boolean", "description": "是否额外探 8 条产品确认路径（默认 true；目标敏感/限流时关掉）"},
			"favicon":    map[string]any{"type": "boolean", "description": "是否计算 favicon mmh3 哈希（默认 true；可用于 FOFA/Shodan 的 icon_hash 反查）"},
			"timeout_ms": intp("单请求超时毫秒（默认 6000，上限 15000）"),
			"proxy":      str("出口代理（可选，如 socks5://127.0.0.1:1080 或 http://…）；不填走平台录制代理，流量自动留痕"),
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				URL       string `json:"url"`
				Deep      *bool  `json:"deep"`
				Favicon   *bool  `json:"favicon"`
				TimeoutMs int    `json:"timeout_ms"`
				Proxy     string `json:"proxy"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			raw := strings.TrimSpace(p.URL)
			if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
				return actool.Errorf("url 必须以 http:// 或 https:// 开头"), nil
			}
			u, perr := url.Parse(raw)
			if perr != nil || u.Host == "" {
				return actool.Errorf("url 无法解析: " + raw), nil
			}
			deep := true
			if p.Deep != nil {
				deep = *p.Deep
			}
			wantFavicon := true
			if p.Favicon != nil {
				wantFavicon = *p.Favicon
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

			page, ferr := fpFetch(ctx, client, raw)
			if ferr != nil {
				return jsonResult(map[string]any{
					"url": raw, "reachable": false,
					"error": ferr.Error(),
					"note":  "请求失败：目标不可达、被拦、或需要认证。先 http_probe 确认可达，再回来识别。",
				})
			}

			hits := map[string]*fpHit{}
			warnings := []string{}
			for i := range fpRules {
				r := &fpRules[i]
				text, ok := fpCorpus(r, page)
				if !ok {
					continue
				}
				loc := r.Re.FindStringSubmatch(text)
				if loc == nil {
					continue
				}
				ver, vfrom := "", ""
				if r.VerRe != nil {
					if m := r.VerRe.FindStringSubmatch(text); len(m) > 1 && m[1] != "" {
						ver, vfrom = m[1], r.Note
					}
				} else if lg := r.Re.SubexpNames(); len(lg) > 1 && lg[1] != "" {
					// 规则把版本写进了自己的第一个捕获组。
					if len(loc) > 1 && loc[1] != "" {
						ver, vfrom = loc[1], r.Note
					}
				}
				if ver == "" {
					if m := genericVersionRe.FindStringSubmatch(loc[0]); len(m) > 1 {
						ver, vfrom = strings.TrimPrefix(m[1], "v"), r.Note+"（从命中片段提取）"
					}
				}
				ev := fpEvidenceOf(r, text, loc[0])
				fpMerge(hits, r, ver, vfrom, ev)
			}

			// deep：确认产品身份的固定路径。401/403 同样算命中。
			if deep {
				base := page.FinalURL
				if base == "" {
					base = raw
				}
				for _, pr := range fpProbePaths(ctx, client, base, timeout) {
					fpMerge(hits, &fpRule{
						Name: pr.name, Product: pr.product, Vendor: pr.vendor,
						Category: pr.category, Conf: pr.conf, Note: "身份确认路径",
					}, "", "", pr.evidence)
				}
			}

			favHash := int32(0)
			favOK := false
			if wantFavicon {
				favHash, favOK = fpFaviconHash(ctx, client, raw, page.FinalURL, timeout)
			}

			list := make([]*fpHit, 0, len(hits))
			for _, h := range hits {
				list = append(list, h)
			}
			sort.Slice(list, func(i, j int) bool {
				oi, oj := fpCategoryOrder[list[i].Category], fpCategoryOrder[list[j].Category]
				if oi != oj {
					return oi < oj
				}
				if list[i].Confidence != list[j].Confidence {
					return list[i].Confidence > list[j].Confidence
				}
				return list[i].Product < list[j].Product
			})

			next := make([]string, 0, len(list))
			for _, h := range list {
				if len(next) >= 12 {
					break
				}
				if h.Version != "" {
					next = append(next, fmt.Sprintf(`search_vulns(product=%q, vendor=%q, version=%q)`, h.Product, h.Vendor, h.Version))
				} else {
					next = append(next, fmt.Sprintf(`search_vulns(product=%q, vendor=%q)  # 无版本，需 get_vuln 核对 CPE 区间`, h.Product, h.Vendor))
				}
			}

			for _, h := range list {
				if h.Version == "" && fpCategoryOrder[h.Category] <= 4 {
					warnings = append(warnings, fmt.Sprintf(
						"%s 未取到版本——不要猜。按 product 查后再用 get_vuln 看 cpe_criteria 的版本区间，或找 /version、/actuator/info、报错页里的版本号。",
						h.Name))
				}
			}
			if len(list) == 0 {
				warnings = append(warnings, "未识别出任何组件：可能被 WAF 抹掉了 Server 头、或首页是纯静态占位页。试试 deep=true，或直接看 http_request 的原始响应头。")
			}

			out := map[string]any{
				"url":        raw,
				"final_url":  page.FinalURL,
				"status":     page.Status,
				"server":     page.Server,
				"title":      page.Title,
				"components": list,
				"count":      len(list),
				"next_queries": next,
			}
			if favOK {
				out["favicon_hash"] = favHash
				out["favicon_note"] = "mmh3(base64(76 列换行)) —— Shodan/FOFA 的 icon_hash 同算法，可直接反查同类资产"
			}
			if page.Trunc {
				out["body_truncated"] = true
			}
			if len(warnings) > 0 {
				out["warnings"] = warnings
			}
			return jsonResult(out)
		},
	)
}

// fpFetch 采一次首页：跟随重定向（≤5 跳）、读头与正文。
func fpFetch(ctx context.Context, client *http.Client, raw string) (*fpPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, rerr := io.ReadAll(io.LimitReader(resp.Body, fpMaxBody+1))
	if rerr != nil {
		return nil, rerr
	}
	trunc := false
	if len(body) > fpMaxBody {
		body = body[:fpMaxBody]
		trunc = true
	}

	p := &fpPage{
		FinalURL: resp.Request.URL.String(),
		Status:   resp.StatusCode,
		Server:   resp.Header.Get("Server"),
		Headers:  resp.Header,
		Body:     string(body),
		BodyLen:  len(body),
		Trunc:    trunc,
	}
	p.Cookie = strings.Join(resp.Header.Values("Set-Cookie"), " ")
	if m := titleRe.FindStringSubmatch(p.Body); len(m) > 1 {
		p.Title = strings.TrimSpace(htmlUnescapeLight(m[1]))
	}
	links := fpLinkRe.FindAllStringSubmatch(p.Body, -1)
	var lb strings.Builder
	for _, l := range links {
		if len(l) > 1 {
			lb.WriteString(l[1])
			lb.WriteString("\n")
		}
	}
	p.Links = lb.String()
	return p, nil
}

// fpCorpus 按规则的 On 取出它该匹配的语料，并给出「这段语料存在」的判定。
func fpCorpus(r *fpRule, p *fpPage) (string, bool) {
	switch r.On {
	case "header":
		if r.Field != "" {
			v := strings.Join(p.Headers.Values(r.Field), " ")
			return v, v != ""
		}
		var b strings.Builder
		for k, vs := range p.Headers {
			for _, v := range vs {
				b.WriteString(k)
				b.WriteString(": ")
				b.WriteString(v)
				b.WriteString("\n")
			}
		}
		return b.String(), b.Len() > 0
	case "cookie":
		return p.Cookie, p.Cookie != ""
	case "title":
		return p.Title, p.Title != ""
	case "body":
		return p.Body, p.Body != ""
	case "link":
		return p.Links, p.Links != ""
	}
	return "", false
}

// fpEvidenceOf 造一条人能核对、能贴进报告的短证据。
func fpEvidenceOf(r *fpRule, corpus, matched string) string {
	src := r.On
	if r.On == "header" && r.Field != "" {
		src = "响应头 " + r.Field
	}
	seg := strings.TrimSpace(matched)
	if len(seg) > fpEvidenceLen {
		seg = seg[:fpEvidenceLen] + "…"
	}
	if seg == "" {
		seg = strings.TrimSpace(corpus)
		if len(seg) > fpEvidenceLen {
			seg = seg[:fpEvidenceLen] + "…"
		}
	}
	return fmt.Sprintf("%s: %s（依据：%s）", src, seg, r.Note)
}

// fpMerge 按 product 去重：只留置信度更高的那条，证据最多攒 3 条。
func fpMerge(hits map[string]*fpHit, r *fpRule, ver, vfrom, ev string) {
	key := r.Product
	if key == "" {
		key = strings.ToLower(r.Name)
	}
	if cur, ok := hits[key]; ok {
		if r.Conf > cur.Confidence {
			cur.Name, cur.Category, cur.Vendor = r.Name, r.Category, r.Vendor
			cur.Confidence = r.Conf
			if ver != "" {
				cur.Version, cur.VersionFrom = ver, vfrom
			}
		}
		for _, e := range cur.Evidence {
			if e == ev {
				return
			}
		}
		if len(cur.Evidence) < fpMaxEvidence {
			cur.Evidence = append(cur.Evidence, ev)
		}
		return
	}
	h := &fpHit{
		Name: r.Name, Category: r.Category, Product: r.Product, Vendor: r.Vendor,
		Version: ver, VersionFrom: vfrom, Confidence: r.Conf,
		Evidence: []string{ev},
	}
	hits[key] = h
}

type fpPathResult struct {
	name, product, vendor, category, evidence string
	conf                                      float64
}

// fpNormalizeBody 把响应体压成「是否与基线同一张页」的比较指纹：小写、去空白、
// 只取前 1024 字节。SPA 兜底页即使每次带不同 nonce，主体模板仍相同，前缀比较足够。
func fpNormalizeBody(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		s.WriteByte(c)
		if s.Len() >= 1024 {
			break
		}
	}
	return s.String()
}

// fpBaseline 探一条高熵不存在的路径，判断「这个站点会不会区分路径存在与否」。
//
// 只有基线正确返 404/410，状态码才可信；SPA 兜底、软 404、整站要认证、WAF
// 友好错误页都会对任意路径给出像样的响应，此时一律只认响应体特征词。
// 拿不到基线也按不可信处理（保守），不会因为一次超时就放开全站误报。
func fpBaseline(ctx context.Context, client *http.Client, base string, timeout time.Duration) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	probe := base + fmt.Sprintf("/__pojun_fp_%x__/", time.Now().UnixNano())
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, probe, nil)
	if err != nil {
		return true, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return true, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	reliable := resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone
	return !reliable, fpNormalizeBody(body)
}

// fpProbePaths 并发探 8 条身份确认路径。并发度 4：够快，又不至于把脆弱目标打抖。
//
// 每次先多打一条随机路径做基线（共 9 个请求）。判定顺序是故意的：
// 与基线同页 → 直接丢弃；正文命中产品特征 → 采信；基线可信且 401/403 → 采信；
// 其余（尤其是 200 但没有特征词）一律不采信。
func fpProbePaths(ctx context.Context, client *http.Client, base string, timeout time.Duration) []fpPathResult {
	base = strings.TrimRight(base, "/")
	// base 可能带路径（如 http://h/app），路径探针必须以站点根为基准。
	if u, err := url.Parse(base); err == nil {
		base = u.Scheme + "://" + u.Host
	}

	unreliable, baseNorm := fpBaseline(ctx, client, base, timeout)

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]fpPathResult, 0, len(fpPathProbes))

	for _, pr := range fpPathProbes {
		pr := pr
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(cctx, http.MethodGet, base+pr.Path, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192)) // 只读一点，避免拉整页
			resp.Body.Close()
			st := resp.StatusCode
			// 404/410/5xx 不算：路径不存在或后端崩了，不能证明产品身份。
			if st == 404 || st == 410 || st >= 500 {
				return
			}
			norm := fpNormalizeBody(body)
			// 站点对任意路径都回同一张兜底页：这条响应不是产品控制台，丢弃。
			// 即使恰好含特征词也丢——兜底页里出现 "solr" 之类词并不罕见。
			if unreliable && baseNorm != "" && norm == baseNorm {
				return
			}
			word := pr.BodyRe != nil && pr.BodyRe.Match(body)
			var reason string
			switch {
			case word:
				reason = "响应体命中产品特征"
			case !unreliable && (st == 401 || st == 403):
				reason = "控制台存在但需认证（基线路径正确返 404）"
			default:
				// 2xx 无特征词 / 站点状态码不可信：宁可漏报也不拼假 CVE 查询。
				return
			}
			mu.Lock()
			out = append(out, fpPathResult{
				name: pr.Name, product: pr.Product, vendor: pr.Vendor,
				category: pr.Category, conf: pr.Conf,
				evidence: fmt.Sprintf("GET %s → %d（%s）", pr.Path, st, reason),
			})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// fpFaviconHash 取 favicon 并算 mmh3 哈希（与 Shodan/FOFA 的 icon_hash 同算法：
// 先 base64 编码、按 76 列换行，再对这段文本做 MurmurHash3 x86_32）。
//
// 这个值本身不参与自动判定——没有权威 hash 库，硬编码匹配表只会制造误判。
// 它的用途是「拿去反查」：FOFA 的 icon_hash="…" 能把同一套 CMS 的资产捞出来。
func fpFaviconHash(ctx context.Context, client *http.Client, raw, final string, timeout time.Duration) (int32, bool) {
	bases := []string{}
	for _, s := range []string{final, raw} {
		if s == "" {
			continue
		}
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			bases = append(bases, u.Scheme+"://"+u.Host)
		}
	}
	seen := map[string]bool{}
	for _, b := range bases {
		if seen[b] {
			continue
		}
		seen[b] = true
		cctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, b+"/favicon.ico", nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		cancel()
		if resp.StatusCode != 200 || len(data) == 0 {
			continue
		}
		// 有些站点对不存在路径返回 200 + HTML，用长度与首字节粗筛掉。
		if len(data) < 16 || strings.HasPrefix(string(data), "<") {
			continue
		}
		return int32(mmh3x86_32(faviconB64(data))), true
	}
	return 0, false
}

// faviconB64 复刻 Python base64.encodebytes：76 列换行、末尾带换行。
// 少了这个换行，算出来的 hash 与公开库对不上（这是最常踩的一脚）。
func faviconB64(data []byte) []byte {
	s := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteByte('\n')
		s = s[76:]
	}
	b.WriteString(s)
	b.WriteByte('\n')
	return []byte(b.String())
}

// mmh3x86_32 是 MurmurHash3 的 32 位变体（Shodan/FOFA 用的那个），
// 标准库没有实现，这里手写约 40 行，避免为一次哈希引入依赖。
func mmh3x86_32(data []byte) uint32 {
	const c1, c2 uint32 = 0xcc9e2d51, 0x1b873593
	var h1 uint32
	n := len(data)
	blocks := n / 4
	for i := 0; i < blocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	var k1 uint32
	tail := data[blocks*4:]
	switch len(tail) & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(n)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// htmlUnescapeLight 只处理标题里最常见的几种实体，不引入 html 包的重解析。
func htmlUnescapeLight(s string) string {
	r := strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", `"`, "&#39;", "'", "&nbsp;", " ",
	)
	return r.Replace(s)
}
