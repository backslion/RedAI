package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 本文件守的是「指纹 → 情报」这一跳：web_fingerprint 给出的 product/vendor/version
// 必须能原样拼进 search_vulns。它一旦悄悄错（版本抓错、product 名不是 CPE 命名），
// 下游得到的是 version_in_range=false 的假安全结论——这是最难被发现的失效方式。

type fpOut struct {
	URL         string   `json:"url"`
	Reachable   bool     `json:"reachable"`
	Status      int      `json:"status"`
	Server      string   `json:"server"`
	Title       string   `json:"title"`
	Components  []fpHit  `json:"components"`
	Count       int      `json:"count"`
	NextQueries []string `json:"next_queries"`
	Warnings    []string `json:"warnings"`
	FaviconHash *int32   `json:"favicon_hash"`
}

func runFingerprint(t *testing.T, body map[string]any) fpOut {
	t.Helper()
	ts := NewToolSet(nil, "worker")
	in, _ := json.Marshal(body)
	res, err := ts.webFingerprint().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	var out fpOut
	if jerr := json.Unmarshal([]byte(res.Flatten()), &out); jerr != nil {
		t.Fatalf("结果不是 JSON: %v\n%s", jerr, res.Flatten())
	}
	return out
}

func findByProduct(out fpOut, product string) *fpHit {
	for i := range out.Components {
		if out.Components[i].Product == product {
			return &out.Components[i]
		}
	}
	return nil
}

// 一个「nginx + PHP + WordPress + Shiro」的典型栈：四层各自靠不同证据命中，
// 版本必须从对应位置精确取到（头 / meta generator），不能互相串。
func TestWebFingerprintIdentifiesStack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/8.1.2")
			w.Header().Add("Set-Cookie", "PHPSESSID=abc123; path=/")
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; path=/")
			_, _ = w.Write([]byte(`<html><head>
<title>演示站点</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/demo/style.css">
<script src="/wp-includes/js/jquery/jquery-3.4.1.min.js"></script>
</head><body>ok</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": false, "favicon": false})

	if out.Status != 200 || out.Title != "演示站点" {
		t.Errorf("status=%d title=%q", out.Status, out.Title)
	}

	cases := []struct {
		product, version, category string
	}{
		{"nginx", "1.18.0", "web-server"},
		{"php", "8.1.2", "language"},
		{"wordpress", "6.4.2", "cms"},
		{"shiro", "", "framework"}, // 只有 rememberMe，没有版本
		{"jquery", "3.4.1", "js-lib"},
	}
	for _, c := range cases {
		h := findByProduct(out, c.product)
		if h == nil {
			t.Errorf("未识别出 %s；实际组件: %s", c.product, dumpProducts(out))
			continue
		}
		if h.Version != c.version {
			t.Errorf("%s 版本 = %q，期望 %q（来源 %q）", c.product, h.Version, c.version, h.VersionFrom)
		}
		if h.Category != c.category {
			t.Errorf("%s 类别 = %q，期望 %q", c.product, h.Category, c.category)
		}
		if len(h.Evidence) == 0 {
			t.Errorf("%s 没有证据", c.product)
		}
	}

	// WordPress 有两条规则（meta generator + /wp-content/），必须去重成一条，
	// 且保留置信度更高、带版本的那条。
	wpCount := 0
	for _, h := range out.Components {
		if h.Product == "wordpress" {
			wpCount++
		}
	}
	if wpCount != 1 {
		t.Errorf("wordpress 应去重为 1 条，实际 %d 条", wpCount)
	}

	// 无版本的高价值组件必须被点名提醒，否则 agent 容易自己编一个版本。
	if !containsStr(out.Warnings, "Shiro") && !containsStr(out.Warnings, "shiro") {
		t.Errorf("缺版本的 Shiro 应进 warnings，实际: %v", out.Warnings)
	}
}

// next_queries 是给模型照抄的：格式必须稳定，且无版本时要显式标注，
// 否则模型会把「product 查全部」当成「已确认受影响」。
func TestWebFingerprintNextQueries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		_, _ = w.Write([]byte(`<html><title>x</title></html>`))
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": false, "favicon": false})
	if len(out.NextQueries) == 0 {
		t.Fatal("next_queries 为空")
	}
	var found bool
	for _, q := range out.NextQueries {
		if strings.Contains(q, `product="httpd"`) && strings.Contains(q, `version="2.4.49"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("应给出 httpd 2.4.49 的查询，实际: %v", out.NextQueries)
	}
}

// deep 模式：403 是「存在但受限」，必须算命中（Nacos 控制台正典型）；
// 404 是「路径不存在」，绝不能命中——否则任何站点都会被判成装了全套中间件。
func TestWebFingerprintDeepPathSemantics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><title>plain</title></html>`))
		case "/nacos/":
			http.Error(w, "unauthorized", http.StatusForbidden) // 存在但受限
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": true, "favicon": false})
	if h := findByProduct(out, "nacos"); h == nil {
		t.Errorf("403 的 /nacos/ 应判为命中；实际: %s", dumpProducts(out))
	} else if len(h.Evidence) == 0 || !strings.Contains(strings.Join(h.Evidence, " "), "403") {
		t.Errorf("证据应写明状态码 403，实际: %v", h.Evidence)
	}

	// /druid/index.html、/actuator/env 等都返回 404，一条都不该命中。
	for _, bad := range []string{"druid", "spring_boot", "jenkins", "phpmyadmin", "solr", "wordpress", "joomla"} {
		if findByProduct(out, bad) != nil {
			t.Errorf("404 路径不应命中 %s", bad)
		}
	}
}

// mmh3 是手写的，必须和独立实现（Python 版）逐值对齐。
// 这些期望值由 /tmp/mmh3ref.py 的纯 Python 实现算出，其中 hello=613153351
// 也与公开的 mmh3.hash("hello") 一致。
func TestMmh3MatchesIndependentImplementation(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"hello", 613153351},
		{"abc", -1277324294},
		{strings.Repeat("a", 77), -20951281},
	}
	for _, c := range cases {
		if got := int32(mmh3x86_32([]byte(c.in))); got != c.want {
			t.Errorf("mmh3(%q) = %d，期望 %d", c.in, got, c.want)
		}
	}

	// favicon 的哈希是「base64 文本」的哈希，不是原始字节的哈希；
	// 用同一个样本验证这条链路（Python 侧同参数：209674549）。
	fake := append([]byte{0, 0, 1, 0, 1, 0, 0x10, 0x10}, make([]byte, 64)...)
	for i := range fake[8:] {
		fake[8+i] = byte(i)
	}
	if got := int32(mmh3x86_32([]byte(faviconB64(fake)))); got != 209674549 {
		t.Errorf("favicon b64 哈希 = %d，期望 209674549", got)
	}
}

// Python base64.encodebytes 的换行规则：每 76 列插 \n，末尾必有 \n。
// 少一个换行，算出来的 icon_hash 就和 FOFA/Shodan 对不上——这是最容易踩的一脚。
func TestFaviconBase64WrapsAt76(t *testing.T) {
	data := make([]byte, 100)
	out := string(faviconB64(data))
	if !strings.HasSuffix(out, "\n") {
		t.Error("末尾缺换行")
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("100 字节应被切成多行，实际 %d 行", len(lines))
	}
	for i, ln := range lines {
		if i < len(lines)-1 && len(ln) != 76 {
			t.Errorf("第 %d 行长度 %d，期望 76", i, len(ln))
		}
	}
	// base64 的 100 字节 = 136 字符 → 76 + 60
	if len(lines[0]) != 76 || len(lines[1]) != 60 {
		t.Errorf("行宽 = %d,%d，期望 76,60", len(lines[0]), len(lines[1]))
	}
}

// 目标不可达时必须给「不可达」而不是「零组件」——后者会被读成「这站没技术栈」。
func TestWebFingerprintUnreachable(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	in, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:1/", "deep": false, "favicon": false, "timeout_ms": 1500})
	res, err := ts.webFingerprint().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	var out fpOut
	if jerr := json.Unmarshal([]byte(res.Flatten()), &out); jerr != nil {
		t.Fatalf("结果不是 JSON: %v", jerr)
	}
	if out.Reachable {
		t.Error("应标记 reachable=false")
	}
	if len(out.Components) != 0 {
		t.Errorf("不可达不应有组件: %s", dumpProducts(out))
	}
}

func dumpProducts(out fpOut) string {
	ps := make([]string, 0, len(out.Components))
	for _, h := range out.Components {
		ps = append(ps, h.Product+"@"+h.Version)
	}
	return strings.Join(ps, ", ")
}

func containsStr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// 绑定守卫：指纹工具必须同时在三处可用——worker 执行、planner 开局定向、
// pentest 独立 agent 全流程。少任何一处，对应角色的链路都会断在同一处：
// worker 缺 → 拿到栈也不会查 CVE；planner 缺 → 派不出具体意图；
// pentest 缺 → 独立 agent 从侦察到利用之间空一格。
func TestWebFingerprintBinding(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	has := func(list []actool.CoreTool, name string) bool {
		for _, x := range list {
			if x.Name() == name {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools(), "web_fingerprint") {
		t.Error("worker 缺 web_fingerprint")
	}
	if !has(ts.PlannerTools(), "web_fingerprint") {
		t.Error("planner 缺 web_fingerprint（开局定不了组件就派不出具体意图）")
	}
	if !has(ts.MainAgentTools(), "web_fingerprint") {
		t.Error("mainagent 缺 web_fingerprint（人无法手动识别栈）")
	}
	pentest, ok := builtinToolsByAgent()["pentest"]
	if !ok {
		t.Fatal("pentest 目录不存在")
	}
	if !has(pentest, "web_fingerprint") {
		t.Error("pentest 默认绑定缺 web_fingerprint")
	}
}

// 软 404 / SPA 兜底：站点对任意路径都回同一张 200 页面。
// 修复前 deep 会把 8 条身份确认路径全部判成命中，凭空造出 8 个产品与 8 条假的
// search_vulns 查询——前端路由、WAF 友好错误页在真实资产里非常常见，是必须钉死的
// 失效模式（一次真实调用演示里 12 条查询有 8 条是这么来的）。
func TestWebFingerprintSoft404DoesNotFabricateProducts(t *testing.T) {
	page := `<html><head><meta name="generator" content="WordPress 6.4.1"></head><body>SPA fallback</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Set-Cookie", "rememberMe=deleteMe; Path=/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page)) // 所有路径（含随机基线路径）都回这张页
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": true, "favicon": false})

	// 首页的真实证据仍然成立——修误报不能把真指纹一起修没了。
	for _, want := range []string{"nginx", "php", "shiro", "wordpress"} {
		if findByProduct(out, want) == nil {
			t.Errorf("首页证据应命中 %s；实际: %s", want, dumpProducts(out))
		}
	}
	// 只可能来自路径误报的产品，一个都不能有，更不能拼进查询。
	for _, bad := range []string{"joomla", "nacos", "druid", "spring_boot", "jenkins", "phpmyadmin", "solr"} {
		if findByProduct(out, bad) != nil {
			t.Errorf("软 404 兜底页被误判成 %s；实际: %s", bad, dumpProducts(out))
		}
		for _, q := range out.NextQueries {
			if strings.Contains(q, `product="`+bad+`"`) {
				t.Errorf("拼出了假的查询 %q", q)
			}
		}
	}
}

// 正向：2xx 路径必须带响应体特征词；401/403 只在基线正确返 404 时才作数。
func TestWebFingerprintPathProbeNeedsBodyEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><title>plain</title></html>`))
		case "/solr/":
			_, _ = w.Write([]byte(`<html><title>Apache Solr Admin</title>solr core</html>`))
		case "/jenkins/":
			_, _ = w.Write([]byte(`<html><title>Company Portal</title>nothing here</html>`)) // 200 但无特征
		case "/nacos/":
			http.Error(w, "unauthorized", http.StatusForbidden) // 403，无特征词
		default:
			http.NotFound(w, r) // 基线路径正确返 404，状态码可信
		}
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": true, "favicon": false})
	if findByProduct(out, "solr") == nil {
		t.Errorf("响应体含 Solr 特征应命中；实际: %s", dumpProducts(out))
	}
	if findByProduct(out, "nacos") == nil {
		t.Errorf("基线正确时 403 控制台应命中；实际: %s", dumpProducts(out))
	}
	if h := findByProduct(out, "jenkins"); h != nil {
		t.Errorf("200 但无特征词不应命中 jenkins；证据: %v", h.Evidence)
	}
}

// 规则库扩容的验收用例：一张同时挂着 Confluence / Nexus / Harbor 的运维入口页。
//
// 扩容前这张页只能认出 nginx + PHP——三个真正带 CVE 的平台一个都看不见，
// 于是 planner 只能派「扫目录」，而正确答案是「查 Confluence 的认证绕过」。
// 这条用例守的就是这个差别：平台级组件必须能被认出来，并且进 next_queries。
func TestWebFingerprintOpsStackCoverage(t *testing.T) {
	body := `<html><head><title>运维入口</title></head><body>
<a href="/confluence/">Wiki</a>
<script>var ctxPath="/confluence";var confluenceBaseUrl="/confluence";</script>
<div id="com-atlassian-confluence"></div>
<a href="/nexus/">Nexus</a><input name="NX-ANTI-CSRF-TOKEN" value="x">
<a href="/harbor/projects"><img class="harbor-logo" src="/images/harbor-logo.png"></a>
</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	out := runFingerprint(t, map[string]any{"url": srv.URL, "deep": false, "favicon": false})

	want := []string{"nginx", "php", "confluence_server", "nexus_repository_manager", "harbor"}
	for _, p := range want {
		if findByProduct(out, p) == nil {
			t.Errorf("未识别出 %s；实际: %s", p, dumpProducts(out))
		}
	}

	// 认出来还不够——必须变成可直接执行的 search_vulns 调用，否则 agent 仍然不知道查什么。
	for _, p := range []string{"confluence_server", "nexus_repository_manager"} {
		found := false
		for _, q := range out.NextQueries {
			if strings.Contains(q, `product="`+p+`"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s 未进 next_queries，agent 拿到组件也不知道查什么：%v", p, out.NextQueries)
		}
	}
}
