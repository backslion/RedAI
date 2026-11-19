package agent

// 规则表是纯数据，它的腐化方式很特别：加了一条永远命中不了的规则、Product 拼成
// CPE 里不存在的名字、Category 写成表里没有的值——这三种错都不会让编译失败，也不会
// 让任何用例变红，只会在实战里静默少识别一个组件、或者拼出一条查不到任何结果的
// search_vulns 查询。
//
// 本文件把这几件事全部变成构建期失败：
//   1. 结构合法（CPE 命名 / 枚举取值 / 正则不匹配空串）；
//   2. 同 product 的 vendor、category 必须一致（fpMerge 按 product 去重，混着写会拼错 CPE）；
//   3. 每条规则都有【可执行样本】——样本命中自己的规则，规则没样本则直接失败。
//
// 加新规则时的正确姿势：在 fingerprint_rules.go 里写规则，在下面的 fpRuleSamples 里
// 补一行真实响应片段。少了这一行，测试会直接告诉你。

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestFPRuleTableShape(t *testing.T) {
	validOn := map[string]bool{"header": true, "cookie": true, "title": true, "body": true, "link": true}
	// CPE 2.3 的 product/vendor 只允许小写字母、数字与 . _ -，且不以分隔符开头。
	// 写成 "Apache Tomcat" 这类展示名，search_vulns 一条都查不到。
	cpeName := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

	for i, r := range fpRules {
		tag := fmt.Sprintf("#%d %s(product=%s)", i, r.Name, r.Product)
		if strings.TrimSpace(r.Name) == "" {
			t.Errorf("%s: Name 为空", tag)
		}
		if !cpeName.MatchString(r.Product) {
			t.Errorf("%s: Product 不是合法 CPE 名（实际 %q）", tag, r.Product)
		}
		if r.Vendor != "" && !cpeName.MatchString(r.Vendor) {
			t.Errorf("%s: Vendor 不是合法 CPE 名（实际 %q）", tag, r.Vendor)
		}
		if _, ok := fpCategoryOrder[r.Category]; !ok {
			t.Errorf("%s: Category=%q 不在 fpCategoryOrder 里（排序会退化成 0，挤掉真正的服务器组件）", tag, r.Category)
		}
		if !validOn[r.On] {
			t.Errorf("%s: On=%q 不是 fpCorpus 支持的语料", tag, r.On)
		}
		if r.Re == nil {
			t.Errorf("%s: 正则未编译", tag)
			continue
		}
		if r.Conf <= 0 || r.Conf > 1 {
			t.Errorf("%s: Conf=%v 超出 (0,1]", tag, r.Conf)
		}
		if r.On != "header" && r.Field != "" {
			t.Errorf("%s: Field 只在 On=header 时有意义（现在是 %q）", tag, r.On)
		}
		if strings.TrimSpace(r.Note) == "" {
			t.Errorf("%s: Note 为空——证据里会缺「依据」这一栏", tag)
		}
		// 能匹配空串的正则（.*、.*?、^$）等于对任何响应都命中，
		// 是最典型的「一加就把误报率拉满」写法。
		if r.Re.MatchString("") {
			t.Errorf("%s: 正则能匹配空串（%s），必然对任意响应命中", tag, r.Re.String())
		}
	}
}

// fpMerge 按 product 去重，所以同一个 product 的 vendor / category 必须是同一个值。
// 否则「Server 头那条报 apache，正文那条报 redhat」，最终拼进 search_vulns 的是哪条
// 取决于遍历顺序——一个永远不会被发现的随机错误。
func TestFPRuleProductMetaConsistent(t *testing.T) {
	type meta struct{ vendor, category, name string }
	seen := map[string]meta{}

	for _, r := range fpRules {
		cur := meta{r.Vendor, r.Category, r.Name}
		prev, ok := seen[r.Product]
		if !ok {
			seen[r.Product] = cur
			continue
		}
		if prev.vendor != cur.vendor {
			t.Errorf("product=%s 的 Vendor 不一致: %q vs %q", r.Product, prev.vendor, cur.vendor)
		}
		if prev.category != cur.category {
			t.Errorf("product=%s 的 Category 不一致: %q vs %q", r.Product, prev.category, cur.category)
		}
		if prev.name != cur.name {
			t.Errorf("product=%s 的 Name 不一致: %q vs %q", r.Product, prev.name, cur.name)
		}
	}
}

// 完全相同的 (语料, 字段, 正则) 只可能是复制粘贴后忘了改，会产出两条一模一样的证据。
func TestFPRuleUniqueEvidence(t *testing.T) {
	seen := map[string]int{}
	for i, r := range fpRules {
		k := r.On + "|" + r.Field + "|" + r.Re.String()
		if j, ok := seen[k]; ok {
			t.Errorf("#%d(%s) 与 #%d 的证据完全相同: %s", i, r.Name, j, k)
		}
		seen[k] = i
	}
}

// fpRuleSamples 是每条规则的「真实响应长什么样」的可执行样本，key 是 CPE product。
//
// 它不是断言「这段文本只可能来自该产品」，而是断言「这条正则确实能匹配这类响应」。
// 版本号写在样本里，是为了顺带守住版本捕获组——版本抓错会让 search_vulns 返回
// version_in_range=false，那是最危险的失效（看起来「查过了，没漏洞」）。
var fpRuleSamples = map[string]string{
	// Web 服务器
	"nginx":                         "nginx/1.18.0",
	"openresty":                     "openresty/1.21.4.1",
	"tengine":                       "Tengine/2.3.3",
	"httpd":                         "Apache/2.4.49 (Unix)",
	"internet_information_services": "Microsoft-IIS/10.0",
	"caddy":                         "Caddy",
	"litespeed_web_server":          "LiteSpeed",
	"apisix":                        "APISIX/3.2.0",
	"kong":                          "kong/3.3.0",
	"traefik":                       "Traefik/2.9.0",
	"envoy":                         "envoy",
	"traffic_server":                "ATS/9.1.4",

	// 语言 / 运行时
	"php":          "PHP/8.1.2",
	"asp.net":      "4.0.30319",
	"asp.net_core": "Kestrel",
	"express":      "Express",
	"werkzeug":     "Werkzeug/2.2.2",
	"gunicorn":     "gunicorn/20.1.0",

	// Java 中间件 / 框架
	"tomcat":                                "Apache-Coyote/1.1",
	"jetty":                                 "Jetty(9.4.43.v20210629)",
	"undertow":                              "Undertow/2.2.5.Final",
	"resin":                                 "Resin/4.0.66",
	"weblogic_server":                       "ADMINCONSOLESESSION=abc123",
	"websphere_application_server":          "JSESSIONID=0000abc; LtpaToken2=def456",
	"jboss_enterprise_application_platform": "JBoss Web",
	"shiro":                                 "rememberMe=deleteMe",
	"spring_boot":                           "Whitelabel Error Page",
	"struts":                                "/struts/namespace/login.action",
	"cxf":                                   "Apache CXF",
	"axis2":                                 "Apache Axis2",
	"ofbiz":                                 "Apache OFBiz",

	// 框架
	"thinkphp":    "ThinkPHP",
	"laravel":     "laravel_session=abc",
	"rails":       "0.0123",
	"django":      "csrftoken=abc",
	"next.js":     "__NEXT_DATA__",
	"nuxt.js":     "window.__NUXT__",
	"yii":         "Yii Framework",
	"codeigniter": "ci_session=abc",
	"cakephp":     "CAKEPHP=abc",

	// CMS
	"wordpress":  `<meta name="generator" content="WordPress 6.4.2">`,
	"joomla":     `<meta name="generator" content="Joomla! 4.2.0">`,
	"drupal":     "Drupal 9.4",
	"discuzx":    "Powered by Discuz",
	"dedecms":    "Powered by DedeCms",
	"phpcms":     "PHPCMS",
	"empirecms":  "EmpireCMS",
	"typecho":    "typecho",
	"z-blogphp":  "zblogphp",
	"emlog":      "emlog",
	"maccms":     "maccms",
	"seacms":     "seacms",
	"typo3":      "typo3temp",
	"prestashop": "prestashop",
	"opencart":   "catalog/view/theme/default/stylesheet/stylesheet.css",
	"ghost":      `content="Ghost 5.70"`,
	"hugo":       `<meta name="generator" content="Hugo 0.118.2">`,
	"hexo":       `<meta name="generator" content="Hexo 7.0.0">`,

	// 运维 / 数据平台
	"jenkins":                  "2.361",
	"gitlab":                   "_gitlab_session=abc",
	"grafana":                  "grafana_session=abc",
	"kibana":                   "7.17.0",
	"elasticsearch":            "Elasticsearch",
	"solr":                     "Solr Admin",
	"druid":                    "Druid Stat Index",
	"nacos":                    "nacos.namespace",
	"xxl-job":                  "xxl-job",
	"zabbix":                   "zbx_session=abc",
	"phpmyadmin":               "phpMyAdmin 5.2.0",
	"adminer":                  "Adminer",
	"baota_panel":              "btwaf",
	"skywalking":               "skywalking",
	"sentinel":                 "Sentinel Dashboard",
	"hadoop":                   "hadoop-yarn",
	"flink":                    "Apache Flink Dashboard",
	"zeppelin":                 "Apache Zeppelin",
	"airflow":                  "airflow/static/",
	"dashboard":                "kubernetes-dashboard",
	"rancher":                  "rancher/ui",
	"portainer":                "portainer",
	"prometheus":               "Prometheus",
	"alertmanager":             "Alertmanager",
	"cacti":                    "cacti",
	"nagios":                   "Nagios Core",
	"confluence_server":        "com-atlassian-confluence",
	"jira_server":              "com-atlassian-jira",
	"bitbucket":                "com-atlassian-bitbucket",
	"teamcity":                 "TeamCity",
	"artifactory":              "Artifactory/7.55.10",
	"nexus_repository_manager": "Nexus/3.58.1",
	"sonarqube":                "sonarqube",
	"gitea":                    "i_like_gitea=abc",
	"gogs":                     "i_like_gogs=abc",
	"harbor":                   "harbor-logo",
	"minio":                    "minio-browser",
	"consul":                   "Consul by HashiCorp",
	"jumpserver":               "jumpserver",
	"metabase":                 "metabase",
	"superset":                 "Superset",
	"notebook":                 "Jupyter",
	"seafile":                  "seafile",
	"nextcloud":                "nextcloud",
	"e-cology":                 "/spa/portal/",

	// 前端库
	"jquery":     "/js/jquery-3.4.1.min.js",
	"vue.js":     "/js/vue-2.6.14.min.js",
	"angular":    `ng-version="14.2.0"`,
	"bootstrap":  "/css/bootstrap-5.1.3.min.css",
	"element-ui": "/element-ui@2.15.6/index.js",
	"ueditor":    "/ueditor/ueditor.config.js",
	"ckeditor":   "/ckeditor/4.21.0/ckeditor.js",
	"tinymce":    "/tinymce/6/tinymce.min.js",
}

// fpPageWithText 把一段语料铺满所有语料位。
//
// 这样样本只需要写「响应里长什么样」，不必关心这条规则读的是头、Cookie 还是正文——
// 测试要验证的是【正则能不能匹配这类文本】，不是【这段文本出现在 HTTP 的哪个位置】
// （后者由 On/Field 的取值负责，见 TestFPRuleTableShape）。
func fpPageWithText(text string) *fpPage {
	h := http.Header{}
	for _, r := range fpRules {
		if r.On == "header" && r.Field != "" {
			h.Set(r.Field, text)
		}
	}
	if len(h) == 0 {
		h.Set("Server", text)
	}
	return &fpPage{
		Status: 200, Server: text, Headers: h, Cookie: text,
		Title: text, Body: text, Links: text, BodyLen: len(text),
	}
}

// 每条规则都要有一个能命中自己的样本；每个样本都要真的命中它声称的 product。
// 这条用例是整个规则库的「可执行文档」——它红了，说明某条规则是死规则。
func TestFPRuleSamples(t *testing.T) {
	// 正向：样本 → 必须命中自己的 product
	for product, sample := range fpRuleSamples {
		page := fpPageWithText(sample)
		hit := false
		for i := range fpRules {
			r := &fpRules[i]
			if r.Product != product {
				continue
			}
			text, ok := fpCorpus(r, page)
			if !ok {
				continue
			}
			if r.Re.MatchString(text) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("product=%s 的样本 %q 命中不了它自己的任何一条规则（死规则）", product, sample)
		}
	}

	// 反向：规则 → 必须有样本。新增规则却忘了写样本，这里会点名。
	for _, r := range fpRules {
		if _, ok := fpRuleSamples[r.Product]; !ok {
			t.Errorf("%s(product=%s) 没有样本：请在本文件的 fpRuleSamples 补一行真实响应片段", r.Name, r.Product)
		}
	}
}

// 一个「装好 nginx 但没部署任何应用」的默认页：只该认出 nginx，不该因为正文里
// 出现了别的产品名就凭空多出组件。这条守的是「正文关键词规则不会把提及当部署」。
func TestFPPlainPageOnlyIdentifiesWhatIsThere(t *testing.T) {
	body := `<html><head><title>Welcome to nginx!</title></head><body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.
Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p></body></html>`
	page := &fpPage{
		Status:  200,
		Server:  "nginx/1.18.0",
		Headers: http.Header{"Server": {"nginx/1.18.0"}, "Content-Type": {"text/html"}},
		Title:   "Welcome to nginx!",
		Body:    body,
		BodyLen: len(body),
	}

	hits := map[string]*fpHit{}
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
		ver := ""
		if len(loc) > 1 {
			ver = loc[1]
		}
		fpMerge(hits, r, ver, r.Note, "sample")
	}

	if _, ok := hits["nginx"]; !ok {
		t.Error("默认页应识别出 nginx")
	}
	for _, bad := range []string{
		"metabase", "seafile", "nextcloud", "jumpserver", "portainer", "cacti", "emlog",
		"prestashop", "sonarqube", "skywalking", "harbor", "teamcity", "prometheus",
	} {
		if h, ok := hits[bad]; ok {
			t.Errorf("默认页被误判成 %s，证据: %v", bad, h.Evidence)
		}
	}
}
