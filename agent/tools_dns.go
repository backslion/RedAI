package agent

// 子域探测工具（YCode 二开）：subdomain_probe 用内置常见子域字典 + DNS 解析做
// 主动子域枚举，带【泛解析检测】（随机子域能解析 → 域名开了泛解析，命中按 IP
// 聚类去噪并明确标注），支持指定解析器（内网 DNS / 自建 resolver）。纯标准库，
// 不依赖外部 API 或第三方字典文件。lookup 函数可注入，便于测试。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// commonSubWords 是内置子域字典（常见运维/业务/中间件命名，约 200 条）。
var commonSubWords = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
	"vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host",
	"support", "dev", "web", "bbs", "mx", "email", "cloud", "1", "mail1", "2",
	"forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange",
	"app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news", "1rer", "lkjkui", "beta",
	"staging", "prod", "production", "demo", "docs", "doc", "wiki", "confluence", "jira", "gitlab",
	"jenkins", "sonar", "nexus", "harbor", "registry", "kibana", "grafana", "prometheus", "zabbix", "nagios",
	"monitor", "status", "sso", "auth", "login", "passport", "id", "account", "oauth", "cas",
	"ldap", "ad", "dc", "dns", "dhcp", "tftp", "proxy", "cache", "gateway", "router",
	"firewall", "waf", "lb", "haproxy", "nginx", "apache", "tomcat", "iis", "weblogic", "websphere",
	"jboss", "wildfly", "activemq", "rabbitmq", "kafka", "zookeeper", "es", "elastic", "search", "solr",
	"db", "mysql", "mssql", "oracle", "postgres", "pgsql", "mongodb", "mongo", "redis", "memcached",
	"backup", "bak", "old", "new", "archive", "nas", "file", "files", "share", "samba",
	"nfs", "cifs", "print", "scanner", "oa", "crm", "erp", "hr", "finance", "pay",
	"payment", "trade", "trading", "stock", "bank", "report", "bi", "etl", "data", "bigdata",
	"hadoop", "spark", "hive", "hbase", "flink", "airflow", "rancher", "k8s", "kube", "docker",
	"ci", "cd", "deploy", "release", "sandbox", "gray", "pre", "preprod", "uat", "qa",
	"static", "assets", "img", "image", "images", "pic", "video", "media", "download", "dl",
	"upload", "cdn1", "cdn2", "img1", "img2", "static1", "static2", "res", "resource", "js",
	"mip", "h5", "mobile", "wap", "ios", "android", "wechat", "wx", "weixin", "mini",
	"internal", "intra", "intranet", "corp", "company", "office", "vpn2", "ssl", "remote2", "jump",
	"bastion", "audit", "log", "logs", "syslog", "splunk", "elastic2", "mq", "queue", "task",
	"job", "worker", "service", "svc", "rpc", "grpc", "api2", "apiv2", "v2", "v3",
	"open", "openapi", "gateway-api", "tfs", "s3", "oss", "cos", "minio", "ceph", "storage",
	"db2", "bi2", "ai", "ml", "nlp", "chat", "im", "msg", "message", "push",
	"sms", "email2", "smtp2", "pop", "imap", "ftp2", "sftp", "ssh", "rdp", "vnc",
}

// lookupFunc resolves a hostname to IPs; injectable for tests.
type lookupFunc func(ctx context.Context, host string) ([]net.IP, error)

func (t *ToolSet) subdomainProbe() actool.CoreTool {
	return readTool("subdomain_probe",
		"(攻击面清点)主动子域枚举：内置约 200 常见子域字典(admin/api/jenkins/oa/gitlab/db/jump…)做 DNS 解析，带泛解析检测(随机子域可解析→自动标注并按 IP 聚类去噪)。支持 resolver 指定内网 DNS(如 10.0.0.53:53)或留空用系统解析——内网场景指向内网 DNS 可枚举内部域名。命中的子域应登记 insert_assets(type=subdomain，父域为 root_domain)。",
		obj(map[string]any{
			"domain": map[string]any{
				"type":        "string",
				"description": "要枚举的根域，如 example.com 或 internal.corp(不要带 scheme/路径)。",
			},
			"words": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "显式子域前缀列表(与 preset 叠加)，如 [\"vpn\",\"gitlab\"]。",
			},
			"preset": map[string]any{
				"type": "string", "default": "common200",
				"description": "字典预设：common200(默认,内置约 200 常见前缀) / none(只用显式 words)。",
			},
			"resolver": map[string]any{
				"type":        "string",
				"description": "DNS 解析器 host:port(可选，如 10.0.0.53:53 或 8.8.8.8:53)；留空用系统默认解析。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 3000,
				"description": "单次解析超时毫秒(500..10000)。",
			},
		}, "domain"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Domain    string   `json:"domain"`
				Words     []string `json:"words"`
				Preset    string   `json:"preset"`
				Resolver  string   `json:"resolver"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			domain := strings.ToLower(strings.Trim(strings.TrimSpace(p.Domain), "."))
			domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
			domain = strings.SplitN(domain, "/", 2)[0]
			if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " :@") {
				return actool.Errorf("domain 非法(应为根域，如 example.com)"), nil
			}
			if p.Preset == "" {
				p.Preset = "common200"
			}
			wordSet := map[string]bool{}
			if p.Preset == "common200" {
				for _, w := range commonSubWords {
					wordSet[w] = true
				}
			} else if p.Preset != "none" {
				return actool.Errorf(fmt.Sprintf("未知 preset %q，可选 common200/none", p.Preset)), nil
			}
			for _, w := range p.Words {
				w = strings.ToLower(strings.TrimSpace(w))
				if w == "" {
					continue
				}
				wordSet[w] = true
			}
			if len(wordSet) == 0 {
				return actool.Errorf("未指定任何子域前缀(preset=none 且 words 为空)"), nil
			}
			if len(wordSet) > 400 {
				return actool.Errorf(fmt.Sprintf("前缀过多(%d>400)，请分批", len(wordSet))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 3 * time.Second
			}
			if timeout > 10*time.Second {
				timeout = 10 * time.Second
			}
			lookup, err := t.dnsLookup(p.Resolver, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			// 泛解析检测：两个随机子域，任一可解析即视为泛解析。
			rand1 := fmt.Sprintf("wcprobe-%d.%s", time.Now().UnixNano()%1e6, domain)
			rand2 := fmt.Sprintf("zz-%d.%s", time.Now().UnixNano()%1e6, domain)
			wildcardIPs := map[string]bool{}
			for _, rnd := range []string{rand1, rand2} {
				if ips, err := lookup(ctx, rnd); err == nil {
					for _, ip := range ips {
						wildcardIPs[ip.String()] = true
					}
				}
			}
			wildcard := len(wildcardIPs) > 0

			words := make([]string, 0, len(wordSet))
			for w := range wordSet {
				words = append(words, w)
			}
			sort.Strings(words)

			type sub struct {
				Sub  string   `json:"subdomain"`
				IPs  []string `json:"ips"`
				Note string   `json:"note,omitempty"`
			}
			subs := make([]sub, 0, 32)
			wildcardHits := 0
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 40)
			for _, w := range words {
				wg.Add(1)
				go func(w string) {
					defer wg.Done()
					if ctx.Err() != nil {
						return
					}
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sem }()
					host := w + "." + domain
					ips, err := lookup(ctx, host)
					if err != nil || len(ips) == 0 {
						return
					}
					strs := make([]string, 0, len(ips))
					for _, ip := range ips {
						strs = append(strs, ip.String())
					}
					s := sub{Sub: host, IPs: strs}
					if wildcard && overlapWith(strs, wildcardIPs) {
						// 泛解析去噪：命中 IP 与随机探测 IP 重合 → 大概率是泛解析兜底。
						s.Note = "疑似泛解析兜底(IP 与随机子域相同)"
						mu.Lock()
						wildcardHits++
						mu.Unlock()
					}
					mu.Lock()
					subs = append(subs, s)
					mu.Unlock()
				}(w)
			}
			wg.Wait()
			sort.Slice(subs, func(i, j int) bool { return subs[i].Sub < subs[j].Sub })
			return jsonResult(map[string]any{
				"domain":        domain,
				"probed":        len(words),
				"resolved":      len(subs),
				"wildcard_dns":  wildcard,
				"wildcard_hits": wildcardHits,
				"subs":          subs,
				"note":          "wildcard_dns=true 时带疑似泛解析标注的命中多为噪音，优先看未标注项；resolver 建议指向目标内网 DNS 以枚举内部域名",
			})
		})
}

// overlapWith reports whether any of strs is in set (泛解析去噪判定).
func overlapWith(strs []string, set map[string]bool) bool {
	for _, s := range strs {
		if set[s] {
			return true
		}
	}
	return false
}

// dnsLookup builds the lookup function: custom resolver (host:port, PreferGo)
// or the system resolver.
func (t *ToolSet) dnsLookup(resolver string, timeout time.Duration) (lookupFunc, error) {
	if resolver == "" {
		return func(ctx context.Context, host string) ([]net.IP, error) {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			var r net.Resolver
			return r.LookupIP(cctx, "ip", host)
		}, nil
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		return nil, fmt.Errorf("resolver 非法(应为 host:port，如 10.0.0.53:53): %v", err)
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", resolver)
		},
	}
	return func(ctx context.Context, host string) ([]net.IP, error) {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return r.LookupIP(cctx, "ip", host)
	}, nil
}
