package agent

// Web 面细致摸底工具（YCode 二开）：dir_probe 对单个 Web 根做敏感路径/管理面/
// 信息泄露面的只读 GET 摸底。设计取向与 tcp_probe 一致：一次调用完成一类系统性
// 检查，让「每个 Web 目标都过一遍细致清点」成为低成本动作（配合严审深挖条令）。
// HTTP(S) 请求默认走本任务的录制代理（SetNetProxy 注入，worker 装配时接线），
// 因此探测流量进流量库、可 traffic_search 回看作为证据；无代理时直连。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// SetNetProxy keeps the YCode-fork entry point name working on top of Pojun's
// existing egress wiring: HTTP-side net tools (dir_probe / waf_probe /
// http_login_check / ssrf_probe) reuse the same recording proxy + CA that
// http_request and session_login already use, so their traffic lands in the
// traffic recorder and can be cited as evidence.
func (t *ToolSet) SetNetProxy(addr, caCertPEM string) {
	t.SetEgressProxy(addr, caCertPEM)
}

// sensitivePaths is the default "sensitive" preset: management consoles, info
// leaks, source/backup artifacts, framework debug endpoints. GET-only recon.
var sensitivePaths = []string{
	// 管理后台 / 控制台
	"admin", "admin/", "admin/login", "administrator", "manage", "manager/html",
	"console", "cp", "cpanel", "backend", "dashboard", "system", "login",
	"user/login", "admin/index.html", "wp-admin/", "wp-login.php", "phpmyadmin/",
	"adminer.php", "mysql/", "solr/", "jenkins/", "grafana/", "kibana/", "nacos/",
	"eureka/", "consul/", "druid/index.html", "druid/login.html", "jmx-console/",
	"web-console/", "sectools/",
	// 敏感文件 / 信息泄露
	".env", ".env.bak", ".git/config", ".git/HEAD", ".svn/entries", ".svn/wc.db",
	".DS_Store", ".htaccess", ".bash_history", "robots.txt", "crossdomain.xml",
	"phpinfo.php", "info.php", "test.php", "phpinfo.php3", "info.json",
	"server-status", "server-info", "actuator", "actuator/health", "actuator/env",
	"actuator/heapdump", "actuator/mappings", "actuator/configprops",
	"swagger-ui.html", "swagger/index.html", "swagger-ui/", "api-docs",
	"v2/api-docs", "v3/api-docs", "doc.html", "api.html", "apis.json",
	"WEB-INF/web.xml", "WEB-INF/classes/", "META-INF/", "WEB-INF/",
	"backup/", "backup.zip", "backup.sql", "backup.tar.gz", "bak.zip",
	"db.sql", "dump.sql", "database.sql", "data.sql", "site.zip", "www.zip",
	"web.zip", "src.zip", "1.zip", "latest.zip",
	"config.php.bak", "config.php~", "config.ini", "config.json", "config.yml",
	"application.yml", "application.properties", "bootstrap.yml",
	"composer.json", "package.json", "package-lock.json", "pom.xml",
	"requirements.txt", ".project", ".classpath",
	"README.md", "readme.txt", "CHANGELOG.md", "INSTALL.md",
	"install/", "install.php", "setup/", "setup.py",
	"upload/", "uploads/", "file/", "files/", "temp/", "tmp/", "cache/",
	"debug/", "test/", "dev/", "old/", "new/", "release/",
	"editor/", "ueditor/", "fckeditor/", "kindeditor/",
	"sso/", "oauth/", "cas/", "shiro/", "j_spring_security_check",
	"monitor/", "monit/", "zabbix/", "nagios/",
	".idea/", ".vscode/", ".gitignore", "Dockerfile", "docker-compose.yml",
	"Makefile", "Thumbs.db", "error.log", "access.log", "debug.log",
	"cgi-bin/", "examples/", "docs/", "javadoc/",
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.{1,120}?)</title>`)

func (t *ToolSet) dirProbe() actool.CoreTool {
	return readTool("dir_probe",
		"(细致摸底)对单个 Web 根(如 http://10.0.1.5:8080)并发做敏感路径/管理面/信息泄露面的只读 GET 探测：管理后台、.git/.env/.svn、actuator/druid/swagger、备份与压缩包、配置与日志文件等(默认 sensitive 预集约 150 条)。返回非 404 的命中(状态码/长度/跳转/标题)，401/403 也算「存在但受限」。用于每个 Web 目标动手利用前的最小清点(严审深挖条令第 5 条)；命中的路径应登记 insert_assets(type=endpoint)。流量默认经录制代理留痕。",
		obj(map[string]any{
			"base_url": map[string]any{
				"type":        "string",
				"description": "Web 根地址，含 scheme 与端口，如 http://10.0.1.5:8080 或 https://target.example.com(结尾不要带路径斜杠)",
			},
			"paths": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "显式路径列表(以 / 开头，与 preset 叠加)，如 [\"/api/internal\",\"/.well-known/security.txt\"]。",
			},
			"preset": map[string]any{
				"type": "string", "default": "sensitive",
				"description": "路径预设：sensitive(默认,管理面+泄露面+备份+调试端点) / none(只用显式 paths)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 4000,
				"description": "单请求超时毫秒(1000..15000)。",
			},
			"proxy": map[string]any{
				"type":        "string",
				"description": "HTTP 代理地址(可选，如 http://127.0.0.1:8788)；留空默认走本任务录制代理(若有)。",
			},
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				BaseURL   string   `json:"base_url"`
				Paths     []string `json:"paths"`
				Preset    string   `json:"preset"`
				TimeoutMs int      `json:"timeout_ms"`
				Proxy     string   `json:"proxy"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			base := strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
			if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
				return actool.Errorf("base_url 必须以 http:// 或 https:// 开头"), nil
			}
			if _, err := url.Parse(base); err != nil {
				return actool.Errorf("base_url 无法解析: " + err.Error()), nil
			}
			if p.Preset == "" {
				p.Preset = "sensitive"
			}
			pathSet := map[string]bool{}
			if p.Preset == "sensitive" {
				for _, s := range sensitivePaths {
					pathSet["/"+s] = true
				}
			} else if p.Preset != "none" {
				return actool.Errorf(fmt.Sprintf("未知 preset %q，可选 sensitive/none", p.Preset)), nil
			}
			for _, s := range p.Paths {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if !strings.HasPrefix(s, "/") {
					s = "/" + s
				}
				pathSet[s] = true
			}
			if len(pathSet) == 0 {
				return actool.Errorf("未指定任何路径(preset=none 且 paths 为空)"), nil
			}
			if len(pathSet) > 300 {
				return actool.Errorf(fmt.Sprintf("路径过多(%d>300)，请分批", len(pathSet))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 4 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}
			client, err := t.probeHTTPClient(p.Proxy, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			paths := make([]string, 0, len(pathSet))
			for s := range pathSet {
				paths = append(paths, s)
			}
			sort.Strings(paths)

			type hit struct {
				Path   string `json:"path"`
				Status int    `json:"status"`
				Len    int64  `json:"len"`
				Title  string `json:"title,omitempty"`
				Loc    string `json:"location,omitempty"`
				Note   string `json:"note,omitempty"`
				Err    string `json:"error,omitempty"`
			}
			hits := make([]hit, 0, 32)
			errCount := 0
			errSample := ""
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 16) // 温和并发：同一目标 16 在飞
			for _, path := range paths {
				wg.Add(1)
				go func(path string) {
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
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent", "YCode-recon/0.3")
					req.Header.Set("Accept", "*/*")
					resp, err := client.Do(req)
					if err != nil {
						// 网络层失败必须计数：全部失败=目标不可达，绝不能伪装成"0 命中"
						mu.Lock()
						errCount++
						if errSample == "" {
							errSample = err.Error()
							if len(errSample) > 160 {
								errSample = errSample[:160]
							}
						}
						mu.Unlock()
						return
					}
					h := hit{Path: path, Status: resp.StatusCode, Len: resp.ContentLength}
					if h.Len < 0 {
						h.Len = 0
					}
					if resp.StatusCode == 401 || resp.StatusCode == 403 {
						h.Note = "存在但受限"
					}
					if loc := resp.Header.Get("Location"); loc != "" {
						h.Loc = loc
					}
					if resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Content-Type"), "html") {
						body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
						if m := titleRe.FindSubmatch(body); m != nil {
							h.Title = strings.TrimSpace(string(m[1]))
							if len(h.Title) > 80 {
								h.Title = h.Title[:80]
							}
						}
					}
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
					_ = resp.Body.Close()
					// 只上报非 404 命中
					if resp.StatusCode != 404 {
						mu.Lock()
						hits = append(hits, h)
						mu.Unlock()
					}
				}(path)
			}
			wg.Wait()
			// 不可达判定：全部请求都网络层失败 → 这是错误结论而非"路径面干净"。
			if errCount == len(paths) && errCount > 0 {
				return actool.Errorf(fmt.Sprintf("目标不可达或代理失败：%d/%d 请求全部出错，样例：%s", errCount, len(paths), errSample)), nil
			}
			sort.Slice(hits, func(i, j int) bool { return hits[i].Path < hits[j].Path })
			return jsonResult(map[string]any{
				"base_url":    base,
				"probed":      len(paths),
				"hit_count":   len(hits),
				"error_count": errCount,
				"hits":        hits,
				"note":        "404/部分网络错误未逐条列出(error_count 为网络错误数)；200 命中含软 404(错误页也回 200)的可能，按 title/len 判断；全部 404 说明默认路径面干净",
			})
		})
}

// probeHTTPClient builds the HTTP client for recon tools: explicit proxy param
// wins, else the task recording proxy (egressProxy), else env, else direct.
// Any proxy without a provided CA skips TLS verification — recording MITM
// proxies re-sign certs, and a hard failure there would silently turn every
// HTTPS hit into a network error (which the tool would then count). The tool
// only judges status/len/title; the proxy itself keeps the true exchange.
func (t *ToolSet) probeHTTPClient(proxyOverride string, timeout time.Duration) (*http.Client, error) {
	proxyAddr := strings.TrimSpace(proxyOverride)
	if proxyAddr == "" {
		proxyAddr = strings.TrimSpace(t.egressProxy)
	}
	transport := &http.Transport{
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
	}
	if proxyAddr != "" {
		pu, err := url.Parse(proxyAddr)
		if err != nil || pu.Scheme == "" || pu.Host == "" {
			return nil, fmt.Errorf("代理地址无效 %q", proxyAddr)
		}
		transport.Proxy = http.ProxyURL(pu)
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if strings.TrimSpace(t.egressCA) != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(t.egressCA)) {
				tlsCfg.InsecureSkipVerify = true //nolint:gosec // CA 解析失败仍走代理：探测仅判状态码/长度
			} else {
				tlsCfg.RootCAs = pool
			}
		} else {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // 录制/显式代理无 CA：避免 HTTPS 全部静默失败
		}
		transport.TLSClientConfig = tlsCfg
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // 不跟随跳转，跳转本身即是信息
	}}, nil
}
