package agent

// SSRF 差分探测工具（YCode 二开）：ssrf_probe 把一组「内网/回环/云元数据」目标注入
// 指定参数，用响应差分(状态码/长度/时延/跳转)判断服务端是否发起了请求。设计取向：
// 一次调用完成一类系统性检查，给「疑似 SSRF」一个可判定的证据面，而不是猜。
// 只做 GET/POST 请求注入与差分对比，不含任何载荷投递；请求经录制代理留痕。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ssrfDefaultTargets 默认注入目标：回环常见端口、本机名、云元数据、保留网段代表。
// 全部是「无害 GET」地址——判定依据是服务端行为差异，不依赖目标内容本身。
var ssrfDefaultTargets = []string{
	"http://127.0.0.1/", "http://127.0.0.1:22/", "http://127.0.0.1:443/",
	"http://127.0.0.1:3306/", "http://127.0.0.1:6379/", "http://127.0.0.1:8080/",
	"http://127.0.0.1:8000/", "http://127.0.0.1:8888/", "http://127.0.0.1:9000/",
	"http://127.0.0.1:27017/", "http://localhost/",
	"http://169.254.169.254/latest/meta-data/", // AWS/GCP 元数据
	"http://100.100.100.200/latest/meta-data/", // 阿里云元数据
	"http://metadata.google.internal/",         // GCP
	"http://192.168.1.1/",                      // 内网网关代表
}

func (t *ToolSet) ssrfProbe() actool.CoreTool {
	return readTool("ssrf_probe",
		"(SSRF 差分探测)对疑似 SSRF 参数做系统性验证：把回环/内网/云元数据目标逐个注入指定参数(默认目标集 ~16 条)，以【响应差分】判定服务端是否发起了请求——状态码/长度/时延/跳转 与基线(不可达域名)的显著差异即证据。用法：url 里用 {SSRF} 占位(任意位置的查询参数或 POST 体皆可)，或用 param 指定查询参数名。发现差异命中后：内网端口差异→「存在 SSRF，可探测内网端口」；元数据命中→高危(云凭据泄露面)，立即 report_finding。参数来源提示：url/fetch/link/source/target/image/file 等名字的参数、导出/代理/预览/webhook 类功能是 SSRF 高发区。",
		obj(map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "目标接口 URL，把要注入的参数值写成 {SSRF} 占位，如 http://t/api/proxy?url={SSRF} ；不用占位时须传 param。",
			},
			"param": map[string]any{
				"type":        "string",
				"description": "按参数名注入(追加/覆盖该查询参数)，与 {SSRF} 占位二选一。",
			},
			"method": map[string]any{
				"type": "string", "default": "GET",
				"description": "HTTP 方法：GET(默认)/POST。",
			},
			"post_body": map[string]any{
				"type":        "string",
				"description": "POST 时的请求体模板(可含 {SSRF} 占位)，默认 application/x-www-form-urlencoded。",
			},
			"targets": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "显式注入目标列表(与默认目标集叠加)，如 [\"http://10.0.0.5:6379/\"]。",
			},
			"preset": map[string]any{
				"type": "string", "default": "standard",
				"description": "目标预设：standard(默认,回环+云元数据+内网网关代表) / none(只用显式 targets)。",
			},
			"headers": map[string]any{
				"type":        "string",
				"description": "附加请求头，每行 'Key: Value'（如需要认证的接口）。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 8000, "description": "单请求超时毫秒(3000..20000)。内网不开放端口可能拖满超时，属预期。",
			},
			"proxy": map[string]any{
				"type": "string", "description": "HTTP 代理地址(可选)；留空默认走本任务录制代理(若有)。",
			},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				URL       string   `json:"url"`
				Param     string   `json:"param"`
				Method    string   `json:"method"`
				PostBody  string   `json:"post_body"`
				Targets   []string `json:"targets"`
				Preset    string   `json:"preset"`
				Headers   string   `json:"headers"`
				TimeoutMs int      `json:"timeout_ms"`
				Proxy     string   `json:"proxy"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			rawURL := strings.TrimSpace(p.URL)
			if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
				return actool.Errorf("url 必须以 http:// 或 https:// 开头"), nil
			}
			usePlaceholder := strings.Contains(rawURL, "{SSRF}") || strings.Contains(p.PostBody, "{SSRF}")
			param := strings.TrimSpace(p.Param)
			if !usePlaceholder && param == "" {
				return actool.Errorf("请在 url/post_body 中用 {SSRF} 占位，或传 param 指定注入参数名"), nil
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
				timeout = 8 * time.Second
			}
			if timeout > 20*time.Second {
				timeout = 20 * time.Second
			}
			client, err := t.probeHTTPClient(p.Proxy, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			targetSet := map[string]bool{}
			if p.Preset == "" {
				p.Preset = "standard"
			}
			if p.Preset == "standard" {
				for _, s := range ssrfDefaultTargets {
					targetSet[s] = true
				}
			} else if p.Preset != "none" {
				return actool.Errorf(fmt.Sprintf("未知 preset %q，可选 standard/none", p.Preset)), nil
			}
			for _, s := range p.Targets {
				if s = strings.TrimSpace(s); s != "" {
					targetSet[s] = true
				}
			}
			if len(targetSet) == 0 {
				return actool.Errorf("未指定任何注入目标(preset=none 且 targets 为空)"), nil
			}
			if len(targetSet) > 40 {
				return actool.Errorf(fmt.Sprintf("注入目标过多(%d>40)，请分批", len(targetSet))), nil
			}
			targets := make([]string, 0, len(targetSet))
			for s := range targetSet {
				targets = append(targets, s)
			}

			buildURL := func(payload string) string {
				if param != "" {
					sep := "?"
					if strings.Contains(rawURL, "?") {
						sep = "&"
					}
					return rawURL + sep + url.QueryEscape(param) + "=" + url.QueryEscape(payload)
				}
				return strings.ReplaceAll(rawURL, "{SSRF}", url.QueryEscape(payload))
			}
			do := func(payload string) (status, size int, loc string, ms int64, err error) {
				var req *http.Request
				if method == http.MethodPost {
					body := strings.ReplaceAll(p.PostBody, "{SSRF}", url.QueryEscape(payload))
					req, err = http.NewRequestWithContext(ctx, http.MethodPost, buildURL(payload), strings.NewReader(body))
					if err != nil {
						return 0, 0, "", 0, err
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, err = http.NewRequestWithContext(ctx, http.MethodGet, buildURL(payload), nil)
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
				start := time.Now()
				resp, err := client.Do(req)
				ms = time.Since(start).Milliseconds()
				if err != nil {
					return 0, 0, "", ms, err
				}
				n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp.StatusCode, int(n), resp.Header.Get("Location"), ms, nil
			}

			// ---- 基线：注入一个保证不可达的域名 ----
			baselinePayload := "http://yc-ssrf-baseline.invalid." + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "/"
			bStatus, bLen, bLoc, bMs, err := do(baselinePayload)
			if err != nil && bStatus == 0 && bLen == 0 {
				// 基线本身网络失败：目标接口不可达（不是 SSRF 结论）
				return actool.Errorf("基线请求失败(目标接口不可达或代理失败): " + err.Error()), nil
			}

			type probe struct {
				Target string `json:"target"`
				Status int    `json:"status"`
				Len    int    `json:"len"`
				Ms     int64  `json:"ms"`
				Loc    string `json:"location,omitempty"`
				Err    string `json:"error,omitempty"`
				Diff   string `json:"diff,omitempty"`
				Hit    bool   `json:"hit"`
			}
			probes := make([]probe, 0, len(targets))
			hits := 0
			for i, tgt := range targets {
				if i > 0 {
					select {
					case <-time.After(250 * time.Millisecond): // 温和间隔
					case <-ctx.Done():
						return actool.Errorf("已取消"), nil
					}
				}
				pr := probe{Target: tgt}
				st, sz, loc, ms, derr := do(tgt)
				pr.Status, pr.Len, pr.Ms, pr.Loc = st, sz, ms, loc
				if derr != nil {
					pr.Err = derr.Error()
					if len(pr.Err) > 120 {
						pr.Err = pr.Err[:120]
					}
				}
				// ---- 差分判定（与基线比）----
				switch {
				case derr != nil && bStatus != 0:
					// 基线有响应而本目标网络层出错：少见，通常不算证据
				case st != bStatus:
					pr.Diff = fmt.Sprintf("状态码差异(%d vs 基线 %d)", st, bStatus)
					pr.Hit = true
				case bLen > 0 && abs(sz-bLen)*100/max(bLen, 1) > 25:
					pr.Diff = fmt.Sprintf("长度差异(%d vs 基线 %d)", sz, bLen)
					pr.Hit = true
				case loc != "" && bLoc == "":
					pr.Diff = "本目标产生跳转(" + loc + ")而基线没有"
					pr.Hit = true
				case abs64(ms-bMs) > 1200:
					pr.Diff = fmt.Sprintf("时延差异显著(%dms vs 基线 %dms)——可能命中内网开放/关闭端口差", ms, bMs)
					pr.Hit = true
				}
				if pr.Hit {
					hits++
				}
				probes = append(probes, pr)
			}

			out := map[string]any{
				"url":       rawURL,
				"method":    method,
				"baseline":  map[string]any{"payload": baselinePayload, "status": bStatus, "len": bLen, "ms": bMs, "location": bLoc},
				"probed":    len(probes),
				"hit_count": hits,
				"probes":    probes,
			}
			if hits > 0 {
				out["verdict"] = fmt.Sprintf("存在 %d 个差分命中——SSRF 疑似成立，按命中目标类型定性(内网端口探测/元数据=高危)并 report_finding", hits)
				out["note"] = "单条差分也可能由服务端缓存/随机抖动造成：对命中目标复跑一次确认稳定性，再下结论"
			} else {
				out["verdict"] = "默认目标集无差分命中——未发现 SSRF 证据(否定结论需附：已注入目标数与基线指纹)"
				out["note"] = "如目标只接受特定格式(域名白名单/协议限制)，请用 targets 传入贴合场景的内部地址再试"
			}
			return jsonResult(out)
		})
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
