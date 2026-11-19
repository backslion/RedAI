package agent

// 蜜罐识别工具（移植自 ARTEX-ymh 的 honeydetect 静态签名层）：
// 对目标服务做一次轻量、只读的特征采集（TCP banner / HTTP 标题与正文 /
// TLS 证书主体与签发者），用公开来源的签名库打分，产出 0-1 的蜜罐置信度
// 与命中证据。
//
// 价值：AI 攻击代理正在成为蜜罐的猎物——在仿真环境里打穿"漏洞"、拿到
// "凭据"、写出"战果"，实际全是喂给防守方的行为样本。这个工具把"先判断
// 这块地是不是陷阱"变成一个廉价动作，任何非 HTTP 的协议面也都能用
// （只要给 banner）。
//
// 无 store 依赖，readTool 构造，worker / pentest / auto 都能用。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chu0119/pojun/honeydetect"

	actool "github.com/Autumn-27/norma/tool"
)

var htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// honeypotCheck 见文件头注释。
func (t *ToolSet) honeypotCheck() actool.CoreTool {
	return readTool("honeypot_check",
		"(反蜜罐/反测绘)判断一个服务是不是蜜罐或仿真环境：对目标采集 TCP banner / HTTP 标题 / 正文片段 / TLS 证书特征，"+
			"用公开来源的签名库(Cowrie / OpenCanary / Kippo / Glastopf / HFish / Dionaea 等)匹配，返回 0-1 置信度、命中证据与处置建议。\n"+
			"何时用：①拿到新资产、准备深入利用之前（尤其「太顺利」的目标）；②扫描发现异常多端口/异常低版本服务时；"+
			"③已拿到 shell 但行为反常（命令回显过于规整、文件系统像预置的）时。\n"+
			"也可只做签名判定：传 banner/title/body/cert_subject 等已知特征并把 probe=false，不发起任何网络请求。\n"+
			"命中高危不等于 100% 蜜罐，但足以要求：禁止在其上执行破坏性操作、上传后门、使用真实凭据；先把结论写成 fact 并换方向。",
		obj(map[string]any{
			"target": str("目标：host、host:port 或完整 URL（如 http://10.0.0.5:8080/）。probe=true 时用于实际采集。"),
			"probe": map[string]any{
				"type": "boolean", "default": true,
				"description": "是否主动采集特征（TCP banner + HTTP + TLS 证书）。false=只用下面传入的特征做纯签名判定。",
			},
			"banner":        str("已知 banner / Server 头等原始文本（可选，传入则参与签名匹配）。"),
			"title":         str("已知 HTTP 页面标题（可选）。"),
			"body":          str("已知 HTTP 正文或片段（可选，建议取前 8KB）。"),
			"cert_subject":  str("已知 TLS 证书 subject（可选）。"),
			"cert_issuer":   str("已知 TLS 证书 issuer（可选）。"),
			"port":          intp("服务端口；不传则从 target 推断（http=80/https=443）。"),
			"timeout_sec":   intp("单个探测动作超时秒数，默认 5，最大 15。"),
			"include_probe": map[string]any{"type": "boolean", "default": true, "description": "结果里是否回显采集到的原始特征（调试/取证用）。"},
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Target       string `json:"target"`
				Probe        *bool  `json:"probe"`
				Banner       string `json:"banner"`
				Title        string `json:"title"`
				Body         string `json:"body"`
				CertSubject  string `json:"cert_subject"`
				CertIssuer   string `json:"cert_issuer"`
				Port         int    `json:"port"`
				TimeoutSec   int    `json:"timeout_sec"`
				IncludeProbe *bool  `json:"include_probe"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(p.Target) == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			doProbe := true
			if p.Probe != nil {
				doProbe = *p.Probe
			}
			includeProbe := true
			if p.IncludeProbe != nil {
				includeProbe = *p.IncludeProbe
			}
			timeout := p.TimeoutSec
			if timeout <= 0 {
				timeout = 5
			}
			if timeout > 15 {
				timeout = 15
			}
			tmo := time.Duration(timeout) * time.Second

			host, port, scheme, path := parseHoneypotTarget(p.Target, p.Port)
			if port <= 0 {
				if scheme == "https" {
					port = 443
				} else {
					port = 80
				}
			}

			view := honeydetect.ServiceView{
				Port:        port,
				Banner:      p.Banner,
				Title:       p.Title,
				Body:        p.Body,
				CertSubject: p.CertSubject,
				CertIssuer:  p.CertIssuer,
			}
			notes := []string{}

			if doProbe {
				if host == "" {
					return actool.Errorf("probe=true 时 target 必须包含可解析的主机名或 IP"), nil
				}
				addr := net.JoinHostPort(host, fmt.Sprint(port))

				// 1) TLS 证书：直连取，不经录制代理——MITM 代理会重签证书，
				//    经代理取到的永远是代理自己的证书，签名匹配毫无意义。
				if scheme == "https" || port == 443 || port == 8443 {
					if sub, iss, err := probeTLSCert(addr, tmo); err != nil {
						notes = append(notes, "TLS 证书采集失败: "+err.Error())
					} else {
						view.CertSubject = firstNonEmpty(view.CertSubject, sub)
						view.CertIssuer = firstNonEmpty(view.CertIssuer, iss)
					}
				} else if b, err := probeTCPBanner(addr, tmo); err != nil {
					notes = append(notes, "banner 采集失败: "+err.Error())
				} else {
					view.Banner = firstNonEmpty(view.Banner, b)
				}

				// 2) HTTP 面：走与 http_request 同源的出口（录制代理在场则留痕）。
				if scheme == "" {
					scheme = "http"
				}
				if sub, srv, body, err := t.probeHoneypotHTTP(scheme, host, port, path, tmo); err != nil {
					notes = append(notes, "HTTP 采集失败: "+err.Error())
				} else {
					view.Title = firstNonEmpty(view.Title, sub)
					view.Body = firstNonEmpty(view.Body, body)
					view.Banner = firstNonEmpty(view.Banner, srv)
				}
			}

			score, evidence := honeydetect.Evaluate(view)
			out := map[string]any{
				"score":     round2(score),
				"level":     honeypotLevel(score),
				"is_likely": score >= 0.6,
				"evidence":  evidence,
				"advice":    honeypotAdvice(score),
				"notes":     notes,
			}
			// 判定可疑 → 登记到熔断表。之后 http_request 打到这个 host 会逐步
			// 减速、累计 8 次后熔断（见 honeydetect/tarpit.go）。只登记不打标记：
			// 0.6 是「可以继续取证但别猛打」的档位，不是「立刻断」。
			if score >= 0.6 && host != "" {
				t.rtTarpit().MarkSuspect(host, score)
				out["tarpit"] = "已登记：该 host 后续 HTTP 访问会逐步减速，累计 8 次熔断"
			}
			if includeProbe {
				out["signals"] = map[string]any{
					"host":         host,
					"port":         port,
					"banner":       clip(view.Banner, 300),
					"title":        clip(view.Title, 200),
					"body_excerpt": clip(view.Body, 400),
					"cert_subject": clip(view.CertSubject, 300),
					"cert_issuer":  clip(view.CertIssuer, 300),
				}
			}
			return jsonResult(out)
		})
}

// parseHoneypotTarget 把 host / host:port / URL 统一拆成 (host, port, scheme, path)。
func parseHoneypotTarget(target string, portOverride int) (host string, port int, scheme, path string) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			scheme = strings.ToLower(u.Scheme)
			host = u.Hostname()
			if ps := u.Port(); ps != "" {
				fmt.Sscanf(ps, "%d", &port)
			}
			path = u.RequestURI()
			if path == "" {
				path = "/"
			}
		}
	} else if h, ps, err := net.SplitHostPort(target); err == nil {
		host = h
		fmt.Sscanf(ps, "%d", &port)
	} else {
		host = target
	}
	if portOverride > 0 {
		port = portOverride
	}
	if path == "" {
		path = "/"
	}
	return host, port, scheme, path
}

// probeTCPBanner 直连读一段 banner（SSH/FTP/SMTP/Redis 等非 HTTP 协议面）。
func probeTCPBanner(addr string, tmo time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, tmo)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(tmo))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// probeTLSCert 直连完成握手并取叶子证书的 subject / issuer。
func probeTLSCert(addr string, tmo time.Duration) (subject, issuer string, err error) {
	d := &net.Dialer{Timeout: tmo}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 只读证书字段做特征判定，不做校验
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", "", fmt.Errorf("目标未提供证书")
	}
	return certs[0].Subject.String(), certs[0].Issuer.String(), nil
}

// probeHoneypotHTTP 取标题、Server 头与正文片段，复用任务出口（录制代理）。
func (t *ToolSet) probeHoneypotHTTP(scheme, host string, port int, path string, tmo time.Duration) (title, server, body string, err error) {
	client, err := t.probeHTTPClient("", tmo)
	if err != nil {
		return "", "", "", err
	}
	u := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, fmt.Sprint(port)), path)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	text := string(raw)
	if m := htmlTitleRe.FindStringSubmatch(text); len(m) == 2 {
		title = strings.TrimSpace(m[1])
	}
	return title, strings.TrimSpace(resp.Header.Get("Server")), text, nil
}

func honeypotLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "high"
	case score >= 0.6:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "none"
	}
}

func honeypotAdvice(score float64) string {
	switch {
	case score >= 0.9:
		return "高度疑似蜜罐/仿真环境：立即停止在该目标上的利用与后渗透动作，不使用任何真实凭据，不上传文件；" +
			"把结论与命中证据写成 fact（标注蜜罐嫌疑）并转向其他资产。若必须继续，先人工确认授权与目标性质。"
	case score >= 0.6:
		return "疑似蜜罐：只做只读验证，不执行破坏性命令、不写文件、不横向；优先换一块资产推进，把该目标留作观察样本。"
	case score >= 0.3:
		return "存在弱蜜罐特征：保持最小伤害原则，避免批量爆破与写入型操作；继续观察响应是否过于规整。"
	default:
		return "未命中公开蜜罐签名（不等于安全，定制蜜罐/高交互蜜罐可能无签名）：仍按常规最小伤害纪律推进。"
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
