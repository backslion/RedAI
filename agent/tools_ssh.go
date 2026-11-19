package agent

// 凭据复用验证工具（YCode 二开）：ssh_check 对单个 SSH 端点做【凭据验证】——
// 每个「用户+口令/私钥」组合只尝试一次，返回可登录/认证失败/不可达。这是内网
// 纵深链里「拿到凭据 → 横向验证」最关键一跳的工具化。刻意设计为验证器而非爆破器：
// 每组合一次尝试、单次调用 ≤10 个组合，配合技能里的防锁定纪律（单账号失败≥3 次即停）。
// 依赖 golang.org/x/crypto/ssh（已在 go.mod）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) sshCheck() actool.CoreTool {
	return readTool("ssh_check",
		"(凭据复用)验证 SSH 凭据：对 host:port 逐个尝试【用户名+口令/私钥】组合，每个组合只试一次，返回每组合的 可登录/认证失败/不可达 结论（并取服务端版本/横幅）。用于拿到凭据后的横向移动验证——一次成功登录即实证横向(登记 fact + record_intelligence)。这是验证器不是爆破器：单次调用 ≤10 组合、每组合一次尝试，遵守防锁定纪律(单账号失败≥3 次即停、后续不再试)。",
		obj(map[string]any{
			"host": map[string]any{
				"type": "string", "description": "目标主机(IP 或域名)。",
			},
			"port": map[string]any{
				"type": "integer", "default": 22, "description": "SSH 端口。",
			},
			"credentials": map[string]any{
				"type":        "array",
				"description": "凭据组合(≤10)：[{\"username\":\"root\",\"password\":\"...\"}] 或 {\"username\":\"ubuntu\",\"private_key\":\"-----BEGIN ...-----\"}。password 与 private_key 二选一。",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"username":    map[string]any{"type": "string"},
						"password":    map[string]any{"type": "string"},
						"private_key": map[string]any{"type": "string", "description": "PEM 私钥全文"},
					},
					"required": []string{"username"},
				},
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 5000, "description": "单连接超时毫秒(1000..15000)。",
			},
		}, "host", "credentials"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Host        string `json:"host"`
				Port        int    `json:"port"`
				Credentials []struct {
					Username   string `json:"username"`
					Password   string `json:"password"`
					PrivateKey string `json:"private_key"`
				} `json:"credentials"`
				TimeoutMs int `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			host := strings.TrimSpace(p.Host)
			if host == "" {
				return actool.Errorf("host 不能为空"), nil
			}
			if p.Port <= 0 {
				p.Port = 22
			}
			if len(p.Credentials) == 0 {
				return actool.Errorf("credentials 不能为空"), nil
			}
			if len(p.Credentials) > 10 {
				return actool.Errorf(fmt.Sprintf("组合过多(%d>10)：这是验证器不是爆破器，请按防锁定纪律分批", len(p.Credentials))), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.Port))

			type comboResult struct {
				Username string `json:"username"`
				Auth     string `json:"auth"` // ok / failed / error
				Method   string `json:"method,omitempty"`
				Error    string `json:"error,omitempty"`
			}
			results := make([]comboResult, 0, len(p.Credentials))
			serverBanner := ""
			anySuccess := false
			perUserFails := map[string]int{}

			// 串行逐个验证（刻意不并发）：对目标温和、避免触发 fail2ban，
			// 并让同用户名失败≥3 次的防锁定兜底在本次调用内即可生效。
			for _, c := range p.Credentials {
				u := strings.TrimSpace(c.Username)
				if u == "" {
					continue
				}
				if perUserFails[u] >= 3 {
					results = append(results, comboResult{Username: u, Auth: "skipped", Method: "lockout-guard"})
					continue
				}
				r := comboResult{Username: u}
				cfg := &ssh.ClientConfig{
					User:            u,
					Timeout:         timeout,
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // 验证场景：不校验主机指纹
				}
				if strings.TrimSpace(c.PrivateKey) != "" {
					signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
					if err != nil {
						r.Auth, r.Error, r.Method = "error", "私钥解析失败: "+err.Error(), "publickey"
						results = append(results, r)
						continue
					}
					cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
					r.Method = "publickey"
				} else {
					cfg.Auth = []ssh.AuthMethod{ssh.Password(c.Password)}
					r.Method = "password"
				}
				client, err := ssh.Dial("tcp", addr, cfg)
				if err != nil {
					r.Auth, r.Error = "failed", err.Error()
					if _, ok := err.(net.Error); ok {
						r.Auth = "error" // 超时/不可达，不是认证失败
					} else if strings.Contains(err.Error(), "SSH-2.0") && serverBanner == "" {
						if i := strings.Index(err.Error(), "SSH-2.0"); i >= 0 {
							serverBanner = strings.TrimSpace(err.Error()[i:])
						}
					}
					if r.Auth == "failed" {
						perUserFails[u]++
					}
					results = append(results, r)
					continue
				}
				_ = client.Close()
				r.Auth = "ok"
				anySuccess = true
				if serverBanner == "" && len(client.ServerVersion()) > 0 {
					serverBanner = string(client.ServerVersion())
				}
				results = append(results, r)
			}

			return jsonResult(map[string]any{
				"host":          host,
				"port":          p.Port,
				"server_banner": serverBanner,
				"any_success":   anySuccess,
				"results":       results,
				"note":          "ok=凭据可登录(实证横向)；failed=认证拒绝；error=不可达/协议异常；skipped=防锁定兜底(该用户已失败≥3次)",
			})
		})
}
