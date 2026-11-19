package agent

// 隧道编排：把「手上有什么」和「该走哪条路」从模型脑子里搬到结构化输出。
//
// 背景：平台已有四种立足点载体，各有硬前提——
//   - pivot_open        SSH：目标必须开 22 且有可用凭据
//   - webshell_pivot_*  WebShell：目标能跑 PHP、能上传脚本、平台能访问到脚本 URL
//   - listener + shell  反弹：目标能主动出网到平台
//   - 已有隧道          直接复用
//
// 缺的从来不是载体，是「选哪条」。模型常见的失败是拿未验证的 SSH 凭据反复试
// （锁账号），或在没有 22 的目标上硬套 pivot_open。本文件提供两个工具：
//
//   pivot_plan   只读：汇总当前任务已有的隧道/会话，输出候选路径与缺口清单。
//                不做任何探测、不产生副作用——判断依据全部来自运行时状态与入参。
//   pivot_deploy 写入：开隧道后立刻做「跳板侧验证」（不是平台侧），验证不通过
//                就自动回滚关闭，避免留下一条看起来通、实际打不通的链路。
//
// 为什么验证必须在跳板侧：SSH 通道建立成功只证明「平台能连上跳板」，不证明
// 「跳板能到内网目标」。WebShell 隧道的 ping/pong 同理——它证明平台与脚本之间
// 通，不证明脚本与内网通。唯一可信的判据是经隧道拨一次真实目标。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/backslion/RedAI/pivot"
	"github.com/backslion/RedAI/webshell"

	actool "github.com/Autumn-27/norma/tool"
)

// pivotPath 是一条候选路径的评估结果。
type pivotPath struct {
	Kind       string   `json:"kind"`     // ssh / webshell / reverse / reuse
	Feasible   string   `json:"feasible"` // yes / no / unknown
	Why        string   `json:"why"`      // 判定依据（来自哪条状态）
	Need       []string `json:"need,omitempty"`
	HowTo      string   `json:"how_to,omitempty"`
	BlockedBy  string   `json:"blocked_by,omitempty"`
	ToolToUse  string   `json:"tool_to_use,omitempty"`
	VerifyHint string   `json:"verify_hint,omitempty"`
}

// pivotPlan 汇总当前任务可用的出口并给出选型建议。
//
// 它刻意不探测：探测要落地脚本、要连目标，属于写入动作，应由 worker 在拿到
// 计划后显式执行。这里只回答「我现在有什么、缺什么」。
func (t *ToolSet) pivotPlan() actool.CoreTool {
	return readTool(
		"pivot_plan",
		"(内网横向)开工前先看「手上有什么出口」：汇总本任务已有的 SSH 隧道 / WebShell 隧道 / WebShell 会话，"+
			"按硬前提给出 ssh / webshell / reverse / reuse 四条路径的可行性与缺口，并给出推荐。"+
			"本工具只读、不探测、不连目标——它读的是已登记的运行时状态。"+
			"用法：拿不到 shell 之前不用调；拿到立足点、准备进内网时先调它，再按 recommended 走，"+
			"不要拿未验证的 SSH 凭据反复试（会锁账号）。",
		obj(map[string]any{
			"webshell_session": map[string]any{
				"type": "string",
				"description": "可选。已登记的 WebShell 会话名（webshell_list 查）。" +
					"给了它就逐项核对这条会话能否作为隧道载体；不给则只按已有隧道给建议。",
			},
			"hint_target": map[string]any{
				"type":        "string",
				"description": "可选。想打的内网目标 host 或 host:port。仅用于生成验证命令示例，不发起探测。",
			},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				WebShellSession string `json:"webshell_session"`
				HintTarget      string `json:"hint_target"`
			}
			_ = json.Unmarshal(in, &p)

			var existingSSH, existingWS []map[string]any
			if m := t.rtPivot(); m != nil {
				for _, tun := range m.List(t.taskID) {
					v := tun.View(0)
					existingSSH = append(existingSSH, map[string]any{
						"id": v.ID, "alive": v.Alive, "mode": v.Mode,
						"socks_url": v.SocksURL, "target": v.Target,
						"hops": v.Hops, "expires_at": v.ExpiresAt, "last_error": v.LastError,
					})
				}
			}
			if m := t.rtShellTunnel(); m != nil {
				for _, tun := range m.List(t.taskID) {
					v := tun.View(0)
					existingWS = append(existingWS, map[string]any{
						"id": v.ID, "alive": v.Alive, "mode": v.Mode,
						"socks_url": v.SocksURL, "target": v.Target,
						"has_auth": v.HasAuth, "expires_at": v.ExpiresAt, "last_error": v.LastError,
					})
				}
			}

			verify := "<内网可达的 host:port>"
			if h := strings.TrimSpace(p.HintTarget); h != "" {
				verify = h
				if !strings.Contains(h, ":") {
					verify = h + ":80"
				}
			}

			paths := make([]pivotPath, 0, 4)

			// 1. 复用已有隧道：任何可用隧道都比新建一条好——新建会多留一个入口。
			aliveSSH, aliveWS := 0, 0
			for _, e := range existingSSH {
				if b, _ := e["alive"].(bool); b {
					aliveSSH++
				}
			}
			for _, e := range existingWS {
				if b, _ := e["alive"].(bool); b {
					aliveWS++
				}
			}
			if aliveSSH+aliveWS > 0 {
				paths = append(paths, pivotPath{
					Kind: "reuse", Feasible: "yes",
					Why:   fmt.Sprintf("已有 %d 条存活隧道（SSH %d / WebShell %d），直接用它打，不要再建新的", aliveSSH+aliveWS, aliveSSH, aliveWS),
					HowTo: "从 existing 里取 socks_url 直接用；本机 curl 记得 --noproxy \"\"",
				})
			} else {
				why := "本任务没有存活隧道"
				if len(existingSSH)+len(existingWS) > 0 {
					why = fmt.Sprintf("有 %d 条隧道但均已断开，需要重建", len(existingSSH)+len(existingWS))
				}
				paths = append(paths, pivotPath{
					Kind: "reuse", Feasible: "no", Why: why,
					BlockedBy: "无存活隧道",
				})
			}

			// 2. SSH pivot：硬前提是 22 + 凭据。这里只能判断「凭据有没有」，22 要 worker 自己验。
			paths = append(paths, pivotPath{
				Kind: "ssh", Feasible: "unknown",
				Why: "前提：目标开 22 且有可用凭据。本工具不探测端口、不校验账号（反复试会锁定账号）",
				Need: []string{
					"目标 22 可达（用 tcp_probe 或 webshell_exec 在目标侧确认）",
					"凭据库里有该主机可用的 SSH 凭据（list_credentials 查，优先 relation=verified）",
				},
				ToolToUse:  "pivot_deploy(kind=ssh)",
				VerifyHint: "部署时传 verify_target=" + verify + "，工具会做跳板侧实测，失败自动回滚",
			})

			// 3. WebShell 隧道：只在给了会话名时评估，因为它是会话绑定的。
			if s := strings.TrimSpace(p.WebShellSession); s != "" {
				ok, why := t.webshellSessionUsable(s)
				path := pivotPath{
					Kind: "webshell", Feasible: "unknown", Why: why,
					Need: []string{
						"该会话能执行命令（webshell_exec 试一条 echo）",
						"能写到 Web 目录并能从平台访问到脚本 URL",
					},
					ToolToUse:  "webshell_tunnel_script → webshell_upload → pivot_deploy(kind=webshell)",
					VerifyHint: "部署时传 verify_target=" + verify + "；WebShell 隧道延迟高，只适合低带宽探测",
				}
				if !ok {
					path.Feasible = "no"
					path.BlockedBy = why
				}
				paths = append(paths, path)
			} else {
				paths = append(paths, pivotPath{
					Kind: "webshell", Feasible: "unknown",
					Why:  "未指定会话。若目标只有一句话马、没开 22，这是唯一不落二进制的出口",
					Need: []string{"先用 webshell_list 确认会话存在", "再把 webshell_session 传进来重新评估"},
				})
			}

			// 4. 反弹：需要目标能主动出网，且平台有可用监听。
			paths = append(paths, pivotPath{
				Kind: "reverse", Feasible: "unknown",
				Why:       "前提：目标能主动出网到平台，且已有 listener 在等。适合目标不出网但可通过命令执行反弹的场景",
				Need:      []string{"listener_start 起一个监听（若还没有）", "确认目标能连到平台 IP:PORT（多数内网目标不能）"},
				ToolToUse: "listener_start → 在目标侧执行反弹命令 → shell_open",
			})

			rec := recommendPivotPath(paths)

			out, _ := json.MarshalIndent(map[string]any{
				"ok":          true,
				"existing":    map[string]any{"ssh": existingSSH, "webshell": existingWS},
				"paths":       paths,
				"recommended": rec,
				"rules": []string{
					"先复用、再新建：多一条隧道就是多一个对内网的长期入口",
					"先用证据选路：22 通不通、凭据可不可用，都要先验证再动手",
					"部署必验证：pivot_deploy 会做跳板侧实测，失败自动回滚——不要自己调 open 绕过验证",
					"打完就收：pivot_close / webshell_pivot_close，并清理目标上的隧道脚本",
				},
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellSessionUsable 只核对会话是否已在运行时登记，不执行命令。
func (t *ToolSet) webshellSessionUsable(name string) (bool, string) {
	m := t.rtShell()
	if m == nil {
		return false, "WebShell 管理器未启用"
	}
	if _, err := m.Get(name); err != nil {
		return false, fmt.Sprintf("会话 %q 未登记（webshell_list 查实际名称）", name)
	}
	return true, fmt.Sprintf("会话 %q 已登记；仍需确认它能执行命令、且脚本 URL 平台可达", name)
}

// recommendPivotPath 按「复用 > SSH > WebShell > 反弹」的优先级给出推荐。
//
// 顺序理由：复用不新增入口；SSH 隧道最稳定（长连接、低延迟）；WebShell 每条
// 连接一次 HTTP，只适合低带宽；反弹依赖目标出网，最不可控。
func recommendPivotPath(paths []pivotPath) map[string]any {
	order := []string{"reuse", "ssh", "webshell", "reverse"}
	for _, kind := range order {
		for _, p := range paths {
			if p.Kind != kind || p.Feasible == "no" {
				continue
			}
			if kind == "reuse" {
				return map[string]any{
					"kind": kind,
					"why":  "已有存活隧道，复用即可；新建只会多留一个入口",
					"next": "直接取 existing 里的 socks_url 使用",
				}
			}
			// unknown 也推荐，但必须带上"先验证前提"的动作。
			return map[string]any{
				"kind": kind,
				"why":  p.Why,
				"next": "先按 need 逐项确认前提，再用 " + p.ToolToUse + "；部署时务必带 verify_target",
			}
		}
	}
	return map[string]any{
		"kind": "none",
		"why":  "四条路径都被明确阻断，需要先补立足点",
		"next": "回到上一阶段：拿 shell（webshell_add / listener_start），或补 SSH 凭据",
	}
}

// pivotDeploy 开隧道并做跳板侧验证，失败自动回滚。
func (t *ToolSet) pivotDeploy() actool.CoreTool {
	return writeTool(
		"pivot_deploy",
		"(内网横向)开一条隧道并立刻做「跳板侧验证」：验证目标必须经这条隧道真实可达，否则自动关闭回滚。\n"+
			"为什么不用 pivot_open / webshell_pivot_open 直接开：那两个只保证通道建立，"+
			"不保证跳板能到内网——本工具多一步实测，避免留下「看起来通、实际打不通」的链路，也避免模型误以为已经进网。\n"+
			"kind=ssh：走 SSH direct-tcpip（需 22 + 凭据）；kind=webshell：走目标上的 PHP 隧道脚本（需已上传脚本）。\n"+
			"verify_target 强烈建议填：填了才会验证，失败会回滚；不填则只做通道自身的探活（弱证据）。\n"+
			"开隧道走审批（对内网的长期入口）。默认 TTL 2 小时，用完 pivot_close / webshell_pivot_close。",
		obj(map[string]any{
			"kind": map[string]any{
				"type":        "string",
				"description": "ssh（SSH 直连跳板）或 webshell（目标上已落隧道脚本）。",
			},
			"verify_target": map[string]any{
				"type": "string",
				"description": "跳板侧验证目标 host:port（例 10.0.0.1:445）。建议填一个你确定内网可达的地址；" +
					"不填则只做通道探活，结论强度低。",
			},
			"label": map[string]any{"type": "string", "description": "用途标注，例：DMZ→核心网段出口。"},
			"ttl_minutes": map[string]any{
				"type": "integer", "default": 120,
				"description": "存活分钟数（默认 120，上限 480）。到期自动关闭。",
			},
			"hops": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"addr":          map[string]any{"type": "string", "description": "host:port（端口省略按 22）。"},
						"credential_id": map[string]any{"type": "integer", "description": "凭据库 id（list_credentials 查）。"},
						"username":      map[string]any{"type": "string"},
						"password":      map[string]any{"type": "string"},
						"private_key":   map[string]any{"type": "string"},
						"passphrase":    map[string]any{"type": "string"},
						"label":         map[string]any{"type": "string"},
					},
					"required": []string{"addr"},
				},
				"description": "kind=ssh 必填：跳板链，按顺序（最多 4 跳）。",
			},
			"webshell_session": map[string]any{
				"type":        "string",
				"description": "kind=webshell 必填：WebShell 会话名。",
			},
			"tunnel_url": map[string]any{
				"type":        "string",
				"description": "kind=webshell 必填：已上传到目标的隧道脚本 URL（能从平台访问到）。",
			},
			"token": map[string]any{
				"type":        "string",
				"description": "kind=webshell 必填：webshell_tunnel_script 返回的 token。",
			},
			"target": map[string]any{
				"type":        "string",
				"description": "可选：portfwd 模式固定转发的内网 host:port。给空则开 SOCKS5。",
			},
			"socks_user": map[string]any{"type": "string", "description": "SOCKS5 入口认证用户名（绑定非回环时必填）。"},
			"socks_pass": map[string]any{"type": "string", "description": "SOCKS5 认证口令。"},
			"bind_host": map[string]any{
				"type": "string", "default": "127.0.0.1",
				"description": "入口绑定地址。默认只绑回环；填 0.0.0.0 必须同时给 socks_user/socks_pass。",
			},
		}, "kind"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Kind            string       `json:"kind"`
				VerifyTarget    string       `json:"verify_target"`
				Label           string       `json:"label"`
				TTLMinutes      int          `json:"ttl_minutes"`
				Hops            []pivotHopIn `json:"hops"`
				WebShellSession string       `json:"webshell_session"`
				TunnelURL       string       `json:"tunnel_url"`
				Token           string       `json:"token"`
				Target          string       `json:"target"`
				SocksUser       string       `json:"socks_user"`
				SocksPass       string       `json:"socks_pass"`
				BindHost        string       `json:"bind_host"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			ttl := time.Duration(p.TTLMinutes) * time.Minute
			if ttl <= 0 {
				ttl = 2 * time.Hour
			}

			switch strings.ToLower(strings.TrimSpace(p.Kind)) {
			case "ssh":
				return t.deploySSHPivot(ctx, p.Hops, p.Target, p.Label, ttl, p.VerifyTarget, p.BindHost, p.SocksUser, p.SocksPass)
			case "webshell":
				return t.deployWebshellPivot(ctx, p.WebShellSession, p.TunnelURL, p.Token, p.Target, p.Label, ttl, p.VerifyTarget, p.BindHost, p.SocksUser, p.SocksPass)
			default:
				return actool.Errorf("kind 必须是 ssh 或 webshell"), nil
			}
		},
	)
}

// deploySSHPivot 建 SSH 隧道 → 经隧道实测 verify_target → 不通则关。
func (t *ToolSet) deploySSHPivot(ctx context.Context, hops []pivotHopIn, target, label string,
	ttl time.Duration, verifyTarget, bindHost, socksUser, socksPass string) (actool.Result, error) {

	if r, bad := t.pivotUnavailable(); bad {
		return r, nil
	}
	if len(hops) == 0 {
		return actool.Errorf("kind=ssh 需要 hops"), nil
	}
	resolved, err := t.resolveHops(hops)
	if err != nil {
		return actool.Errorf("解析跳板失败: " + err.Error()), nil
	}

	tun, err := t.rtPivot().Open(ctx, pivot.OpenOptions{
		TaskID: t.taskID, Label: label, Mode: "socks", Hops: resolved,
		TTL: ttl, BindHost: bindHost, SocksUser: socksUser, SocksPass: socksPass,
	})
	if err != nil {
		return actool.Errorf("建立 SSH 隧道失败: " + err.Error()), nil
	}

	validation := map[string]any{"checked": false, "reason": "未提供 verify_target"}
	if vt := strings.TrimSpace(verifyTarget); vt != "" {
		host, port, perr := splitHostPort(vt, 80)
		if perr != nil {
			_ = t.rtPivot().Close(tun.ID)
			return actool.Errorf("verify_target 格式错误: " + perr.Error()), nil
		}
		start := time.Now()
		results, perr := t.rtPivot().Probe(ctx, tun.ID, pivot.ProbeOptions{
			Hosts: []string{host}, Ports: []int{port},
			Timeout: 10 * time.Second, Concurrency: 1,
		})
		elapsed := time.Since(start).Milliseconds()
		if perr != nil {
			_ = t.rtPivot().Close(tun.ID)
			out, _ := json.MarshalIndent(map[string]any{
				"ok": false, "rolled_back": true, "reason": "跳板侧验证无法执行",
				"error": perr.Error(), "verify_target": vt,
				"advice": "隧道已关闭。先确认目标网段真的可达（在跳板上直接 ping/nc 一次），再重试。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		}
		open := len(results) == 1 && results[0].Open
		validation = map[string]any{
			"checked": true, "target": vt, "open": open,
			"latency_ms": elapsed, "detail": results,
		}
		if !open {
			_ = t.rtPivot().Close(tun.ID)
			out, _ := json.MarshalIndent(map[string]any{
				"ok": false, "rolled_back": true,
				"reason":     "跳板侧验证失败：经隧道拨不通 " + vt + "，隧道已自动关闭",
				"validation": validation,
				"advice": "不要就此认定内网不通——先换一个更可能可达的目标（同网段网关、跳板本机回环、" +
					"或已确认开放的 22/445/80）重试，排除「目标本身关闭」与「路由不通」两种情况。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		}
	}

	v := tun.View(0)
	out, _ := json.MarshalIndent(map[string]any{
		"ok": true, "tunnel": v, "validation": validation,
		"usage": fmt.Sprintf("SOCKS5 入口 %s。例：curl --socks5-hostname %s http://%s/ （本机 NO_PROXY 覆盖时加 --noproxy \"\"）",
			v.SocksURL, v.SocksURL, strings.TrimSuffix(verifyTarget, ":80")),
		"next": "隧道已验证可用。用 pivot_probe 摸网段，打完 pivot_close。",
	}, "", "  ")
	return actool.Text(string(out)), nil
}

// deployWebshellPivot 建 WebShell 隧道 → 经 SOCKS5 实测 → 不通则关。
func (t *ToolSet) deployWebshellPivot(ctx context.Context, session, tunnelURL, token, target, label string,
	ttl time.Duration, verifyTarget, bindHost, socksUser, socksPass string) (actool.Result, error) {

	if r, bad := t.wsTunnelUnavailable(); bad {
		return r, nil
	}
	if strings.TrimSpace(session) == "" || strings.TrimSpace(tunnelURL) == "" || strings.TrimSpace(token) == "" {
		return actool.Errorf("kind=webshell 需要 webshell_session / tunnel_url / token"), nil
	}
	tun, err := t.rtShellTunnel().Open(ctx, webshell.TunnelOptions{
		TaskID: t.taskID, Session: session, TunnelURL: tunnelURL, Token: token,
		Mode: "socks", Target: target, Label: label, TTL: ttl,
		BindHost: bindHost, SocksUser: socksUser, SocksPass: socksPass,
	})
	if err != nil {
		return actool.Errorf("建立 WebShell 隧道失败: " + err.Error()), nil
	}

	validation := map[string]any{"checked": false, "reason": "未提供 verify_target"}
	if vt := strings.TrimSpace(verifyTarget); vt != "" {
		host, port, perr := splitHostPort(vt, 80)
		if perr != nil {
			_ = t.rtShellTunnel().Close(tun.ID)
			return actool.Errorf("verify_target 格式错误: " + perr.Error()), nil
		}
		start := time.Now()
		// 认证从隧道的 SocksURL 取，而不是复用入参：调用方可能只给了 bind_host
		// 而认证是 Open 时生成/继承的，用入参会对不上。
		socksAddr, socksU, socksP, perr := parseSocksURL(tun.SocksURL)
		if perr != nil || socksAddr == "" {
			socksAddr, socksU, socksP = tun.Listen, socksUser, socksPass
		}
		dialErr := socks5ConnectProbe(ctx, socksAddr, socksU, socksP, host, port, 12*time.Second)
		elapsed := time.Since(start).Milliseconds()
		ok := dialErr == nil
		validation = map[string]any{
			"checked": true, "target": vt, "open": ok,
			"latency_ms": elapsed,
		}
		if !ok {
			validation["error"] = dialErr.Error()
			_ = t.rtShellTunnel().Close(tun.ID)
			out, _ := json.MarshalIndent(map[string]any{
				"ok": false, "rolled_back": true,
				"reason":     "跳板侧验证失败：经隧道脚本拨不通 " + vt + "，隧道已自动关闭",
				"validation": validation,
				"advice": "WebShell 隧道失败常见原因：① 目标 PHP 禁用了 fsockopen/curl；" +
					"② 目标到内网无路由；③ 验证目标本身关闭。先换一个已知开放端口重试，" +
					"再考虑改用 SSH pivot 或反弹 shell。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		}
	}

	v := tun.View(0)
	out, _ := json.MarshalIndent(map[string]any{
		"ok": true, "tunnel": v, "validation": validation,
		"usage":   webshellPivotUsage(tun),
		"next":    "隧道已验证可用。WebShell 隧道延迟高，适合低带宽探测，不适合大流量传输。",
		"cleanup": "打完 webshell_pivot_close，并 webshell_remove(remove_remote=true) 清掉目标上的隧道脚本。",
	}, "", "  ")
	return actool.Text(string(out)), nil
}

// splitHostPort 把 "host" / "host:port" 统一成 (host, port)。
func splitHostPort(s string, defPort int) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("目标为空")
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// 没有冒号，或 IPv6 字面量没带端口。
		if strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
			return s, defPort, nil
		}
		return s, defPort, nil
	}
	if host == "" {
		return "", 0, fmt.Errorf("主机为空")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("端口非法: %s", portStr)
	}
	return host, port, nil
}

// socks5ConnectProbe 经 SOCKS5 入口做一次真实 CONNECT，成功即证明「跳板→目标」通。
//
// 只完成握手与 CONNECT，不发应用层数据：目标是 HTTP/FTP/445 都能用同一个判据，
// 也不会在目标上留下请求日志。
func socks5ConnectProbe(ctx context.Context, socksAddr, user, pass, host string, port int, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return fmt.Errorf("连 SOCKS 入口失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	useAuth := user != "" || pass != ""
	greeting := []byte{0x05, 0x01, 0x00}
	if useAuth {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("SOCKS 协商发送失败: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("SOCKS 协商应答失败: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("SOCKS 版本错误: 0x%02x", resp[0])
	}
	switch resp[1] {
	case 0x00:
		// 免认证
	case 0x02:
		if !useAuth {
			return fmt.Errorf("入口要求认证，但未提供 socks_user/socks_pass")
		}
		ub, pb := []byte(user), []byte(pass)
		if len(ub) > 255 || len(pb) > 255 {
			return fmt.Errorf("认证字段过长")
		}
		req := make([]byte, 0, 3+len(ub)+len(pb))
		req = append(req, 0x01, byte(len(ub)))
		req = append(req, ub...)
		req = append(req, byte(len(pb)))
		req = append(req, pb...)
		if _, err := conn.Write(req); err != nil {
			return fmt.Errorf("SOCKS 认证发送失败: %w", err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return fmt.Errorf("SOCKS 认证应答失败: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("SOCKS 认证被拒（状态 0x%02x）", ar[1])
		}
	case 0xFF:
		return fmt.Errorf("入口不接受任何认证方式")
	default:
		return fmt.Errorf("入口选择了不支持的认证方式 0x%02x", resp[1])
	}

	// CONNECT：IP 用 ATYP=1，域名用 ATYP=3。
	var req []byte
	req = append(req, 0x05, 0x01, 0x00)
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip != nil {
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("CONNECT 发送失败: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("CONNECT 应答读取失败: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("CONNECT 应答版本错误")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("CONNECT 被拒（%s）", socksReplyText(head[1]))
	}
	// 吃掉绑定地址，避免连接停在半读状态。
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return fmt.Errorf("读取绑定地址长度失败: %w", err)
		}
		skip = int(lb[0]) + 2
	default:
		return fmt.Errorf("CONNECT 应答地址类型未知: 0x%02x", head[3])
	}
	if skip > 0 {
		if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
			return fmt.Errorf("读取绑定地址失败: %w", err)
		}
	}
	return nil
}

// socksReplyText 把 SOCKS5 应答码翻成可执行的中文结论。
func socksReplyText(code byte) string {
	switch code {
	case 0x01:
		return "一般性失败"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达——跳板到该网段没有路由"
	case 0x04:
		return "主机不可达——目标主机不存在或已被隔离"
	case 0x05:
		return "连接被拒——主机活着但端口关闭"
	case 0x06:
		return "TTL 过期"
	case 0x07:
		return "不支持的命令"
	case 0x08:
		return "地址类型不支持"
	default:
		return fmt.Sprintf("未知错误 0x%02x", code)
	}
}

// parseSocksURL 从 socks5://[user:pass@]host:port 里取地址与认证。
func parseSocksURL(raw string) (addr, user, pass string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", err
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("socks_url 缺少主机")
	}
	addr = u.Host
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return addr, user, pass, nil
}
