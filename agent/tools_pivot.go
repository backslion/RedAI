package agent

// 内网横向穿透工具：把「已验证可登录的主机」变成平台的内网出口。
//
// 设计边界与 pivot 包一致：
//   - 只做 SSH 通道（目标机本来就开着 sshd），不落二进制、不开反向 shell。
//   - 凭据只允许两种来源：asset_credentials（credential_id）或人工在当前调用里
//     显式给出。不接受「猜」——爆破是另一件事，且会触发锁定。
//   - 开隧道是对内网的长期入口，走拦截规则「[内置] 开启内网穿透隧道」（ask）。
//
// 为什么单独给一组工具而不是复用 tcp_probe：
//   tcp_probe 从平台本机拨号，打不到目标内网；nmap 不走 SOCKS5（除非装
//   proxychains，而部署环境未必有）。SSH 的 direct-tcpip 通道是「由跳板机代拨」，
//   通道打开即证明端口可达，这是本组工具的核心价值。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/backslion/RedAI/pivot"

	actool "github.com/Autumn-27/norma/tool"
)

// pivot 依赖经 Runtime 取（见 runtime.go）：server 注入默认实例，ToolSet 也可显式指定。
// 取不到时报「未启用」而不是 panic。

// SetPivotManager wires the process-wide pivot manager.
func SetPivotManager(m *pivot.Manager) {
	setDefaultRuntime(func(r *Runtime) { r.Pivot = m })
}

func (t *ToolSet) pivotUnavailable() (actool.Result, bool) {
	if t.rtPivot() == nil {
		return actool.Errorf("内网穿透未启用（服务端未初始化 pivot manager）"), true
	}
	return actool.Result{}, false
}

// pivotHopIn 是 pivot_open 的跳板输入。凭据二选一：credential_id 或明文字段。
type pivotHopIn struct {
	Addr         string `json:"addr"`
	CredentialID int64  `json:"credential_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	PrivateKey   string `json:"private_key"`
	Passphrase   string `json:"passphrase"`
	Label        string `json:"label"`
}

// resolveHops 把输入转成 pivot.Hop，secret 只在内存里过一手。
//
// 收口纪律：credential_id 走 CredentialStore.SecretByID(taskID, id)，它本身带
// 任务范围校验（凭据关联资产不在任务范围内会直接报错）。这里读到的 secret
// 只用于 SSH 握手，绝不进入工具返回值、fact、报告。
func (t *ToolSet) resolveHops(in []pivotHopIn) ([]pivot.Hop, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("hops 不能为空")
	}
	if len(in) > pivot.MaxHops {
		return nil, fmt.Errorf("跳板链最多 %d 跳", pivot.MaxHops)
	}
	out := make([]pivot.Hop, 0, len(in))
	for i, h := range in {
		hop := pivot.Hop{
			Addr:  strings.TrimSpace(h.Addr),
			User:  strings.TrimSpace(h.Username),
			Label: strings.TrimSpace(h.Label),
		}
		if hop.Addr == "" {
			return nil, fmt.Errorf("第 %d 跳缺少 addr", i+1)
		}
		if !strings.Contains(hop.Addr, ":") {
			hop.Addr = net.JoinHostPort(hop.Addr, "22")
		}
		if h.CredentialID > 0 {
			if t.ts == nil || t.ts.DB() == nil {
				return nil, fmt.Errorf("第 %d 跳给了 credential_id，但凭据库不可用", i+1)
			}
			sec, err := t.ts.DB().Credentials().SecretByID(t.taskID, h.CredentialID)
			if err != nil {
				return nil, fmt.Errorf("第 %d 跳读取凭据 %d 失败: %w", i+1, h.CredentialID, err)
			}
			if strings.TrimSpace(hop.User) == "" {
				hop.User = sec.Username
			}
			if sec.Domain != "" && sec.Domain != "local" && !strings.Contains(hop.User, "\\") {
				// AD 账号在 Linux sshd 上通常写成 DOMAIN\user 或 user@domain；
				// 这里保持原样，只把 domain 记进 label 免得人看不懂是哪个域。
				if hop.Label == "" {
					hop.Label = sec.Domain + "\\" + sec.Username
				}
			}
			if sec.CredType == "key" || strings.Contains(sec.Secret, "PRIVATE KEY") {
				hop.PrivateKey = []byte(sec.Secret)
			} else {
				hop.Password = sec.Secret
			}
		} else {
			if strings.TrimSpace(h.PrivateKey) != "" {
				hop.PrivateKey = []byte(h.PrivateKey)
				hop.Passphrase = []byte(h.Passphrase)
			} else if h.Password != "" {
				hop.Password = h.Password
			}
		}
		if hop.User == "" {
			return nil, fmt.Errorf("第 %d 跳缺少 username（或给 credential_id 让平台自己取）", i+1)
		}
		if hop.Password == "" && len(hop.PrivateKey) == 0 {
			return nil, fmt.Errorf("第 %d 跳没有可用凭据：给 credential_id，或 username+password / private_key", i+1)
		}
		out = append(out, hop)
	}
	return out, nil
}

// pivotUsage 生成「接下来怎么用」的提示。这是工具输出里最容易被忽略、
// 但直接决定模型能不能真正打出内网的一段。
func pivotUsage(t *pivot.Tunnel) string {
	if t.Mode == pivot.ModeSocks {
		addr := t.Listen
		auth := ""
		if t.HasAuth {
			auth = "（需要用户名口令，见 socks_url）"
		}
		return fmt.Sprintf(
			"SOCKS5 入口 %s %s。用法：\n"+
				"  curl --socks5-hostname %s http://<内网IP>:<端口>/      # 域名也走隧道解析\n"+
				"  ssh -o ProxyCommand='nc -x %s %%h %%p' user@<内网IP>   # 再跳一层\n"+
				"  pivot_probe(pivot_id=%q, hosts=[...], ports=[...])     # 批量探端口（nmap 不走 SOCKS5）\n"+
				"注意：--socks5 会本地解析域名，打内网必须用 --socks5-hostname；"+
				"别把 %s 写进报告或工单——它是当前任务可用的内网入口。",
			addr, auth, addr, addr, t.ID, addr)
	}
	return fmt.Sprintf(
		"端口转发 %s → %s。用法：直接连 %s 即可（例如 curl http://%s/、nc %s <port>）；"+
			"目标固定，不能换。要访问别的目标请再开一条 portfwd 或改用 socks 模式。",
		t.Listen, t.Target, t.Listen, t.Listen, t.Listen)
}

// pivotOpen 建隧道。
func (t *ToolSet) pivotOpen() actool.CoreTool {
	return writeTool(
		"pivot_open",
		"(内网横向)建立 SSH 穿透隧道，把已控主机变成平台的内网出口。\n"+
			"两种模式：socks（平台回环开 SOCKS5，可打任意内网目标）/ portfwd（固定转发到一个内网 host:port）。\n"+
			"多跳：hops 按顺序给，第 2 跳起的连接建在前一跳的通道上，中间主机不需要装任何东西、不需要出网。\n"+
			"凭据：hops[].credential_id 引用 asset_credentials（推荐，secret 不出平台、且校验任务范围）；"+
			"也接受 username+password 或 private_key 直填（仅当凭据不在库里）。\n"+
			"返回：隧道 id、socks 地址、主机密钥指纹、TTL、以及可直接照抄的用法。\n"+
			"什么时候用：ssh_check 已验证某主机可登录、且需要访问它背后的网段时。不要用未验证的凭据反复试（会锁定账号）。\n"+
			"**优先用 pivot_deploy(kind=ssh)**：它在开完后会做跳板侧实测、失败自动回滚，还能顺带给出选型建议（pivot_plan）。\n"+
			"本工具只建通道、不验证内网可达——自己调它就要自己承担「看起来通、实际打不通」的风险。\n"+
			"用完必须 pivot_close：隧道留着就是一条对内网的长期开放入口。默认 TTL 2 小时，到期自动关。",
		obj(map[string]any{
			"hops": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"addr":          map[string]any{"type": "string", "description": "host:port（端口省略按 22）。例：10.0.0.5:22"},
						"credential_id": map[string]any{"type": "integer", "description": "凭据库 id（list_credentials 查）。给了它就不用再填 username/password。"},
						"username":      map[string]any{"type": "string", "description": "SSH 用户名（给 credential_id 时可省略）。"},
						"password":      map[string]any{"type": "string", "description": "口令（仅当凭据不在库里时用）。"},
						"private_key":   map[string]any{"type": "string", "description": "PEM 私钥全文（仅当凭据不在库里时用）。"},
						"passphrase":    map[string]any{"type": "string", "description": "私钥口令（如有）。"},
						"label":         map[string]any{"type": "string", "description": "标注（如「办公网跳板-01」）。"},
					},
					"required": []string{"addr"},
				},
				"description": "跳板链，按顺序（第 1 跳从平台直连）。最多 4 跳。",
			},
			"mode": map[string]any{
				"type": "string", "default": "socks",
				"description": "socks（默认，任意目标）/ portfwd（固定单目标）。",
			},
			"target": map[string]any{
				"type": "string", "description": "portfwd 模式必填：最终要访问的内网 host:port（经最后一跳拨号）。",
			},
			"label": map[string]any{
				"type": "string", "description": "隧道用途标注，例：核心网段出口。",
			},
			"ttl_minutes": map[string]any{
				"type": "integer", "default": 120,
				"description": "存活分钟数（默认 120，上限 480）。到期自动关闭。",
			},
			"socks_user": map[string]any{
				"type": "string", "description": "给 SOCKS5 入口加认证（绑定非回环地址时必填）。",
			},
			"socks_pass": map[string]any{"type": "string", "description": "SOCKS5 认证口令。"},
			"bind_host": map[string]any{
				"type": "string", "default": "127.0.0.1",
				"description": "入口绑定地址。默认只绑回环（只有本平台能用）；填 0.0.0.0 必须同时给 socks_user/socks_pass。",
			},
		}, "hops"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.pivotUnavailable(); bad {
				return r, nil
			}
			var p struct {
				Hops       []pivotHopIn `json:"hops"`
				Mode       string       `json:"mode"`
				Target     string       `json:"target"`
				Label      string       `json:"label"`
				TTLMinutes int          `json:"ttl_minutes"`
				SocksUser  string       `json:"socks_user"`
				SocksPass  string       `json:"socks_pass"`
				BindHost   string       `json:"bind_host"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			hops, err := t.resolveHops(p.Hops)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ttl := time.Duration(p.TTLMinutes) * time.Minute
			if ttl <= 0 {
				ttl = pivot.DefaultTTL
			}
			tun, err := t.rtPivot().Open(ctx, pivot.OpenOptions{
				TaskID:    t.taskID,
				Label:     p.Label,
				Mode:      p.Mode,
				Hops:      hops,
				Target:    p.Target,
				TTL:       ttl,
				BindHost:  p.BindHost,
				SocksUser: p.SocksUser,
				SocksPass: p.SocksPass,
			})
			if err != nil {
				return actool.Errorf("开隧道失败: " + err.Error()), nil
			}
			v := tun.View(0)
			out, _ := json.MarshalIndent(map[string]any{
				"ok":       true,
				"tunnel":   v,
				"usage":    pivotUsage(tun),
				"host_key": v.HostKey,
				"next": "隧道已可用。先用 pivot_probe 确认目标网段哪些端口开着，再决定打哪个；" +
					"打完记得 pivot_close（隧道不关就是长期入口）。",
				"warning": "主机密钥未预校验（渗透现场无 known_hosts），已记录指纹供核对；" +
					"若该网段有中间人风险，先人工比对指纹再继续。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// pivotList 列出隧道。
func (t *ToolSet) pivotList() actool.CoreTool {
	return readTool(
		"pivot_list",
		"列出当前任务的穿透隧道（含剩余 TTL、连接数、上下行字节、最近连接目标、最近错误）。\n"+
			"开隧道后先看这里确认存活；排查「为什么打不通」时看 last_error 与 recent：\n"+
			"recent 里的 error 是跳板机代拨失败的真实原因（refused=端口关、timeout=被过滤、prohibited=sshd 禁止转发）。",
		obj(map[string]any{
			"all_tasks": map[string]any{"type": "boolean", "description": "true = 看所有任务的隧道（默认只看本任务）。"},
			"recent":    map[string]any{"type": "integer", "description": "每条隧道附带最近 N 条连接记录（默认 3，上限 20）。"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.pivotUnavailable(); bad {
				return r, nil
			}
			var p struct {
				AllTasks bool `json:"all_tasks"`
				Recent   int  `json:"recent"`
			}
			_ = json.Unmarshal(in, &p)
			tid := t.taskID
			if p.AllTasks {
				tid = 0
			}
			n := p.Recent
			if n <= 0 {
				n = 3
			}
			if n > 20 {
				n = 20
			}
			list := t.rtPivot().List(tid)
			views := make([]pivot.TunnelView, 0, len(list))
			for _, tun := range list {
				views = append(views, tun.View(n))
			}
			st := t.rtPivot().Stats()
			out, _ := json.MarshalIndent(map[string]any{
				"tunnels": views,
				"stats":   st,
				"hint":    "没有隧道时先 pivot_open；有隧道但目标不通，看 recent[].error 判断是端口关、被过滤还是 sshd 禁止转发。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// pivotClose 关闭隧道。
func (t *ToolSet) pivotClose() actool.CoreTool {
	return writeTool(
		"pivot_close",
		"关闭穿透隧道（或 all=true 关闭本任务全部）。横向动作结束时必须调用：\n"+
			"隧道是一条对内网的长期开放入口，留着就是风险，也会占用端口与连接配额。",
		obj(map[string]any{
			"id":  map[string]any{"type": "string", "description": "隧道 id（pivot_list 查）。"},
			"all": map[string]any{"type": "boolean", "description": "true = 关闭本任务全部隧道。"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.pivotUnavailable(); bad {
				return r, nil
			}
			var p struct {
				ID  string `json:"id"`
				All bool   `json:"all"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if p.All {
				n := t.rtPivot().CloseTask(t.taskID)
				b, _ := json.Marshal(map[string]any{"ok": true, "closed": n})
				return actool.Text(string(b)), nil
			}
			if strings.TrimSpace(p.ID) == "" {
				return actool.Errorf("id 不能为空（或用 all=true 关全部）"), nil
			}
			// 归属校验：不能关别的任务的隧道。
			if tun, ok := t.rtPivot().Get(p.ID); ok && tun.TaskID != 0 && t.taskID != 0 && tun.TaskID != t.taskID {
				return actool.Errorf(fmt.Sprintf("隧道 %s 属于任务 %d，不是当前任务", p.ID, tun.TaskID)), nil
			}
			if err := t.rtPivot().Close(p.ID); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(map[string]any{"ok": true, "closed": 1, "id": p.ID})
			return actool.Text(string(b)), nil
		},
	)
}

// pivotProbe 经隧道探测内网端口。
func (t *ToolSet) pivotProbe() actool.CoreTool {
	return readTool(
		"pivot_probe",
		"(内网横向)经已建隧道批量探测内网端口。连接由跳板机代拨（SSH direct-tcpip），\n"+
			"所以能到平台本机到不了的网段；不需要 nmap，也不依赖目标出网。\n"+
			"返回每个 host:port 的 open / latency_ms / error（refused=端口关闭但主机可达，timeout=被过滤或主机不存在，prohibited=跳板机 sshd 禁止转发）。\n"+
			"语义是连通性探测，不爆破、不发应用层 payload（banner 是被动读）。开放端口应登记 insert_assets(type=service)。",
		obj(map[string]any{
			"pivot_id": map[string]any{"type": "string", "description": "隧道 id（pivot_list 查）。必须是对应方向可达的隧道。"},
			"hosts": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "目标主机（IP 或域名），一次最多 256 个。",
			},
			"ports": map[string]any{
				"type": "array", "items": map[string]any{"type": "integer"},
				"description": "显式端口列表，与 preset 叠加。",
			},
			"preset": map[string]any{
				"type": "string", "default": "top100",
				"description": "端口预设：top100 / web / db / win / nix / none（只用显式 ports）。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 1500,
				"description": "单次拨号超时毫秒（500..10000）。经隧道通常比本机慢，内网段建议 2000。",
			},
			"concurrency": map[string]any{
				"type": "integer", "default": 32,
				"description": "并发数（上限 128）。跳板机 sshd 有 MaxSessions 限制，大范围扫段别开太高。",
			},
			"grab_banner": map[string]any{
				"type": "boolean", "description": "对开放端口被动读 256 字节 banner（默认 false，会慢）。",
			},
		}, "pivot_id", "hosts"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, bad := t.pivotUnavailable(); bad {
				return r, nil
			}
			var p struct {
				PivotID   string   `json:"pivot_id"`
				Hosts     []string `json:"hosts"`
				Ports     []int    `json:"ports"`
				Preset    string   `json:"preset"`
				TimeoutMs int      `json:"timeout_ms"`
				Conc      int      `json:"concurrency"`
				Grab      bool     `json:"grab_banner"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			tun, ok := t.rtPivot().Get(p.PivotID)
			if !ok {
				return actool.Errorf(fmt.Sprintf("隧道 %s 不存在（先 pivot_list 或 pivot_open）", p.PivotID)), nil
			}
			if tun.TaskID != 0 && t.taskID != 0 && tun.TaskID != t.taskID {
				return actool.Errorf(fmt.Sprintf("隧道 %s 属于任务 %d，不是当前任务", p.PivotID, tun.TaskID)), nil
			}
			if p.Preset == "" {
				p.Preset = "top100"
			}
			portSet := map[int]bool{}
			if p.Preset != "none" {
				preset, ok := portPresets[p.Preset]
				if !ok {
					return actool.Errorf(fmt.Sprintf("未知 preset %q，可选 top100/web/db/win/nix/none", p.Preset)), nil
				}
				for _, pt := range preset {
					portSet[pt] = true
				}
			}
			for _, pt := range p.Ports {
				if pt < 1 || pt > 65535 {
					return actool.Errorf(fmt.Sprintf("非法端口 %d", pt)), nil
				}
				portSet[pt] = true
			}
			if len(portSet) == 0 {
				return actool.Errorf("未指定任何端口"), nil
			}
			ports := make([]int, 0, len(portSet))
			for pt := range portSet {
				ports = append(ports, pt)
			}
			sort.Ints(ports)

			res, err := t.rtPivot().Probe(ctx, p.PivotID, pivot.ProbeOptions{
				Hosts:       p.Hosts,
				Ports:       ports,
				Timeout:     time.Duration(p.TimeoutMs) * time.Millisecond,
				Concurrency: p.Conc,
				GrabBanner:  p.Grab,
			})
			if err != nil {
				return actool.Errorf("探测失败: " + err.Error()), nil
			}
			open := make([]pivot.ProbeResult, 0, 16)
			refused, timeout := 0, 0
			for _, r := range res {
				if r.Open {
					open = append(open, r)
					continue
				}
				if strings.Contains(r.Error, "refused") {
					refused++
				} else if strings.Contains(r.Error, "timeout") {
					timeout++
				}
			}
			out, _ := json.MarshalIndent(map[string]any{
				"pivot_id": p.PivotID,
				"via":      tun.Hops,
				"probed":   len(res),
				"open":     open,
				"open_cnt": len(open),
				"refused":  refused,
				"timeout":  timeout,
				"hosts":    len(p.Hosts),
				"ports":    len(ports),
				"note":     "open 才有价值；refused 说明主机活着但端口关闭；timeout 集中的网段通常是路由不通或被防火墙丢包，别继续在同一网段耗时间。",
			}, "", "  ")
			return actool.Text(string(out)), nil
		},
	)
}

// pivotIPTablesHint 给「隧道起来了但目标仍不通」提供最短排查路径。
// 保留为常量而不是塞进工具描述：描述已经很长，这里是给报告/技能引用的。
const pivotIPTablesHint = `隧道连通性排查顺序：
1) pivot_list 看 alive 与 last_error —— 心跳失败说明链路已断，重开。
2) pivot_probe 打跳板机自己的 127.0.0.1:22 —— 不通说明 sshd 禁止转发
   （AllowTcpForwarding no / PermitOpen 限制），需要换跳板。
3) 打目标网段网关 —— 不通说明路由问题，不是凭据问题。
4) 打目标端口 refused —— 主机可达但服务没起，换端口或换主机。`
