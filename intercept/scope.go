package intercept

// 网段扩权审批（scope gate）。
//
// ## 解决什么问题
// task_scope 是任务的授权边界（企业/域名/网段），但它目前只在**资产入库**时
// 起作用——autoScopeAllowed 决定一条自动发现要不要记进任务范围。工具调用本身
// 不受它约束：agent 可以直接 curl 一个授权网段之外的地址，只是结果不会记成
// 任务资产。于是「授权范围」退化成了统计口径，而不是安全边界。
//
// 这里把它补成真正的边界：工具调用的目标 IP 落在基线网段之外时走 ask 人工审批；
// 批准后把该 IP 所在的 /24 写进 task_scope（source=manual），下一次自动放行。
// 这才是「扩权」——范围是被审批显式扩大的，不是 agent 自己踩出去的。
//
// ## 为什么默认关闭
// 开着的代价是可能卡住无人值守的任务：没人审批时 ask 会等到全局兜底上限
// （默认 6 小时）才按 deny 收口，一次夜间自动跑就可能挂在一次越界访问上。
// 所以默认 off，由使用者按交战规则显式打开（scope_gate_enabled）。
//
// ## 为什么只判 IP，不判域名
// 域名基线在有基线时要求「同根域」，但 agent 正常干活必须访问搜索、文档、CDN
// 这些外部域名——按域名卡会把正常侦察全挡下来。网段没有这个问题：没有 ip/cidr
// 基线的任务这里一律放行（与 allowsIP 的既有语义一致），所以对存量任务零影响。
//
// ## 为什么批准后按 /24 而不是 /32 授权
// 内网操作的单位是网段（拿到一个入口就扫一个 C 段）。逐主机授权会变成几百次
// 点击，没有人会认真看每一次——那等于把审批变成走过场，比不批更糟。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/chu0119/pojun/db"
)

const (
	// settingScopeGateEnabled 是网段扩权闸门的开关（settings KV）。默认 false。
	settingScopeGateEnabled = "scope_gate_enabled"

	// scopeAskTimeoutSecs 是网段审批的等待上限。刻意比全局兜底（6 小时）短得多：
	// 全局兜底是为「审批人离场」设计的最后防线，不是正常等待时长。扩权审批是
	// 强交互动作，半小时没人理就应当按拒绝收口，让任务继续走别的路。
	scopeAskTimeoutSecs = 30 * 60

	// scopeMaxScanBytes 限制单次扫描的输入体积。超大输入（例如 Write 一整份文件）
	// 逐字符抠 IP 是浪费；超过就直接放行——这是安全边界上的 fail-open，但代价
	// 可控：真正的网络动作都走 Bash/webshell_exec 这类短命令。
	scopeMaxScanBytes = 1 << 20
)

// scopeTextTools：输入是「自由文本命令」而非结构化 JSON 的工具。它们的 IP 嵌在
// 命令串里（curl http://10.0.0.5/x?a=1），必须从文本里抠，不能整串解析。
var scopeTextTools = map[string]bool{
	"Bash":          true,
	"shell_open":    true, // 开交互式 shell 时的 command
	"shell_send":    true, // 交互式 shell 里敲的每一行
	"webshell_exec": true,
}

// reIPv4 只用来从自由文本里捞候选；真伪一律交给 net.ParseIP 判定
// （它会把 999.1.1.1 判掉），正则不做数值范围校验。
var reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// ScopeGate 判定一次工具调用是否越出任务授权网段。命中越界时返回一个
// Action=ask 的 Decision 和 true；其余情况返回 false（不干预）。
//
// 只判 IP/CIDR，不判域名——理由见文件头。
func (i *Interceptor) ScopeGate(ctx context.Context, toolName string, input []byte) (Decision, bool) {
	if i == nil || i.db == nil {
		return Decision{}, false
	}
	if !i.db.GetBool(settingScopeGateEnabled, false) {
		return Decision{}, false
	}
	// 会话模式（chat）没有 task_scope，也就没有「范围」这回事——不判。
	taskIDStr, _ := taskInfoFromCtx(ctx)
	taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
	if err != nil || taskID <= 0 {
		return Decision{}, false
	}
	if len(input) > scopeMaxScanBytes {
		return Decision{}, false
	}

	ips := scopeCandidates(toolName, input)
	if len(ips) == 0 {
		return Decision{}, false
	}
	assets := i.db.Assets()
	outside := ""
	for _, ip := range ips {
		if !assets.ScopeAllowsIP(taskID, ip) {
			outside = ip
			break
		}
	}
	if outside == "" {
		return Decision{}, false
	}

	cidr := db.CSegmentOf(outside)
	authorized := assets.ScopeNetworks(taskID)
	msg := scopeAskMessage(outside, cidr, authorized, toolName)
	return Decision{
		Action:         "ask",
		Message:        msg,
		ScopeCIDR:      cidr,
		TimeoutEnabled: true,
		TimeoutSeconds: scopeAskTimeoutSecs,
		TimeoutAction:  "deny",
	}, true
}

// scopeAskMessage 是审批人看到的文案。必须回答三个问题：目标是什么、为什么被拦、
// 批准之后会发生什么。只写「是否允许」的审批框，审批人只能瞎点。
func scopeAskMessage(ip, cidr string, authorized []string, toolName string) string {
	cur := "无"
	if len(authorized) > 0 {
		show := authorized
		if len(show) > 5 {
			show = show[:5]
		}
		cur = strings.Join(show, "、")
		if len(authorized) > 5 {
			cur += fmt.Sprintf(" 等 %d 个", len(authorized))
		}
	}
	grant := "按单主机授权"
	if cidr != "" {
		grant = cidr + " 将被加入任务授权范围"
	}
	// [网段] 前缀让审批历史能把这类审批与规则/模型判定区分开（见 db.interceptSource）。
	// 不带前缀会落成 "unknown"，历史页只能显示「来源未知」，复盘时分不清这是
	// 哪条链路拦下来的。
	return fmt.Sprintf("[网段] 网段扩权审批：%s 调用的目标 %s 不在任务授权网段内（当前授权：%s）。"+
		"批准后 %s，本次调用继续执行；拒绝则本次调用不执行，任务可改用已知范围内的目标。",
		toolName, ip, cur, grant)
}

// HandleScopeAsk 走完整审批流程，并在批准后真正扩权。
//
// 两个动作必须绑在一起：只建 pending 不写 task_scope，等于「批了但没生效」，
// 下一次同样的目标会再问一遍，审批人很快就会习惯性点同意——比不批更糟。
// 写库失败不回滚放行决定：审批人已经明确批了，那一次调用照常执行，只是记日志
// 让运维知道「这次批准没能落库，下次还会问」。
func (i *Interceptor) HandleScopeAsk(ctx context.Context, convID int64, dec Decision, toolName string, input []byte) bool {
	if i == nil || i.db == nil {
		return false
	}
	if !i.HandleAsk(ctx, convID, dec, toolName, input) {
		return false
	}
	if dec.ScopeCIDR == "" {
		return true
	}
	taskIDStr, _ := taskInfoFromCtx(ctx)
	taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
	if err != nil || taskID <= 0 {
		return true
	}
	if _, err := i.db.Assets().AddAgentScope(taskID, "cidr", dec.ScopeCIDR,
		"网段扩权审批通过（"+toolName+"）", "manual"); err != nil {
		log.Printf("[intercept] 网段扩权写库失败（审批已通过，本次调用照常执行）：task=%d cidr=%s err=%v",
			taskID, dec.ScopeCIDR, err)
	}
	return true
}

// scopeCandidates 从一次工具调用里提取所有可能是「网络目标」的 IP。
//
// 提取策略分两档，是为了在不误杀的前提下尽量不漏：
//   - 命令类工具（Bash/shell_*）：从自由文本里正则抠 IPv4。IP 在命令串中间，
//     整串解析不出来。
//   - 其余工具：只认「看起来本身就是一个地址」的字符串（裸 IP、IP:端口、
//     URL 的 host、CIDR）。不做子串搜索——否则 Write 写一份含 IP 的文档就会
//     被当成访问目标拦下来。
func scopeCandidates(toolName string, input []byte) []string {
	if len(input) == 0 {
		return nil
	}
	var payload any
	if err := json.Unmarshal(input, &payload); err != nil {
		// 不是 JSON（个别工具收裸文本）：按自由文本处理。
		return dedupIPsValidated(reIPv4.FindAllString(string(input), -1))
	}
	textMode := scopeTextTools[toolName]
	var found []string
	walkStrings(payload, func(s string) {
		if textMode {
			found = append(found, reIPv4.FindAllString(s, -1)...)
			return
		}
		if ip := ipFromToken(s); ip != "" {
			found = append(found, ip)
		}
	})
	return dedupIPsValidated(found)
}

// walkStrings 递归遍历 JSON 解出的任意值，对每个字符串调用 fn。
func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	case map[string]any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	}
}

// ipFromToken 判断一个字符串「本身」是不是地址，是则返回其中的 host IP。
// 支持：裸 IP、CIDR、host:port、scheme://host[:port]/path。
// 不是地址一律返回 ""——宁可漏判也不误杀。
func ipFromToken(s string) string {
	t := strings.TrimSpace(s)
	t = strings.Trim(t, "\"'` ")
	if t == "" || len(t) > 2048 {
		return ""
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String()
	}
	if strings.Contains(t, "/") {
		if ip, _, err := net.ParseCIDR(t); err == nil {
			return ip.String()
		}
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil {
			if ip := net.ParseIP(u.Hostname()); ip != nil {
				return ip.String()
			}
		}
		return ""
	}
	if host, _, err := net.SplitHostPort(t); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// dedupIPsValidated 去重并丢掉非法串（正则捞出来的候选必须过 ParseIP）。
func dedupIPsValidated(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		ip := net.ParseIP(strings.Trim(raw, "\"'` "))
		if ip == nil {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
