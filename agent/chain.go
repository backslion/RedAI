package agent

// 攻击链自动续跳（v0.7.0）：report_finding 成功后，按漏洞类别自动派一条
// 「继续打穿」的意图，把「漏洞存在」推进到「拿到影响」。
//
// ## 为什么需要它
//
// 客户反馈的核心缺陷是「到瓶颈就放弃，不会自己想办法打出利用」。现场事实：
// worker 能确认漏洞（267 次 report_finding），但确认之后**没有下一步**——
// planner 下一轮看到的是「已有漏洞」，容易转去补覆盖面，而不是利用它。
//
// 这里做确定性续跳：高风险漏洞入库后立刻生成一条继任意图（维度=下一跳），
// 锚在该 finding 节点上。规划者仍然掌握全局（可 steer/kill/改编排），但
// 「从存在到影响」这一步不再取决于模型是否想起来。

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chu0119/pojun/db"
)

// chainNext 返回某维度对应的下一跳维度与目标描述（空=不续跳）。
func chainNext(dim string) (string, string) {
	switch dim {
	case dimInjection:
		return dimDataExport, "用已确认的注入点导出数据/凭据（只读取证）：拿到可交付的库表、账号或配置证据，并评估影响范围"
	case dimUpload, dimRCE:
		return dimCredReuse, "利用已确认的命令执行/上传点在目标主机收集凭据与配置（只读），确认权限级别与内网可达面"
	case dimAuthz:
		return dimDataExport, "用已确认的越权点回读他人数据（限证明所需），并验证改状态/改价的业务影响"
	case dimSSRF:
		return dimRecon, "用 SSRF 探测内网服务与云元数据，找出下一跳可打的服务"
	case dimCredReuse:
		return dimLateral, "用已拿到的凭据尝试横向下一个系统（先确认授权边界内的目标）"
	case dimPayment:
		return dimDataExport, "验证支付/订单状态机被篡改后能产生多少实际影响（测试订单、金额、回调），取证后停止"
	case dimPrivesc:
		return dimDataExport, "提权后只读取证：确认可访问的敏感数据与持久化位置，不做破坏性操作"
	// 以下三条是补的缺口。在此之前 recon / data-export / lateral 只作为
	// **目标**出现、从不作为**源**——后果是「横向移动成功」这条最高价值的高危
	// finding 恰好没有下一跳，内网纵深打完第一层就停住。
	case dimRecon:
		return dimAuthz, "把已确认的暴露面推到一条可验证的入口：对暴露的管理端点/接口做一次未授权访问或弱口令验证，" +
			"拿到权限证据，或明确记录还缺哪一份凭据"
	case dimDataExport:
		// 条件式文案是刻意的：纯 Web 项目里 data-export 就是终点，没有内网入口时
		// 强行派「去横向」只会让 worker 空转一轮再写一条 blocked——用预算换噪声。
		// 把「没有入口就收尾」写进目标里，链在纯 Web 任务上自然终止。
		return dimLateral, "若任务已取得内网入口（跳板/隧道/webshell 隧道任一）：用已导出的凭据或连接串确认它在哪些主机上有效，" +
			"并验证一次登录成功；若没有任何内网入口，明确记录「无内网入口，链止于此」后结束，不要重复派同维度意图"
	case dimLateral:
		return dimPrivesc, "在已立足的主机上验证能否提权到系统权限（只读：id/whoami 与可读范围），" +
			"说清为何能提、影响多大；不写持久化、不装后门"
	default:
		return "", ""
	}
}

// vulnClassChain 是「标准漏洞类别 →（下一跳维度, 目标）」的直接映射。
//
// ## 为什么需要它
//
// vulnclass 是系统自己的 19 值标准枚举（写入时 `db.NormalizeVulnClass` 已归一），
// 比 summary 里的自由文本可靠得多。但 inferDimension 的关键词表是按「手法」写的，
// 覆盖不到「任意文件读取 / XXE / 信息泄露 / 认证绕过 / 逻辑漏洞 / 已知漏洞」——
// 这六类推不出维度，而 dispatchChainIntent 对空维度的处理是「missing 为空就不续跳」。
// 结果正好反过来：**证据最齐全的高危漏洞，最不会被继续打穿**，停在「存在性」。
//
// ## 为什么只填这六类
//
// 注入 / XSS / RCE / 反序列化 / 任意文件上传 / 未授权访问 / 弱口令 / 权限提升
// 已经能被 inferDimension 正确推断（有 TestChainPlanNoDoubleDefinition 守着）。
// 这里再写一份等于双写，两处定义迟早在改动中漂移——漂移的表现是「同一条 finding
// 的续跳目标时好时坏」，比没续跳更难查。
var vulnClassChain = map[string]struct{ next, goal string }{
	"任意文件读取": {dimDataExport, "用已确认的文件读取点取配置/密钥/源码（只读取证）：拿到可交付的凭据或连接串，并说明还能读到哪些范围"},
	"XXE":    {dimDataExport, "用已确认的 XXE 读本地文件并探测内网可达面（只读取证）：拿到配置与凭据证据，不写文件、不落地"},
	"信息泄露":   {dimCredReuse, "用泄露的凭据/密钥/接口信息尝试登录或横向下一个系统（先确认授权边界内的目标）"},
	"认证绕过":   {dimDataExport, "用已确认的认证绕过进入后台，回读敏感数据并验证一条可执行的管理操作（限证明所需）"},
	"逻辑漏洞":   {dimDataExport, "验证业务逻辑缺陷的实际影响（金额/状态/权限），用自建测试对象取证后停止"},
	"已知漏洞":   {dimDataExport, "按该 CVE 的利用方式验证实际影响（命令执行/数据读取/权限），取证后停止"},
}

// chainPlanFor 决定续跳目标：标准类别优先，自由文本兜底。
//
// 顺序是刻意的。vulnclass 是结构化枚举，说明「模型认定的漏洞类别」；summary 是
// 叙述，里面会提到别的词（"通过 SSRF 拿到 AK/SK" 里的 AK/SK 会让 cred-reuse 抢先
// 命中，把一条本该「SSRF→探内网」的链改成「凭据→横向」）。结构化字段优先，
// 自由文本只在结构字段给不出结论时兜底。
func chainPlanFor(vulnclass, name, summary string) (string, string) {
	if p, ok := vulnClassChain[db.NormalizeVulnClass(vulnclass)]; ok {
		return p.next, p.goal
	}
	return chainNext(inferDimension(vulnclass + " " + name + " " + summary))
}

// dispatchChainIntent 生成继任意图。返回 (intentID, note)。intentID<=0 时 note 说明原因。
// missing 是 SRC 证据审查列出的缺口；有缺口时续跳目标优先补齐影响证明，而不是泛泛“再打穿”。
func (t *ToolSet) dispatchChainIntent(vulnclass, name, summary, severity string, assetIDs []int64, findingNodeID, intentID int64, missing []string) (int64, string) {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "critical" && sev != "high" {
		return 0, ""
	}
	nextDim, goal := chainPlanFor(vulnclass, name, summary)
	if nextDim == "" {
		if len(missing) == 0 {
			return 0, ""
		}
		// 既不在 vulnClassChain、也推不出维度（如拒绝服务/配置错误/其他），
		// 但证据缺口很明确：仍然派一条取数/影响证明意图，避免高危 finding 停在存在性。
		nextDim = dimDataExport
		goal = "补齐该漏洞的完整危害证据"
	}
	// 证据缺口优先：高/危漏洞只有“存在性”时，续跳第一目标是把危害证明补齐。
	if len(missing) > 0 {
		goal = "补齐该漏洞的完整危害证据：" + strings.Join(missing, "、") +
			"；要求原始请求/响应、真实数据条数与敏感字段、权限矩阵或自建测试对象的写测试回读，不脱敏；补不齐就明确记录阻塞原因。"
	}
	// 摘要必须具体：带上漏洞名与维度，避免和别的意图撞车被 dedupe 掉。
	// name 可能为空（模型只给了 summary），回落到 summary 前 40 字。
	label := strings.TrimSpace(name)
	if label == "" {
		label = trimForSummary(strings.TrimSpace(summary), 40)
	}
	sum := fmt.Sprintf("利用「%s」继续打穿：%s", trimForSummary(label, 40), goal)
	it := intentItem{Summary: sum, Dimension: nextDim, Priority: 8}
	for _, id := range assetIDs {
		if raw, err := json.Marshal(id); err == nil {
			it.AssetIDs = append(it.AssetIDs, raw)
		}
	}
	if findingNodeID > 0 {
		if raw, err := json.Marshal(findingNodeID); err == nil {
			it.ParentIDs = append(it.ParentIDs, raw)
		}
	}
	id, err := t.addOneIntent(it)
	if err != nil {
		return 0, "攻击链续跳未派： " + err.Error()
	}
	return id, fmt.Sprintf("已自动派继任意图 #%d（维度=%s）：从「漏洞存在」推进到「拿到影响」。", id, nextDim)
}

func trimForSummary(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
