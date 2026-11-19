package agent

// 攻击链续跳的语义守卫。
//
// chainPlanFor 决定「report_finding 之后自动派什么意图」。它不出错则已，错了就是
// 高危漏洞停在「存在性」——而这是客户反馈的原始痛点。这里把「哪个类别该跳到哪」
// 全部钉死，包括那六个原先推不出维度、missing 为空就直接不续跳的标准类别。

import (
	"strings"
	"testing"
)

// 标准 19 值枚举里，能续跳的类别必须给出确定的下一跳维度。
// 期望值来自 chainNext 的语义：注入/越权→取数，执行类→拿凭据，凭据→横向，
// SSRF→回到侦察看内网。
func TestChainPlanStandardVulnClasses(t *testing.T) {
	cases := []struct {
		vulnclass, wantDim, why string
	}{
		// ── 原先就能推断正确，防回归 ──────────────────────────────────────
		{"注入", dimDataExport, "注入→导出数据/凭据"},
		{"XSS", dimDataExport, "XSS 归注入类→取数"},
		{"任意文件上传", dimCredReuse, "上传→主机上收集凭据"},
		{"反序列化", dimCredReuse, "反序列化=RCE→收集凭据"},
		{"RCE", dimCredReuse, "RCE→收集凭据"},
		{"未授权访问", dimDataExport, "越权→回读他人数据"},
		{"SSRF", dimRecon, "SSRF→探内网找下一跳"},
		{"弱口令", dimLateral, "有凭据→横向"},
		{"权限提升", dimDataExport, "提权→只读取证"},

		// ── 原有的缺口：这六类推不出维度，missing 为空时整条链就断了 ──────
		{"任意文件读取", dimDataExport, "读文件→取配置/密钥"},
		{"XXE", dimDataExport, "XXE→读文件探内网"},
		{"信息泄露", dimCredReuse, "泄露的凭据→登录/横向"},
		{"认证绕过", dimDataExport, "进后台→回读数据"},
		{"逻辑漏洞", dimDataExport, "验业务影响"},
		{"已知漏洞", dimDataExport, "按 CVE 验实际影响"},
	}

	for _, c := range cases {
		dim, goal := chainPlanFor(c.vulnclass, "", "")
		if dim != c.wantDim {
			t.Errorf("vulnclass=%q 的下一跳维度 = %q，期望 %q（%s）", c.vulnclass, dim, c.wantDim, c.why)
		}
		if goal == "" {
			t.Errorf("vulnclass=%q 给了维度却没给目标描述", c.vulnclass)
		}
	}
}

// DoS / MITM / 配置错误 / 其他 本来就没有「打穿到影响」的下一步：
// 给它们派意图只会制造噪音意图。这里钉住「宁可不续跳」。
func TestChainPlanSkipsClassesWithoutNextStep(t *testing.T) {
	for _, vc := range []string{"拒绝服务", "中间人劫持", "配置错误", "其他", ""} {
		if dim, goal := chainPlanFor(vc, "", ""); dim != "" || goal != "" {
			t.Errorf("vulnclass=%q 不该续跳，实际得到 (%q, %q)", vc, dim, goal)
		}
	}
}

// 模型报的 vulnclass 是自由文本（"LFI" / "xxe" / "信息泄漏" / "CVE-2023-1234"），
// 归一到标准枚举是 chainPlanFor 的责任。不归一的话，这些写法全都匹配不到
// vulnClassChain，续跳照样断——等于改了等于没改。
func TestChainPlanNormalizesVulnClassVariants(t *testing.T) {
	cases := []struct{ in, wantDim string }{
		{"LFI", dimDataExport},
		{"lfi", dimDataExport},
		{"路径穿越", dimDataExport},
		{"任意文件包含", dimDataExport},
		{"xxe", dimDataExport},
		{"xml实体注入", dimDataExport},
		{"xmlexternalentity", dimDataExport},
		{"信息泄漏", dimCredReuse},
		{"源码泄露", dimCredReuse},
		{"登陆绕过", dimDataExport},
		{"authentication bypass", dimDataExport},
		{"业务逻辑", dimDataExport},
		{"支付逻辑", dimDataExport},
		{"CVE-2023-46604", dimDataExport},
		{"cve-2021-44228", dimDataExport},
	}
	for _, c := range cases {
		dim, goal := chainPlanFor(c.in, "", "")
		if dim != c.wantDim {
			t.Errorf("vulnclass=%q 的下一跳维度 = %q，期望 %q", c.in, dim, c.wantDim)
		}
		if goal == "" {
			t.Errorf("vulnclass=%q 没给目标描述", c.in)
		}
	}
}

// 续跳目标必须「具体到能直接执行」：只说「继续利用」等于把问题原样还给模型。
// 这里只做长度与关键词的粗检查——真值由人读，防止有人把它改成空话。
func TestChainPlanGoalsAreActionable(t *testing.T) {
	seen := map[string]string{}
	for vc, p := range vulnClassChain {
		if len([]rune(p.goal)) < 20 {
			t.Errorf("vulnclass=%q 的目标描述太短，无法执行: %q", vc, p.goal)
		}
		if prev, ok := seen[vc]; ok && prev != p.goal {
			t.Errorf("vulnclass=%q 重复定义且目标不一致: %q vs %q", vc, prev, p.goal)
		}
		seen[vc] = p.goal
		if p.next == "" {
			t.Errorf("vulnclass=%q 有目标却没给维度", vc)
		}
	}
}

// 反向一致性：vulnClassChain 里只该出现「自由文本推断推不出」的类别。
// 若某类别 inferDimension 已经能推断出来，这里再写一份就是双写——
// 两处定义迟早漂移，而漂移的表现是「同一条 finding 续跳目标时好时坏」。
func TestChainPlanNoDoubleDefinition(t *testing.T) {
	for vc := range vulnClassChain {
		if inferred := inferDimension(vc); inferred != "" {
			t.Errorf("vulnclass=%q 已能被 inferDimension 推断为 %q，不要在 vulnClassChain 重复定义",
				vc, inferred)
		}
	}
}

// allDimensions 是维度枚举的唯一测试来源。新增维度时必须同时想清楚它的下一跳，
// 否则 chainNext 会落到 default 分支静默返回空——症状是「某类高危漏洞打完就停」，
// 而且没有任何报错。
var allDimensions = []string{
	dimRecon, dimAuthz, dimInjection, dimUpload, dimSSRF, dimRCE,
	dimCredReuse, dimDataExport, dimPayment, dimPrivesc, dimLateral,
}

// TestChainCoversEveryDimension 钉住「维度全覆盖」。
//
// v0.4.84 之前 recon / data-export / lateral 只作为目标出现、从不作为源，
// 后果是「横向移动成功」这条最高价值的高危 finding 没有下一跳——内网纵深
// 打完第一层就停住。这条测试守住那个缺口不再回来。
func TestChainCoversEveryDimension(t *testing.T) {
	for _, d := range allDimensions {
		next, goal := chainNext(d)
		if next == "" {
			t.Errorf("维度 %q 没有下一跳：这类 finding 会停在「存在性」", d)
			continue
		}
		if goal == "" {
			t.Errorf("维度 %q 给了下一跳却没给目标描述", d)
		}
	}
}

// TestChainNextNeverSelfMaps：下一跳不能等于当前维度。
// 自映射会让同一条 finding 反复派同维度意图，dedupe 一失效就是死循环。
func TestChainNextNeverSelfMaps(t *testing.T) {
	for _, d := range allDimensions {
		if next, _ := chainNext(d); next == d {
			t.Errorf("维度 %q 的下一跳是自己，会形成自环", d)
		}
	}
}

// TestChainDataExportTellsHowToStop：data-export → lateral 必须带终止条件。
//
// 纯 Web 任务里 data-export 就是终点，没有内网入口。目标描述里不写清「没有入口
// 就记录并结束」，worker 会为一个做不到的横向意图空转一轮，最后只写一条 blocked
// ——那是用预算换噪声。
func TestChainDataExportTellsHowToStop(t *testing.T) {
	next, goal := chainNext(dimDataExport)
	if next != dimLateral {
		t.Fatalf("data-export 的下一跳应为 lateral，实际 %q", next)
	}
	if !strings.Contains(goal, "若没有任何内网入口") || !strings.Contains(goal, "链止于此") {
		t.Errorf("data-export→lateral 的目标缺少终止条件，纯 Web 任务会空转：%q", goal)
	}
}
