package agent

// dimension.go 里有两份「token → 维度」的定义：
//   - dimensionAliases：planner 显式给维度时用；
//   - dimensionInferRules：从 summary 自由文本推断时用。
//
// 同一个 token 走这两条路必须得到同一个维度。否则同一条 finding，planner 显式标注时
// 归到 A 类、只写 summary 时归到 B 类，「同资产×同手法」的确定性去重就不成立了——
// 而 dedupe 失效的表现是「同一个点被打两遍」，只会浪费 token，不会报错。
//
// 注：alias 那条路径目前没有调用点（见 dimensionAliases 上方说明）。这条用例的价值
// 在于把它接线的那一天不会踩坑。

import "testing"

func TestDimensionAliasAgreesWithInference(t *testing.T) {
	for token, want := range dimensionAliases {
		got := inferDimension(token)
		if got == "" {
			// 推不出来不算冲突：alias 只要求「给得出标准维度」，不要求这个词必须能推断。
			continue
		}
		if got != want {
			t.Errorf("token %q: alias 归到 %q，但 inferDimension 归到 %q —— 显式维度与推断维度打架", token, want, got)
		}
	}
}

// 标准 19 值 vulnclass 都该被 inferDimension 识别或由 vulnClassChain 兜住。
// 这条守的是「新增一个标准类别时忘了接维度」——那种漏会让该类漏洞永远不续跳。
func TestEveryStandardVulnClassIsRouted(t *testing.T) {
	// 这四类本来就没有「打穿到影响」的下一步，不续跳是对的。
	noNext := map[string]bool{
		"拒绝服务": true, "中间人劫持": true, "配置错误": true, "其他": true,
	}

	for _, vc := range []string{
		"注入", "XSS", "未授权访问", "弱口令", "任意文件上传", "任意文件读取",
		"反序列化", "RCE", "SSRF", "XXE", "信息泄露", "权限提升", "认证绕过",
		"逻辑漏洞", "拒绝服务", "中间人劫持", "已知漏洞", "配置错误", "其他",
	} {
		dim, goal := chainPlanFor(vc, "", "")
		if noNext[vc] {
			if dim != "" || goal != "" {
				t.Errorf("vulnclass=%q 不该续跳，实际 (%q, %q)", vc, dim, goal)
			}
			continue
		}
		if dim == "" || goal == "" {
			t.Errorf("vulnclass=%q 没有续跳方案：该类别的高危漏洞会停在「存在性」", vc)
		}
	}
}
