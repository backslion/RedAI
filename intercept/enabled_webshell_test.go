package intercept

import (
	"regexp"
	"testing"

	"github.com/backslion/RedAI/db"
)

// WebShell 三个工具必须进「拦截启用集」，理由分两类：
//
//   - webshell_add / webshell_remove：有内置 ask 规则（v7），不进集合规则永不命中；
//   - webshell_pivot_open：有内置 ask 规则（v8），同上；
//   - webshell_exec：它没有自己的 ask 规则，但必须被**全局的 tool_input 危险命令
//     规则**覆盖（mkfs / dd of=/dev/ / shred）。那些规则按入参文本匹配，不看工具名，
//     所以只要 tool 在启用集里就会命中——不在就是一条绕过 Bash 硬拦截的旁路。
//
// 这个守卫防的是「加了规则忘了加工具」：两者在代码里隔了两个包，最容易漏。
func TestWebShellToolsAreInterceptEnabled(t *testing.T) {
	want := []string{"webshell_add", "webshell_exec", "webshell_remove", "webshell_pivot_open"}
	have := map[string]bool{}
	for _, n := range defaultEnabledTools {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("defaultEnabledTools 缺少 %s：内置规则或全局危险命令规则将永远不命中", n)
		}
	}

	// 反向：只读/平台本地的动作不该进集合——每轮都会调，进了就是噪音。
	for _, n := range []string{
		"webshell_list", "webshell_payload_list", "webshell_payload_get",
		"webshell_download", "webshell_probe", "webshell_upload",
		"webshell_tunnel_script", "webshell_pivot_list", "webshell_pivot_close",
	} {
		if have[n] {
			t.Errorf("%s 不该进拦截启用集：只读或平台侧动作不该走审批", n)
		}
	}
}

// 全局危险命令规则必须能命中 webshell_exec 的入参形态。
//
// 这是「webshell_exec 不是 Bash，但要受同样的硬约束」这条设计的直接验证：
// 规则按 tool_input 匹配，而 webshell_exec 的入参是 {"name":..,"command":"mkfs /dev/sda"}。
func TestDangerousCommandRulesMatchWebShellExecInput(t *testing.T) {
	// 从内置规则里取 mkfs 那条，用 webshell_exec 的真实入参测试匹配。
	var mkfsRule *compiledRule
	builtin := builtinRulesForTest()
	for i := range builtin {
		if builtin[i].Pattern == `\bmkfs\b` {
			mkfsRule = &builtin[i]
			break
		}
	}
	if mkfsRule == nil {
		t.Fatal("找不到 mkfs 内置规则")
	}
	input := []byte(`{"name":"web-01","command":"mkfs.ext4 /dev/sda1"}`)
	if !ruleMatches(*mkfsRule, "webshell_exec", input) {
		t.Fatal("webshell_exec 入参里的 mkfs 未被危险命令规则命中——这是一条绕过 Bash 硬拦截的旁路")
	}
	// 批量 commands[] 形态同样要命中——不能因为命令挪到 commands 数组就绕过硬拦截。
	batchInput := []byte(`{"name":"web-01","commands":["whoami","mkfs.ext4 /dev/sda1"]}`)
	if !ruleMatches(*mkfsRule, "webshell_exec", batchInput) {
		t.Fatal("webshell_exec 批量入参里的 mkfs 未被危险命令规则命中——批量成了绕过 Bash 硬拦截的新旁路")
	}
	// 同一规则对普通命令不应误报。
	safe := []byte(`{"name":"web-01","command":"ls -la /var/www"}`)
	if ruleMatches(*mkfsRule, "webshell_exec", safe) {
		t.Fatal("普通命令被误判为危险命令")
	}
}

// builtinRulesForTest 把 db 包的内置规则编译成本包可直接匹配的形态。
//
// 不直接 import db 的编译逻辑（它在 db 包里是私有的），这里只取 pattern/target
// 并用同一套正则语义重建——守卫要在「规则文本 → 匹配行为」这一层成立，
// 而不是依赖 db 包的内部实现。
func builtinRulesForTest() []compiledRule {
	mk := func(target, pat string) compiledRule {
		return compiledRule{
			InterceptRule: db.InterceptRule{MatchTarget: target, MatchType: "regex", Pattern: pat},
			re:            regexp.MustCompile(pat),
		}
	}
	return []compiledRule{
		mk("tool_input", `\bmkfs\b`),
		mk("tool_input", `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`),
	}
}
