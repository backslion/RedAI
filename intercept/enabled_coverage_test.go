package intercept

// 「规则声明了、但工具不在拦截启用集」的通用守卫。
//
// 背景：guard 的判定顺序是 IsToolEnabled → Match。工具不在启用集里，规则写得
// 再对也永远不会被看到——这是**静默失效**：没有报错、没有日志，只是不拦。
//
// 这个坑已经踩过三次（pivot_open / webshell_pivot_open / pivot_deploy），
// 每次的形态都一样：
//   1. 在 builtinInterceptRules 里加一条 target=tool_name 的规则；
//   2. 在 builtinRuleBatches 里配 ensureTools ——**新库不生效**，因为
//      ensureInterceptToolsEnabled 只在 intercept_enabled_tools 设置已存在时
//      才 merge，而全新库根本没有这条设置；
//   3. 忘了同步 intercept.defaultEnabledTools（新库走的是这份硬编码集合）。
//
// 逐条硬编码的守卫（enabled_pivot_test.go 等）能挡住具体案例，但挡不住「下一
// 个新工具」。这里改成从声明表反向核对，新增规则/批次时自动生效。

import (
	"regexp"
	"testing"

	"github.com/chu0119/pojun/db"
)

func defaultEnabledSet() map[string]bool {
	m := make(map[string]bool, len(defaultEnabledTools))
	for _, n := range defaultEnabledTools {
		m[n] = true
	}
	return m
}

// 批次里声明的 ensureTools 必须同时在默认集合里。
func TestBatchEnsureToolsAreDefaultEnabled(t *testing.T) {
	set := defaultEnabledSet()
	for _, tool := range db.BuiltinEnsureTools() {
		if !set[tool] {
			t.Errorf("批次声明 ensureTools=%q，但它不在 intercept.defaultEnabledTools 里。"+
				"后果：全新库没有 intercept_enabled_tools 设置时走硬编码默认集合，"+
				"该工具的内置规则永远不会被匹配（静默失效）。", tool)
		}
	}
}

// 每条以工具名为作用对象的内置规则，其 pattern 必须至少匹配一个默认启用的工具。
//
// 只覆盖 target=tool_name 的规则：target=tool_input 的规则看的是入参文本，
// 与具体工具无关，硬套这条会误报。
func TestEveryToolNameRuleMatchesDefaultEnabled(t *testing.T) {
	tools := defaultEnabledTools
	for _, pattern := range db.BuiltinToolNamePatterns() {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Errorf("内置规则 pattern %q 编译失败: %v", pattern, err)
			continue
		}
		hit := ""
		for _, tool := range tools {
			if re.MatchString(tool) {
				hit = tool
				break
			}
		}
		if hit == "" {
			t.Errorf("内置规则 pattern=%q 在 defaultEnabledTools 里没有任何匹配项——"+
				"这条规则在全新库上永远不会被匹配。需要把目标工具加进 intercept.defaultEnabledTools。",
				pattern)
		}
	}
}

// 反向：默认集合里不该残留已删除工具名的拼写错误（拼错等于没启用）。
// 这里只检查「集合里的名字都非空且不像正则」，具体存在性无法在此断言
// （工具清单在 agent 包，会有循环依赖）。
func TestDefaultEnabledToolsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range defaultEnabledTools {
		if n == "" {
			t.Error("defaultEnabledTools 里出现空字符串")
		}
		if seen[n] {
			t.Errorf("defaultEnabledTools 里 %q 重复", n)
		}
		seen[n] = true
	}
}
