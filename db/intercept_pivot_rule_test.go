package db

import (
	"regexp"
	"testing"
)

// 内置规则「开启内网穿透隧道」的匹配面必须是「只拦 open」。
//
// 拦多了（比如把 pivot_close 也拦）会让关隧道这件安全动作走审批——恰恰在最需要
// 立刻止血的时候卡住；拦少了（只写 pivot 前缀）会把只读的 pivot_list 也拖进审批。
func TestPivotRuleMatchesOnlyOpen(t *testing.T) {
	pat := builtinRulePattern("[内置] 开启内网穿透隧道")
	if pat == "" {
		t.Fatal("内置规则「开启内网穿透隧道」不存在")
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("规则正则非法: %v", err)
	}
	if !re.MatchString("pivot_open") {
		t.Fatalf("%q 应匹配 pivot_open", pat)
	}
	for _, n := range []string{"pivot_list", "pivot_close", "pivot_probe", "pivot_open_extra"} {
		if re.MatchString(n) {
			t.Errorf("%q 不该匹配 %s", pat, n)
		}
	}
}

// 规则本身必须是 ask + 超时放行：无人值守时不能把整条横向链卡死。
func TestPivotRuleShape(t *testing.T) {
	for _, r := range builtinInterceptRules {
		if r.name != "[内置] 开启内网穿透隧道" {
			continue
		}
		if r.action != "ask" {
			t.Errorf("action 应为 ask，实际 %s", r.action)
		}
		if r.target != "tool_name" {
			t.Errorf("target 应为 tool_name，实际 %s", r.target)
		}
		if !r.timeoutEnabled || r.timeoutAction != "allow" {
			t.Errorf("必须有超时放行策略（否则人不在时隧道永远开不起来）: enabled=%v action=%s",
				r.timeoutEnabled, r.timeoutAction)
		}
		if r.timeoutSeconds <= 0 || r.timeoutSeconds > 600 {
			t.Errorf("超时时长应在 (0,600] 秒，实际 %d", r.timeoutSeconds)
		}
		return
	}
	t.Fatal("规则不存在")
}
