package intercept

import "testing"

// pivot_open 必须进「拦截启用集」，否则内置规则「开启内网穿透隧道」形同虚设：
// guard 先过 IsToolEnabled 再 Match，工具不在集合里就直接放行，规则永远不会被看到。
//
// 这个守卫防的是「加了规则忘了加工具」——两者在代码里隔了两个包，最容易漏。
func TestPivotOpenIsInterceptEnabled(t *testing.T) {
	found := false
	for _, n := range defaultEnabledTools {
		if n == "pivot_open" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("defaultEnabledTools 缺少 pivot_open：内置 ask 规则将永远不会命中")
	}

	// 反向：只读/收缩暴露面的三个不该进集合——它们每轮都会调，进了就是噪音。
	for _, n := range []string{"pivot_list", "pivot_close", "pivot_probe"} {
		for _, e := range defaultEnabledTools {
			if e == n {
				t.Errorf("%s 不该进拦截启用集：只读或收缩暴露面的动作不该走审批", n)
			}
		}
	}
}
