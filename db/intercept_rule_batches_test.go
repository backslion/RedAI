package db

// 内置拦截规则批次表的守卫（不需要数据库）。
//
// 声明式重构把 V1..V9 里逐份复制的「整批插入 → 按名补种 → 补 enabled 工具集」
// 收成了一张表。表与规则数据是两份东西，最容易出的错是：加了规则忘了配批次，
// 或者加了批次忘了把新工具补进 enabled 集合——两者都会让规则静默失效（不报错、
// 只是不拦），而这条链本身是安全边界，静默失效比报错危险得多。
//
// 所以这里把「表 ↔ 规则」的对应关系钉死。

import (
	"testing"
)

func TestBuiltinRuleBatchesCoverEveryRule(t *testing.T) {
	declared := map[string]builtinRuleBatch{}
	for _, b := range builtinRuleBatches {
		if _, dup := declared[b.batch]; dup {
			t.Errorf("批次 %q 在表里重复声明", b.batch)
		}
		declared[b.batch] = b
	}

	for _, r := range builtinInterceptRules {
		if _, ok := declared[r.seedBatch]; !ok {
			t.Errorf("规则 %q 的 seedBatch=%q 不在 builtinRuleBatches 里——这条规则永远不会被种入，且没有任何报错",
				r.name, r.seedBatch)
		}
	}

	// 反向也要查：声明了批次却没有任何规则属于它，说明拼写错了（seedBatch 与表不一致）。
	count := map[string]int{}
	for _, r := range builtinInterceptRules {
		count[r.seedBatch]++
	}
	for _, b := range builtinRuleBatches {
		if count[b.batch] == 0 {
			t.Errorf("批次 %q 声明在表里，但没有任何规则使用这个 seedBatch（多半是拼写不一致）", b.batch)
		}
	}
}

func TestBuiltinRuleBatchesOrderAndFlags(t *testing.T) {
	// 顺序即执行顺序：v1 → v9。重排会让「先有 v1 基础规则、再有后续补充」的前提失效。
	want := []string{"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"}
	if len(builtinRuleBatches) != len(want) {
		t.Fatalf("批次数量 %d，期望 %d（%v）", len(builtinRuleBatches), len(want), want)
	}
	for i, b := range builtinRuleBatches {
		if b.batch != want[i] {
			t.Errorf("第 %d 个批次是 %q，期望 %q（顺序被改动）", i, b.batch, want[i])
		}
	}

	// flag 是一次性完成标记：两个批次共用同一个 flag，后一个会永远早退。
	seen := map[string]string{}
	for _, b := range builtinRuleBatches {
		if b.flag == "" {
			t.Errorf("批次 %q 没有 flag", b.batch)
		}
		if prev, dup := seen[b.flag]; dup {
			t.Errorf("flag %q 被批次 %q 与 %q 共用", b.flag, prev, b.batch)
		}
		seen[b.flag] = b.batch
	}
}

// v4 的补种历史上按【规则名】过滤（"[内置] 启停回连接收器"），重构后统一按批次过滤。
// 两者等价的前提是 v4 批次里只有这一条规则——这里把它钉住，否则哪天给 v4 加了第二条，
// 行为就从「只补 listener」变成「补整个 v4」，属于静默的行为变更。
func TestBuiltinRuleBatchV4IsSingleRule(t *testing.T) {
	var names []string
	for _, r := range builtinInterceptRules {
		if r.seedBatch == "v4" {
			names = append(names, r.name)
		}
	}
	if len(names) != 1 {
		t.Fatalf("v4 批次应只有 1 条规则（按名补种与按批次补种等价的前提），实际 %d 条: %v", len(names), names)
	}
	if names[0] != "[内置] 启停回连接收器" {
		t.Fatalf("v4 唯一规则的名称变了：%q，需重新核对 V4 的补种语义", names[0])
	}
}

// 每个声明的补种批次都要能查到规则（reseed=true 但批次为空等于空转），
// 且补工具集的批次必须真的带工具名——否则「补了批次没补工具」会让 guard 的
// IsToolEnabled 把整条规则挡掉。
func TestBuiltinRuleBatchReseedConfig(t *testing.T) {
	count := map[string]int{}
	for _, r := range builtinInterceptRules {
		count[r.seedBatch]++
	}
	for _, b := range builtinRuleBatches {
		if b.reseed && count[b.batch] == 0 {
			t.Errorf("批次 %q 声明了 reseed，但没有规则，补种是空转", b.batch)
		}
		for _, tool := range b.ensureTools {
			if tool == "" {
				t.Errorf("批次 %q 的 ensureTools 里有空字符串", b.batch)
			}
		}
	}
}
