package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 知识库工具的绑定守卫（v0.5.x）：漏绑的表现是「模型不会去查资料」，
// 代码评审看不出，实战里表现为凭空编造方法论，所以写成断言。
func TestKnowledgeToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	want := []string{"knowledge_search", "knowledge_add", "knowledge_list"}

	worker := names(ts.WorkerTools())
	for _, n := range want {
		if !worker[n] {
			t.Errorf("worker 未绑定 %s——执行侧查不到甲方资料，只能凭想象", n)
		}
	}
	planner := names(ts.PlannerTools())
	for _, n := range want {
		if !planner[n] {
			t.Errorf("planner 未绑定 %s——规划阶段不该凭空派意图", n)
		}
	}
	main := names(ts.MainAgentTools())
	for _, n := range want {
		if !main[n] {
			t.Errorf("mainagent 未绑定 %s——人在环路上查不到资料", n)
		}
	}
	all := names(ts.AllDomainTools())
	for _, n := range want {
		if !all[n] {
			t.Errorf("AllDomainTools 缺少 %s——Auto/自定义 agent 拿不到", n)
		}
	}
}

// 知识库工具不得出现在「默认不给」名单里：那条通道是给需要人工审批的
// 破坏性工具的，误加会让工具在运行时被静默丢弃。
func TestKnowledgeToolsNotUnboundByDefault(t *testing.T) {
	for _, n := range []string{"knowledge_search", "knowledge_add", "knowledge_list"} {
		if defaultUnbound[n] {
			t.Errorf("%s 被列入 defaultUnbound，运行时会被丢弃", n)
		}
	}
}

// 三个工具必须有非空描述与 object schema：空 required 字段名会让模型调用报错，
// 在 tools_ported_test 里已有同类守卫，这里只覆盖新增工具。
func TestKnowledgeToolSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	for _, tl := range append(ts.WorkerTools(), ts.PlannerTools()...) {
		switch tl.Name() {
		case "knowledge_search", "knowledge_add", "knowledge_list":
			if tl.Description() == "" {
				t.Errorf("%s 描述为空", tl.Name())
			}
			if tl.InputSchema() == nil {
				t.Errorf("%s schema 为空", tl.Name())
			}
		}
	}
}
