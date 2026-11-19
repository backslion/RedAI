package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/backslion/RedAI/pivot"

	actool "github.com/Autumn-27/norma/tool"
)

// pivot 工具的绑定守卫。
//
// 漏绑的后果分两种，都很隐蔽：
//   - worker 缺 pivot_open/probe：模型会退回「让用户自己开隧道」，横向链断在
//     验证完那一跳，能力看起来有、实际用不上。
//   - worker 缺 pivot_close：隧道开了关不掉，TTL 到点前一直是开放入口。
//
// planner 只该有 pivot_list（知道有哪些出口以便规划），不该有开关能力。
func TestPivotToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	execTools := []string{"pivot_open", "pivot_list", "pivot_close", "pivot_probe"}
	worker, main, all, planner := names(ts.WorkerTools()), names(ts.MainAgentTools()), names(ts.AllDomainTools()), names(ts.PlannerTools())

	for _, n := range execTools {
		if !worker[n] {
			t.Errorf("worker 未绑定 %s——横向链在「验证完凭据」这一步断掉", n)
		}
		if !main[n] {
			t.Errorf("mainagent 未绑定 %s——人在环路上无法开/关隧道", n)
		}
		if !all[n] {
			t.Errorf("AllDomainTools 缺少 %s——Auto/自定义 agent 拿不到", n)
		}
		if defaultUnbound[n] {
			t.Errorf("%s 被列入 defaultUnbound，运行时会被静默丢弃", n)
		}
	}
	if !planner["pivot_list"] {
		t.Error("planner 应能 pivot_list：规划时要看「已有哪些出口、能到哪些网段」")
	}
	for _, n := range []string{"pivot_open", "pivot_close", "pivot_probe"} {
		if planner[n] {
			t.Errorf("planner 不该有 %s：开/关隧道与经隧道探测都是有具体目标的执行动作", n)
		}
	}
}

func TestPivotToolsInPentestCatalog(t *testing.T) {
	tools, ok := builtinToolsByAgent()["pentest"]
	if !ok {
		t.Fatal("pentest 目录不存在")
	}
	have := map[string]bool{}
	for _, tl := range tools {
		have[tl.Name()] = true
	}
	for _, n := range []string{"pivot_open", "pivot_list", "pivot_close", "pivot_probe"} {
		if !have[n] {
			t.Errorf("pentest 独立 agent 缺少 %s：没有 planner 兜底时，横向只能自己闭环", n)
		}
	}
}

// schema 守卫：required 里的字段必须真的在 properties 里，否则模型按 schema
// 填参会被服务端拒绝，表现成「工具总是报参数错」。
func TestPivotToolSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	cases := []struct {
		tool     actool.CoreTool
		required []string
	}{
		{ts.pivotOpen(), []string{"hops"}},
		{ts.pivotProbe(), []string{"pivot_id", "hosts"}},
		{ts.pivotList(), nil},
		{ts.pivotClose(), nil},
	}
	for _, c := range cases {
		sc := c.tool.InputSchema()
		if sc["type"] != "object" {
			t.Errorf("%s schema 顶层不是 object", c.tool.Name())
			continue
		}
		props, _ := sc["properties"].(map[string]any)
		if props == nil {
			t.Errorf("%s schema 没有 properties", c.tool.Name())
			continue
		}
		for _, r := range c.required {
			if _, ok := props[r]; !ok {
				t.Errorf("%s 的 required 字段 %q 不在 properties 里", c.tool.Name(), r)
			}
		}
	}
}

// 未注入 manager 时必须给出可读错误，而不是 panic 或返回成功。
func TestPivotToolsWithoutManager(t *testing.T) {
	old := defaultRuntimeSnapshot().Pivot
	setDefaultRuntime(func(r *Runtime) { r.Pivot = nil })
	defer func() { setDefaultRuntime(func(r *Runtime) { r.Pivot = old }) }()

	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{
		"hops": []map[string]any{{"addr": "10.0.0.9:22", "username": "u", "password": "p"}},
	})
	res, err := ts.pivotOpen().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("不应返回 error（应由工具结果表达）: %v", err)
	}
	if !strings.Contains(res.Flatten(), "未启用") {
		t.Fatalf("错误应说明未启用，实际 %q", res.Flatten())
	}
}

// 参数校验：缺跳板、缺凭据、缺端口都要在本地拦住，不要白建 TCP 连接。
func TestPivotOpenValidation(t *testing.T) {
	old := defaultRuntimeSnapshot().Pivot
	pm := pivot.NewManager()
	setDefaultRuntime(func(r *Runtime) { r.Pivot = pm })
	defer func() {
		pm.CloseAll()
		setDefaultRuntime(func(r *Runtime) { r.Pivot = old })
	}()

	ts := NewToolSet(nil, "")
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"空跳板", map[string]any{}, "hops 不能为空"},
		{"缺凭据", map[string]any{"hops": []map[string]any{{"addr": "10.0.0.9:22", "username": "u"}}}, "没有可用凭据"},
		{"缺用户名", map[string]any{"hops": []map[string]any{{"addr": "10.0.0.9:22", "password": "p"}}}, "缺少 username"},
		{"portfwd 缺目标", map[string]any{
			"mode": "portfwd",
			"hops": []map[string]any{{"addr": "10.0.0.9:22", "username": "u", "password": "p"}},
		}, "必须给 target"},
	}
	for _, c := range cases {
		in, _ := json.Marshal(c.body)
		res, err := ts.pivotOpen().Call(context.Background(), in, nil)
		if err != nil {
			t.Errorf("%s: 不应返回 error: %v", c.name, err)
			continue
		}
		if !strings.Contains(res.Flatten(), c.want) {
			t.Errorf("%s: 应含 %q，实际 %q", c.name, c.want, res.Flatten())
		}
	}
}

// 关闭时不能越权操作别的任务的隧道。
func TestPivotCloseRejectsForeignTunnel(t *testing.T) {
	old := defaultRuntimeSnapshot().Pivot
	pm := pivot.NewManager()
	setDefaultRuntime(func(r *Runtime) { r.Pivot = pm })
	defer func() {
		pm.CloseAll()
		setDefaultRuntime(func(r *Runtime) { r.Pivot = old })
	}()

	// 手工塞一条属于任务 99 的隧道（不需要真实链路，只验证归属判断）。
	tun := &pivot.Tunnel{ID: "pv-foreign", TaskID: 99, Mode: pivot.ModeSocks, Alive: true}
	pm.InjectForTest(tun)

	ts := NewToolSet(nil, "")
	ts.taskID = 7
	in, _ := json.Marshal(map[string]any{"id": "pv-foreign"})
	res, err := ts.pivotClose().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("不应返回 error: %v", err)
	}
	if !strings.Contains(res.Flatten(), "不是当前任务") {
		t.Fatalf("应拒绝跨任务关闭，实际 %q", res.Flatten())
	}
	if _, ok := pm.Get("pv-foreign"); !ok {
		t.Fatal("拒绝后隧道不应被关闭")
	}
}
