package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chu0119/pojun/webshell"

	actool "github.com/Autumn-27/norma/tool"
)

// WebShell 工具绑定守卫。
//
// 这组工具的漏绑后果比 pivot 更隐蔽：worker 少了 webshell_add 会退回「自己
// curl 一句话马」，少了 webshell_remove 则马留在目标上没人管——两者都不会报错，
// 只会在复盘时表现为「有入口但说不清怎么来的」和「残留没清干净」。
//
// planner 只该看到台账（有哪些马、载荷可选哪些），登记/执行/清理都是有具体
// 目标与副作用的本体动作，属 worker 与人类。
func TestWebShellToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	all9 := []string{
		"webshell_payload_list", "webshell_payload_get",
		"webshell_add", "webshell_list", "webshell_exec",
		"webshell_upload", "webshell_download", "webshell_probe", "webshell_remove",
	}
	worker := names(ts.WorkerTools())
	main := names(ts.MainAgentTools())
	every := names(ts.AllDomainTools())
	planner := names(ts.PlannerTools())

	for _, n := range all9 {
		if !worker[n] {
			t.Errorf("worker 未绑定 %s——落马后无法复用/复查，会退回手工 curl", n)
		}
		if !main[n] {
			t.Errorf("mainagent 未绑定 %s——人在环路上无法登记或清理入口", n)
		}
		if !every[n] {
			t.Errorf("AllDomainTools 缺少 %s——Auto/自定义 agent 拿不到", n)
		}
		if defaultUnbound[n] {
			t.Errorf("%s 被列入 defaultUnbound，运行时会被静默丢弃", n)
		}
	}

	// planner 只读台账。
	if !planner["webshell_list"] || !planner["webshell_payload_list"] {
		t.Error("planner 应能 webshell_list / webshell_payload_list：规划要看「已有几个入口、能落什么马」")
	}
	for _, n := range []string{"webshell_add", "webshell_exec", "webshell_upload", "webshell_download", "webshell_probe", "webshell_remove", "webshell_payload_get"} {
		if planner[n] {
			t.Errorf("planner 不该有 %s：登记/执行/传文件/清理都是有目标与本体的动作", n)
		}
	}
}

// 独立 pentest agent 没有 planner 兜底，九件必须齐。
func TestWebShellToolsInPentestCatalog(t *testing.T) {
	tools, ok := builtinToolsByAgent()["pentest"]
	if !ok {
		t.Fatal("pentest 目录不存在")
	}
	have := map[string]bool{}
	for _, tl := range tools {
		have[tl.Name()] = true
	}
	for _, n := range []string{
		"webshell_payload_list", "webshell_payload_get", "webshell_add", "webshell_list",
		"webshell_exec", "webshell_upload", "webshell_download", "webshell_probe", "webshell_remove",
	} {
		if !have[n] {
			t.Errorf("pentest 独立 agent 缺少 %s：没有 planner 派意图时只能自己闭环", n)
		}
	}
}

// schema 守卫：required 字段必须存在且类型合理。
func TestWebShellToolSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	cases := []struct {
		tool     actool.CoreTool
		required []string
	}{
		{ts.webshellPayloadList(), nil},
		{ts.webshellPayloadGet(), []string{"name"}},
		{ts.webshellAdd(), []string{"url", "type"}},
		{ts.webshellList(), nil},
		{ts.webshellExec(), []string{"name"}},
		{ts.webshellUpload(), []string{"name", "remote_path"}},
		{ts.webshellDownload(), []string{"name", "remote_path"}},
		{ts.webshellProbe(), nil},
		{ts.webshellRemove(), []string{"name"}},
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

// 布尔字段必须是真布尔：写成 {"type":"string"} 会让模型把 "true" 当字符串传，
// 服务端 json.Unmarshal 到 bool 直接失败。
func TestWebShellBooleanSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	checks := []struct {
		tool  actool.CoreTool
		field string
	}{
		{ts.webshellAdd(), "proxy_rotate"},
		{ts.webshellAdd(), "overwrite"},
		{ts.webshellProbe(), "deep"},
		{ts.webshellRemove(), "remove_remote"},
		{ts.webshellRemove(), "force"},
	}
	for _, c := range checks {
		sc := c.tool.InputSchema()
		props, _ := sc["properties"].(map[string]any)
		f, ok := props[c.field].(map[string]any)
		if !ok {
			t.Errorf("%s 缺字段 %s", c.tool.Name(), c.field)
			continue
		}
		if f["type"] != "boolean" {
			t.Errorf("%s.%s 类型 = %v，应为 boolean", c.tool.Name(), c.field, f["type"])
		}
	}
}

// 未注入 manager 时给出可读错误，而不是 panic。
func TestWebShellToolsWithoutManager(t *testing.T) {
	old := defaultRuntimeSnapshot().WebShell
	setDefaultRuntime(func(r *Runtime) { r.WebShell = nil })
	defer func() { setDefaultRuntime(func(r *Runtime) { r.WebShell = old }) }()

	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"name": "x", "command": "id"})
	res, err := ts.webshellExec().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("不应返回 error（应由工具结果表达）: %v", err)
	}
	if !strings.Contains(res.Flatten(), "未启用") {
		t.Fatalf("错误应说明未启用，实际 %q", res.Flatten())
	}
}

// 跨任务隔离：worker 只能看到自己任务登记的会话。
func TestWebShellListIsTaskScoped(t *testing.T) {
	old := defaultRuntimeSnapshot().WebShell
	m, err := webshell.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	setDefaultRuntime(func(r *Runtime) { r.WebShell = m })
	defer func() { setDefaultRuntime(func(r *Runtime) { r.WebShell = old }) }()

	if _, err := m.Add(webshell.AddOptions{
		Name: "mine", URL: "http://10.0.0.1/x.php", Type: "php", Param: "p", TaskID: 7,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(webshell.AddOptions{
		Name: "other", URL: "http://10.0.0.2/x.php", Type: "php", Param: "p", TaskID: 8,
	}); err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(nil, "")
	ts.taskID = 7
	res, err := ts.webshellList().Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	if !strings.Contains(out, "mine") {
		t.Fatalf("看不到自己的会话: %s", out)
	}
	if strings.Contains(out, "other") {
		t.Fatalf("看到了别的任务的会话（越权）: %s", out)
	}
}

// 登记时 proxy 非法要在本地拦住，不要等到执行时才发现。
func TestWebShellAddRejectsBadProxy(t *testing.T) {
	old := defaultRuntimeSnapshot().WebShell
	m, err := webshell.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	setDefaultRuntime(func(r *Runtime) { r.WebShell = m })
	defer func() { setDefaultRuntime(func(r *Runtime) { r.WebShell = old }) }()

	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{
		"url": "http://10.0.0.1/x.php", "type": "php", "proxy": "ftp://a:1",
	})
	res, err := ts.webshellAdd().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("不应返回 error: %v", err)
	}
	if !strings.Contains(res.Flatten(), "代理") {
		t.Fatalf("应拒绝非法代理，实际 %q", res.Flatten())
	}
	if len(m.List(0)) != 0 {
		t.Fatal("非法代理不该落库")
	}
}

// payload_get 必须把占位符换成实际参数名，否则落地的马用不了。
func TestWebShellPayloadGetRenders(t *testing.T) {
	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"name": "builtin/php-eval", "param": "zz9"})
	res, err := ts.webshellPayloadGet().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	if !strings.Contains(out, "zz9") {
		t.Fatalf("参数名没渲染进去: %s", out)
	}
	if strings.Contains(out, webshell.ParamPlaceholder) {
		t.Fatal("占位符没被替换")
	}
}
