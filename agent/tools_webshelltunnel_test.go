package agent

// WebShell 隧道工具绑定守卫。漏绑的后果：worker 遇到「只有马、没开 22」的目标
// 时没有替代 pivot 的手段，横向就断在验证一跳——这正是本工具要解的卡点。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/backslion/RedAI/webshell"

	actool "github.com/Autumn-27/norma/tool"
)

func TestWebShellTunnelToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	all := []string{
		"webshell_tunnel_script", "webshell_pivot_open", "webshell_pivot_list", "webshell_pivot_close",
	}
	worker := names(ts.WorkerTools())
	main := names(ts.MainAgentTools())
	every := names(ts.AllDomainTools())
	planner := names(ts.PlannerTools())

	for _, n := range all {
		if !worker[n] || !main[n] || !every[n] {
			t.Errorf("worker/main/AllDomain 未绑定 %s：只有马没 22 时无法开 SOCKS5", n)
		}
		if defaultUnbound[n] {
			t.Errorf("%s 被列入 defaultUnbound，运行时会被静默丢弃", n)
		}
	}
	// planner 只读台账：开隧道是执行动作，属 worker 与人类。
	if !planner["webshell_pivot_list"] {
		t.Error("planner 应能 webshell_pivot_list（知道哪些目标已有内网出口）")
	}
	for _, n := range []string{"webshell_tunnel_script", "webshell_pivot_open", "webshell_pivot_close"} {
		if planner[n] {
			t.Errorf("planner 不该有 %s：开/关隧道是有副作用的执行动作", n)
		}
	}
}

func TestWebShellTunnelToolsInPentestCatalog(t *testing.T) {
	tools, ok := builtinToolsByAgent()["pentest"]
	if !ok {
		t.Fatal("pentest 目录不存在")
	}
	have := map[string]bool{}
	for _, tl := range tools {
		have[tl.Name()] = true
	}
	for _, n := range []string{
		"webshell_tunnel_script", "webshell_pivot_open", "webshell_pivot_list", "webshell_pivot_close",
	} {
		if !have[n] {
			t.Errorf("pentest 独立 agent 缺少 %s", n)
		}
	}
}

func TestWebShellTunnelToolSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	cases := []struct {
		tool     actool.CoreTool
		required []string
	}{
		{ts.webshellTunnelScript(), nil},
		{ts.webshellPivotOpen(), []string{"name", "tunnel_url", "token"}},
		{ts.webshellPivotList(), nil},
		{ts.webshellPivotClose(), []string{"id"}},
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
				t.Errorf("%s schema 缺 required 字段 %q", c.tool.Name(), r)
			}
		}
	}
}

func TestWebShellTunnelScriptTool(t *testing.T) {
	dir := t.TempDir()
	mgr, err := webshell.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldSnap := defaultRuntimeSnapshot()
	SetWebShellManager(mgr)
	SetWebShellTunnelManager(webshell.NewTunnelManager(mgr))
	defer func() {
		setDefaultRuntime(func(r *Runtime) { r.WebShell = oldSnap.WebShell; r.WebShellTunnel = oldSnap.WebShellTunnel })
	}()

	ts := NewToolSet(nil, "worker")
	ts.SetTaskID(1)
	res, err := ts.webshellTunnelScript().Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	// JSON 里的 < 会被 MarshalIndent 转成 \u003c，所以不断言 "<?php" 字面串，
	// 只断言 token 既在顶层又嵌进了脚本（浅校验一致）。
	if !strings.Contains(out, `"token"`) || !strings.Contains(out, `"script"`) {
		t.Fatalf("script tool 输出缺 token/script: %s", out)
	}
	// token 必须是脚本里嵌入的那个（浅校验一致）。
	var parsed struct {
		Token  string `json:"token"`
		Script string `json:"script"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Token == "" || !strings.Contains(parsed.Script, parsed.Token) {
		t.Fatal("token 未嵌入脚本，open 时会校验失败")
	}
}
