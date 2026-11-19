package agent

import (
	"context"
	"encoding/json"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// TestBuiltinToolSeeds ensures the catalog builds from a nil-store ToolSet without
// panicking, has stable keys, unions agent bindings, and carries real descriptions.
func TestBuiltinToolSeeds(t *testing.T) {
	seeds := BuiltinToolSeeds()
	if len(seeds) == 0 {
		t.Fatal("no seeds")
	}
	byKey := map[string]ToolSeed{}
	for _, s := range seeds {
		if s.Key == "" || s.Desc == "" {
			t.Errorf("seed %q missing key/desc", s.Key)
		}
		byKey[s.Key] = s
	}
	// record_fact is bound to worker (also mainagent, which can log confirmed facts).
	rf, ok := byKey["record_fact"]
	hasWorker := false
	for _, a := range rf.Agents {
		if a == "worker" {
			hasWorker = true
		}
	}
	if !ok || !hasWorker {
		t.Errorf("record_fact agents = %v, want to include worker", rf.Agents)
	}
	// add_task_scope is bound to the planner (deliberate scope widening).
	if ts, ok := byKey["add_task_scope"]; !ok || len(ts.Agents) == 0 {
		t.Errorf("add_task_scope not seeded / has no agent binding: %v", ts.Agents)
	}
	// SDK generic tools (incl. sleep, now part of DefaultTools) are deliberately NOT
	// seeded — every agent owns them; they flow through ToolResolve untouched.
	for _, k := range []string{"Bash", "Read", "Write", "Edit", "Grep", "sleep"} {
		if _, ok := byKey[k]; ok {
			t.Errorf("SDK tool %q should not be seeded", k)
		}
	}
}

// TestEverySeedHasAgentBinding 守住「加了工具但忘了绑 agent」。
//
// ToolResolve 对空绑定的工具按 agent 一律丢弃（defaultUnbound 是有意的空绑定，
// 当前为空表）。所以「新写了一个工具、忘了加进任何 agent 的工具集」在编译期完全
// 合法、运行期也绝不报错——只是模型永远看不到它。这类缺陷只能靠表级断言拦。
func TestEverySeedHasAgentBinding(t *testing.T) {
	for _, s := range BuiltinToolSeeds() {
		if defaultUnbound[s.Key] {
			continue
		}
		if len(s.Agents) == 0 {
			t.Errorf("工具 %q 没有任何 agent 绑定：模型不可见，等于没实现", s.Key)
		}
	}
}

// TestIntranetToolsReachWorker 守住内网纵深链路的工具可见性。
//
// 这些工具是「拿到立足点之后」唯一能继续推进的手段。worker 是真正执行意图的
// agent，一旦某个工具从 worker 的工具集里掉出去（重构、改名、漏注册），链路会
// 静默断在中间——planner 仍会照常派意图，worker 却发现没有工具可用。
func TestIntranetToolsReachWorker(t *testing.T) {
	byKey := map[string]ToolSeed{}
	for _, s := range BuiltinToolSeeds() {
		byKey[s.Key] = s
	}
	want := []string{
		// WebShell 通道
		"webshell_add", "webshell_list", "webshell_exec",
		"webshell_upload", "webshell_download", "webshell_probe", "webshell_remove",
		// WebShell 隧道（无 22 端口时的唯一入口）
		"webshell_tunnel_script", "webshell_pivot_open", "webshell_pivot_list", "webshell_pivot_close",
		// SSH pivot 与隧道编排
		"pivot_open", "pivot_list", "pivot_close", "pivot_probe",
		"pivot_plan", "pivot_deploy",
		// 反弹回连与文件投递
		"listener_start", "listener_stop", "stage_share",
		// 凭据复用（横向的前置）
		"record_credential", "list_credentials", "credential_reuse_matrix",
	}
	for _, k := range want {
		s, ok := byKey[k]
		if !ok {
			t.Errorf("内网工具 %q 未进目录", k)
			continue
		}
		hasWorker := false
		for _, a := range s.Agents {
			if a == "worker" {
				hasWorker = true
				break
			}
		}
		if !hasWorker {
			t.Errorf("内网工具 %q 未绑定 worker（当前 %v）", k, s.Agents)
		}
	}
}

// TestDecorateToolInjectsDefaults verifies a schema "default" fills a missing param
// before the underlying handler runs, and an explicitly-provided value is kept.
func TestDecorateToolInjectsDefaults(t *testing.T) {
	var seen map[string]any
	base := actool.Build(actool.Spec{
		Name: "probe", Description: "orig",
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			_ = json.Unmarshal(in, &seen)
			return actool.Text("ok"), nil
		},
	})
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"limit": map[string]any{"type": "integer", "description": "n", "default": float64(3)},
		"q":     map[string]any{"type": "string", "description": "query"},
	}}
	dec := DecorateTool(base, "new desc", schema)
	if dec.Description() != "new desc" {
		t.Errorf("description = %q", dec.Description())
	}

	// limit omitted → default 3 injected; q kept.
	if _, err := dec.Call(context.Background(), json.RawMessage(`{"q":"x"}`), nil); err != nil {
		t.Fatal(err)
	}
	if seen["limit"] != float64(3) || seen["q"] != "x" {
		t.Errorf("injected = %v, want limit=3 q=x", seen)
	}

	// limit provided → default does NOT override.
	if _, err := dec.Call(context.Background(), json.RawMessage(`{"limit":9}`), nil); err != nil {
		t.Fatal(err)
	}
	if seen["limit"] != float64(9) {
		t.Errorf("limit = %v, want 9 (no override)", seen["limit"])
	}
}
