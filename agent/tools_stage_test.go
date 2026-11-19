package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chu0119/pojun/stage"

	actool "github.com/Autumn-27/norma/tool"
)

// 受管投递工具的绑定守卫：漏绑的表现是「模型手上明明有 payload 却送不到目标机，
// 只能退回去让用户自己传」。worker 必须能投，mainagent 必须能手投；planner 刻意
// 不给——规划阶段不产生文件，也不该自己往目标机送东西。
func TestStageToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	for _, n := range []string{"stage_share", "stage_list"} {
		if !names(ts.WorkerTools())[n] {
			t.Errorf("worker 未绑定 %s——执行侧无法把 payload 投递到目标", n)
		}
		if !names(ts.MainAgentTools())[n] {
			t.Errorf("mainagent 未绑定 %s——人在环路上无法手工投递", n)
		}
		if !names(ts.AllDomainTools())[n] {
			t.Errorf("AllDomainTools 缺少 %s——Auto/自定义 agent 拿不到", n)
		}
		if names(ts.PlannerTools())[n] {
			t.Errorf("planner 不该有 %s：规划阶段不产生文件，投递是执行动作", n)
		}
		if defaultUnbound[n] {
			t.Errorf("%s 被列入 defaultUnbound，运行时会被静默丢弃", n)
		}
	}
}

// pentest 独立 agent 没有 planner 兜底，必须默认绑上投递能力。
func TestStageToolsInPentestCatalog(t *testing.T) {
	var have map[string]bool
	if tools, ok := builtinToolsByAgent()["pentest"]; ok {
		have = map[string]bool{}
		for _, tl := range tools {
			have[tl.Name()] = true
		}
	}
	for _, n := range []string{"stage_share", "stage_list"} {
		if !have[n] {
			t.Errorf("pentest 默认绑定缺少 %s", n)
		}
	}
}

func TestStageToolSchemas(t *testing.T) {
	ts := NewToolSet(nil, "")
	for _, tl := range []actool.CoreTool{ts.stageShare(), ts.stageListTool()} {
		if strings.TrimSpace(tl.Description()) == "" {
			t.Errorf("%s 描述为空", tl.Name())
		}
		sc := tl.InputSchema()
		if sc["type"] != "object" {
			t.Errorf("%s schema.type = %v", tl.Name(), sc["type"])
		}
		props, _ := sc["properties"].(map[string]any)
		if req, ok := sc["required"].([]any); ok {
			for _, r := range req {
				if name, _ := r.(string); name != "" {
					if _, exists := props[name]; !exists {
						t.Errorf("%s required %q 不在 properties 里", tl.Name(), name)
					}
				}
			}
		}
	}
}

// 端到端：注入真 manager → 投递工作区文件 → 返回可下载 URL 且任务归属来自 RunInfo。
func TestStageShareToolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m, err := stage.New(context.Background(), filepath.Join(dir, "stage"))
	if err != nil {
		t.Fatalf("stage.New: %v", err)
	}
	t.Cleanup(m.Close)
	prev := defaultRuntimeSnapshot().Stage
	SetStageManager(m)
	t.Cleanup(func() { SetStageManager(prev) })

	src := filepath.Join(dir, "agent.bin")
	if err := os.WriteFile(src, []byte("payload-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"path": src, "one_shot": true, "ttl_minutes": 5})
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 99, Kind: KindWorker})
	res, err := ts.stageShare().Call(ctx, in, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var out struct {
		URL     string `json:"url"`
		Expires string `json:"expires_at"`
		OneShot bool   `json:"one_shot"`
		Size    int64  `json:"size"`
		TaskID  int64  `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode %q: %v", res.Flatten(), err)
	}
	if !strings.Contains(out.URL, "/s/") {
		t.Fatalf("url = %q", out.URL)
	}
	if out.Size != int64(len("payload-bytes")) || !out.OneShot || out.Expires == "" {
		t.Fatalf("entry fields = %+v", out)
	}
	if out.TaskID != 99 {
		t.Fatalf("task_id = %d, want 99（必须来自 RunInfo，不接受模型传参）", out.TaskID)
	}
	// list 用 task_only 过滤：本任务看得到，别的任务看不到。
	listIn, _ := json.Marshal(map[string]any{"task_only": true})
	res, err = ts.stageListTool().Call(ctx, listIn, nil)
	if err != nil {
		t.Fatalf("list run: %v", err)
	}
	if !strings.Contains(res.Flatten(), "agent.bin") {
		t.Fatalf("list 未包含刚投递的条目: %s", res.Flatten())
	}
	otherCtx := WithRunInfo(context.Background(), RunInfo{TaskID: 100, Kind: KindWorker})
	res, _ = ts.stageListTool().Call(otherCtx, listIn, nil)
	if strings.Contains(res.Flatten(), "agent.bin") {
		t.Fatalf("跨任务不该看到别人的投递条目: %s", res.Flatten())
	}
}

// 未注入 manager 时必须是「明确不可用」而不是 panic：部署时关掉暂存是正常配置。
func TestStageShareDisabled(t *testing.T) {
	prev := defaultRuntimeSnapshot().Stage
	SetStageManager(nil)
	t.Cleanup(func() { SetStageManager(prev) })
	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"path": "/nonexistent"})
	res, err := ts.stageShare().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Flatten(), "未启用") {
		t.Fatalf("期望明确提示未启用，got %q", res.Flatten())
	}
}
