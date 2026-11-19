package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/backslion/RedAI/metrics"
)

// fakeTool 用 actool.Build 造一个行为可控的最小工具。
func fakeTool(name string, run func() (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:   name,
		Schema: map[string]any{"type": "object", "properties": map[string]any{}},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return run()
		},
	})
}

func renderMetrics(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := metrics.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

// 工具埋点是所有 agent 的唯一收口，三种结局必须分得开：
// 正常返回、工具自报错误（IsError）、panic 被兜住。
func TestGuardedToolRecordsOutcomes(t *testing.T) {
	metrics.Default.Reset()
	ctx := context.Background()

	cases := []struct {
		name    string
		tool    string
		run     func() (actool.Result, error)
		outcome string
	}{
		{"ok", "pojun_fake_ok", func() (actool.Result, error) { return actool.Text("done"), nil }, "ok"},
		{"self-reported error", "pojun_fake_err", func() (actool.Result, error) { return actool.Errorf("boom"), nil }, "error"},
		{"panic", "pojun_fake_panic", func() (actool.Result, error) { panic("kaboom") }, "panic"},
	}
	for _, c := range cases {
		g := guardPanic(fakeTool(c.tool, c.run))
		res, err := g.Call(ctx, json.RawMessage(`{}`), nil)
		if err != nil {
			t.Fatalf("%s: 不应返回 error（应由结果表达）: %v", c.name, err)
		}
		if c.outcome == "panic" && !res.IsError {
			t.Errorf("%s: panic 必须转成 IsError 结果", c.name)
		}
	}

	out := renderMetrics(t)
	for _, c := range cases {
		want := `pojun_tool_calls_total{tool="` + c.tool + `",result="` + c.outcome + `"} 1`
		if !strings.Contains(out, want) {
			t.Errorf("缺 %q:\n%s", want, out)
		}
		if !strings.Contains(out, `pojun_tool_duration_seconds_count{tool="`+c.tool+`"} 1`) {
			t.Errorf("%s 未记录耗时:\n%s", c.tool, out)
		}
	}
}

// 埋点不能吞掉返回值：包装前后的结果内容必须一致。
func TestGuardedToolPassesResultThrough(t *testing.T) {
	g := guardPanic(fakeTool("pojun_fake_passthrough", func() (actool.Result, error) {
		return actool.Text("原始内容不被改动"), nil
	}))
	res, err := g.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(res.Flatten(), "原始内容不被改动") {
		t.Errorf("结果被埋点改动了: %q", res.Flatten())
	}
}
