package webshell

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExecBatchEvalStructured(t *testing.T) {
	m := newTestManager(t)
	f := newFakeShell()
	srv, url := startFake(t, f)
	_ = srv
	addSession(t, m, "ws", url, "php", "p")

	cmds := []string{"id", "uname -a", "whoami"}
	results, err := m.ExecBatch(context.Background(), "ws", "", cmds, 5*time.Second)
	if err != nil {
		t.Fatalf("ExecBatch: %v", err)
	}
	if len(results) != len(cmds) {
		t.Fatalf("got %d results want %d", len(results), len(cmds))
	}
	for i, r := range results {
		if !r.OK || r.Index != i || r.Command != cmds[i] {
			t.Errorf("result %d bad: %+v", i, r)
		}
		if r.ExitCode != 0 {
			t.Errorf("eval result %d exit_code=%d want 0", i, r.ExitCode)
		}
		if !strings.Contains(r.Output, cmds[i]) {
			t.Errorf("result %d output %q missing command", i, r.Output)
		}
	}
}

func TestExecBatchLimits(t *testing.T) {
	m := newTestManager(t)
	f := newFakeShell()
	_, url := startFake(t, f)
	addSession(t, m, "ws", url, "php", "p")

	if _, err := m.ExecBatch(context.Background(), "ws", "", nil, 0); err == nil {
		t.Fatal("empty batch should fail")
	}
	many := make([]string, MaxBatchCommands+1)
	for i := range many {
		many[i] = "echo x"
	}
	if _, err := m.ExecBatch(context.Background(), "ws", "", many, 0); err == nil {
		t.Fatal("oversized batch should fail")
	}
}

func TestExecBatchCmdTypeDegradesNoExitCode(t *testing.T) {
	m := newTestManager(t)
	f := newFakeShell()
	_, url := startFake(t, f)
	addSession(t, m, "jspws", url, "jsp", "p")

	results, err := m.ExecBatch(context.Background(), "jspws", "", []string{"id", "whoami"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		// 命令型马拿不到退出码，必须如实报 -1，不能编造 0。
		if r.ExitCode != -1 {
			t.Errorf("cmd-type result %d exit_code=%d want -1", i, r.ExitCode)
		}
		if !r.OK {
			t.Errorf("cmd-type result %d not ok: %+v", i, r)
		}
	}
}

func TestBatchResultJSONShape(t *testing.T) {
	// 结构化结果的字段名是工具契约的一部分，钉住防止回归。
	b, _ := json.Marshal(BatchResult{Index: 1, Command: "id", OK: true, Output: "uid=0", ExitCode: 0, Mode: "eval"})
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"index", "command", "ok", "output", "exit_code", "mode"} {
		if _, ok := m[k]; !ok {
			t.Errorf("BatchResult JSON 缺字段 %q", k)
		}
	}
}
