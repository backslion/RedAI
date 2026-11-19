package intercept

// 网段扩权闸门的测试。
//
// 分两层：
//   - 纯函数层（scopeCandidates / ipFromToken）：不需要数据库，覆盖「误杀」和
//     「漏判」这两个真实风险点。
//   - 闸门层（ScopeGate）：需要真实 PostgreSQL（与 db 包测试同样的约定：没有
//     数据库就 skip，不假造一个内存库——那会掩盖 SQL 语义差异）。

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/backslion/RedAI/db"
)

// --- 纯函数层 ---

func TestIPFromToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"10.20.30.40", "10.20.30.40"},
		{" 10.20.30.40 ", "10.20.30.40"},
		{`"10.20.30.40"`, "10.20.30.40"},
		{"10.20.30.40:8080", "10.20.30.40"},
		{"http://10.20.30.40/x?a=1", "10.20.30.40"},
		{"https://10.20.30.40:8443/", "10.20.30.40"},
		{"10.20.30.0/24", "10.20.30.0"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		// 不该被当成目标的：域名、自由文本、版本号
		{"example.com", ""},
		{"api.example.com:443", ""},
		{"see 10.20.30.40 for details", ""},
		{"1.2.3.4.5", ""},
		{"", ""},
		{"999.1.1.1", ""},
	}
	for _, c := range cases {
		if got := ipFromToken(c.in); got != c.want {
			t.Errorf("ipFromToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScopeCandidatesCommandMode(t *testing.T) {
	// 命令类工具：IP 嵌在命令串里，必须抠出来。
	got := scopeCandidates("Bash", []byte(`{"command":"nmap -p80,443 10.20.30.0/24 --script=x 1.2.3.4"}`))
	if len(got) != 2 {
		t.Fatalf("Bash 应抠出 2 个地址，实际 %v", got)
	}
	if got[0] != "10.20.30.0" || got[1] != "1.2.3.4" {
		t.Errorf("抠出的地址不符合预期: %v", got)
	}
}

func TestScopeCandidatesStructuredModeIgnoresProse(t *testing.T) {
	// 结构化工具：只认「本身就是一个地址」的字符串。Write 正文里提到 IP 不算访问目标，
	// 否则写一份报告就会被拦下来。
	got := scopeCandidates("Write", []byte(`{"path":"a.md","content":"目标 10.20.30.40 开放 80 端口"}`))
	if len(got) != 0 {
		t.Fatalf("Write 正文里的 IP 不该被当作访问目标，实际 %v", got)
	}
	// 但结构化字段里明确给了目标，就要认。
	got = scopeCandidates("pivot_deploy", []byte(`{"kind":"ssh","host":"10.20.30.40","port":22}`))
	if len(got) != 1 || got[0] != "10.20.30.40" {
		t.Fatalf("pivot_deploy 的 host 应被识别，实际 %v", got)
	}
}

func TestScopeCandidatesNonJSON(t *testing.T) {
	got := scopeCandidates("Bash", []byte("curl http://10.20.30.40/x"))
	if len(got) != 1 || got[0] != "10.20.30.40" {
		t.Fatalf("非 JSON 输入应按自由文本处理，实际 %v", got)
	}
}

func TestScopeCandidatesDedup(t *testing.T) {
	got := scopeCandidates("Bash", []byte(`{"command":"curl 10.0.0.5 && curl 10.0.0.5:8080"}`))
	if len(got) != 1 {
		t.Fatalf("同一地址应去重，实际 %v", got)
	}
}

// --- 闸门层（需要真实 PG）---

func scopeTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	return d
}

// scopeTestTask 建一个任务并挂上指定网段基线，返回任务 id 与清理函数。
func scopeTestTask(t *testing.T, d *db.DB, cidrs ...string) (int64, func()) {
	t.Helper()
	task, err := d.CreateTask("scope gate test", "scope gate test", nil, 0, 0)
	if err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	taskID := task.ID
	for _, c := range cidrs {
		if _, err := d.Assets().AddAgentScope(taskID, "cidr", c, "test baseline", "manual"); err != nil {
			t.Fatalf("写基线失败: %v", err)
		}
	}
	cleanup := func() {
		d.Exec(`DELETE FROM task_scope WHERE task_id=$1`, taskID)
		d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
	}
	return taskID, cleanup
}

func setScopeGate(t *testing.T, d *db.DB, on bool) {
	t.Helper()
	prev, ok, _ := d.GetSetting(settingScopeGateEnabled)
	if err := d.SetBool(settingScopeGateEnabled, on); err != nil {
		t.Fatalf("写开关失败: %v", err)
	}
	t.Cleanup(func() {
		if ok {
			_ = d.SetSetting(settingScopeGateEnabled, prev)
		} else {
			d.Exec(`DELETE FROM settings WHERE key=$1`, settingScopeGateEnabled)
		}
	})
}

func scopeCtx(taskID int64) context.Context {
	return WithTaskContext(context.Background(), strconv.FormatInt(taskID, 10), "worker", nil)
}

func TestScopeGateOffByDefault(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	taskID, cleanup := scopeTestTask(t, d, "10.20.30.0/24")
	defer cleanup()
	// 显式删掉这个键，让本用例不依赖「上一次运行有没有留下设置」。
	// 键不存在 = 默认状态（GetBool 回落 false），这正是要验证的路径。
	d.Exec(`DELETE FROM settings WHERE key=$1`, settingScopeGateEnabled)
	if _, need := ic.ScopeGate(scopeCtx(taskID), "Bash", []byte(`{"command":"curl 8.8.8.8"}`)); need {
		t.Fatal("开关默认关闭时不该产生任何审批")
	}
}

func TestScopeGateNoBaselineAllows(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	setScopeGate(t, d, true)
	taskID, cleanup := scopeTestTask(t, d) // 没有网段基线
	defer cleanup()
	if _, need := ic.ScopeGate(scopeCtx(taskID), "Bash", []byte(`{"command":"curl 8.8.8.8"}`)); need {
		t.Fatal("任务没有网段基线时应放行（与 allowsIP 既有语义一致）")
	}
}

func TestScopeGateInsideBaselineAllows(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	setScopeGate(t, d, true)
	taskID, cleanup := scopeTestTask(t, d, "10.20.30.0/24")
	defer cleanup()
	if _, need := ic.ScopeGate(scopeCtx(taskID), "Bash", []byte(`{"command":"curl http://10.20.30.77:8080/x"}`)); need {
		t.Fatal("基线内的地址不该触发审批")
	}
}

func TestScopeGateOutsideAsks(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	setScopeGate(t, d, true)
	taskID, cleanup := scopeTestTask(t, d, "10.20.30.0/24")
	defer cleanup()

	dec, need := ic.ScopeGate(scopeCtx(taskID), "Bash", []byte(`{"command":"curl http://10.20.31.5/x"}`))
	if !need {
		t.Fatal("基线外的地址必须触发审批")
	}
	if dec.Action != "ask" {
		t.Errorf("动作应为 ask，实际 %q", dec.Action)
	}
	if dec.ScopeCIDR != "10.20.31.0/24" {
		t.Errorf("扩权粒度应为 /24，实际 %q", dec.ScopeCIDR)
	}
	if !strings.Contains(dec.Message, "10.20.31.5") || !strings.Contains(dec.Message, "10.20.30.0/24") {
		t.Errorf("审批文案应同时给出目标与当前授权，实际 %q", dec.Message)
	}
	if dec.TimeoutEnabled && dec.TimeoutSeconds != scopeAskTimeoutSecs {
		t.Errorf("审批超时应为 %d 秒，实际 %d", scopeAskTimeoutSecs, dec.TimeoutSeconds)
	}
}

// TestScopeGateGrantTakesEffect 是「扩权」闭环的核心断言：按审批文案里的网段
// 授权一次之后，同一个目标必须不再被问。这守的是 HandleScopeAsk 的写库行为——
// 只批不写就退化成「每次都问」。
func TestScopeGateGrantTakesEffect(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	setScopeGate(t, d, true)
	taskID, cleanup := scopeTestTask(t, d, "10.20.30.0/24")
	defer cleanup()

	input := []byte(`{"command":"curl http://10.20.31.5/x"}`)
	dec, need := ic.ScopeGate(scopeCtx(taskID), "Bash", input)
	if !need {
		t.Fatal("前置条件不成立：越界地址未触发审批")
	}
	// 复现 HandleScopeAsk 在审批通过后的写库动作。
	if _, err := d.Assets().AddAgentScope(taskID, "cidr", dec.ScopeCIDR, "网段扩权审批通过（Bash）", "manual"); err != nil {
		t.Fatalf("扩权写库失败: %v", err)
	}
	if _, need := ic.ScopeGate(scopeCtx(taskID), "Bash", input); need {
		t.Fatal("扩权后同一目标不该再触发审批")
	}
}

func TestScopeGateSkipsChatSessions(t *testing.T) {
	d := scopeTestDB(t)
	t.Cleanup(func() { d.Close() })
	ic := New(d)
	setScopeGate(t, d, true)
	// 会话模式（无 task 上下文）没有 task_scope，不判。
	if _, need := ic.ScopeGate(context.Background(), "Bash", []byte(`{"command":"curl 8.8.8.8"}`)); need {
		t.Fatal("没有任务上下文的会话不该触发网段审批")
	}
}
