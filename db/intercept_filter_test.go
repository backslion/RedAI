package db

import (
	"slices"
	"testing"
)

func TestInterceptApprovalFilters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "approval-filter-" + t.Name()
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id IN ($1,$2)`, scope, scope+"-other") })
	rule, err := d.CreateInterceptRule("filter fixture", "tool_name", "string", "Bash", "deny", "fixture", 1, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, rule.ID) })
	filter := InterceptApprovalFilter{Status: "denied", DecisionSource: "model"}
	_, baseline, err := d.ListAllInterceptsPage(1, 20, filter)
	if err != nil {
		t.Fatal(err)
	}
	expected := []int64{}
	for _, task := range []string{scope, scope + "-other"} {
		copies := 3
		if task != scope {
			copies = 1
		}
		for _, status := range []string{"pending", "allowed", "denied", "timeout"} {
			for _, source := range []string{"model", "rule", "unknown"} {
				for i := 0; i < copies; i++ {
					var ruleID int64
					reason := "legacy reason"
					if source == "rule" {
						ruleID = rule.ID
					}
					if source == "model" {
						reason = "[模型] fixture"
					}
					id, err := d.CreateDecidedIntercept(ruleID, 0, task, "test", "Bash", []byte(`{"command":"fixture"}`), status, reason)
					if err != nil {
						t.Fatal(err)
					}
					// Legacy source fields and tied timestamps must filter/page consistently.
					if i == 0 {
						if _, err = d.Exec(`UPDATE intercept_pending SET decision_source='' WHERE id=$1`, id); err != nil {
							t.Fatal(err)
						}
					}
					if task == scope && status == "denied" && source == "model" {
						expected = append(expected, id)
					}
				}
			}
		}
	}
	if _, err := d.Exec(`UPDATE intercept_pending SET created_at='2099-01-01' WHERE task_id IN ($1,$2)`, scope, scope+"-other"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		filter InterceptApprovalFilter
		want   int
	}{
		{"all", InterceptApprovalFilter{}, 36},
	}
	for _, s := range []string{"pending", "allowed", "denied", "timeout"} {
		cases = append(cases, struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{s, InterceptApprovalFilter{Status: s}, 9})
	}
	for _, s := range []string{"model", "rule", "unknown"} {
		cases = append(cases, struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{s, InterceptApprovalFilter{DecisionSource: s}, 12})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, total, err := d.ListTaskInterceptsPage(scope, 1, 100, tc.filter)
			if err != nil || total != tc.want || len(rows) != tc.want {
				t.Fatalf("count=%d rows=%d err=%v", total, len(rows), err)
			}
			for _, r := range rows {
				if r.TaskID == nil || *r.TaskID != scope || tc.filter.Status != "" && r.Status != tc.filter.Status || tc.filter.DecisionSource != "" && r.DecisionSource != tc.filter.DecisionSource {
					t.Fatalf("nonmatching row: %+v", r)
				}
			}
		})
	}
	slices.Reverse(expected)
	var seen []int64
	for page := 1; page <= 2; page++ {
		rows, total, err := d.ListTaskInterceptsPage(scope, page, 2, filter)
		if err != nil || total != 3 {
			t.Fatalf("page %d total=%d err=%v", page, total, err)
		}
		for _, r := range rows {
			seen = append(seen, r.ID)
		}
	}
	if !slices.Equal(seen, expected) {
		t.Fatalf("unstable combined-filter pagination: got %v want %v", seen, expected)
	}
	rows, total, err := d.ListTaskInterceptsPage(scope, 3, 2, filter)
	if err != nil || len(rows) != 0 || total != 3 {
		t.Fatalf("empty page count=%d rows=%d err=%v", total, len(rows), err)
	}
	_, total, err = d.ListAllInterceptsPage(1, 100, filter)
	if err != nil || total != baseline+4 {
		t.Fatalf("global filter count=%d want=%d err=%v", total, baseline+4, err)
	}
	// Values must remain SQL parameters even for direct store callers.
	rows, total, err = d.ListTaskInterceptsPage(scope, 1, 20, InterceptApprovalFilter{Status: "denied' OR 1=1 --"})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("invalid value escaped filter: %d %v", total, err)
	}
	// A rule's persisted source survives deletion of its associated rule.
	_, err = d.Exec(`UPDATE intercept_pending SET decision_source='rule' WHERE task_id=$1 AND rule_id=$2`, scope, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteInterceptRule(rule.ID); err != nil {
		t.Fatal(err)
	}
	rows, total, err = d.ListTaskInterceptsPage(scope, 1, 100, InterceptApprovalFilter{DecisionSource: "rule"})
	if err != nil || total != 12 {
		t.Fatalf("deleted-rule source count=%d err=%v", total, err)
	}
	for _, r := range rows {
		if r.RuleID != nil || r.DecisionSource != "rule" {
			t.Fatal("deleted rule lost its source")
		}
	}
}

// 审批来源标注：rule_id 为空的三种来源必须靠前缀区分。
// 网段扩权没有对应的规则行（范围是任务数据，不是规则），漏了这段就会落成
// "unknown"，历史页只能显示「来源未知」，复盘时分不清是哪条链路拦的。
func TestInterceptSourceLabels(t *testing.T) {
	cases := []struct {
		ruleID int64
		reason string
		want   string
	}{
		{7, "", "rule"},
		{0, "[模型] 疑似批量删除", "model"},
		{0, "[网段] 网段扩权审批：Bash 调用的目标 10.20.31.5 不在任务授权网段内", "scope"},
		{0, "普通理由", "unknown"},
	}
	for _, c := range cases {
		if got := interceptSource(c.ruleID, c.reason); got != c.want {
			t.Errorf("interceptSource(%d, %q) = %q, want %q", c.ruleID, c.reason, got, c.want)
		}
	}
}
