package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 知识库工具的端到端测试（真实 PG，无 DSN 时跳过）。
// 单元测试只能验绑定与打分，验不了工具真的能拿到 DB 句柄、任务作用域是否生效、
// 全局库的写入限制是否落在服务端而不是提示词里。

func knowledgeToolEnv(t *testing.T) (*ToolSet, int64) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })

	expID, err := d.CreateExploration("kbtool-desc", "kbtool-goal")
	if err != nil {
		t.Fatalf("create exploration: %v", err)
	}
	task, err := d.CreateTask("kbtool-desc", "kbtool-goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if _, err := d.Exec(`UPDATE tasks SET name='kbtool-task' WHERE id=$1`, task.ID); err != nil {
		t.Fatalf("rename task: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM knowledge_docs WHERE title LIKE 'kbtool-%'`)
		_, _ = d.Exec(`DELETE FROM tasks WHERE name='kbtool-task'`)
		_, _ = d.Exec(`DELETE FROM explorations WHERE goal='kbtool-goal'`)
	})
	ts := NewToolSet(d.Exploration(expID), "worker")
	ts.SetTaskID(task.ID)
	return ts, task.ID
}

func callKnowledge(t *testing.T, tl actool.CoreTool, payload any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	res, err := tl.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("%s Call error: %v", tl.Name(), err)
	}
	return res.Flatten()
}

func TestKnowledgeToolRoundTrip(t *testing.T) {
	ts, taskID := knowledgeToolEnv(t)

	// 1) worker 写任务库：应成功，并且落库的 task_id 是本任务。
	addOut := callKnowledge(t, ts.knowledgeAdd(), map[string]any{
		"title":      "kbtool-客户资料",
		"category":   "客户资料",
		"source_ref": "现场导出.txt",
		"content":    "客户内网段 10.20.0.0/16；域控 10.20.0.10；跳板机 10.20.0.5 开放 3389。",
		"scope":      "task",
		"embed":      false,
	})
	var added struct {
		DocID     int64  `json:"doc_id"`
		Chunks    int    `json:"chunks"`
		Scope     string `json:"scope"`
		Warning   string `json:"warning"`
		Embedded  int    `json:"embedded_chunks"`
		EmbedMode string `json:"embed_model"`
	}
	if err := json.Unmarshal([]byte(addOut), &added); err != nil {
		t.Fatalf("add 返回无法解析: %v\n%s", err, addOut)
	}
	if added.DocID <= 0 {
		t.Fatalf("add 未返回 doc_id: %s", addOut)
	}
	if added.Scope != "task" || added.Chunks == 0 {
		t.Fatalf("add 结果异常: %s", addOut)
	}
	doc, _, err := ts.ts.DB().Knowledge().GetDoc(added.DocID)
	if err != nil || doc == nil {
		t.Fatalf("读回文档失败: %v", err)
	}
	if doc.TaskID != taskID {
		t.Fatalf("任务库文档的 task_id 应为 %d，实得 %d", taskID, doc.TaskID)
	}

	// 2) 检索命中，且结果来自刚写的文档。
	searchOut := callKnowledge(t, ts.knowledgeSearch(), map[string]any{"query": "域控 10.20.0.10"})
	var sr struct {
		Hits []struct {
			DocID     int64   `json:"doc_id"`
			Title     string  `json:"title"`
			SourceRef string  `json:"source_ref"`
			Score     float64 `json:"score"`
		} `json:"hits"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(searchOut), &sr); err != nil {
		t.Fatalf("search 返回无法解析: %v\n%s", err, searchOut)
	}
	if len(sr.Hits) == 0 || sr.Hits[0].DocID != added.DocID {
		t.Fatalf("检索没有命中刚入库的文档: %s", searchOut)
	}
	if sr.Hits[0].SourceRef != "现场导出.txt" {
		t.Fatalf("命中缺少来源标注: %+v", sr.Hits[0])
	}

	// 3) worker 写全局库必须被拒（防止单任务资料污染全局库）。
	denied := callKnowledge(t, ts.knowledgeAdd(), map[string]any{
		"title": "kbtool-越权全局", "content": "worker 不该能写这里", "scope": "global",
	})
	if !strings.Contains(denied, "只有 planner") {
		t.Fatalf("worker 写全局库应被拒绝，实际返回: %s", denied)
	}

	// 4) planner 写全局库应允许。
	tsPlanner := NewToolSet(ts.ts, "planner")
	tsPlanner.SetTaskID(taskID)
	okOut := callKnowledge(t, tsPlanner.knowledgeAdd(), map[string]any{
		"title": "kbtool-全局方法论", "category": "内部规范", "content": "横向移动前先用 credential_reuse_matrix 验证。", "scope": "global",
	})
	if strings.Contains(okOut, "只有 planner") {
		t.Fatalf("planner 写全局库被误拒: %s", okOut)
	}
	var globalAdded struct {
		DocID int64 `json:"doc_id"`
	}
	if err := json.Unmarshal([]byte(okOut), &globalAdded); err != nil || globalAdded.DocID <= 0 {
		t.Fatalf("planner 写全局库未成功: %s", okOut)
	}

	// 5) knowledge_list 能看到「全局 + 本任务」两篇。
	listOut := callKnowledge(t, ts.knowledgeList(), map[string]any{"limit": 50})
	var lr struct {
		Total int `json:"total"`
		Docs  []struct {
			ID    int64  `json:"id"`
			Scope string `json:"scope"`
		} `json:"docs"`
	}
	if err := json.Unmarshal([]byte(listOut), &lr); err != nil {
		t.Fatalf("list 返回无法解析: %v\n%s", err, listOut)
	}
	scopes := map[string]int{}
	for _, d := range lr.Docs {
		scopes[d.Scope]++
	}
	if scopes["global"] < 1 || scopes["task"] < 1 {
		t.Fatalf("列表应同时包含全局与任务库文档: %s", listOut)
	}
}

func TestKnowledgeToolWithoutTaskContext(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ts := NewToolSet(d.Exploration(0), "worker") // taskID 未设置

	out := callKnowledge(t, ts.knowledgeAdd(), map[string]any{
		"title": "kbtool-无任务", "content": "没有任务上下文时不能写任务库", "scope": "task",
	})
	if !strings.Contains(out, "任务上下文") {
		t.Fatalf("无任务上下文写任务库应报错，实际: %s", out)
	}
}
