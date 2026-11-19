package db

import (
	"strings"
	"testing"
)

// 知识库的集成测试：必须真实 PostgreSQL（无 DSN 时跳过）。
// 单元测试能验分块与打分，验不了这里真正容易错的东西——两层作用域的可见性、
// 外键级联删除、JSONB 向量的写入与解码、ILIKE 候选集与占位符对齐。

func cleanKnowledgeTestData(t *testing.T, d *DB) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM knowledge_docs WHERE title LIKE 'kbtest-%'`,
		`DELETE FROM tasks WHERE name LIKE 'kbtest-%'`,
		`DELETE FROM settings WHERE key='knowledge_embed_config'`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("cleanup %q: %v", q, err)
		}
	}
}

func seedKnowledgeTask(t *testing.T, d *DB, name string) int64 {
	t.Helper()
	task, err := d.CreateTask("kbtest-desc", "kbtest-goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if _, err := d.Exec(`UPDATE tasks SET name=$1 WHERE id=$2`, name, task.ID); err != nil {
		t.Fatalf("rename task: %v", err)
	}
	return task.ID
}

func TestKnowledgeDocScopes(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanKnowledgeTestData(t, d)
	defer cleanKnowledgeTestData(t, d)

	store := d.Knowledge()
	taskA := seedKnowledgeTask(t, d, "kbtest-A")
	taskB := seedKnowledgeTask(t, d, "kbtest-B")

	chunks := []KnowledgeChunkInput{
		{Seq: 0, Text: "全局规范：报告必须附证据链与复现步骤。"},
		{Seq: 1, Text: "全局规范：危害结论要写明影响面。"},
	}
	if _, err := store.CreateDoc(KnowledgeDocInput{
		Title: "kbtest-global", Category: "内部规范", Source: KnowledgeSourceManual,
		SourceRef: "报告规范.md", Content: "全局规范：报告必须附证据链与复现步骤。\n全局规范：危害结论要写明影响面。",
	}, chunks, ""); err != nil {
		t.Fatalf("create global doc: %v", err)
	}
	if _, err := store.CreateDoc(KnowledgeDocInput{
		TaskID: taskA, Title: "kbtest-task-a", Category: "客户资料",
		Source: KnowledgeSourceFile, SourceRef: "客户资产清单.xlsx", Content: "A 任务专属资料",
	}, []KnowledgeChunkInput{{Seq: 0, Text: "A 任务专属资料：10.0.0.0/8"}}, ""); err != nil {
		t.Fatalf("create task doc: %v", err)
	}

	// 任务 A 看到「全局 + 自己」，看不到任务 B（B 没有文档，这里验证的是可见性口径）。
	docsA, totalA, err := store.ListDocs(KnowledgeDocFilter{TaskID: taskA, Limit: 50})
	if err != nil {
		t.Fatalf("list docs A: %v", err)
	}
	if totalA != 2 {
		t.Fatalf("任务 A 应看到 2 篇（全局+本任务），实得 %d", totalA)
	}
	for _, doc := range docsA {
		if doc.TaskID != 0 && doc.TaskID != taskA {
			t.Fatalf("任务 A 看到了别的任务的文档: %+v", doc)
		}
	}
	// 任务 B 只看到全局那一篇。
	_, totalB, err := store.ListDocs(KnowledgeDocFilter{TaskID: taskB, Limit: 50})
	if err != nil {
		t.Fatalf("list docs B: %v", err)
	}
	if totalB != 1 {
		t.Fatalf("任务 B 应只看到 1 篇全局文档，实得 %d", totalB)
	}
	// scope=global / scope=task 两个显式口径。
	_, globalOnly, err := store.ListDocs(KnowledgeDocFilter{Scope: "global", Limit: 50})
	if err != nil {
		t.Fatalf("list global: %v", err)
	}
	if globalOnly != 1 {
		t.Fatalf("全局库应只有 1 篇，实得 %d", globalOnly)
	}
	_, taskOnly, err := store.ListDocs(KnowledgeDocFilter{TaskID: taskA, Scope: "task", Limit: 50})
	if err != nil {
		t.Fatalf("list task: %v", err)
	}
	if taskOnly != 1 {
		t.Fatalf("任务库应只有 1 篇，实得 %d", taskOnly)
	}
	// 关键词过滤命中正文与标题。
	hits, _, err := store.ListDocs(KnowledgeDocFilter{TaskID: taskA, Query: "证据链", Limit: 50})
	if err != nil {
		t.Fatalf("query docs: %v", err)
	}
	if len(hits) != 1 || !strings.HasPrefix(hits[0].Title, "kbtest-global") {
		t.Fatalf("正文关键词过滤未命中预期文档: %+v", hits)
	}
	if hits[0].ChunkCount != 2 {
		t.Fatalf("chunk_count 应为 2，实得 %d", hits[0].ChunkCount)
	}
	if !strings.Contains(hits[0].Preview, "证据链") {
		t.Fatalf("preview 应包含正文前 200 字: %q", hits[0].Preview)
	}
}

func TestKnowledgeChunksAndDelete(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanKnowledgeTestData(t, d)
	defer cleanKnowledgeTestData(t, d)

	store := d.Knowledge()
	docID, err := store.CreateDoc(KnowledgeDocInput{
		Title: "kbtest-chunks", Category: "payload", Content: "SSRF 打 169.254.169.254 元数据；SMB 横向用 impacket。",
	}, []KnowledgeChunkInput{
		{Seq: 0, Text: "SSRF 打 169.254.169.254 元数据服务，可以拿到临时凭据。"},
		{Seq: 1, Text: "SMB 横向用 impacket 的 psexec，注意 445 端口。"},
		{Seq: 2, Text: "与本次查询无关的第三块内容。"},
	}, "test-embed")
	if err != nil {
		t.Fatalf("create doc: %v", err)
	}

	total, err := store.ChunksTotal(0)
	if err != nil {
		t.Fatalf("chunks total: %v", err)
	}
	if total != 3 {
		t.Fatalf("全局库应有 3 个分块，实得 %d", total)
	}

	// ILIKE 候选：正文命中。
	cands, err := store.CandidateChunks(0, []string{"%impacket%"}, 10)
	if err != nil {
		t.Fatalf("candidate chunks: %v", err)
	}
	if len(cands) != 1 || cands[0].Seq != 1 {
		t.Fatalf("关键词候选不对: %+v", cands)
	}
	if cands[0].Title != "kbtest-chunks" {
		t.Fatalf("候选没有带上文档元信息: %+v", cands[0])
	}
	// ILIKE 候选：标题命中也要能召回（标题是人工摘要，命中通常代表整篇相关）。
	byTitle, err := store.CandidateChunks(0, []string{"%kbtest-chun%"}, 10)
	if err != nil {
		t.Fatalf("candidate by title: %v", err)
	}
	if len(byTitle) != 3 {
		t.Fatalf("按标题应召回 3 块，实得 %d", len(byTitle))
	}

	// 删除文档时记录级联删除；再删一次返回 false（404 语义）。
	ok, err := store.DeleteDoc(docID)
	if err != nil || !ok {
		t.Fatalf("delete doc: ok=%v err=%v", ok, err)
	}
	if total, _ := store.ChunksTotal(0); total != 0 {
		t.Fatalf("级联删除后仍有 %d 个分块", total)
	}
	ok, err = store.DeleteDoc(docID)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if ok {
		t.Fatal("重复删除应返回 false")
	}
}

func TestKnowledgeEmbeddingRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanKnowledgeTestData(t, d)
	defer cleanKnowledgeTestData(t, d)

	store := d.Knowledge()
	vec := []float32{0.11, -0.25, 0.5, 0.75}
	if _, err := store.CreateDoc(KnowledgeDocInput{
		Title: "kbtest-embed", Category: "内部规范", Content: "向量化示例",
	}, []KnowledgeChunkInput{
		{Seq: 0, Text: "带向量的块", Embedding: vec},
		{Seq: 1, Text: "不带向量的块"},
	}, "test-embed"); err != nil {
		t.Fatalf("create doc: %v", err)
	}

	emb, err := store.EmbeddedChunks(0, 100)
	if err != nil {
		t.Fatalf("embedded chunks: %v", err)
	}
	if len(emb) != 1 {
		t.Fatalf("只有 1 块有向量，实得 %d", len(emb))
	}
	if len(emb[0].Embedding) != len(vec) {
		t.Fatalf("向量长度不对: %v", emb[0].Embedding)
	}
	for i := range vec {
		if diff := emb[0].Embedding[i] - vec[i]; diff > 1e-6 || diff < -1e-6 {
			t.Fatalf("向量第 %d 位不一致: %v vs %v", i, emb[0].Embedding[i], vec[i])
		}
	}

	st, err := store.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Docs != 1 || st.Embedded != 1 || st.Chunks != 2 {
		t.Fatalf("统计不对: %+v", st)
	}
}
