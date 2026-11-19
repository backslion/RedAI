// knowledge.go：知识库的文档与分块存储（两层作用域：全局 / 任务级）。
//
// 主要函数/类型：
//   - KnowledgeStore：knowledge_docs + knowledge_chunks 的存储入口。
//   - CreateDoc：一次写入「文档 + 全部分块」，同事务，失败整篇回滚。
//   - ListDocs / GetDoc / DeleteDoc / Stats：管理端列表、详情、删除与概览。
//   - CandidateChunks / EmbeddedChunks / ChunksTotal：检索侧取候选集与语料规模。
//
// 语义约束：
//   - task_id IS NULL 是全局库（跨任务可读）；task_id=N 是任务库。
//     可见性口径固定为「全局 + 本任务」，任务之间绝不互相可见。
//   - 分块上冗余 task_id：检索是最热的路径，单表过滤比 JOIN documents 便宜，
//     写入时由 CreateDoc 从文档继承，不接受外部传入。
//   - embedding 以 JSONB（float 数组）存放而不是 pgvector：见 schema.sql 里的说明。
//     读取投影里 embedding 是可选列，只有检索需要向量时才取。

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 知识来源常量（仅用于展示与筛选，不参与业务判断）。
const (
	KnowledgeSourceManual = "manual" // 页面粘贴 / 工具写入
	KnowledgeSourceFile   = "file"   // 本机文件导入
	KnowledgeSourceURL    = "url"    // 网页抓取
)

// KnowledgeStore 是知识库存储句柄。
type KnowledgeStore struct{ db *DB }

// Knowledge 返回知识库存储句柄。
func (d *DB) Knowledge() *KnowledgeStore {
	if d == nil {
		return nil
	}
	return &KnowledgeStore{db: d}
}

// Knowledge 便于 agent 工具从已有的 ExplorationStore 直接拿到知识库句柄，
// 不必把 *DB 一路透传进工具集。
func (s *ExplorationStore) Knowledge() *KnowledgeStore {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Knowledge()
}

// DB 返回存储背后的连接句柄，仅用于跨包构造服务（如 knowledge.Service 需要读写
// settings 里的向量配置）。业务读写请走各 Store，不要在这里拼 SQL。
func (s *ExplorationStore) DB() *DB {
	if s == nil {
		return nil
	}
	return s.db
}

// KnowledgeDoc 是文档的列表/详情视图（不含正文，正文由 GetDoc 单独取）。
type KnowledgeDoc struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"` // 0 = 全局
	Title      string    `json:"title"`
	Category   string    `json:"category"`
	Source     string    `json:"source"`
	SourceRef  string    `json:"source_ref"`
	CharCount  int       `json:"char_count"`
	ChunkCount int       `json:"chunk_count"`
	EmbedModel string    `json:"embed_model"`
	Preview    string    `json:"preview"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// KnowledgeChunkInput 是一个待写入分块。Embedding 为空表示该块未向量化。
type KnowledgeChunkInput struct {
	Seq       int
	Text      string
	Embedding []float32
}

// KnowledgeDocInput 是文档写入输入。TaskID=0 表示写入全局库。
type KnowledgeDocInput struct {
	TaskID    int64
	Title     string
	Category  string
	Source    string
	SourceRef string
	Content   string
}

// KnowledgeChunk 是检索候选块（带文档元信息）。
type KnowledgeChunk struct {
	ID        int64     `json:"chunk_id"`
	DocID     int64     `json:"doc_id"`
	TaskID    int64     `json:"task_id"`
	Seq       int       `json:"seq"`
	Title     string    `json:"title"`
	Category  string    `json:"category"`
	SourceRef string    `json:"source_ref"`
	Text      string    `json:"text"`
	Embedding []float32 `json:"-"`
}

// KnowledgeDocFilter 是文档列表筛选。Scope 取 ""（全部）/global/task。
type KnowledgeDocFilter struct {
	TaskID   int64
	Scope    string
	Query    string
	Category string
	Limit    int
	Offset   int
}

// KnowledgeStats 是概览数字。
type KnowledgeStats struct {
	Docs        int            `json:"docs"`
	GlobalDocs  int            `json:"global_docs"`
	TaskDocs    int            `json:"task_docs"`
	Chunks      int            `json:"chunks"`
	Embedded    int            `json:"embedded_chunks"`
	Chars       int            `json:"chars"`
	Categories  []KnowledgeAgg `json:"categories"`
	LastUpdated time.Time      `json:"last_updated"`
}

// KnowledgeAgg 是分类聚合的一行。
type KnowledgeAgg struct {
	Category string `json:"category"`
	Docs     int    `json:"docs"`
}

// knowledgeScopeClause 生成分块可见性条件：全局 + 指定任务（taskID<=0 时只有全局）。
// alias 是表别名（""=不分表）；返回的片段以 AND 开头，占位符从 args 长度续号。
func knowledgeScopeClause(alias string, taskID int64, args []any) (string, []any) {
	col := "task_id"
	if alias != "" {
		col = alias + ".task_id"
	}
	if taskID > 0 {
		args = append(args, taskID)
		return fmt.Sprintf(" AND (%s = $%d OR %s IS NULL)", col, len(args), col), args
	}
	return fmt.Sprintf(" AND %s IS NULL", col), args
}

// CreateDoc 在一个事务里写入文档与全部分块，返回文档 id。
func (s *KnowledgeStore) CreateDoc(in KnowledgeDocInput, chunks []KnowledgeChunkInput, embedModel string) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("knowledge store unavailable")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var taskID any
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	var docID int64
	if err := tx.QueryRow(`INSERT INTO knowledge_docs
		(task_id, title, category, source, source_ref, content, char_count, chunk_count, embed_model)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		taskID, strings.TrimSpace(in.Title), strings.TrimSpace(in.Category),
		strings.TrimSpace(in.Source), strings.TrimSpace(in.SourceRef),
		in.Content, len([]rune(in.Content)), len(chunks), strings.TrimSpace(embedModel),
	).Scan(&docID); err != nil {
		return 0, err
	}
	for _, c := range chunks {
		var emb any
		if len(c.Embedding) > 0 {
			raw, err := json.Marshal(c.Embedding)
			if err != nil {
				return 0, err
			}
			emb = string(raw)
		}
		if _, err := tx.Exec(`INSERT INTO knowledge_chunks (doc_id, task_id, seq, text, embedding)
			VALUES ($1,$2,$3,$4,NULLIF($5,'')::jsonb)`,
			docID, taskID, c.Seq, c.Text, emb); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return docID, nil
}

// knowledgeDocCols 是列表投影（不含正文，避免把大字段带到列表里）。
const knowledgeDocCols = `id, COALESCE(task_id,0), title, category, source, source_ref,
	char_count, chunk_count, embed_model, left(content, 200), created_at, updated_at`

func scanKnowledgeDoc(sc interface{ Scan(...any) error }) (KnowledgeDoc, error) {
	var d KnowledgeDoc
	err := sc.Scan(&d.ID, &d.TaskID, &d.Title, &d.Category, &d.Source, &d.SourceRef,
		&d.CharCount, &d.ChunkCount, &d.EmbedModel, &d.Preview, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

// ListDocs 分页返回文档列表与匹配总数。
func (s *KnowledgeStore) ListDocs(f KnowledgeDocFilter) ([]KnowledgeDoc, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, fmt.Errorf("knowledge store unavailable")
	}
	var (
		where []string
		args  []any
	)
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	switch strings.TrimSpace(f.Scope) {
	case "global":
		where = append(where, "task_id IS NULL")
	case "task":
		if f.TaskID > 0 {
			add("task_id = $%d", f.TaskID)
		} else {
			// 未指定任务却要「只看任务库」，语义上等于排除全局。
			where = append(where, "task_id IS NOT NULL")
		}
	default:
		if f.TaskID > 0 {
			add("(task_id = $%d OR task_id IS NULL)", f.TaskID)
		}
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+q+"%")
		where = append(where, fmt.Sprintf(
			"(title ILIKE $%d OR source_ref ILIKE $%d OR content ILIKE $%d)",
			len(args), len(args), len(args)))
	}
	if c := strings.TrimSpace(f.Category); c != "" {
		add("category = $%d", c)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM knowledge_docs`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(`SELECT `+knowledgeDocCols+` FROM knowledge_docs`+clause+
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]KnowledgeDoc, 0, limit)
	for rows.Next() {
		d, err := scanKnowledgeDoc(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// GetDoc 返回文档元信息与正文。不存在时返回 (nil, "", nil)。
func (s *KnowledgeStore) GetDoc(id int64) (*KnowledgeDoc, string, error) {
	if s == nil || s.db == nil {
		return nil, "", fmt.Errorf("knowledge store unavailable")
	}
	var (
		d       KnowledgeDoc
		content string
	)
	err := s.db.QueryRow(`SELECT `+knowledgeDocCols+`, content FROM knowledge_docs WHERE id=$1`, id).
		Scan(&d.ID, &d.TaskID, &d.Title, &d.Category, &d.Source, &d.SourceRef,
			&d.CharCount, &d.ChunkCount, &d.EmbedModel, &d.Preview, &d.CreatedAt, &d.UpdatedAt, &content)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &d, content, nil
}

// DeleteDoc 删除文档（分块跟随外键级联）。返回是否真的删掉了一行。
func (s *KnowledgeStore) DeleteDoc(id int64) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("knowledge store unavailable")
	}
	res, err := s.db.Exec(`DELETE FROM knowledge_docs WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Stats 返回全平台知识库概览。
func (s *KnowledgeStore) Stats() (KnowledgeStats, error) {
	var st KnowledgeStats
	if s == nil || s.db == nil {
		return st, fmt.Errorf("knowledge store unavailable")
	}
	if err := s.db.QueryRow(`SELECT
			count(*),
			count(*) FILTER (WHERE task_id IS NULL),
			count(*) FILTER (WHERE task_id IS NOT NULL),
			COALESCE(sum(chunk_count),0),
			COALESCE(sum(char_count),0),
			COALESCE(max(updated_at), now())
		FROM knowledge_docs`).
		Scan(&st.Docs, &st.GlobalDocs, &st.TaskDocs, &st.Chunks, &st.Chars, &st.LastUpdated); err != nil {
		return st, err
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM knowledge_chunks WHERE embedding IS NOT NULL`).
		Scan(&st.Embedded); err != nil {
		return st, err
	}
	rows, err := s.db.Query(`SELECT category, count(*) FROM knowledge_docs
		GROUP BY category ORDER BY count(*) DESC, category LIMIT 30`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var a KnowledgeAgg
		if err := rows.Scan(&a.Category, &a.Docs); err != nil {
			return st, err
		}
		st.Categories = append(st.Categories, a)
	}
	return st, rows.Err()
}

// ChunksTotal 返回可见范围内的分块总数（用于关键词打分的逆文档频率）。
func (s *KnowledgeStore) ChunksTotal(taskID int64) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("knowledge store unavailable")
	}
	clause, args := knowledgeScopeClause("", taskID, nil)
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM knowledge_chunks WHERE 1=1`+clause, args...).Scan(&n)
	return n, err
}

// CandidateChunks 取关键词候选块。patterns 是已经包好 % 的 ILIKE 模式，
// 命中正文、标题或来源文件名任意一处即算候选；正文短的优先（更可能是要点段）。
func (s *KnowledgeStore) CandidateChunks(taskID int64, patterns []string, limit int) ([]KnowledgeChunk, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("knowledge store unavailable")
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	clause, args := knowledgeScopeClause("c", taskID, nil)
	args = append(args, patterns)
	patIdx := len(args)
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT c.id, c.doc_id, COALESCE(c.task_id,0), c.seq,
			d.title, d.category, d.source_ref, c.text
		FROM knowledge_chunks c JOIN knowledge_docs d ON d.id = c.doc_id
		WHERE (c.text ILIKE ANY($`+fmt.Sprint(patIdx)+`) OR d.title ILIKE ANY($`+fmt.Sprint(patIdx)+`)
			OR d.source_ref ILIKE ANY($`+fmt.Sprint(patIdx)+`))`+clause+
		fmt.Sprintf(` ORDER BY length(c.text) ASC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]KnowledgeChunk, 0, limit)
	for rows.Next() {
		var c KnowledgeChunk
		if err := rows.Scan(&c.ID, &c.DocID, &c.TaskID, &c.Seq, &c.Title, &c.Category, &c.SourceRef, &c.Text); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EmbeddedChunks 取可见范围内已向量化的分块（向量检索候选）。
func (s *KnowledgeStore) EmbeddedChunks(taskID int64, limit int) ([]KnowledgeChunk, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("knowledge store unavailable")
	}
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	clause, args := knowledgeScopeClause("c", taskID, nil)
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT c.id, c.doc_id, COALESCE(c.task_id,0), c.seq,
			d.title, d.category, d.source_ref, c.text, c.embedding
		FROM knowledge_chunks c JOIN knowledge_docs d ON d.id = c.doc_id
		WHERE c.embedding IS NOT NULL`+clause+
		fmt.Sprintf(` ORDER BY c.id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]KnowledgeChunk, 0, 256)
	for rows.Next() {
		var (
			c   KnowledgeChunk
			raw []byte
		)
		if err := rows.Scan(&c.ID, &c.DocID, &c.TaskID, &c.Seq, &c.Title, &c.Category, &c.SourceRef, &c.Text, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &c.Embedding); err != nil {
				continue // 坏数据跳过，不让一条脏向量毁掉整次检索
			}
		}
		if len(c.Embedding) == 0 {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
