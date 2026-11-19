// Package knowledge 实现两层（全局 / 任务级）RAG 知识库：
// 分块、可选向量化、混合检索。
//
// 设计取舍（与 antifox 上游的差异）：
//   - 不依赖 pgvector：向量以 JSONB 存在 knowledge_chunks，余弦在 Go 里算。
//     没装扩展也能上线；装上向量模型才启用语义召回，否则纯关键词也能用。
//   - 不用 PostgreSQL 全文检索：'simple' 配置不切中文，tsquery 对中文基本无效。
//     候选集走 ILIKE，打分在 Go 侧做（中文二元组 + 词频 / 逆文档频率）。
//   - 向量只做「重排与补充召回」，不单独决定结果：关键词没命中的块也可能被
//     向量捞回来，但最终分数里关键词权重更高——避免向量模型换一次结果全变。
package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/chu0119/pojun/db"
)

const (
	// DefaultChunkChars / DefaultChunkOverlap 是分块窗口：700 字 + 80 字重叠。
	// 700 字约等于 500～700 token，足够放下一条完整方法论；80 字重叠保证
	// 跨块的句子不会因为被切断而两边都检索不到。
	DefaultChunkChars   = 700
	DefaultChunkOverlap = 80
	// maxTerms 是一次检索最多使用的查询词数，防止长问句退化成全表扫描。
	maxTerms = 12
	// keywordCandidates / vectorCandidates 是两路召回各自的上限。
	keywordCandidates = 200
	vectorCandidates  = 5000
	// maxPerDoc 限制单篇文档在结果里的占比，避免一篇长文淹没其他来源。
	maxPerDoc = 3
)

// Config 是向量化配置（存 settings 表，读时对密钥脱敏）。
type Config struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"` // OpenAI 兼容根地址，如 https://api.zhihu.com/v1
	Model   string `json:"model"`    // 如 embedding-3 / text-embedding-3-small
	APIKey  string `json:"api_key"`
	Dim     int    `json:"dim"` // 0 = 由服务端决定
}

// configKey 是 settings 表里的键名。
const configKey = "knowledge_embed_config"

// Ready 判断是否可以走语义召回。
func (c Config) Ready() bool {
	return c.Enabled && strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.Model) != "" && strings.TrimSpace(c.APIKey) != ""
}

// Service 是知识库业务入口：写入（分块 → 可选向量化 → 落库）与检索。
type Service struct{ pg *db.DB }

// NewService 返回知识库服务。pg 为 nil 时所有方法安全失败。
func NewService(pg *db.DB) *Service { return &Service{pg: pg} }

// Available 表示底层存储是否可用（工具据此给出明确提示，而不是空结果）。
func (s *Service) Available() bool { return s != nil && s.pg != nil }

// LoadConfig 读取向量化配置。缺失或解析失败时返回零值（= 未启用）。
func LoadConfig(pg *db.DB) Config {
	var c Config
	if pg == nil {
		return c
	}
	raw, ok, err := pg.GetSetting(configKey)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return c
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		log.Printf("[knowledge] 向量配置解析失败，按未启用处理: %v", err)
		return Config{}
	}
	return c
}

// SaveConfig 写入向量化配置。apiKey 为空时保留原值（与 LLM profile 同一约定，
// 避免前端拿到掩码后回存把密钥清空）。
func SaveConfig(pg *db.DB, c Config) error {
	if pg == nil {
		return fmt.Errorf("db unavailable")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		if old := LoadConfig(pg); old.APIKey != "" {
			c.APIKey = old.APIKey
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return pg.SetSetting(configKey, string(raw))
}

// IngestInput 是一篇文档的写入输入。
type IngestInput struct {
	TaskID    int64  // 0 = 全局库
	Title     string // 为空时用 source_ref 兜底
	Category  string
	Source    string // manual/file/url
	SourceRef string // 文件名或 URL
	Content   string
	Embed     bool // 是否尝试向量化（未配置向量模型时会自动跳过并给出 warning）
}

// IngestResult 描述写入结果。
type IngestResult struct {
	DocID      int64  `json:"doc_id"`
	Title      string `json:"title"`
	Chunks     int    `json:"chunks"`
	Embedded   int    `json:"embedded_chunks"`
	EmbedModel string `json:"embed_model"`
	Chars      int    `json:"chars"`
	Warning    string `json:"warning,omitempty"`
}

// Ingest 分块并写入一篇文档。
func (s *Service) Ingest(ctx context.Context, in IngestInput) (IngestResult, error) {
	var res IngestResult
	if !s.Available() {
		return res, fmt.Errorf("知识库不可用：数据库未初始化")
	}
	content := Normalize(in.Content)
	if strings.TrimSpace(content) == "" {
		return res, fmt.Errorf("正文为空，没有可入库的内容")
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = strings.TrimSpace(in.SourceRef)
	}
	if title == "" {
		title = firstLine(content, 60)
	}
	if title == "" {
		title = "未命名资料"
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = db.KnowledgeSourceManual
	}

	parts := Split(content)
	chunks := make([]db.KnowledgeChunkInput, 0, len(parts))
	for i, p := range parts {
		chunks = append(chunks, db.KnowledgeChunkInput{Seq: i, Text: p})
	}

	embedModel := ""
	if in.Embed {
		if cfg := LoadConfig(s.pg); cfg.Ready() {
			vecs, err := cfg.EmbedBatch(ctx, parts)
			if err != nil {
				res.Warning = "向量化失败，已按纯关键词入库：" + err.Error()
				log.Printf("[knowledge] 文档「%s」向量化失败: %v", title, err)
			} else {
				for i := range chunks {
					if i < len(vecs) {
						chunks[i].Embedding = vecs[i]
					}
				}
				embedModel = cfg.Model
			}
		} else {
			res.Warning = "未配置向量模型，已按纯关键词入库"
		}
	}

	docID, err := s.pg.Knowledge().CreateDoc(db.KnowledgeDocInput{
		TaskID:    in.TaskID,
		Title:     title,
		Category:  in.Category,
		Source:    source,
		SourceRef: in.SourceRef,
		Content:   content,
	}, chunks, embedModel)
	if err != nil {
		return res, err
	}
	res.DocID = docID
	res.Title = title
	res.Chunks = len(chunks)
	res.Chars = len([]rune(content))
	res.EmbedModel = embedModel
	for _, c := range chunks {
		if len(c.Embedding) > 0 {
			res.Embedded++
		}
	}
	return res, nil
}

// Hit 是一条检索结果。
type Hit struct {
	DocID     int64   `json:"doc_id"`
	ChunkID   int64   `json:"chunk_id"`
	TaskID    int64   `json:"task_id"`
	Title     string  `json:"title"`
	Category  string  `json:"category"`
	SourceRef string  `json:"source_ref"`
	Text      string  `json:"text"`
	Snippet   string  `json:"snippet"`
	Score     float64 `json:"score"`
	Keyword   float64 `json:"keyword"`
	Vector    float64 `json:"vector"`
}

// SearchResult 是一次检索的完整结果（含降级说明，便于 agent 判断可信度）。
type SearchResult struct {
	Hits       []Hit  `json:"hits"`
	Mode       string `json:"mode"` // keyword | hybrid
	Warning    string `json:"warning,omitempty"`
	Candidates int    `json:"candidates"`
}

// Search 在「全局 + 本任务」范围内检索。
func (s *Service) Search(ctx context.Context, taskID int64, query string, limit int) (SearchResult, error) {
	var out SearchResult
	if !s.Available() {
		return out, fmt.Errorf("知识库不可用：数据库未初始化")
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return out, fmt.Errorf("query 不能为空")
	}
	if limit <= 0 || limit > 30 {
		limit = 8
	}
	terms := QueryTerms(q)
	if len(terms) == 0 {
		return out, fmt.Errorf("query 里没有可检索的词（至少给一个 2 字符以上的词或中文词）")
	}
	patterns := make([]string, 0, len(terms))
	for _, t := range terms {
		patterns = append(patterns, "%"+t+"%")
	}

	store := s.pg.Knowledge()
	cands, err := store.CandidateChunks(taskID, patterns, keywordCandidates)
	if err != nil {
		return out, err
	}
	total, _ := store.ChunksTotal(taskID)

	cos := map[int64]float64{}
	out.Mode = "keyword"
	if cfg := LoadConfig(s.pg); cfg.Ready() {
		vecs, embedErr := cfg.EmbedBatch(ctx, []string{q})
		if embedErr != nil {
			out.Warning = "查询向量化失败，本次只用关键词：" + embedErr.Error()
		} else if len(vecs) == 1 {
			emb, err := store.EmbeddedChunks(taskID, vectorCandidates)
			if err == nil {
				seen := make(map[int64]bool, len(cands))
				for _, c := range cands {
					seen[c.ID] = true
				}
				type scored struct {
					c  db.KnowledgeChunk
					cs float64
				}
				ranked := make([]scored, 0, len(emb))
				for _, c := range emb {
					sim := Cosine(vecs[0], c.Embedding)
					cos[c.ID] = sim
					if !seen[c.ID] {
						ranked = append(ranked, scored{c: c, cs: sim})
					}
				}
				sort.Slice(ranked, func(i, j int) bool { return ranked[i].cs > ranked[j].cs })
				for i, r := range ranked {
					if i >= keywordCandidates {
						break
					}
					if r.cs < 0.30 { // 语义召回的下限，低于它的块与问题无关
						break
					}
					cands = append(cands, r.c)
				}
				out.Mode = "hybrid"
			}
		}
	}

	out.Candidates = len(cands)
	out.Hits = Rank(q, terms, cands, cos, total, limit)
	return out, nil
}

// Rank 对候选块打分排序。纯函数，便于单测：
//   - keyword：查询词在块内的词频（对数饱和）× 逆文档频率，再按块长度归一。
//   - vector：余弦相似度（无向量时按 0 计）。
//   - 总分 = 0.65×keyword + 0.35×vector，关键词命中永远优先于纯语义相似。
func Rank(query string, terms []string, cands []db.KnowledgeChunk, cos map[int64]float64, total, limit int) []Hit {
	if len(cands) == 0 {
		return nil
	}
	lower := make([]string, len(cands))
	df := make(map[string]int, len(terms))
	for i, c := range cands {
		lower[i] = strings.ToLower(c.Text)
		for _, t := range terms {
			if strings.Contains(lower[i], t) {
				df[t]++
			}
		}
	}
	if total < len(cands) {
		total = len(cands)
	}
	queryLower := strings.ToLower(query)

	hits := make([]Hit, 0, len(cands))
	for i, c := range cands {
		var kw float64
		for _, t := range terms {
			tf := strings.Count(lower[i], t)
			if tf == 0 {
				continue
			}
			idf := math.Log(1 + float64(total)/(1+float64(df[t])))
			kw += (1 + math.Log(float64(tf))) * idf
		}
		// 长度归一：长块天然词频高，用 sqrt(长度/300) 压一下，避免长文霸榜。
		length := float64(len([]rune(c.Text)))
		kw = kw / math.Sqrt(math.Max(length, 60)/300)
		// 标题命中加一点权重：标题是人工写的摘要，命中通常意味着整篇相关。
		if containsAny(strings.ToLower(c.Title), terms) || strings.Contains(strings.ToLower(c.Title), queryLower) {
			kw += 1.5
		}
		vec := 0.0
		if cos != nil {
			vec = cos[c.ID]
			if vec < 0 {
				vec = 0
			}
		}
		score := 0.65*normKeyword(kw) + 0.35*vec
		if score <= 0 {
			continue
		}
		hits = append(hits, Hit{
			DocID:     c.DocID,
			ChunkID:   c.ID,
			TaskID:    c.TaskID,
			Title:     c.Title,
			Category:  c.Category,
			SourceRef: c.SourceRef,
			Text:      c.Text,
			Snippet:   Snippet(c.Text, query, terms),
			Score:     round4(score),
			Keyword:   round4(normKeyword(kw)),
			Vector:    round4(vec),
		})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score == hits[j].Score {
			return hits[i].ChunkID < hits[j].ChunkID
		}
		return hits[i].Score > hits[j].Score
	})
	if limit <= 0 || limit > len(hits) {
		limit = len(hits)
	}
	perDoc := map[int64]int{}
	out := make([]Hit, 0, limit)
	for _, h := range hits {
		if perDoc[h.DocID] >= maxPerDoc {
			continue
		}
		perDoc[h.DocID]++
		out = append(out, h)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// normKeyword 把关键词原始分压到 0..1（原始分经验范围 0～12）。
func normKeyword(v float64) float64 {
	if v <= 0 {
		return 0
	}
	return v / (v + 3)
}

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

func containsAny(s string, terms []string) bool {
	for _, t := range terms {
		if t != "" && strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// QueryTerms 把查询串切成检索词：英文/数字按词切（长度≥2），
// 中文按二元组切（单字查询保留单字）。全部小写。
func QueryTerms(q string) []string {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	var (
		out  []string
		seen = map[string]bool{}
		word []rune
		cjk  []rune
	)
	flushWord := func() {
		if len(word) >= 2 {
			w := string(word)
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
		word = word[:0]
	}
	flushCJK := func() {
		switch {
		case len(cjk) == 1:
			w := string(cjk)
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		case len(cjk) > 1:
			for i := 0; i+1 < len(cjk); i++ {
				w := string(cjk[i : i+2])
				if !seen[w] {
					seen[w] = true
					out = append(out, w)
				}
			}
		}
		cjk = cjk[:0]
	}
	for _, r := range q {
		switch {
		case unicode.Is(unicode.Han, r):
			flushWord()
			cjk = append(cjk, r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			flushCJK()
			word = append(word, r)
		default:
			flushWord()
			flushCJK()
		}
		if len(out) >= maxTerms {
			return out[:maxTerms]
		}
	}
	flushWord()
	flushCJK()
	if len(out) > maxTerms {
		out = out[:maxTerms]
	}
	return out
}

// Snippet 截取命中附近的片段（约 240 字），命中词用 【】 标出。
func Snippet(text, query string, terms []string) string {
	runes := []rune(text)
	const maxLen = 240
	if len(runes) <= maxLen {
		return strings.TrimSpace(text)
	}
	lowerText := strings.ToLower(text)
	idx := -1
	for _, t := range terms {
		if t == "" {
			continue
		}
		if p := strings.Index(lowerText, t); p >= 0 {
			// 字节偏移转 rune 偏移
			idx = len([]rune(text[:p]))
			break
		}
	}
	if idx < 0 {
		return strings.TrimSpace(string(runes[:maxLen])) + "…"
	}
	start := idx - maxLen/3
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(runes) {
		end = len(runes)
		start = end - maxLen
		if start < 0 {
			start = 0
		}
	}
	s := string(runes[start:end])
	if start > 0 {
		s = "…" + s
	}
	if end < len(runes) {
		s = s + "…"
	}
	return strings.TrimSpace(s)
}

// Normalize 统一换行、去掉零宽字符与首尾空白。
func Normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\u200b", "")
	s = strings.ReplaceAll(s, "\ufeff", "")
	return strings.TrimSpace(s)
}

func firstLine(s string, max int) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r := []rune(line)
		if len(r) > max {
			return string(r[:max]) + "…"
		}
		return line
	}
	return ""
}

// NowString 统一时间展示（server / tool 共用）。
func NowString() string { return time.Now().Format(time.RFC3339) }
