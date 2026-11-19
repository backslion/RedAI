// tools_knowledge.go：知识库工具组（检索 / 入库 / 盘点）。
//
// 主要函数：
//   - knowledgeSearch：在「全局 + 本任务」范围内混合检索（关键词优先，向量补充）。
//   - knowledgeAdd：把一段资料入库（可给 URL 由服务端抓取；writer 可写任务库，
//     全局库只允许 planner / 人类主控写）。
//   - knowledgeList：盘点当前可见的文档，判断「要不要先补资料」。
//
// ## 为什么这三个工具值得占系统提示的篇幅
//
// 技能（skills/）是方法论，工具是动作，`record_fact` 是结论——唯独「甲方给的
// 文档、历史报告、内部规范、从目标机带回来的资料」没有归宿。过去只有两条路：
// 塞进 fact（污染事实图、被压缩后丢失），或者干脆不读（模型凭想象编）。
// 知识库把这类内容变成可检索的外部记忆，且天然带出处，报告里能引用。
//
// ## 语义纪律
//
//   - 检索范围固定「全局 + 本任务」，不接受跨任务查询：任务隔离与凭据库同一纪律。
//   - 命中结果必须带 source_ref，报告里引用资料要能追到文件名/URL。
//   - 入库不做「总结后再存」：原文整篇存，分块由服务端做——模型先总结会丢掉
//     检索时才需要的关键字（IP、路径、报错码）。
//   - 全局库只允许 planner / 人类主控写入，避免 worker 把单任务现场资料写进
//     全局库污染其他任务。

package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/knowledge"
)

// knowledgeService 按需构造知识库服务（构造是廉价的，不做缓存，避免测试里
// 共享状态）。
func (t *ToolSet) knowledgeService() *knowledge.Service {
	if t == nil || t.ts == nil {
		return nil
	}
	return knowledge.NewService(t.ts.DB())
}

// knowledgeSearch 是混合检索工具（只读）。
func (t *ToolSet) knowledgeSearch() actool.CoreTool {
	return readTool(
		"knowledge_search",
		"检索知识库（甲方文档、历史报告、内部规范、现场取回的资料）。范围固定为「全局库 + 当前任务库」，查不到别的任务。\n"+
			"检索是关键词优先 + 向量补充的混合模式：中文按二元组匹配，命中标题会加权，向量只做补充召回。\n"+
			"返回：mode（keyword=未配置向量模型，hybrid=混合）、每条命中的 doc_id/chunk_id/title/category/source_ref/score/snippet/text。\n"+
			"**什么时候该查**：动手前先看有没有甲方给的资料（账号体系、网络拓扑、已知限制）；"+
			"遇到不熟的技术栈查方法论；写报告前查内部报告规范与历史同类漏洞的写法。\n"+
			"**引用纪律**：把结论写进 fact/finding 时带上 source_ref，报告里要能追到出处，不要凭记忆复述。",
		obj(map[string]any{
			"query":    str("检索词（必填）。中英文均可；多个词用空格分隔，越具体越好"),
			"category": str("只返回该分类的命中（可选，分类名先由 knowledge_list 查）"),
			"limit":    intp("返回条数，默认 6，上限 20"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query    string `json:"query"`
				Category string `json:"category"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			svc := t.knowledgeService()
			if svc == nil || !svc.Available() {
				return actool.Errorf("knowledge_search 未启用：知识库存储不可用"), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 6
			}
			if limit > 20 {
				limit = 20
			}
			// 分类过滤在结果侧做：分类是展示维度，不该影响候选集大小。
			fetch := limit
			if strings.TrimSpace(a.Category) != "" {
				fetch = 20
			}
			res, err := svc.Search(ctx, t.taskID, a.Query, fetch)
			if err != nil {
				return actool.Errorf("检索知识库失败: " + err.Error()), nil
			}
			if cat := strings.TrimSpace(a.Category); cat != "" {
				kept := res.Hits[:0]
				for _, h := range res.Hits {
					if strings.EqualFold(strings.TrimSpace(h.Category), cat) {
						kept = append(kept, h)
					}
				}
				res.Hits = kept
			}
			if len(res.Hits) > limit {
				res.Hits = res.Hits[:limit]
			}
			if len(res.Hits) == 0 {
				return jsonResult(map[string]any{
					"mode":    res.Mode,
					"warning": res.Warning,
					"total":   0,
					"hint":    "没有命中。可以换更具体的词（技术栈名/漏洞名/IP 段），或先用 knowledge_list 看看库里到底有什么。",
				})
			}
			return jsonResult(map[string]any{
				"mode":       res.Mode,
				"warning":    res.Warning,
				"total":      len(res.Hits),
				"candidates": res.Candidates,
				"hits":       res.Hits,
			})
		},
	)
}

// knowledgeAdd 是入库工具（写入）。
func (t *ToolSet) knowledgeAdd() actool.CoreTool {
	return writeTool(
		"knowledge_add",
		"把一段资料原文存进知识库，供后续 knowledge_search 检索。\n"+
			"两种用法：① content 直接给正文（从目标机带回来的配置文件、日志、文档片段）；"+
			"② 给 url，由服务端抓取并去标签（只支持 http/https）。\n"+
			"**存原文，不要先总结**：分块与索引由服务端做，模型先摘要把 IP、路径、报错码这些"+
			"检索关键信息丢掉了。\n"+
			"scope=task（默认）只进当前任务库；scope=global 进全局库供所有任务复用——"+
			"**只有 planner 与人类主控能写全局库**，worker 写会被拒绝。\n"+
			"返回：doc_id、分块数、是否向量化。入库不等于找到了漏洞，别把它当 record_fact 用。",
		obj(map[string]any{
			"title":      str("标题（可选，默认取正文首行或来源名）"),
			"content":    str("正文文本（与 url 二选一，正文优先）"),
			"url":        str("要抓取的网页地址（与 content 二选一，仅 http/https）"),
			"category":   str("分类（可选），如 客户资料/历史报告/内部规范/payload/现场取证"),
			"source_ref": str("来源标注（可选）：文件名、URL 或主机路径，报告引用时用"),
			"scope":      str("task（默认）或 global"),
			"embed":      map[string]any{"type": "boolean", "description": "是否尝试向量化，默认 true；未配置向量模型时自动降级为关键词"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Title     string `json:"title"`
				Content   string `json:"content"`
				URL       string `json:"url"`
				Category  string `json:"category"`
				SourceRef string `json:"source_ref"`
				Scope     string `json:"scope"`
				Embed     *bool  `json:"embed"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			svc := t.knowledgeService()
			if svc == nil || !svc.Available() {
				return actool.Errorf("knowledge_add 未启用：知识库存储不可用"), nil
			}
			scope := strings.ToLower(strings.TrimSpace(a.Scope))
			if scope == "" {
				scope = "task"
			}
			if scope != "task" && scope != "global" {
				return actool.Errorf("scope 只能是 task 或 global"), nil
			}
			if scope == "global" && t.worker != "planner" && t.worker != "human" {
				return actool.Errorf("只有 planner 与人类主控能写全局知识库；worker 请用 scope=task（全局库被单任务资料污染后很难清理）"), nil
			}
			taskID := int64(0)
			if scope == "task" {
				if t.taskID <= 0 {
					return actool.Errorf("knowledge_add 写任务库需要任务上下文(当前无 task)；可改用 scope=global（若角色允许）"), nil
				}
				taskID = t.taskID
			}
			content := a.Content
			sourceRef := strings.TrimSpace(a.SourceRef)
			source := db.KnowledgeSourceManual
			if strings.TrimSpace(content) == "" {
				if strings.TrimSpace(a.URL) == "" {
					return actool.Errorf("content 与 url 至少给一个"), nil
				}
				text, _, err := knowledge.FetchText(ctx, a.URL)
				if err != nil {
					return actool.Errorf("抓取失败: " + err.Error()), nil
				}
				content = text
				source = db.KnowledgeSourceURL
				if sourceRef == "" {
					sourceRef = strings.TrimSpace(a.URL)
				}
			}
			embed := true
			if a.Embed != nil {
				embed = *a.Embed
			}
			res, err := svc.Ingest(ctx, knowledge.IngestInput{
				TaskID:    taskID,
				Title:     a.Title,
				Category:  a.Category,
				Source:    source,
				SourceRef: sourceRef,
				Content:   content,
				Embed:     embed,
			})
			if err != nil {
				return actool.Errorf("入库失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"doc_id":          res.DocID,
				"title":           res.Title,
				"scope":           scope,
				"chunks":          res.Chunks,
				"embedded_chunks": res.Embedded,
				"embed_model":     res.EmbedModel,
				"warning":         res.Warning,
			})
		},
	)
}

// knowledgeList 盘点可见文档（只读）。
func (t *ToolSet) knowledgeList() actool.CoreTool {
	return readTool(
		"knowledge_list",
		"列出当前可见的知识库文档（全局库 + 当前任务库），用于判断库里有没有可用资料、分类怎么命名。\n"+
			"返回每篇的 id/title/category/source/source_ref/chars/chunks/embedded/scope 与正文前 200 字预览。\n"+
			"只要正文请用 knowledge_search 命中后再引用，不要靠预览下结论。",
		obj(map[string]any{
			"query":    str("关键词过滤标题/来源/正文（可选）"),
			"category": str("只看该分类（可选）"),
			"scope":    str("global=只看全局库；task=只看任务库；留空=全部可见"),
			"limit":    intp("返回条数，默认 20，上限 100"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query    string `json:"query"`
				Category string `json:"category"`
				Scope    string `json:"scope"`
				Limit    int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			store := t.ts.Knowledge()
			if store == nil {
				return actool.Errorf("knowledge_list 未启用：知识库存储不可用"), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 20
			}
			if limit > 100 {
				limit = 100
			}
			scope := strings.ToLower(strings.TrimSpace(a.Scope))
			if scope != "" && scope != "global" && scope != "task" {
				return actool.Errorf("scope 只能是 global / task / 空"), nil
			}
			docs, total, err := store.ListDocs(db.KnowledgeDocFilter{
				TaskID:   t.taskID,
				Scope:    scope,
				Query:    a.Query,
				Category: a.Category,
				Limit:    limit,
			})
			if err != nil {
				return actool.Errorf("盘点知识库失败: " + err.Error()), nil
			}
			type row struct {
				ID        int64  `json:"id"`
				Title     string `json:"title"`
				Category  string `json:"category"`
				Source    string `json:"source"`
				SourceRef string `json:"source_ref"`
				Scope     string `json:"scope"`
				Chars     int    `json:"chars"`
				Chunks    int    `json:"chunks"`
				Embedded  bool   `json:"embedded"`
				Preview   string `json:"preview"`
				CreatedAt string `json:"created_at"`
			}
			out := make([]row, 0, len(docs))
			for _, d := range docs {
				sc := "task"
				if d.TaskID == 0 {
					sc = "global"
				}
				out = append(out, row{
					ID: d.ID, Title: d.Title, Category: d.Category, Source: d.Source,
					SourceRef: d.SourceRef, Scope: sc, Chars: d.CharCount, Chunks: d.ChunkCount,
					Embedded: d.EmbedModel != "", Preview: d.Preview,
					CreatedAt: d.CreatedAt.Format("2006-01-02 15:04"),
				})
			}
			return jsonResult(map[string]any{"total": total, "count": len(out), "docs": out})
		},
	)
}
