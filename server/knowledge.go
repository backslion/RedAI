package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/backslion/RedAI/db"
	"github.com/backslion/RedAI/knowledge"
)

// 知识库 API（v0.5.x）。
//
// 设计约束：
//   - 全局库（task_id 为空）任何登录用户可读；写全局库只在页面上显式选择 scope=global，
//     不做角色区分（本产品是单租户自用工具，权限模型只到 token 一级）。
//   - 抓取 URL 由服务端发起：只接受 http/https，走 knowledge.FetchText（8MB 上限、
//     45 秒超时、非 2xx 直接报错），不落盘、不回显原始 HTML。
//   - 向量配置的 api_key 只写不读：GET 返回 has_key + 掩码，PUT 传空串表示保留原值。

// knowledgeScopeTask 把 scope 参数转换成列表筛选用的 task 口径。
func knowledgeScopeTask(scope string, taskID int64) (string, int64) {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "global":
		return "global", 0
	case "task":
		return "task", taskID
	default:
		return "", taskID
	}
}

// listKnowledgeDocs 分页返回知识库文档。
func (s *Server) listKnowledgeDocs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	taskID := int64(credentialQueryInt(q.Get("task_id"), 0))
	scope, taskID := knowledgeScopeTask(q.Get("scope"), taskID)
	limit := credentialQueryInt(q.Get("limit"), 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := credentialQueryInt(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	docs, total, err := s.m.pg.Knowledge().ListDocs(db.KnowledgeDocFilter{
		TaskID:   taskID,
		Scope:    scope,
		Query:    strings.TrimSpace(q.Get("q")),
		Category: strings.TrimSpace(q.Get("category")),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items": docs, "total": total,
		"limit": limit, "offset": offset, "page": offset/limit + 1,
	})
}

// getKnowledgeDoc 返回单篇文档（含正文），供页面详情抽屉查看与复制。
func (s *Server) getKnowledgeDoc(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "文档 id 非法")
		return
	}
	doc, content, err := s.m.pg.Knowledge().GetDoc(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if doc == nil {
		writeErr(w, 404, "文档不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"doc": doc, "content": content})
}

// createKnowledgeDoc 新建文档：正文优先；只有给 url 时才由服务端抓取。
func (s *Server) createKnowledgeDoc(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title     string `json:"title"`
		Content   string `json:"content"`
		URL       string `json:"url"`
		Category  string `json:"category"`
		SourceRef string `json:"source_ref"`
		TaskID    int64  `json:"task_id"`
		Scope     string `json:"scope"`
		Embed     *bool  `json:"embed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	taskID := req.TaskID
	if strings.EqualFold(strings.TrimSpace(req.Scope), "global") {
		taskID = 0
	} else if taskID > 0 {
		// 校验任务存在，避免外键错误变成 500。GetTask 对不存在返回 (nil, nil)，
		// 只判 err 会把「任务不存在」漏成 500。
		if t, err := s.m.pg.GetTask(taskID); err != nil {
			writeErr(w, 404, "任务不存在")
			return
		} else if t == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
	}
	content := req.Content
	source := db.KnowledgeSourceManual
	sourceRef := strings.TrimSpace(req.SourceRef)
	if strings.TrimSpace(content) == "" {
		if strings.TrimSpace(req.URL) == "" {
			writeErr(w, 400, "content 与 url 至少给一个")
			return
		}
		text, _, err := knowledge.FetchText(r.Context(), req.URL)
		if err != nil {
			writeErr(w, 400, "抓取失败: "+err.Error())
			return
		}
		content = text
		source = db.KnowledgeSourceURL
		if sourceRef == "" {
			sourceRef = strings.TrimSpace(req.URL)
		}
	}
	embed := true
	if req.Embed != nil {
		embed = *req.Embed
	}
	res, err := knowledge.NewService(s.m.pg).Ingest(r.Context(), knowledge.IngestInput{
		TaskID:    taskID,
		Title:     req.Title,
		Category:  req.Category,
		Source:    source,
		SourceRef: sourceRef,
		Content:   content,
		Embed:     embed,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, res)
}

// deleteKnowledgeDoc 删除文档（分块级联）；语义与凭据删除一致：没删掉就 404。
func (s *Server) deleteKnowledgeDoc(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "文档 id 非法")
		return
	}
	ok, err := s.m.pg.Knowledge().DeleteDoc(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "文档不存在或已被删除")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

// knowledgeStats 返回页面头部的汇总数字。
func (s *Server) knowledgeStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.m.pg.Knowledge().Stats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cfg := knowledge.LoadConfig(s.m.pg)
	writeJSON(w, 200, map[string]any{
		"stats":       st,
		"embed_ready": cfg.Ready(),
		"embed_model": cfg.Model,
		"embed_base":  cfg.BaseURL,
	})
}

// searchKnowledge 页面侧的检索入口（与 agent 的 knowledge_search 同一套打分）。
func (s *Server) searchKnowledge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query  string `json:"query"`
		TaskID int64  `json:"task_id"`
		Limit  int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	res, err := knowledge.NewService(s.m.pg).Search(r.Context(), req.TaskID, req.Query, req.Limit)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// getKnowledgeConfig 返回向量配置（不含明文密钥）。
func (s *Server) getKnowledgeConfig(w http.ResponseWriter, r *http.Request) {
	cfg := knowledge.LoadConfig(s.m.pg)
	writeJSON(w, 200, map[string]any{
		"enabled":  cfg.Enabled,
		"base_url": cfg.BaseURL,
		"model":    cfg.Model,
		"dim":      cfg.Dim,
		"has_key":  cfg.APIKey != "",
		"key_hint": maskSecret(cfg.APIKey),
		"ready":    cfg.Ready(),
	})
}

// saveKnowledgeConfig 保存向量配置。api_key 传空串表示保留原值。
func (s *Server) saveKnowledgeConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		BaseURL string `json:"base_url"`
		Model   string `json:"model"`
		APIKey  string `json:"api_key"`
		Dim     int    `json:"dim"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if req.Dim < 0 || req.Dim > 8192 {
		writeErr(w, 400, "dim 非法")
		return
	}
	cfg := knowledge.Config{
		Enabled: req.Enabled,
		BaseURL: strings.TrimSpace(req.BaseURL),
		Model:   strings.TrimSpace(req.Model),
		APIKey:  strings.TrimSpace(req.APIKey),
		Dim:     req.Dim,
	}
	if err := knowledge.SaveConfig(s.m.pg, cfg); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	saved := knowledge.LoadConfig(s.m.pg)
	writeJSON(w, 200, map[string]any{
		"enabled": saved.Enabled, "base_url": saved.BaseURL, "model": saved.Model,
		"dim": saved.Dim, "has_key": saved.APIKey != "", "ready": saved.Ready(),
		"note": "配置对后续入库与检索立即生效；已入库但未向量化的分块不会自动补算。",
	})
}
