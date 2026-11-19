package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/backslion/RedAI/db"
)

// 凭据台账 API（v0.4.82）。
//
// 设计约束：这些端点只暴露脱敏投影（CredentialRow / CredentialStats），
// 永不返回 secret——secret 的唯一读取入口是 db.CredentialStore.SecretByID，
// 只服务于 auth_request 组命令。前端即使抓包也看不到明文。

// listCredentials 分页返回全平台凭据关系，支持关系/类型/企业/内网/关键词筛选。
func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := credentialQueryInt(q.Get("limit"), 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := credentialQueryInt(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	intranet := q.Get("intranet")
	f := db.CredentialListFilter{
		Relation:     strings.TrimSpace(q.Get("relation")),
		CredType:     strings.TrimSpace(q.Get("type")),
		Query:        strings.TrimSpace(q.Get("q")),
		CompanyID:    int64(credentialQueryInt(q.Get("company_id"), 0)),
		IntranetOnly: intranet == "1" || intranet == "true",
		Limit:        limit,
		Offset:       offset,
	}
	rows, total, err := s.m.pg.Credentials().ListAll(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items":     rows,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"page":      offset/limit + 1,
		"page_size": limit,
	})
}

// credentialStats 返回台账页头部的汇总数字。
func (s *Server) credentialStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.m.pg.Credentials().Stats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// deleteCredential 删除一条凭据身份（关系级联删除）。
// 明确返回 deleted=false + 404 而不是静默成功：台账里点删除却没删掉，
// 会让人误以为凭据已处置。
func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "凭据 id 非法")
		return
	}
	ok, err := s.m.pg.Credentials().Delete(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "凭据不存在或已被删除")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

// credentialQueryInt 解析整数查询参数，缺失或非法时返回 def。
func credentialQueryInt(raw string, def int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}
