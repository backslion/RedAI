package server

import "net/http"

// registerAssetRoutes 注册资产、凭据台账、知识库、公司归属。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerAssetRoutes(mux *http.ServeMux) {
	// asset system
	mux.HandleFunc("GET /api/assets", s.listAssets)
	mux.HandleFunc("GET /api/assets/counts", s.assetCounts)
	mux.HandleFunc("POST /api/assets", s.insertAssets)
	mux.HandleFunc("DELETE /api/assets", s.deleteAssets)

	// credential ledger（脱敏台账：列表/汇总/删除；secret 不出接口）
	mux.HandleFunc("GET /api/credentials", s.listCredentials)
	mux.HandleFunc("GET /api/credentials/stats", s.credentialStats)
	mux.HandleFunc("DELETE /api/credentials/{id}", s.deleteCredential)

	// 知识库（v0.5.x，源自 antifox 的两层 RAG）：文档增删查 + 混合检索 + 向量配置。
	// 索引接口是 POST /search 而不是 GET：查询串里经常带 # / & 之类需要转义的字符，
	// 放 body 里更省心，也避免长查询把 URL 撑爆。
	mux.HandleFunc("GET /api/knowledge/docs", s.listKnowledgeDocs)
	mux.HandleFunc("POST /api/knowledge/docs", s.createKnowledgeDoc)
	mux.HandleFunc("GET /api/knowledge/docs/{id}", s.getKnowledgeDoc)
	mux.HandleFunc("DELETE /api/knowledge/docs/{id}", s.deleteKnowledgeDoc)
	mux.HandleFunc("GET /api/knowledge/stats", s.knowledgeStats)
	mux.HandleFunc("POST /api/knowledge/search", s.searchKnowledge)
	mux.HandleFunc("GET /api/knowledge/config", s.getKnowledgeConfig)
	mux.HandleFunc("PUT /api/knowledge/config", s.saveKnowledgeConfig)

	// company system
	mux.HandleFunc("GET /api/companies", s.listCompanies)
	mux.HandleFunc("POST /api/companies", s.createCompany)
	mux.HandleFunc("GET /api/companies/{id}", s.getCompany)
	mux.HandleFunc("DELETE /api/companies/{id}", s.deleteCompany)
	mux.HandleFunc("POST /api/companies/{id}/scope", s.addCompanyScope)
	mux.HandleFunc("POST /api/companies/reattribute", s.reattribute)
}
