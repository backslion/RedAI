package server

import "net/http"

// registerArtifactRoutes 注册证据附件：列表、归属调整、扫描补登记、导出与在线预览。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerArtifactRoutes(mux *http.ServeMux) {
	// 证据附件（v0.5.0）：列表 / 单文件下载 / 证据包 zip。
	mux.HandleFunc("GET /api/tasks/{id}/artifacts", s.listTaskArtifacts)
	mux.HandleFunc("PATCH /api/tasks/{id}/artifacts/{aid}", s.patchTaskArtifact)    // 改归属（任务级 ↔ 漏洞）
	mux.HandleFunc("POST /api/tasks/{id}/artifacts/scan", s.scanTaskArtifacts)      // 历史目录补登记
	mux.HandleFunc("POST /api/tasks/{id}/artifacts/auto-bind", s.autoBindArtifacts) // 智能关联（v0.4.42）
	mux.HandleFunc("GET /api/tasks/{id}/artifacts/export", s.exportTaskArtifacts)
	mux.HandleFunc("GET /api/tasks/{id}/artifacts/{aid}", s.serveTaskArtifact)
	mux.HandleFunc("GET /api/tasks/{id}/artifacts/{aid}/preview/{page}", s.serveArtifactPreview)
	mux.HandleFunc("GET /api/tasks/{id}/artifacts/{aid}/data-preview", s.serveArtifactDataPreview) // 数据文件在线查看（v0.4.41）
	mux.HandleFunc("POST /api/tasks/{id}/artifacts/{aid}/preview", s.regenerateArtifactPreview)
}
