package server

import "net/http"

// registerReportRoutes 注册报告导出、工具清单、宿主环境体检、C2 配置与回连接收器。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/report", s.getReport)
	mux.HandleFunc("GET /api/report/export", s.exportTaskDocx)
	mux.HandleFunc("GET /api/findings/{id}/export", s.exportFindingDocx)
	mux.HandleFunc("GET /api/tools/inventory", s.toolsInventory)
	// 宿主环境:体检(含一键安装可用性)+ 一键安装(经特权助手 pojun-hostd)
	mux.HandleFunc("GET /api/hostenv/status", s.hostenvStatus)
	mux.HandleFunc("GET /api/c2/config", s.c2ConfigGet)
	mux.HandleFunc("PUT /api/c2/config", s.c2ConfigPut)
	mux.HandleFunc("GET /api/listeners", s.listenerList)
	mux.HandleFunc("POST /api/listeners", s.listenerStart)
	mux.HandleFunc("GET /api/listeners/{name}", s.listenerSessions)
}
