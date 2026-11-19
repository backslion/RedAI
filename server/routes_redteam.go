package server

import "net/http"

// registerRedTeamRoutes 注册红队作战面：受管投递、内网穿透、WebShell 通道与隧道、宿主工具安装、对话入口。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerRedTeamRoutes(mux *http.ServeMux) {
	// 受管文件投递（stage）管理 API（JWT 之后）。下载路由 /s/ 不在这里——它挂在
	// 根 mux 上单独暴露（见 Handler 末尾），因为目标机没有 JWT。
	mux.HandleFunc("GET /api/stage", s.stageList)
	mux.HandleFunc("GET /api/stage/summary", s.stageSummary)
	mux.HandleFunc("POST /api/stage", s.stageCreate)
	mux.HandleFunc("DELETE /api/stage/{token}", s.stageDelete)

	// 内网穿透（pivot）：隧道是平台资源，网页与 worker 共用同一张台账。
	mux.HandleFunc("GET /api/pivots", s.pivotListAll)
	mux.HandleFunc("GET /api/pivots/summary", s.pivotSummary)
	mux.HandleFunc("POST /api/pivots", s.pivotOpen)
	mux.HandleFunc("DELETE /api/pivots/{id}", s.pivotDelete)

	// WebShell 会话：会话库是平台资源，网页与 worker 共用同一份台账。
	// 参数名（param）只写不读——列表与详情一律脱敏。
	mux.HandleFunc("GET /api/webshells", s.webshellListAll)
	mux.HandleFunc("GET /api/webshells/summary", s.webshellSummary)
	mux.HandleFunc("GET /api/webshells/payloads", s.webshellPayloads)
	// 载荷名走 query 而不是路径段：`builtin/php-eval`、`php/mine.php` 里带 /，
	// 用 {name...} 通配会与下面的 {name}/download 冲突（ServeMux 直接 panic）。
	mux.HandleFunc("GET /api/webshells/payload", s.webshellPayloadDetail)
	mux.HandleFunc("POST /api/webshells", s.webshellAdd)
	mux.HandleFunc("POST /api/webshells/probe", s.webshellProbe)
	mux.HandleFunc("PATCH /api/webshells/{name}", s.webshellUpdate)
	mux.HandleFunc("DELETE /api/webshells/{name}", s.webshellDelete)
	mux.HandleFunc("POST /api/webshells/{name}/exec", s.webshellExec)
	mux.HandleFunc("POST /api/webshells/{name}/upload", s.webshellUpload)
	mux.HandleFunc("GET /api/webshells/{name}/download", s.webshellDownload)
	// WebShell 隧道（webshell pivot）：把只有马、没开 22 的目标变成 SOCKS5 出口。
	// 前缀用 webshell-tunnels（不是 webshells/xxx），避免与上面的 {name}/... 路由冲突。
	mux.HandleFunc("GET /api/webshell-tunnels", s.webshellTunnelsList)
	mux.HandleFunc("GET /api/webshell-tunnels/summary", s.webshellTunnelsSummary)
	mux.HandleFunc("POST /api/webshell-tunnels", s.webshellTunnelOpen)
	mux.HandleFunc("DELETE /api/webshell-tunnels/{id}", s.webshellTunnelClose)
	mux.HandleFunc("POST /api/listeners/{name}/stop", s.listenerStop)
	mux.HandleFunc("POST /api/hostenv/install", s.hostenvInstall)
	mux.HandleFunc("POST /api/hostenv/install-batch", s.hostenvInstallBatch)
	mux.HandleFunc("GET /api/hostenv/jobs/{id}", s.hostenvJob)
	mux.HandleFunc("POST /api/hostenv/jobs/{id}/cancel", s.hostenvCancel)
	mux.HandleFunc("POST /api/hostenv/proxy-check", s.hostenvProxyCheck)
	mux.HandleFunc("GET /api/chat/mentions", s.searchChatMentions)
	mux.HandleFunc("POST /api/chat", s.chat)
	mux.HandleFunc("POST /api/chat/upload", s.chatUpload) // 方式1 文件上传:落到会话/任务工作目录 uploads/
	mux.HandleFunc("GET /api/tasks/{id}/chat/status", s.taskChatStatus)
	mux.HandleFunc("POST /api/tasks/{id}/chat/stop", s.stopChat)
}
