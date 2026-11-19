package server

import "net/http"

// registerOpsRoutes 注册平台运维：审计、GC、流量、工具执行记录、LLM 录制、设置、通知、漏洞情报、代理池。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit", s.getAudit)
	// Prometheus 文本格式指标（走 requireAuth：里面有工具名与任务规模，属于部署指纹）。
	mux.HandleFunc("GET /api/metrics", s.metricsHandler)
	mux.HandleFunc("POST /api/gc", s.gc)
	mux.HandleFunc("GET /api/traffic", s.getTraffic)
	mux.HandleFunc("GET /api/traffic/hosts", s.getTrafficHosts)
	mux.HandleFunc("DELETE /api/traffic", s.deleteTraffic)
	mux.HandleFunc("DELETE /api/traffic/hosts", s.deleteTrafficHosts)
	mux.HandleFunc("DELETE /api/traffic/all", s.deleteAllTraffic)
	mux.HandleFunc("GET /api/traffic/exchange", s.getTrafficExchange)
	mux.HandleFunc("GET /api/traffic/blob", s.getTrafficBlob)
	mux.HandleFunc("GET /api/commands", s.pgListCommands)
	mux.HandleFunc("GET /api/commands/stats", s.pgToolStats) // 按工具聚合调用次数
	mux.HandleFunc("GET /api/llm/records", s.pgListLLMRecords)
	mux.HandleFunc("DELETE /api/llm/records", s.pgDeleteLLMRecords)
	mux.HandleFunc("GET /api/llm/records/tasks", s.pgLLMTasks)
	mux.HandleFunc("GET /api/llm/records/by-model", s.pgTokenByModel) // 按模型聚合本任务 token 用量
	mux.HandleFunc("GET /api/llm/records/{id}", s.pgGetLLMRecord)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	// 访问门控（伪装门控）：默认关闭，开启后未通过门控的页面请求只看到 nginx 404。
	// 只作用于前端页面，不影响 /api（Bearer）与 /s（capability URL）。
	mux.HandleFunc("GET /api/system/gate", s.getGate)
	mux.HandleFunc("PUT /api/system/gate", s.putGate)
	// 漏洞 IM 推送。渠道是「多实例 + 各自过滤规则」的资源，因此独立成一组
	// REST 接口，而不是塞进扁平的 /api/settings 键值里。
	mux.HandleFunc("GET /api/notify/meta", s.notifyMeta)
	mux.HandleFunc("GET /api/notify/channels", s.notifyListChannels)
	mux.HandleFunc("POST /api/notify/channels", s.notifyCreateChannel)
	mux.HandleFunc("PATCH /api/notify/channels/{id}", s.notifyUpdateChannel)
	mux.HandleFunc("DELETE /api/notify/channels/{id}", s.notifyDeleteChannel)
	mux.HandleFunc("POST /api/notify/channels/{id}/test", s.notifyTestChannel)
	mux.HandleFunc("GET /api/notify/deliveries", s.notifyListDeliveries)
	mux.HandleFunc("POST /api/notify/deliveries/{id}/retry", s.notifyRetryDelivery)
	mux.HandleFunc("GET /api/vulnintel/status", s.vulnintelStatus)
	mux.HandleFunc("PUT /api/vulnintel/config", s.vulnintelSaveConfig)
	mux.HandleFunc("POST /api/vulnintel/sync", s.vulnintelSyncNow)
	mux.HandleFunc("POST /api/vulnintel/sync/cancel", s.vulnintelSyncCancel)
	mux.HandleFunc("POST /api/vulnintel/probe", s.vulnintelProbe)
	mux.HandleFunc("GET /api/proxypool", s.proxyPoolGet)
	mux.HandleFunc("PUT /api/proxypool", s.proxyPoolPut)
	mux.HandleFunc("POST /api/proxypool/bulk", s.proxyPoolBulk)
	mux.HandleFunc("POST /api/proxypool/check", s.proxyPoolCheck)
	mux.HandleFunc("POST /api/settings/web-search/test", s.testWebSearch)
}
