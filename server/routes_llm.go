package server

import "net/http"

// registerLLMRoutes 注册版本号与 LLM 单通道配置（多 profile 见 routes_registry.go）。
// 只做路由装配，handler 实现分别在各自文件；拆出来是为了让新增接口
// 只改一个领域文件，而不是改一个 3000+ 行的注册函数。
func (s *Server) registerLLMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/version", s.version)
	mux.HandleFunc("GET /api/llm", s.getLLM)
	mux.HandleFunc("POST /api/llm", s.setLLM)
	mux.HandleFunc("POST /api/llm/test", s.testLLM)
}
