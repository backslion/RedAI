package server

// 路由注册守卫：新增 /api/webshell-tunnels/* 不能与既有 webshells 路由冲突。
// ServeMux 对模式冲突是启动即 panic，不是运行时报错——必须有个测试兜住。
// （历史上 /api/webshells/payloads/{name...} 与 {name}/download 就撞过一次。）

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebShellTunnelRoutesRegisterAndRespond(t *testing.T) {
	// 空 Server 也能注册路由：Handler() 只挂 handler，不访问 store。
	s := &Server{}
	var h http.Handler
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handler() 注册路由时 panic（模式冲突）: %v", r)
			}
		}()
		h = s.Handler()
	}()
	if h == nil {
		t.Fatal("Handler 为 nil")
	}

	// 隧道未启用时，各路由应返回 503 而不是 404/500/panic。
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/api/webshell-tunnels"},
		{"GET", "/api/webshell-tunnels/summary"},
		{"POST", "/api/webshell-tunnels"},
		{"DELETE", "/api/webshell-tunnels/wpt-xxx"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusServiceUnavailable {
			// 无 token 时鉴权中间件可能先拦（401），隧道未启用是 503；两者都可接受。
			t.Errorf("%s %s: 状态码 %d，期望 401（未鉴权）或 503（未启用）", tc.method, tc.path, rec.Code)
		}
	}
}
