package server

import (
	"testing"

	"github.com/chu0119/pojun/listener"
	"github.com/chu0119/pojun/pivot"
)

// 未装配完成的 Server（测试/降级路径）也必须能给出 Runtime：
// 缺的子系统留 nil，由工具报「未启用」，不能 panic。
func TestAgentRuntimeOnEmptyServer(t *testing.T) {
	s := &Server{}
	rt := s.agentRuntime()
	if rt == nil {
		t.Fatal("agentRuntime 返回 nil")
	}
	if rt.Listener != nil || rt.Pivot != nil || rt.Stage != nil ||
		rt.WebShell != nil || rt.WebShellTunnel != nil || rt.VulnIntel != nil {
		t.Errorf("空 Server 应给出全 nil 的依赖，实际 %+v", rt)
	}
}

// 装配好的 Server 必须原样带出它持有的那几样。
// 这条一旦错，工具会静默报「未启用」，而启动日志一切正常——最难查的那类退化。
func TestAgentRuntimeCarriesServerManagers(t *testing.T) {
	lm := listener.NewManager()
	pm := pivot.NewManager()
	s := &Server{listeners: lm, pivots: pm}

	rt := s.agentRuntime()
	if rt.Listener != lm {
		t.Error("Runtime.Listener 与 Server.listeners 不一致")
	}
	if rt.Pivot != pm {
		t.Error("Runtime.Pivot 与 Server.pivots 不一致")
	}
	// 没装配的仍应为 nil，不能被别处的注入串进来。
	if rt.WebShell != nil || rt.WebShellTunnel != nil || rt.Stage != nil {
		t.Errorf("未装配的子系统应为 nil，实际 %+v", rt)
	}
}
