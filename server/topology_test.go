package server

// 内网拓扑装配层的测试。
//
// 只测两件在真实部署里容易出事、又不需要起 HTTP 的事：
//   - 隧道管理器未初始化（pivot 未启用 / webshell 未启用）时不能 panic——
//     这两个字段在部分启动路径上确实为 nil，拓扑是只读页面，不该因此 500。
//   - 连接日志里的 target 形态很杂（host:port / [ipv6]:port / 裸 IP / 域名），
//     拆错就会画出错误的边。

import (
	"testing"

	"github.com/backslion/RedAI/db"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantPort int
	}{
		{"10.20.30.5:445", "10.20.30.5", 445},
		{"10.20.30.5", "10.20.30.5", 0},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		// 域名不画进拓扑：域名到 IP 的映射会变，画上去第二天就错了。
		{"example.com:443", "", 0},
		{"example.com", "", 0},
		{"", "", 0},
		{"  10.20.30.5:8080  ", "10.20.30.5", 8080},
	}
	for _, c := range cases {
		ip, port := splitTarget(c.in)
		if ip != c.wantIP || port != c.wantPort {
			t.Errorf("splitTarget(%q) = (%q,%d), want (%q,%d)", c.in, ip, port, c.wantIP, c.wantPort)
		}
	}
}

// TestEnrichTopologyWithoutManagers 守 nil 安全：pivot / webshell 隧道在部分
// 启动路径上没有初始化，此时拓扑接口应返回空 landings 而不是 panic。
func TestEnrichTopologyWithoutManagers(t *testing.T) {
	s := &Server{} // pivots / wsTunnels 都是 nil
	topo := &db.Topology{
		Segments: []db.TopologySegment{{CIDR: "10.20.30.0/24", HostCount: 1}},
	}
	s.enrichTopology(topo, 1) // 不许 panic
	if len(topo.Landings) != 0 {
		t.Errorf("没有隧道管理器时不该产生立足点，实际 %d 个", len(topo.Landings))
	}
	if len(topo.Edges) != 0 {
		t.Errorf("没有隧道时不该产生可达边，实际 %d 条", len(topo.Edges))
	}
}
