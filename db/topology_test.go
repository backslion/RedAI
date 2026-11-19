package db

// 内网拓扑聚合的测试。
//
// 重点守两件事：
//   - 范围：只有落在任务授权网段内的资产才进拓扑。范围外的地址进来了，
//     拓扑就变成「整个资产库的转储」，那和资产页没有区别。
//   - 归并：同一个 IP 的多条服务资产要合成一个主机节点，端口并集不能重复。
//     归并错了图形会碎成一堆孤立节点。

import (
	"net"
	"testing"
)

func TestPortsFromJSON(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{`[{"port":22,"service":"ssh"},{"port":80,"service":"http"}]`, []int{22, 80}},
		{`[]`, nil},
		{``, nil},
		{`null`, nil},
		{`not-json`, nil},
		// 越界端口必须丢掉：65536 这种值画上去只会误导。
		{`[{"port":0},{"port":70000},{"port":443}]`, []int{443}},
	}
	for _, c := range cases {
		got := portsFromJSON(c.in)
		if len(got) != len(c.want) {
			t.Errorf("portsFromJSON(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("portsFromJSON(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestIPLessNumericOrder(t *testing.T) {
	// 字符串排序会把 10.0.0.10 排在 10.0.0.9 前面——图上顺序一眼就错。
	if !ipLess("10.0.0.9", "10.0.0.10") {
		t.Error("ipLess 应按数值比较，10.0.0.9 < 10.0.0.10")
	}
	if ipLess("10.0.0.10", "10.0.0.9") {
		t.Error("ipLess 方向反了")
	}
}

func TestSegmentAuthorized(t *testing.T) {
	nets := []*net.IPNet{}
	for _, c := range []string{"10.0.0.0/8", "192.168.5.0/24"} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		nets = append(nets, n)
	}
	if !segmentAuthorized("10.20.30.0/24", nets) {
		t.Error("/24 落在 /8 授权内应算授权")
	}
	if !segmentAuthorized("192.168.5.0/24", nets) {
		t.Error("完全相同的网段应算授权")
	}
	if segmentAuthorized("192.168.6.0/24", nets) {
		t.Error("不在任何授权网段内的网段不该算授权")
	}
	if segmentAuthorized("未归段", nets) {
		t.Error("非 CIDR 文本不该算授权")
	}
}

func TestBuildTopologyScopesAndMerges(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()

	task, err := d.CreateTask("topology test", "topology test", nil, 0, 0)
	if err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	taskID := task.ID
	if _, err := as.AddAgentScope(taskID, "cidr", "10.20.30.0/24", "topology test", "manual"); err != nil {
		t.Fatalf("写范围失败: %v", err)
	}
	cleanup := func() {
		d.Exec(`DELETE FROM task_scope WHERE task_id=$1`, taskID)
		d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
	}
	defer cleanup()
	// 资产是共享的，必须按 id 精确清理，不能按 task 删。
	defer func() {
		d.Exec(`DELETE FROM assets WHERE ip IN ('10.20.30.5','10.20.31.9')`)
	}()

	// 同一个 IP 的两条服务资产（端口不同）——必须归并成一个主机节点。
	inID1, err := as.UpsertIP(UpsertIPReq{
		IP: "10.20.30.5", TaskID: taskID,
		OpenPorts: []PortService{{Port: 22, Service: "ssh"}},
	})
	if err != nil {
		t.Fatalf("写 IP 资产失败: %v", err)
	}
	inID2, err := as.UpsertIP(UpsertIPReq{
		IP: "10.20.30.5", TaskID: taskID,
		OpenPorts: []PortService{{Port: 80, Service: "http"}},
	})
	if err != nil {
		t.Fatalf("写第二条 IP 资产失败: %v", err)
	}
	// 范围外的地址：不该出现在拓扑里。
	outID, err := as.UpsertIP(UpsertIPReq{
		IP: "10.20.31.9", TaskID: taskID,
		OpenPorts: []PortService{{Port: 443, Service: "https"}},
	})
	if err != nil {
		t.Fatalf("写范围外资产失败: %v", err)
	}
	_ = inID1
	_ = inID2
	_ = outID

	topo, err := as.BuildTopology(taskID)
	if err != nil {
		t.Fatalf("聚合失败: %v", err)
	}
	if len(topo.ScopeNets) == 0 || topo.ScopeNets[0] != "10.20.30.0/24" {
		t.Errorf("ScopeNets 应含 10.20.30.0/24，实际 %v", topo.ScopeNets)
	}
	if len(topo.Segments) != 1 {
		t.Fatalf("应只有 1 个网段（范围外的 10.20.31.9 不该进来），实际 %d 个: %+v",
			len(topo.Segments), topo.Segments)
	}
	seg := topo.Segments[0]
	if seg.CIDR != "10.20.30.0/24" {
		t.Errorf("网段应为 10.20.30.0/24，实际 %q", seg.CIDR)
	}
	if !seg.Authorized {
		t.Error("该网段在授权范围内，authorized 应为 true")
	}
	if seg.HostCount != 1 || len(seg.Hosts) != 1 {
		t.Fatalf("同一 IP 应归并为一个主机，实际 host_count=%d hosts=%d", seg.HostCount, len(seg.Hosts))
	}
	host := seg.Hosts[0]
	if host.IP != "10.20.30.5" {
		t.Errorf("主机 IP 应为 10.20.30.5，实际 %q", host.IP)
	}
	if len(host.Ports) != 2 || host.Ports[0] != 22 || host.Ports[1] != 80 {
		t.Errorf("端口应为去重升序的 [22 80]，实际 %v", host.Ports)
	}
}

func TestBuildTopologyEmptyTask(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	topo, err := as.BuildTopology(0)
	if err != nil {
		t.Fatalf("taskID=0 不该报错: %v", err)
	}
	if topo == nil || len(topo.Segments) != 0 {
		t.Errorf("taskID=0 应返回空拓扑，实际 %+v", topo)
	}
}
