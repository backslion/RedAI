package honeydetect

import (
	"testing"
	"time"
)

// 未标记的目标必须完全不受影响——这是「不误伤」的底线。
func TestTarpitUnmarkedTargetPasses(t *testing.T) {
	tp := NewTarpit()
	for i := 0; i < 20; i++ {
		v := tp.Gate("10.0.0.1")
		if v.Blocked || v.Delay != 0 || v.Hits != 0 {
			t.Fatalf("未标记目标不应被干预，第 %d 次得到 %+v", i+1, v)
		}
	}
}

// 前三次放行：honeypot_check 有误报，一刀切会砍掉合法取证。
func TestTarpitFreeHits(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("10.0.0.2", 0.8)
	for i := 1; i <= tarpitFreeHits; i++ {
		v := tp.Gate("10.0.0.2")
		if v.Blocked || v.Delay != 0 {
			t.Fatalf("第 %d 次应放行，得到 %+v", i, v)
		}
	}
}

// 4~8 次指数退避，且不超过上限。
func TestTarpitBackoff(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("10.0.0.3", 0.9)
	want := []time.Duration{
		0, 0, 0, // 1-3 放行
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, // 4-8
	}
	for i, w := range want {
		v := tp.Gate("10.0.0.3")
		if v.Blocked {
			t.Fatalf("第 %d 次不应熔断", i+1)
		}
		if v.Delay != w {
			t.Fatalf("第 %d 次延迟 %v, want %v", i+1, v.Delay, w)
		}
	}
}

// 超过阈值熔断，且理由要可执行（模型据此换目标）。
func TestTarpitBlocksAfterMax(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("10.0.0.4", 0.95)
	for i := 0; i < tarpitMaxHits; i++ {
		tp.Gate("10.0.0.4")
	}
	v := tp.Gate("10.0.0.4")
	if !v.Blocked {
		t.Fatalf("第 %d 次应熔断，得到 %+v", tarpitMaxHits+1, v)
	}
	if v.Reason == "" {
		t.Error("熔断必须给理由")
	}
}

// 人工确认误报后可解除。
func TestTarpitClear(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("10.0.0.5", 0.9)
	tp.Gate("10.0.0.5")
	tp.Clear("10.0.0.5")
	if v := tp.Gate("10.0.0.5"); v.Blocked || v.Delay != 0 || v.Hits != 0 {
		t.Errorf("Clear 后应回到未标记状态，得到 %+v", v)
	}
}

// 空闲过期：避免 map 随任务无界增长。
func TestTarpitIdleGC(t *testing.T) {
	tp := NewTarpit()
	base := time.Now()
	tp.now = func() time.Time { return base }
	tp.MarkSuspect("10.0.0.6", 0.9)
	tp.Gate("10.0.0.6")

	// 跳到 TTL 之后：下一次 Gate 应先清理，再按「未标记」处理。
	tp.now = func() time.Time { return base.Add(tarpitIdleTTL + time.Minute) }
	if v := tp.Gate("10.0.0.6"); v.Hits != 0 || v.Delay != 0 {
		t.Errorf("过期目标应被清理，得到 %+v", v)
	}
	if len(tp.Snapshot()) != 0 {
		t.Errorf("清理后快照应为空，实际 %v", tp.Snapshot())
	}
}

// 空 host 不应该 panic 或计数。
func TestTarpitEmptyHost(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("", 1)
	if v := tp.Gate(""); v.Blocked || v.Hits != 0 {
		t.Errorf("空 host 应无操作，得到 %+v", v)
	}
}

// 后一次更低的评分不应覆盖已记录的更高评分（否则熔断依据会被稀释）。
func TestTarpitScoreKeepsMax(t *testing.T) {
	tp := NewTarpit()
	tp.MarkSuspect("10.0.0.7", 0.95)
	tp.MarkSuspect("10.0.0.7", 0.6)
	if got := tp.Snapshot()["10.0.0.7"].Score; got != 0.95 {
		t.Errorf("score = %v, want 0.95", got)
	}
}
