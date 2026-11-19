package agent

import (
	"testing"

	"github.com/chu0119/pojun/listener"
	"github.com/chu0119/pojun/pivot"
	"github.com/chu0119/pojun/webshell"
)

// 这组测试守的是「把六个包级 var 收成一个 Runtime」之后的等价性：
// server 仍然走 SetXxx 填默认实例，任何一条调用路径看到的东西都必须和以前一样。

// restoreDefaultRuntime 在每个用例后把进程默认依赖恢复原样，避免污染的用例
// 影响同包其他测试（比如工具「未启用」分支的断言）。
func restoreDefaultRuntime(t *testing.T) {
	t.Helper()
	prev := defaultRuntimeSnapshot()
	t.Cleanup(func() {
		setDefaultRuntime(func(r *Runtime) { *r = prev })
	})
}

// 默认实例路径：走 SetXxx 注入的 manager，没显式指定的 ToolSet 必须看得到。
func TestRuntimeDefaultsFromProcessInstance(t *testing.T) {
	restoreDefaultRuntime(t)

	lm := listener.NewManager()
	pm := pivot.NewManager()
	SetListenerManager(lm)
	SetPivotManager(pm)

	ts := NewToolSet(nil, "worker")
	if got := ts.rtListener(); got != lm {
		t.Errorf("rtListener 未回落到进程默认实例：got %p want %p", got, lm)
	}
	if got := ts.rtPivot(); got != pm {
		t.Errorf("rtPivot 未回落到进程默认实例：got %p want %p", got, pm)
	}
}

// 六个 Setter 各写各的字段。合成一个结构后最容易写错的就是这里：
// 若某个 Setter 整份覆盖而不是按字段合并，前一个子系统会被静默关掉
// ——工具然后报「未启用」，没有任何报错。
func TestRuntimeSettersDoNotClobberEachOther(t *testing.T) {
	restoreDefaultRuntime(t)
	// 从一个干净状态开始，避免历史注入掩盖「互相覆盖」。
	setDefaultRuntime(func(r *Runtime) { *r = Runtime{} })

	lm := listener.NewManager()
	pm := pivot.NewManager()
	wm, err := webshell.NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("创建 webshell manager: %v", err)
	}

	SetListenerManager(lm)
	SetPivotManager(pm)
	SetWebShellManager(wm)

	ts := NewToolSet(nil, "worker")
	if ts.rtListener() != lm {
		t.Error("SetPivotManager/SetWebShellManager 把 Listener 覆盖掉了")
	}
	if ts.rtPivot() != pm {
		t.Error("SetListenerManager/SetWebShellManager 把 Pivot 覆盖掉了")
	}
	if ts.rtShell() != wm {
		t.Error("SetWebShellManager 没有生效")
	}
}

// 显式注入只影响当前 ToolSet，不动进程默认实例；置 nil 恢复回落。
func TestToolSetRuntimeOverridesDefault(t *testing.T) {
	restoreDefaultRuntime(t)

	def := listener.NewManager()
	SetListenerManager(def)
	own := listener.NewManager()

	ts := NewToolSet(nil, "worker")
	ts.SetRuntime(&Runtime{Listener: own})
	if got := ts.rtListener(); got != own {
		t.Errorf("显式注入未优先生效：got %p want %p", got, own)
	}
	if got := NewToolSet(nil, "worker").rtListener(); got != def {
		t.Errorf("显式注入污染了进程默认实例：got %p want %p", got, def)
	}

	ts.SetRuntime(nil)
	if got := ts.rtListener(); got != def {
		t.Errorf("置 nil 后未回落到默认实例：got %p want %p", got, def)
	}
}

// 工具的「未启用」判定必须跟着生效依赖走：以前读包级 var，现在读 Runtime，
// 但对外表现（能不能用、报什么错）必须一模一样。
func TestRuntimeUnavailableGateFollowsInjection(t *testing.T) {
	restoreDefaultRuntime(t)
	setDefaultRuntime(func(r *Runtime) { *r = Runtime{} })

	ts := NewToolSet(nil, "worker")
	if _, un := ts.wsUnavailable(); !un {
		t.Fatal("没有 WebShell manager 时应报「未启用」")
	}
	if _, un := ts.wsTunnelUnavailable(); !un {
		t.Fatal("没有隧道 manager 时应报「未启用」")
	}
	if _, un := ts.pivotUnavailable(); !un {
		t.Fatal("没有 pivot manager 时应报「未启用」")
	}

	wm, err := webshell.NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("创建 webshell manager: %v", err)
	}
	ts.SetRuntime(&Runtime{WebShell: wm})
	if _, un := ts.wsUnavailable(); un {
		t.Error("注入 WebShell manager 后不应再报「未启用」")
	}
	if _, un := ts.wsTunnelUnavailable(); !un {
		t.Error("只注入 WebShell、没有隧道 manager 时仍应报隧道未启用")
	}
}

// 值拷贝语义：defaultRuntimeSnapshot 返回的是快照，调用方拿到后
// 后续 Setter 不该改到它（否则工具读到「半新半旧」的依赖组合）。
func TestDefaultRuntimeSnapshotIsStable(t *testing.T) {
	restoreDefaultRuntime(t)

	first := listener.NewManager()
	SetListenerManager(first)

	snap := defaultRuntimeSnapshot()
	SetListenerManager(listener.NewManager())

	if snap.Listener != first {
		t.Error("快照被后续 Setter 改到了，说明没有按值拷贝")
	}
	if defaultRuntimeSnapshot().Listener == first {
		t.Error("新快照没有反映最近一次 Setter")
	}
}
