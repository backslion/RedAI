package agent

import (
	"sync/atomic"

	"github.com/backslion/RedAI/honeydetect"
	"github.com/backslion/RedAI/listener"
	"github.com/backslion/RedAI/pivot"
	"github.com/backslion/RedAI/stage"
	"github.com/backslion/RedAI/vulnintel"
	"github.com/backslion/RedAI/webshell"
)

// Runtime 是一个平台实例的「执行面依赖」：回连接收器、内网穿透、受管投递、
// WebShell 通道与隧道、漏洞情报库。
//
// 这六样以前是六个包级 var，只能靠 agent.SetXxx 从 server 灌一份进来，
// 后果是「一个进程只能有一套」：测试之间共享状态、没法并行起两个实例、
// 也没法给单个 ToolSet 换一套替身做验证。
//
// 现在收成一个结构体，配两种来源：
//   - 进程默认实例：server 启动时照旧调 SetXxx 填 defaultRuntime，装配代码不用改；
//   - 实例级实例：ToolSet.SetRuntime 显式指定，工具优先用它。
//
// 回落到默认实例是刻意的——既有的启动路径一行不改，工具行为完全等价；
// 需要隔离的场景（单测、多实例）显式注入即可，不必再动 40 多处工具实现。
type Runtime struct {
	Listener       *listener.Manager
	Pivot          *pivot.Manager
	Stage          *stage.Manager
	WebShell       *webshell.Manager
	WebShellTunnel *webshell.TunnelManager
	VulnIntel      *vulnintel.Store
	// Tarpit 是反 AI 蜜罐的访问计数器：honeypot_check 判定可疑后登记，
	// http_request 每次访问前查一次，决定是否减速/熔断。nil 时回落到
	// honeydetect.DefaultTarpit()（纯内存表，无资源需释放）。
	Tarpit *honeydetect.Tarpit
}

// defaultRuntime 是进程默认依赖。存不可变快照的指针，读侧无锁：
// 工具调用是热路径，没必要为一次指针读去抢锁；Setter 只在启动期与
// 极少数重配置点发生，CAS 足以保证一致性。
var defaultRuntime atomic.Pointer[Runtime]

// setDefaultRuntime 对默认依赖做一次读-改-CAS，保留未被本次修改的字段。
// 多个 Setter 各自只改自己那一格，互不覆盖。
func setDefaultRuntime(mut func(*Runtime)) {
	for {
		cur := defaultRuntime.Load()
		next := &Runtime{}
		if cur != nil {
			*next = *cur
		}
		mut(next)
		if defaultRuntime.CompareAndSwap(cur, next) {
			return
		}
	}
}

// defaultRuntimeSnapshot 返回一份稳定的默认依赖视图；从未注入过时返回零值。
func defaultRuntimeSnapshot() Runtime {
	if cur := defaultRuntime.Load(); cur != nil {
		return *cur
	}
	return Runtime{}
}

// SetRuntime 指定这个 ToolSet 使用哪一份依赖；nil = 恢复回落到进程默认。
// 只影响调用它的 ToolSet，不改变进程默认实例（那是 SetXxx 的事）。
func (t *ToolSet) SetRuntime(r *Runtime) { t.runtime = r }

// runtimeOr 返回本 ToolSet 生效的依赖：显式注入的优先，否则进程默认。
func (t *ToolSet) runtimeOr() Runtime {
	if t.runtime != nil {
		return *t.runtime
	}
	return defaultRuntimeSnapshot()
}

// 下面六个访问器是工具实现读依赖的唯一入口。以前各处直接读包级 var，
// 现在统一走这里，才能让「显式注入」对每个工具都生效。
func (t *ToolSet) rtListener() *listener.Manager { return t.runtimeOr().Listener }

func (t *ToolSet) rtPivot() *pivot.Manager { return t.runtimeOr().Pivot }

func (t *ToolSet) rtStage() *stage.Manager { return t.runtimeOr().Stage }

func (t *ToolSet) rtShell() *webshell.Manager { return t.runtimeOr().WebShell }

func (t *ToolSet) rtShellTunnel() *webshell.TunnelManager { return t.runtimeOr().WebShellTunnel }

func (t *ToolSet) rtIntel() *vulnintel.Store { return t.runtimeOr().VulnIntel }

// rtTarpit 返回反蜜罐熔断表。未注入时用进程默认实例：它只是一张内存计数表，
// 没有端口/连接/goroutine 需要归属，与 listener/pivot 那类管理器不同。
func (t *ToolSet) rtTarpit() *honeydetect.Tarpit {
	if m := t.runtimeOr().Tarpit; m != nil {
		return m
	}
	return honeydetect.DefaultTarpit()
}
