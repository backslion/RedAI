package server

import (
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/honeydetect"
)

// agentRuntime 把本实例的执行面依赖打成一个包交给 agent。
//
// 以前这六样只能通过 agent.SetXxx 灌进 agent 包的包级变量，等于「进程里只有
// 一套」。现在 planner / worker / mainagent 各自持有一份 Runtime，构造 ToolSet
// 时传下去；同一个进程里换个实例、或在测试里换一套替身，都不必再动全局状态。
//
// 字段允许为 nil（子系统没启用），工具会照常报「未启用」——与走全局变量的
// 那条路径完全一致，所以这一步不改变任何既有行为。
func (s *Server) agentRuntime() *agent.Runtime {
	rt := &agent.Runtime{
		Listener:       s.listeners,
		Pivot:          s.pivots,
		Stage:          s.stageSvc,
		WebShell:       s.webshells,
		WebShellTunnel: s.wsTunnels,
		// 反蜜罐熔断表：进程级共享（同一个目标被不同 agent 访问时计数要累加，
		// 否则每个 worker 各算各的，熔断永远触发不了）。
		Tarpit: honeydetect.DefaultTarpit(),
	}
	if s.m != nil {
		rt.VulnIntel = s.m.vulnintel
	}
	return rt
}
