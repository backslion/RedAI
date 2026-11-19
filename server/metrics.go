package server

// 指标端点（GET /api/metrics，Prometheus 文本格式）。
//
// 为什么挂在 /api 下而不是根路径 /metrics：本项目所有 /api/* 都过 requireAuth，
// 指标里带着工具名、LLM 角色、任务规模——这些都是部署结构的指纹，公网部署时不该
// 无鉴权暴露（/api/health 刻意连版本号都不带，同一口径）。抓取方带 Bearer token：
//
//	scrape_configs:
//	  - job_name: pojun
//	    scheme: http
//	    authorization: { type: Bearer, credentials_file: /etc/pojun-token }
//	    static_configs: [{ targets: ["127.0.0.1:8787"] }]
//
// 埋点分两处，都是既有代码里的唯一收口，只记录、不改变任何返回：
//   - 工具：agent.guardedTool.Call（覆盖 domain / SDK / MCP / skill 全部工具）
//   - LLM：taskLLMRuntime.Stream / Complete（所有任务 agent 的模型调用）
//
// 进程级 gauge 在这里现场采集，不进 Registry：它们没有"注册一次"的生命周期，
// 每次抓取现算最省事，也不会因为重启前后指标名不一致而丢序列。

import (
	"bytes"
	"database/sql"
	"iter"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/Autumn-27/norma/llm"

	"github.com/chu0119/pojun/metrics"
)

// processStart 是包初始化时刻，作为 uptime 起点（不依赖 Server 构造，
// 因此 /api/metrics 在装配未完成时也能给出合理值）。
var processStart = time.Now()

// llmDurationBuckets 覆盖「小模型几百毫秒」到「长上下文思考几分钟」。
var llmDurationBuckets = []float64{0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300}

// llmFirstOutputBuckets 是首事件延迟（流式路径的体感指标）。
var llmFirstOutputBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60}

// metricsHandler 输出 Prometheus 文本格式：先输出埋点指标，再追加现场采集的 gauge。
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	var b bytes.Buffer
	if _, err := metrics.WriteTo(&b); err != nil {
		// 指标是旁路能力：写失败也要把已经拿到的部分返回，不能变成 500 让抓取方
		// 误判成「服务挂了」。
		b.WriteString("# pojun_metrics_write_error 1\n")
	}
	writeProcessMetrics(&b)
	writeTaskMetrics(&b, s)
	writeDBPoolMetrics(&b, s)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b.Bytes())
}

func writeProcessMetrics(b *bytes.Buffer) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	gauge := func(name, help string, v float64) {
		b.WriteString("# HELP " + name + " " + help + "\n")
		b.WriteString("# TYPE " + name + " gauge\n")
		b.WriteString(name + " " + strconv.FormatFloat(v, 'g', -1, 64) + "\n")
	}
	gauge("pojun_process_uptime_seconds", "进程已运行时间（秒）", time.Since(processStart).Seconds())
	gauge("pojun_process_goroutines", "当前 goroutine 数", float64(runtime.NumGoroutine()))
	gauge("pojun_process_gomaxprocs", "GOMAXPROCS", float64(runtime.GOMAXPROCS(0)))
	gauge("pojun_process_mem_heap_alloc_bytes", "堆上已分配字节数", float64(ms.HeapAlloc))
	gauge("pojun_process_mem_heap_inuse_bytes", "堆已用字节数（含未回收 span）", float64(ms.HeapInuse))
	gauge("pojun_process_mem_sys_bytes", "向操作系统申请的总字节数", float64(ms.Sys))
	gauge("pojun_process_gc_total", "GC 次数累计", float64(ms.NumGC))
}

// writeTaskMetrics 现场统计任务规模。只用内存里的任务表（List 是加锁读），
// 不查库——抓取可能每 15 秒一次，不能让它变成 PG 的压力源。
func writeTaskMetrics(b *bytes.Buffer, s *Server) {
	if s == nil || s.m == nil {
		return
	}
	tasks := s.m.List()
	if tasks == nil {
		return
	}
	counts := map[string]int{}
	for _, t := range tasks {
		// 走 TaskStatus 而不是直接读 t.Status：前者在 Manager 的读锁下取
		// lifecycleSnapshot，是权威值；后者可能读到生命周期写入的半途状态。
		st := "unknown"
		if t != nil {
			if v := s.m.TaskStatus(t.ID); v != "" {
				st = v
			}
		}
		counts[st]++
	}

	b.WriteString("# HELP pojun_tasks 任务数（按状态）\n")
	b.WriteString("# TYPE pojun_tasks gauge\n")
	// 常见状态即使为 0 也输出（零值对告警有用），其余状态按名字排序补齐，
	// 避免以后新增状态时它在面板上凭空消失。
	known := []string{"running", "paused", "done", "failed", "timeout", "queued"}
	for _, st := range known {
		b.WriteString(`pojun_tasks{state="` + st + `"} ` + strconv.Itoa(counts[st]) + "\n")
		delete(counts, st)
	}
	rest := make([]string, 0, len(counts))
	for st := range counts {
		rest = append(rest, st)
	}
	sort.Strings(rest)
	for _, st := range rest {
		b.WriteString(`pojun_tasks{state="` + st + `"} ` + strconv.Itoa(counts[st]) + "\n")
	}
}

// writeDBPoolMetrics 现场采集两条连接池的水位。
//
// 这是"后台池到底有没有按预期隔离"的唯一观测手段，也是判断该不该调大
// POJUN_PG_BG_POOL 的唯一依据：
//   - 主池 wait_total 涨得快 → 在线路径在排队，后台池该扩或该查慢查询；
//   - 后台池 wait_total 涨得快而主池不动 → 情报同步被自己的上限压住了，
//     这是预期内的（隔离生效），只有同步耗时明显变长才需要扩。
//
// 只用 sql.DBStats（内存计数器），不查库——抓取可能每 15 秒一次。
func writeDBPoolMetrics(b *bytes.Buffer, s *Server) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	type poolStat struct {
		name string
		st   sql.DBStats
	}
	stats := []poolStat{{name: "main", st: s.m.pg.DB.Stats()}}
	// intel 序列只在独立池真的建起来时输出：不存在这条序列，比输出一条恒为 0
	// 的序列更能说明"当前是回落主池"的状态。
	if s.m.intelPool != nil {
		stats = append(stats, poolStat{name: "intel", st: s.m.intelPool.Stats()})
	}

	emit := func(name, help, typ string, pick func(sql.DBStats) float64) {
		b.WriteString("# HELP " + name + " " + help + "\n")
		b.WriteString("# TYPE " + name + " " + typ + "\n")
		for _, p := range stats {
			b.WriteString(name + `{pool="` + p.name + `"} ` +
				strconv.FormatFloat(pick(p.st), 'g', -1, 64) + "\n")
		}
	}
	emit("pojun_db_pool_open", "连接池已打开的连接数（空闲 + 使用中）", "gauge",
		func(st sql.DBStats) float64 { return float64(st.OpenConnections) })
	emit("pojun_db_pool_in_use", "正在被查询占用的连接数", "gauge",
		func(st sql.DBStats) float64 { return float64(st.InUse) })
	emit("pojun_db_pool_idle", "空闲连接数", "gauge",
		func(st sql.DBStats) float64 { return float64(st.Idle) })
	emit("pojun_db_pool_max_open", "连接池上限（0 = 不限）", "gauge",
		func(st sql.DBStats) float64 { return float64(st.MaxOpenConnections) })
	emit("pojun_db_pool_wait_total", "因池满而排队等待连接的总次数", "counter",
		func(st sql.DBStats) float64 { return float64(st.WaitCount) })
	emit("pojun_db_pool_wait_seconds_total", "排队等待连接的总耗时（秒）", "counter",
		func(st sql.DBStats) float64 { return st.WaitDuration.Seconds() })
}

// observeLLMStream 包住一次流式模型调用，记录成败、墙钟耗时与首事件延迟。
//
// 包装 yield 而不是解析事件：迭代语义完全不变，调用方（planner / worker /
// mainagent 的循环）拿到的顺序、内容、错误都与未包装时一致；统计在迭代结束后
// 落地，提前 break 也会执行。
func observeLLMStream(agentKey string, seq iter.Seq2[llm.StreamEvent, error]) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		start := time.Now()
		firstSeen := false
		failed := false
		seq(func(ev llm.StreamEvent, err error) bool {
			if !firstSeen {
				firstSeen = true
				metrics.Observe("pojun_llm_first_event_seconds",
					"流式调用从发起到收到第一个事件的耗时（秒）", llmFirstOutputBuckets,
					time.Since(start).Seconds(), "agent", agentKey)
			}
			if err != nil {
				failed = true
			}
			return yield(ev, err)
		})
		recordLLMCall(agentKey, time.Since(start), failed)
	}
}

// recordLLMCall 记录一次模型调用的结果与耗时。
func recordLLMCall(agentKey string, d time.Duration, failed bool) {
	result := "ok"
	if failed {
		result = "error"
	}
	metrics.ObserveCounter("pojun_llm_requests_total",
		"模型调用次数（agent 为 planner/worker/mainagent，result 为 ok/error）",
		"agent", agentKey, "result", result)
	metrics.Observe("pojun_llm_duration_seconds",
		"模型调用墙钟耗时（秒）", llmDurationBuckets,
		d.Seconds(), "agent", agentKey)
}
