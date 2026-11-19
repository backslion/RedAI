// Package metrics 是进程内指标登记表，输出 Prometheus 文本格式。
//
// 为什么手写而不引 prometheus/client_golang：本项目只跑单进程、只暴露一个
// /api/metrics，需要的就三样——计数器、直方图、现场 gauge。引官方客户端会
// 拖进 protobuf 与一堆注册期校验，换来的能力（多进程聚合、pushgateway）这里都用不上。
//
// 设计约束：
//   - 埋点必须零失败：指标是旁路，任何指标侧的异常都不允许影响被观测的调用。
//   - 名字与标签都由代码里写死，不接受外部输入，所以不做名字合法性校验。
//   - 只累加、不做聚合窗口——窗口留给抓取方（Prometheus）算。
package metrics

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Default 是进程级默认登记表。埋点处直接用包级函数即可；
// 需要隔离的测试可以用 New() 拿到独立实例。
var Default = New()

// Registry 是一组指标族的集合。并发安全。
type Registry struct {
	mu    sync.RWMutex
	fams  map[string]*family
	order []string // 首次注册顺序，输出时保持稳定
}

type family struct {
	name   string
	help   string
	typ    string    // "counter" | "histogram"
	bounds []float64 // 直方图族的桶边界；counter 族为空
	// series 的键是渲染好的标签串（含大括号），无标签时为 ""。
	series map[string]*series
	keys   []string // 保持稳定输出顺序
}

type series struct {
	labels string // 形如 `{tool="bash",result="ok"}`，无标签为 ""
	ctr    atomic.Int64
	hist   *Histogram
}

// Histogram 是固定桶直方图，桶边界在族级别共享。
type Histogram struct {
	bounds []float64 // 只读，建族时定下

	mu     sync.Mutex
	counts []int64 // 长度 = len(bounds)+1，最后一格是 +Inf
	sum    float64
	total  int64
}

// New 建一个独立登记表（测试用；生产用 Default）。
func New() *Registry {
	return &Registry{fams: make(map[string]*family)}
}

// labelString 把 "k1","v1","k2","v2" 渲染成 `{k1="v1",k2="v2"}`。
// 顺序即入参顺序，不做重排——埋点处写成固定顺序，同一序列就只有一把键。
func labelString(pairs []string) string {
	if len(pairs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i])
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(pairs[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabelValue 按 Prometheus 文本格式转义标签值。
func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Counter 返回（必要时创建）指定标签序列的计数器。
// 同一 (name, labels) 只有一个实例，所以可以在热路径反复调用。
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{s: r.seriesFor(name, help, "counter", nil, labels)}
}

// ObserveCounter 是 Counter(...).Add(1) 的便捷写法。
func (r *Registry) ObserveCounter(name, help string, labels ...string) {
	r.seriesFor(name, help, "counter", nil, labels).ctr.Add(1)
}

// Histogram 返回（必要时创建）指定标签序列的直方图。bounds 只在首次创建时生效。
func (r *Registry) Histogram(name, help string, bounds []float64, labels ...string) *Histogram {
	return r.seriesFor(name, help, "histogram", bounds, labels).hist
}

// Observe 是 Histogram(...).Observe(v) 的便捷写法。
func (r *Registry) Observe(name, help string, bounds []float64, v float64, labels ...string) {
	if h := r.seriesFor(name, help, "histogram", bounds, labels).hist; h != nil {
		h.Observe(v)
	}
}

func (r *Registry) seriesFor(name, help, typ string, bounds []float64, labels []string) *series {
	key := labelString(labels)

	r.mu.RLock()
	if f := r.fams[name]; f != nil {
		if s := f.series[key]; s != nil {
			r.mu.RUnlock()
			return s
		}
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.fams[name]
	if f == nil {
		f = &family{name: name, help: help, typ: typ, bounds: bounds, series: make(map[string]*series)}
		r.fams[name] = f
		r.order = append(r.order, name)
	}
	if s := f.series[key]; s != nil {
		return s
	}
	s := &series{labels: key}
	if typ == "histogram" {
		s.hist = &Histogram{bounds: f.bounds, counts: make([]int64, len(f.bounds)+1)}
	}
	f.series[key] = s
	if key != "" {
		f.keys = append(f.keys, key)
	} else {
		f.keys = append([]string{""}, f.keys...)
	}
	return s
}

// Counter 是单调递增的计数器。
type Counter struct{ s *series }

func (c *Counter) Add(n int64) { c.s.ctr.Add(n) }

func (c *Counter) Inc() { c.s.ctr.Add(1) }

// Observe 记录一次观测值到对应桶，并累加总和与次数。
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	idx := len(h.counts) - 1
	for i, b := range h.bounds {
		if v <= b {
			idx = i
			break
		}
	}
	h.counts[idx]++
	h.sum += v
	h.total++
	h.mu.Unlock()
}

// WriteTo 输出 Prometheus 文本格式（text/plain; version=0.0.4）。
// 输出顺序按族的注册顺序与序列的创建顺序，保证同一进程内多次抓取可比。
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var n int64
	var firstErr error
	write := func(s string) {
		if firstErr != nil {
			return
		}
		c, err := io.WriteString(w, s)
		n += int64(c)
		firstErr = err
	}

	for _, name := range r.order {
		f := r.fams[name]
		write("# HELP " + f.name + " " + f.help + "\n")
		write("# TYPE " + f.name + " " + f.typ + "\n")
		for _, k := range f.keys {
			s := f.series[k]
			if f.typ == "counter" {
				write(f.name + s.labels + " " + strconv.FormatInt(s.ctr.Load(), 10) + "\n")
				continue
			}
			s.hist.mu.Lock()
			counts := append([]int64(nil), s.hist.counts...)
			sum, total := s.hist.sum, s.hist.total
			s.hist.mu.Unlock()
			if total == 0 {
				continue
			}
			var cum int64
			for i, c := range counts {
				cum += c
				bound := "+Inf"
				if i < len(f.bounds) {
					bound = strconv.FormatFloat(f.bounds[i], 'g', -1, 64)
				}
				write(f.name + "_bucket" + withLE(s.labels, bound) + " " + strconv.FormatInt(cum, 10) + "\n")
			}
			write(f.name + "_sum" + s.labels + " " + strconv.FormatFloat(sum, 'g', -1, 64) + "\n")
			write(f.name + "_count" + s.labels + " " + strconv.FormatInt(total, 10) + "\n")
		}
	}
	if firstErr != nil {
		return n, fmt.Errorf("写指标文本: %w", firstErr)
	}
	return n, nil
}

// withLE 在标签串里追加 le="..."。
func withLE(labels, le string) string {
	if labels == "" {
		return `{le="` + le + `"}`
	}
	return labels[:len(labels)-1] + `,le="` + le + `"}`
}

// --- 包级便捷入口（用 Default 登记表）---

// NewCounter 取或创建计数器（同 Registry.Counter）。
func NewCounter(name, help string, labels ...string) *Counter {
	return Default.Counter(name, help, labels...)
}

// ObserveCounter 见 Registry.ObserveCounter。
func ObserveCounter(name, help string, labels ...string) {
	Default.ObserveCounter(name, help, labels...)
}

// NewHistogram 取或创建直方图（同 Registry.Histogram）。
func NewHistogram(name, help string, bounds []float64, labels ...string) *Histogram {
	return Default.Histogram(name, help, bounds, labels...)
}

// Observe 见 Registry.Observe。
func Observe(name, help string, bounds []float64, v float64, labels ...string) {
	Default.Observe(name, help, bounds, v, labels...)
}

// WriteTo 见 Registry.WriteTo。
func WriteTo(w io.Writer) (int64, error) { return Default.WriteTo(w) }

// Reset 清空登记表。仅供测试：生产代码不要在运行期调用。
func (r *Registry) Reset() {
	r.mu.Lock()
	r.fams = make(map[string]*family)
	r.order = nil
	r.mu.Unlock()
}
