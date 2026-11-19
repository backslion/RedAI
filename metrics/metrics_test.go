package metrics

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

func TestCounterAccumulates(t *testing.T) {
	r := New()
	c := r.Counter("pojun_x_total", "测试计数", "k", "v")
	c.Inc()
	c.Add(2)
	r.ObserveCounter("pojun_x_total", "测试计数", "k", "v")

	out := render(t, r)
	if !strings.Contains(out, "# TYPE pojun_x_total counter") {
		t.Errorf("缺 TYPE 行:\n%s", out)
	}
	if !strings.Contains(out, `pojun_x_total{k="v"} 4`) {
		t.Errorf("计数不对（Inc + Add(2) + ObserveCounter 应为 4）:\n%s", out)
	}
}

// 同一 (name,labels) 必须是同一实例，否则热路径反复取会各记一份、永远显示 1。
func TestCounterSameSeriesIsShared(t *testing.T) {
	r := New()
	r.Counter("pojun_shared_total", "h", "a", "1").Inc()
	r.Counter("pojun_shared_total", "h", "a", "1").Inc()

	out := render(t, r)
	if !strings.Contains(out, `pojun_shared_total{a="1"} 2`) {
		t.Errorf("同名同标签未共享计数:\n%s", out)
	}
	if strings.Count(out, "pojun_shared_total{a=") != 1 {
		t.Errorf("同一序列被输出了多行:\n%s", out)
	}
}

func TestCounterWithoutLabels(t *testing.T) {
	r := New()
	r.ObserveCounter("pojun_bare_total", "h")
	out := render(t, r)
	if !strings.Contains(out, "pojun_bare_total 1\n") {
		t.Errorf("无标签序列应输出 `name value`:\n%s", out)
	}
	if strings.Contains(out, "pojun_bare_total{") {
		t.Errorf("无标签序列不该带大括号:\n%s", out)
	}
}

// 桶是累积语义：le=0.5 的值必须同时计入 le=1 与 le=+Inf。
func TestHistogramBucketsAreCumulative(t *testing.T) {
	r := New()
	bounds := []float64{0.5, 1, 5}
	r.Observe("pojun_dur_seconds", "h", bounds, 0.2, "t", "a")
	r.Observe("pojun_dur_seconds", "h", bounds, 0.9, "t", "a")
	r.Observe("pojun_dur_seconds", "h", bounds, 3.0, "t", "a")

	out := render(t, r)
	for _, want := range []string{
		`pojun_dur_seconds_bucket{t="a",le="0.5"} 1`,
		`pojun_dur_seconds_bucket{t="a",le="1"} 2`,
		`pojun_dur_seconds_bucket{t="a",le="5"} 3`,
		`pojun_dur_seconds_bucket{t="a",le="+Inf"} 3`,
		`pojun_dur_seconds_count{t="a"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺 %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `pojun_dur_seconds_sum{t="a"} 4.1`) {
		t.Errorf("sum 应为 4.1:\n%s", out)
	}
}

// 从未观测过的直方图序列不该输出一排 0 桶（会让人以为「调用过但都很快」）。
func TestHistogramUnobservedIsOmitted(t *testing.T) {
	r := New()
	r.Histogram("pojun_empty_seconds", "h", []float64{1}, "t", "never")
	out := render(t, r)
	if strings.Contains(out, "pojun_empty_seconds_bucket") {
		t.Errorf("未观测的序列不应输出桶:\n%s", out)
	}
}

// 标签值里的引号、反斜杠、换行必须转义，否则整段 exposition 会被抓取方丢弃。
func TestLabelValueEscaping(t *testing.T) {
	r := New()
	r.ObserveCounter("pojun_esc_total", "h", "cmd", "a\"b\\c\nd")
	out := render(t, r)
	if !strings.Contains(out, `cmd="a\"b\\c\nd"`) {
		t.Errorf("标签值未转义:\n%s", out)
	}
	if strings.Count(out, "\n") != strings.Count(strings.Split(out, "# TYPE")[1], "\n")+0 &&
		strings.Contains(out, "\nd\"") {
		t.Errorf("换行没有被转义成 \\n:\n%s", out)
	}
}

// 输出必须每行都是合法样本行：`name{labels} value` 或用 # 开头的元信息。
func TestOutputLinesAreWellFormed(t *testing.T) {
	r := New()
	r.ObserveCounter("pojun_a_total", "h", "x", "1")
	r.Observe("pojun_b_seconds", "h", []float64{1, 2}, 1.5, "x", "1")
	out := render(t, r)

	sample := regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?[0-9.eE+]+$`)
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "# HELP ") && !strings.HasPrefix(line, "# TYPE ") {
				t.Errorf("非常规元信息行: %q", line)
			}
			continue
		}
		if !sample.MatchString(line) {
			t.Errorf("样本行格式不合法: %q", line)
		}
	}
}

// 并发打点不能丢计数、也不能 panic（配合 -race 跑）。
func TestConcurrentObserve(t *testing.T) {
	r := New()
	bounds := []float64{0.001, 0.01, 1}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.ObserveCounter("pojun_conc_total", "h", "g", "same")
				r.Observe("pojun_conc_seconds", "h", bounds, float64(j)/1000, "g", "same")
			}
		}(i)
	}
	wg.Wait()

	out := render(t, r)
	if !strings.Contains(out, `pojun_conc_total{g="same"} 800`) {
		t.Errorf("并发计数丢失:\n%s", out)
	}
	if !strings.Contains(out, `pojun_conc_seconds_count{g="same"} 800`) {
		t.Errorf("并发观测丢失:\n%s", out)
	}
}

// Reset 后必须干净：测试之间靠它隔离，残留会让断言假通过。
func TestResetClears(t *testing.T) {
	r := New()
	r.ObserveCounter("pojun_reset_total", "h")
	if !strings.Contains(render(t, r), "pojun_reset_total") {
		t.Fatal("前置条件不成立")
	}
	r.Reset()
	if strings.Contains(render(t, r), "pojun_reset_total") {
		t.Error("Reset 未清空")
	}
}
