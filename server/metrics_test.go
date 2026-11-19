package server

import (
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"

	"github.com/chu0119/pojun/metrics"
)

// 指标端点必须在装配未完成的 Server 上也能给出完整响应：
// 探活、抓取这类旁路请求不能因为某个子系统没初始化就 500。
func TestMetricsEndpointOnEmptyServer(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.metricsHandler(rec, httptest.NewRequest("GET", "/api/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type = %q，应为 Prometheus 文本格式", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE pojun_process_uptime_seconds gauge",
		"pojun_process_goroutines",
		"pojun_process_mem_heap_alloc_bytes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("缺 %q:\n%s", want, body)
		}
	}
	// 没有 Manager 时不该凭空造任务序列。
	if strings.Contains(body, "pojun_tasks{") {
		t.Errorf("s.m 为 nil 时不应输出任务指标:\n%s", body)
	}
	// 没有 Manager 也就没有连接池，池序列同样不该出现。
	if strings.Contains(body, "pojun_db_pool_") {
		t.Errorf("s.m 为 nil 时不应输出连接池指标:\n%s", body)
	}
}

// 每一行都必须是合法的 exposition 行：要么 # HELP/# TYPE，要么 name{labels} value。
func TestMetricsEndpointLinesWellFormed(t *testing.T) {
	// 先打一条埋点，确保覆盖带标签的样本行。
	metrics.ObserveCounter("pojun_test_marker_total", "测试用", "k", "v")

	s := &Server{}
	rec := httptest.NewRecorder()
	s.metricsHandler(rec, httptest.NewRequest("GET", "/api/metrics", nil))

	for _, line := range strings.Split(strings.TrimSuffix(rec.Body.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "# HELP ") && !strings.HasPrefix(line, "# TYPE ") {
				t.Errorf("非常规元信息行: %q", line)
			}
			continue
		}
		if !strings.Contains(line, " ") {
			t.Errorf("样本行缺值: %q", line)
		}
	}
}

// 流式包装不能改变迭代语义：事件顺序、内容、提前 break 都要和原序列一致。
func TestObserveLLMStreamKeepsIteration(t *testing.T) {
	got := []string{}
	seq := func(yield func(llm.StreamEvent, error) bool) {
		for _, s := range []string{"a", "b", "c"} {
			if !yield(llm.StreamEvent{Text: s}, nil) {
				return
			}
		}
	}
	for ev, err := range observeLLMStream("test-agent", seq) {
		if err != nil {
			t.Fatalf("意外错误: %v", err)
		}
		got = append(got, ev.Text)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("事件顺序被改变: %v", got)
	}
}

// 提前 break 也要落记录：否则「用户中断」这类最常见的路径会在指标里消失。
func TestObserveLLMStreamRecordsOnEarlyBreak(t *testing.T) {
	metrics.Default.Reset()

	seq := func(yield func(llm.StreamEvent, error) bool) {
		for i := 0; i < 10; i++ {
			if !yield(llm.StreamEvent{Text: "x"}, nil) {
				return
			}
		}
	}
	for range observeLLMStream("break-agent", seq) {
		break
	}

	var b strings.Builder
	if _, err := metrics.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, `pojun_llm_requests_total{agent="break-agent",result="ok"}`) {
		t.Errorf("提前 break 未记录调用:\n%s", out)
	}
	if !strings.Contains(out, `pojun_llm_first_event_seconds_count{agent="break-agent"}`) {
		t.Errorf("未记录首事件延迟:\n%s", out)
	}
}

// 出错要记成 error，而不是「模型没返回内容」也算 ok。
func TestObserveLLMStreamRecordsError(t *testing.T) {
	metrics.Default.Reset()

	seq := func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, io.ErrUnexpectedEOF)
	}
	for range observeLLMStream("err-agent", seq) {
	}

	var b strings.Builder
	_, _ = metrics.WriteTo(&b)
	if !strings.Contains(b.String(), `pojun_llm_requests_total{agent="err-agent",result="error"}`) {
		t.Errorf("失败调用未记成 error:\n%s", b.String())
	}
}

// 无标签统计与多维统计都能正常序列化（iter.Seq2 换成泛型函数后最容易漏的类型断言）。
var _ iter.Seq2[llm.StreamEvent, error] = observeLLMStream("compile-check", nil)
