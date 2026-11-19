package agent

import (
	"strings"
	"testing"
)

// 同一目标必须始终同一 UA：会话中途换浏览器本身就是可疑信号。
func TestDefaultUAStablePerHost(t *testing.T) {
	first := defaultUA("http://10.0.0.5:8080/login")
	for i := 0; i < 10; i++ {
		if got := defaultUA("http://10.0.0.5/other/path"); got != first {
			t.Fatalf("同一 host 的 UA 必须稳定，第 %d 次得到 %q（首次 %q）", i+1, got, first)
		}
	}
	// 裸 host 与 URL 应解析成同一个 host。
	if got := defaultUA("10.0.0.5"); got != first {
		t.Errorf("裸 host 与 URL 应一致，得到 %q vs %q", got, first)
	}
}

// 不同目标要分散，否则跨目标仍能被一条 header 关联。
func TestDefaultUADistributesAcrossHosts(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range []string{
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
		"example.com", "test.local", "192.168.1.10", "172.16.0.9",
	} {
		seen[defaultUA(h)] = true
	}
	if len(seen) < 2 {
		t.Errorf("不同 host 应分散到多个 UA，实际只有 %d 种", len(seen))
	}
}

// 池里不能有空的或可疑的 UA。
func TestUAPoolSane(t *testing.T) {
	if len(uaPool) < 4 {
		t.Fatalf("UA 池太小: %d", len(uaPool))
	}
	for _, ua := range uaPool {
		if !strings.HasPrefix(ua, "Mozilla/5.0 ") {
			t.Errorf("UA 应以 Mozilla/5.0 开头: %q", ua)
		}
		for _, bad := range []string{"pojun", "Go-http-client", "curl", "python"} {
			if strings.Contains(strings.ToLower(ua), bad) {
				t.Errorf("UA 不应含 %q: %q", bad, ua)
			}
		}
	}
}

// 空输入不能返回空 UA（空 UA 比固定 UA 更显眼）。
func TestDefaultUAEmptyInput(t *testing.T) {
	if got := defaultUA(""); got == "" {
		t.Fatal("空输入必须返回兜底 UA")
	}
}
