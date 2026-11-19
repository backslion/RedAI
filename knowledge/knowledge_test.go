package knowledge

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestSplitKeepsContentAndOverlap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		b.WriteString("第七步：把配置文件里的连接串取出来验证权限。\n")
	}
	text := b.String()
	chunks := Split(text)
	if len(chunks) < 3 {
		t.Fatalf("期望切成多块，实得 %d 块", len(chunks))
	}
	for i, c := range chunks {
		if c == "" {
			t.Fatalf("第 %d 块为空", i)
		}
		if n := len([]rune(c)); n > DefaultChunkChars {
			t.Fatalf("第 %d 块长度 %d 超过上限 %d", i, n, DefaultChunkChars)
		}
	}
	// 行级边界：每块都应以完整句子结尾（切点落在换行后）。
	for i, c := range chunks {
		if !strings.HasSuffix(strings.TrimSpace(c), "。") {
			t.Fatalf("第 %d 块没有在句末切开: %q", i, []rune(c)[len([]rune(c))-10:])
		}
	}
	// 内容不丢：拼接后长度应不少于原文（重叠会更多）。
	var total int
	for _, c := range chunks {
		total += len([]rune(c))
	}
	if total < len([]rune(text))/2 {
		t.Fatalf("分块后内容明显丢失: 原文 %d 字, 分块合计 %d 字", len([]rune(text)), total)
	}
}

func TestSplitShortTextSingleChunk(t *testing.T) {
	chunks := Split("  一段很短的资料。  ")
	if len(chunks) != 1 || chunks[0] != "一段很短的资料。" {
		t.Fatalf("短文本应原样返回单块，实得 %#v", chunks)
	}
	if got := Split("   \n\n  "); got != nil {
		t.Fatalf("空白文本应返回 nil，实得 %#v", got)
	}
}

func TestSplitNoBoundaryDoesNotLoop(t *testing.T) {
	// 没有任何标点与换行的长串（比如 base64 样本）必须能前进并在有限步内结束。
	text := strings.Repeat("A", 5000)
	chunks := Split(text)
	if len(chunks) == 0 {
		t.Fatal("没有产出分块")
	}
	for i, c := range chunks {
		if len([]rune(c)) > DefaultChunkChars {
			t.Fatalf("第 %d 块过长: %d", i, len([]rune(c)))
		}
	}
}

func TestQueryTerms(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", nil}, // 单字母英文不算词
		{"SQL 注入", []string{"sql", "注入"}},                  // 中英混合
		{"内网横向移动", []string{"内网", "网横", "横向", "向移", "移动"}}, // 中文二元组
		{"Spring Boot Actuator", []string{"spring", "boot", "actuator"}},
	}
	for _, c := range cases {
		got := QueryTerms(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Fatalf("QueryTerms(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRankPrefersKeywordOverVector(t *testing.T) {
	cands := []db.KnowledgeChunk{
		{ID: 1, DocID: 10, Title: "内网横向", Text: "用 impacket 做 SMB 横向移动，先确认 445 端口开放。"},
		{ID: 2, DocID: 11, Title: "无关资料", Text: "这是一段与查询无关的说明文字，只用来占位。"},
	}
	cos := map[int64]float64{1: 0.20, 2: 0.80}
	hits := Rank("SMB 横向移动", QueryTerms("SMB 横向移动"), cands, cos, 2, 5)
	if len(hits) == 0 {
		t.Fatal("没有命中")
	}
	if hits[0].DocID != 10 {
		t.Fatalf("关键词命中应排在纯语义相似之前，实得首条 doc=%d score=%.3f", hits[0].DocID, hits[0].Score)
	}
	if hits[0].Keyword <= 0 || hits[0].Vector != 0.2 {
		t.Fatalf("分数构成不对: %#v", hits[0])
	}
}

func TestRankCapsPerDoc(t *testing.T) {
	cands := make([]db.KnowledgeChunk, 0, 8)
	for i := 0; i < 8; i++ {
		cands = append(cands, db.KnowledgeChunk{
			ID: int64(i + 1), DocID: 1, Title: "同一篇",
			Text: "SSRF 打内网元数据服务获取临时凭据。",
		})
	}
	hits := Rank("SSRF 元数据", QueryTerms("SSRF 元数据"), cands, nil, 8, 6)
	if len(hits) != maxPerDoc {
		t.Fatalf("单篇文档最多 %d 条，实得 %d", maxPerDoc, len(hits))
	}
}

func TestSnippetCentersOnTerm(t *testing.T) {
	text := strings.Repeat("前置废话。", 100) + "这里是关键结论：可以读 /root/.ssh/id_rsa。" + strings.Repeat("后置废话。", 100)
	s := Snippet(text, "id_rsa", QueryTerms("id_rsa"))
	if !strings.Contains(s, "id_rsa") {
		t.Fatalf("片段没有覆盖命中词: %q", s)
	}
	if len([]rune(s)) > 300 {
		t.Fatalf("片段过长: %d", len([]rune(s)))
	}
}

func TestStripHTML(t *testing.T) {
	in := `<html><head><style>body{color:red}</style><script>alert(1)</script></head>
<body><h1>报告</h1><p>第一段&nbsp;内容 &amp; 结论</p><div>第二段</div><!-- 注释 --></body></html>`
	got := StripHTML(in)
	for _, bad := range []string{"alert(1)", "color:red", "<p>", "<!--"} {
		if strings.Contains(got, bad) {
			t.Fatalf("残留了 %q: %q", bad, got)
		}
	}
	for _, want := range []string{"报告", "第一段 内容 & 结论", "第二段"} {
		if !strings.Contains(got, want) {
			t.Fatalf("缺少 %q: %q", want, got)
		}
	}
}

func TestCosine(t *testing.T) {
	if got := Cosine([]float32{1, 0}, []float32{1, 0}); got < 0.999 {
		t.Fatalf("同向量余弦应为 1，实得 %v", got)
	}
	if got := Cosine([]float32{1, 0}, []float32{0, 1}); got != 0 {
		t.Fatalf("正交向量余弦应为 0，实得 %v", got)
	}
	if got := Cosine(nil, []float32{1}); got != 0 {
		t.Fatalf("空向量应返回 0，实得 %v", got)
	}
}

func TestConfigReady(t *testing.T) {
	if (Config{Enabled: true, BaseURL: "x", Model: "m"}).Ready() {
		t.Fatal("缺 api_key 不应 Ready")
	}
	if !(Config{Enabled: true, BaseURL: "x", Model: "m", APIKey: "k"}).Ready() {
		t.Fatal("四要素齐全应 Ready")
	}
	if (Config{Enabled: false, BaseURL: "x", Model: "m", APIKey: "k"}).Ready() {
		t.Fatal("enabled=false 不应 Ready")
	}
}
