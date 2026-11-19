// chunk.go：文本分块。段落优先、句子次之，最后才硬切。
//
// 为什么分块质量值得单独写：检索结果的天花板由分块决定。按固定长度硬切会把
// 「利用条件」和「利用结果」切到两个块里，命中任何一半都是残句；按段落切则
// 天然对齐语义边界。

package knowledge

import "strings"

// Split 把正文切成若干块（每块约 DefaultChunkChars 字，相邻块重叠
// DefaultChunkOverlap 字）。返回的块已去首尾空白，空块被丢弃。
func Split(text string) []string {
	text = Normalize(text)
	if text == "" {
		return nil
	}
	r := []rune(text)
	if len(r) <= DefaultChunkChars {
		return []string{text}
	}
	out := make([]string, 0, len(r)/DefaultChunkChars+1)
	pos := 0
	for pos < len(r) {
		end := pos + DefaultChunkChars
		if end >= len(r) {
			if s := strings.TrimSpace(string(r[pos:])); s != "" {
				out = append(out, s)
			}
			break
		}
		cut := findCut(r, pos+DefaultChunkChars-160, end)
		if cut <= pos {
			cut = end
		}
		if s := strings.TrimSpace(string(r[pos:cut])); s != "" {
			out = append(out, s)
		}
		next := cut - DefaultChunkOverlap
		if next <= pos {
			next = cut
		}
		pos = next
	}
	// 尾块过短时并入上一块：一个 20 字的块既检索不准，也浪费一次向量调用。
	if n := len(out); n >= 2 && len([]rune(out[n-1])) < 120 {
		out[n-2] = out[n-2] + "\n" + out[n-1]
		out = out[:n-1]
	}
	return out
}

// findCut 在 [lo, hi] 内从后往前找最合适的切点，优先级：
// 段落分隔 > 句末标点 > 标点/空格 > 硬切 hi。
func findCut(r []rune, lo, hi int) int {
	if lo < 0 {
		lo = 0
	}
	if hi > len(r) {
		hi = len(r)
	}
	for i := hi; i > lo; i-- {
		if r[i-1] == '\n' && i < len(r) && r[i] == '\n' {
			return i
		}
	}
	for i := hi; i > lo; i-- {
		switch r[i-1] {
		case '。', '！', '？', '；', '?', '!', ';', '\n':
			return i
		}
	}
	for i := hi; i > lo; i-- {
		switch r[i-1] {
		case '，', ',', '、', ' ', '）', ')', '」', '】':
			return i
		}
	}
	return hi
}
