// extract.go：把网页 / 二进制无关的纯文本取出来。
//
// 只做一件事：HTML → 可读文本。不做正文抽取算法（Readability 之类），因为
// 知识库的读者是 agent：导航栏和页脚冗余一点不致命，正文被误判裁掉才致命。
// 因此策略是「去标签、保留块级换行」，再交给分块逻辑处理。

package knowledge

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// maxFetchBytes 是单次抓取的上限（8MB），防止把大文件读进内存。
const maxFetchBytes = 8 << 20

var (
	reScriptStyle = regexp.MustCompile(`(?is)<(script|style|noscript|template|svg)[^>]*>.*?</\s*(script|style|noscript|template|svg)\s*>`)
	reComment     = regexp.MustCompile(`(?s)<!--.*?-->`)
	reBlockBreak  = regexp.MustCompile(`(?i)</?(p|div|br|li|ul|ol|tr|h[1-6]|section|article|header|footer|pre|table|blockquote|dd|dt)\b[^>]*>`)
	reTag         = regexp.MustCompile(`(?s)<[^>]+>`)
	reBlankLines  = regexp.MustCompile(`\n{3,}`)
	reSpaces      = regexp.MustCompile(`[ \t\f\v]{2,}`)
)

// StripHTML 把 HTML 片段转成纯文本。
func StripHTML(s string) string {
	if s == "" {
		return ""
	}
	s = reComment.ReplaceAllString(s, "")
	s = reScriptStyle.ReplaceAllString(s, "")
	s = reBlockBreak.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "\u00a0", " ")
	s = reSpaces.ReplaceAllString(s, " ")
	s = reBlankLines.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// FetchText 抓取一个 http(s) 地址并返回纯文本（HTML 会被转成文本）。
// 只接受 http/https；4xx/5xx 直接报错，避免把错误页当资料入库。
func FetchText(ctx context.Context, rawURL string) (string, string, error) {
	u := strings.TrimSpace(rawURL)
	lower := strings.ToLower(u)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", "", fmt.Errorf("只支持 http/https 地址")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Pojun-Knowledge/1.0)")
	req.Header.Set("Accept", "text/html,text/plain,application/json;q=0.9,*/*;q=0.5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("抓取返回 %d", resp.StatusCode)
	}
	ctype := strings.ToLower(resp.Header.Get("Content-Type"))
	body := string(raw)
	if strings.Contains(ctype, "html") || strings.Contains(body, "<html") {
		return StripHTML(body), ctype, nil
	}
	return Normalize(body), ctype, nil
}
