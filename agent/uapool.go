package agent

// UA 池：让默认 User-Agent 不再是「所有目标同一个 Chrome/131」。
//
// 解决什么：平台原来把默认 UA 写死成一个 Chrome 131 字符串。这意味着
//   - 同一操作者对所有目标的请求 UA 完全相同，防守方一旦在一处看到这个 UA，
//     就能在流量里横向关联出「同一个人还打了哪些站」；
//   - 蜜罐/反制系统常按 UA 做「非浏览器客户端」判定，固定 UA 等于给自己贴标签。
//
// 怎么选：按目标 host 做确定性选择（FNV-1a），不是每次随机。
//   - 同一目标始终同一 UA：一个真实用户不会在同一次会话里每小时换一次浏览器，
//     频繁变 UA 本身就是强可疑信号；
//   - 不同目标分散到不同 UA：避免跨目标关联。
//
// 能力边界（必须诚实）：UA 只能骗过读 header 的规则，**骗不过 TLS 指纹**。
// Go 的 crypto/tls ClientHello 有固定特征（JA3/JA4），与 UA 声称的 Chrome 不符，
// 成熟的检测设备直接看 TLS 层就知道不是浏览器。要真正对齐需要 uTLS 之类的
// 指纹伪装，那是另一个量级的工程。所以这里的定位是「降低简单规则的命中率」，
// 不是「隐身」。
//
// 显式传 user_agent 时永远优先——复现特定客户端、伪装移动端等场景不能被池覆盖。

import (
	"hash/fnv"
	"net/url"
	"strings"
)

// uaPool 是常见浏览器的真实 UA 形态。
//
// 版本刻意分散在近两年的几个大版本上：全都是同一版本反而更假（真实用户的
// 浏览器版本分布是长尾的）。平台/内核也分散，避免出现「全是 Windows Chrome」。
var uaPool = []string{
	// Windows Chrome / Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
	// macOS Chrome / Safari
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	// Firefox（Windows / Linux）
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	// 移动端（Android Chrome / iOS Safari）
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
}

// defaultUA 返回该目标应使用的默认 UA。
//
// rawURL 可以是完整 URL（http://10.0.0.5:8080/x）或裸 host。解析失败时
// 退回对整串做哈希——宁可 UA 不稳定，也不要 panic 或返回空 UA（空 UA 比固定
// UA 更显眼）。
func defaultUA(rawURL string) string {
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	if host == "" {
		host = rawURL
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return uaPool[0]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	return uaPool[int(h.Sum32())%len(uaPool)]
}
