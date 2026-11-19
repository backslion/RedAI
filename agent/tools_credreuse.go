// tools_credreuse.go：凭据复用矩阵——把「凭据库」变成「横向移动的实物证据」。
//
// 主要函数：
//   - credentialReuseMatrix：给定凭据集合与目标资产，自动选择协议（ssh/smb/http/
//     mysql/postgres/redis）、逐个调用对应验证工具，汇总成「凭据 × 资产」矩阵，
//     并把判定成功的关系批量写回凭据库（verified）。
//
// ## 为什么需要它
//
// 移植进来的四个验证器（ssh_check / smb_check / http_login_check / db_check）各自
// 都很强，但它们要求调用方把「用户名 + 口令」明文写进参数。这意味着模型必须：
//   1. 先用 list_assets 读出凭据（明文进上下文）；
//   2. 记住哪条对应哪台机器；
//   3. 手工拼 J 组凭据 × K 台资产的参数；
//   4. 每次调用最多 5~10 组，几十个组合就是十几次工具调用；
//   5. 成功后还要记得回来 mark_credential_verified。
//
// 实际使用中第 3 步基本做不完——上下文里塞满明文凭据，模型会挑几条试，剩下的
// 就"忘了"。凭据库存在的意义（知道手上有什么）因此转化不成结果（知道能用在哪）。
// 本工具把 2~5 全部自动化，模型只需要说「这批凭据在这些机器上试一遍」。
//
// ## 与「爆破器」的界线（硬性纪律，不可调参关闭）
//
//   - 每条凭据在每个目标上只尝试 **一次**；同一账号累计失败 ≥2 次即整体停止
//     （防锁定），出现 locked / disabled / 429 立即中止全部剩余尝试。
//   - 单次调用总尝试数上限 40（默认 20），超出直接拒绝——要更多请分批调用，
//     强制模型在批次之间看一眼结果。
//   - 串行执行，行间隔 300ms；不并发。
//   - 只对显式传入的 asset_id 生效，绝不"扫全任务资产"。
//
// 这不是保守，是因为锁定一次就永久失去这个账号——横向移动里凭据比速度值钱。

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/backslion/RedAI/db"
)

// 矩阵的硬上限：单次调用最多尝试多少组合。
const (
	credMatrixMaxAttempts     = 40
	credMatrixDefaultAttempts = 20
	// 同一账号（跨资产累计）允许的失败次数；达到即整体停止。
	credMatrixMaxFailsPerAccount = 2
	// 相邻两次尝试之间的间隔。
	credMatrixAttemptGap = 300 * time.Millisecond
)

// credMatrixProbe 是一条待执行的尝试。
type credMatrixProbe struct {
	cred       *db.CredentialSecret
	credID     int64
	assetID    int64
	assetLabel string
	protocol   string
	port       int
	host       string
	url        string
}

// credMatrixOutcome 是一条尝试的结果。
type credMatrixOutcome struct {
	CredentialID int64  `json:"credential_id"`
	Username     string `json:"username"`
	AssetID      int64  `json:"asset_id"`
	Asset        string `json:"asset"`
	Protocol     string `json:"protocol"`
	Verdict      string `json:"verdict"`
	Evidence     string `json:"evidence,omitempty"`
	Note         string `json:"note,omitempty"`
}

// probeResultEnvelope 是四个验证器共用的返回外壳。
// 它们的 results[] 都带 verdict，成功值分别是 ok（ssh/smb/db）与 success（web）。
type probeResultEnvelope struct {
	AnySuccess bool `json:"any_success"`
	Locked     bool `json:"locked"`
	Results    []struct {
		Username string `json:"username"`
		Domain   string `json:"domain"`
		Verdict  string `json:"verdict"`
		Detail   string `json:"detail"`
		Evidence string `json:"evidence"`
	} `json:"results"`
}

// credentialReuseMatrix 是工具实现。
func (t *ToolSet) credentialReuseMatrix() actool.CoreTool {
	return writeTool(
		"credential_reuse_matrix",
		"(凭据复用)把凭据库里的凭据在指定资产上批量验证一遍，返回「凭据 × 资产」结果矩阵，"+
			"并把成功的组合自动写回凭据库（verified 关系，含证据）。\n"+
			"用途：拿到一批凭据后回答「这些账号到底能登进哪几台机器」——横向移动前最重要的一步。\n"+
			"协议自动按资产端口/URL 选择：22→ssh_check、445→smb_check、3306/5432/6379→db_check、"+
			"有 URL 或 80/443→http_login_check；也可用 protocols 限定。\n"+
			"凭据来源：不传 credential_ids 时用当前任务范围内【全部】凭据（建议先用 list_credentials 看一眼）。\n"+
			"**必须显式传 asset_ids**——本工具不会替你扫全任务资产。\n"+
			"防锁定纪律（不可关闭）：每凭据每资产只试 1 次、同账号失败 ≥2 次即停、遇锁定/禁用/429 立即中止、"+
			"单次上限 40 组合、串行 300ms 间隔。\n"+
			"dry_run=true 只返回将要执行的组合清单，不发任何请求——不确定时先 dry_run 看一眼。",
		obj(map[string]any{
			"asset_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "目标资产 id 列表（必填，须在当前任务范围内）。可用 list_assets 查询。",
			},
			"credential_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "要用哪些凭据（可选；不传=任务范围内全部凭据）。id 来自 list_credentials。",
			},
			"protocols": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string", "enum": []string{"ssh", "smb", "http", "mysql", "postgres", "redis"}},
				"description": "限定协议（可选；不传=按资产端口/URL 自动选择）。",
			},
			"max_attempts": map[string]any{
				"type":        "integer",
				"default":     credMatrixDefaultAttempts,
				"description": fmt.Sprintf("本次最多尝试多少组合（默认 %d，上限 %d）。超出的组合不会执行，返回里会标注。", credMatrixDefaultAttempts, credMatrixMaxAttempts),
			},
			"dry_run": map[string]any{
				"type":        "boolean",
				"default":     false,
				"description": "true=只返回将要执行的组合清单，不发请求（推荐先跑一次确认范围）。",
			},
		}, "asset_ids"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("credential_reuse_matrix 未启用: AssetStore 未初始化"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("credential_reuse_matrix 需要任务上下文(当前无 task)"), nil
			}
			var a struct {
				AssetIDs      []int64  `json:"asset_ids"`
				CredentialIDs []int64  `json:"credential_ids"`
				Protocols     []string `json:"protocols"`
				MaxAttempts   int      `json:"max_attempts"`
				DryRun        bool     `json:"dry_run"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			if len(a.AssetIDs) == 0 {
				return actool.Errorf("asset_ids 不能为空：本工具不会替你扫全任务资产，请先用 list_assets 选定目标"), nil
			}
			budget := a.MaxAttempts
			if budget <= 0 {
				budget = credMatrixDefaultAttempts
			}
			if budget > credMatrixMaxAttempts {
				budget = credMatrixMaxAttempts
			}

			assets, err := t.as.GetByIDsInScope(t.taskID, a.AssetIDs)
			if err != nil {
				return actool.Errorf("读取资产失败: " + err.Error()), nil
			}
			if len(assets) == 0 {
				return actool.Errorf("给定的 asset_ids 都不在当前任务范围内（请确认资产归属）"), nil
			}
			missing := len(a.AssetIDs) - len(assets)

			creds, err := t.matrixCredentials(a.CredentialIDs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(creds) == 0 {
				return actool.Errorf("没有可用凭据：请先用 record_credential 登记，或检查 credential_ids"), nil
			}

			allow := map[string]bool{}
			for _, p := range a.Protocols {
				if s := strings.ToLower(strings.TrimSpace(p)); s != "" {
					allow[s] = true
				}
			}

			// 生成计划：凭据 × 资产 × 该资产支持的协议。
			var plan []credMatrixProbe
			for _, asset := range assets {
				protos := matrixProtocolsForAsset(asset)
				if len(allow) > 0 {
					filtered := protos[:0]
					for _, p := range protos {
						if allow[p.protocol] {
							filtered = append(filtered, p)
						}
					}
					protos = filtered
				}
				for _, p := range protos {
					for i := range creds {
						c := &creds[i]
						if !matrixCredentialFits(c, p.protocol) {
							continue
						}
						plan = append(plan, credMatrixProbe{
							cred:       c,
							credID:     c.ID,
							assetID:    asset.ID,
							assetLabel: matrixAssetLabel(asset),
							protocol:   p.protocol,
							port:       p.port,
							host:       matrixAssetHost(asset),
							url:        matrixAssetURL(asset),
						})
					}
				}
			}

			if len(plan) == 0 {
				return jsonResult(map[string]any{
					"planned": 0,
					"note": "没有可执行的组合：检查凭据与资产的协议是否匹配" +
						"（如 token 型凭据不能用于 ssh/smb；资产需有对应端口或 URL）。",
					"assets_scanned": len(assets),
					"credentials":    len(creds),
				})
			}

			truncated := 0
			if len(plan) > budget {
				truncated = len(plan) - budget
				plan = plan[:budget]
			}

			if a.DryRun {
				preview := make([]map[string]any, 0, len(plan))
				for _, p := range plan {
					preview = append(preview, map[string]any{
						"credential_id": p.credID,
						"username":      p.cred.Username,
						"asset_id":      p.assetID,
						"asset":         p.assetLabel,
						"protocol":      p.protocol,
					})
				}
				return jsonResult(map[string]any{
					"dry_run":        true,
					"planned":        len(plan),
					"truncated":      truncated,
					"plan":           preview,
					"assets_scanned": len(assets),
					"assets_missing": missing,
					"credentials":    len(creds),
					"note":           "以上组合【未执行】。确认范围后把 dry_run 设为 false 再调用一次。",
				})
			}

			// 执行：串行 + 间隔 + 失败计数熔断。
			outcomes := make([]credMatrixOutcome, 0, len(plan))
			failsByAccount := map[string]int{}
			aborted := ""
			for i, p := range plan {
				if i > 0 {
					select {
					case <-ctx.Done():
						aborted = "上下文结束，已中止剩余尝试"
					case <-time.After(credMatrixAttemptGap):
					}
					if aborted != "" {
						break
					}
				}
				oc := t.runMatrixProbe(ctx, p)
				outcomes = append(outcomes, oc)

				key := strings.ToLower(strings.TrimSpace(p.cred.Username))
				switch {
				case oc.Verdict == "ok":
					// 成功不累计失败。
				case oc.Verdict == "locked" || oc.Verdict == "disabled" ||
					strings.Contains(strings.ToLower(oc.Note), "锁定") ||
					strings.Contains(strings.ToLower(oc.Note), "429"):
					aborted = fmt.Sprintf("检测到账号锁定/禁用/限流（%s @ %s），已立即中止剩余 %d 个组合",
						p.cred.Username, p.assetLabel, len(plan)-i-1)
				case oc.Verdict == "failed" || oc.Verdict == "auth_failed" ||
					oc.Verdict == "wrong_password" || oc.Verdict == "no_such_user":
					if key != "" {
						failsByAccount[key]++
						if failsByAccount[key] >= credMatrixMaxFailsPerAccount {
							aborted = fmt.Sprintf("账号 %s 累计失败 %d 次，触发防锁定熔断，已中止剩余 %d 个组合",
								p.cred.Username, failsByAccount[key], len(plan)-i-1)
						}
					}
				}
				if aborted != "" {
					break
				}
			}

			// 成功的关系写回凭据库（verified）。
			var writes []db.CredentialVerifiedItem
			for _, oc := range outcomes {
				if oc.Verdict != "ok" {
					continue
				}
				writes = append(writes, db.CredentialVerifiedItem{
					CredentialID: oc.CredentialID,
					AssetID:      oc.AssetID,
					Target:       oc.Protocol,
					Evidence:     oc.Evidence,
				})
			}
			written := 0
			if len(writes) > 0 {
				n, err := t.as.Credentials().MarkVerifiedBatch(writes)
				if err != nil {
					return jsonResult(map[string]any{
						"outcomes": outcomes,
						"error":    "验证已执行但写回凭据库失败: " + err.Error() + "（结果仍在上面的 outcomes 里，可手工 mark_credential_verified 补写）",
					})
				}
				written = n
			}

			successes := make([]credMatrixOutcome, 0, len(outcomes))
			for _, oc := range outcomes {
				if oc.Verdict == "ok" {
					successes = append(successes, oc)
				}
			}
			res := map[string]any{
				"attempted":        len(outcomes),
				"successes":        len(successes),
				"verified_written": written,
				"truncated":        truncated,
				"assets_scanned":   len(assets),
				"assets_missing":   missing,
				"credentials":      len(creds),
				"outcomes":         outcomes,
			}
			if len(successes) > 0 {
				res["success_list"] = successes
				res["note"] = "success_list 里的组合已写回凭据库（verified）。" +
					"下一步：对成功的主机做权限/信息收集（record_fact 记事实、报漏洞），" +
					"并优先用成功账号在同一网段再跑一次矩阵（凭据复用）。"
			} else {
				res["note"] = "本轮无成功组合。失败原因看 outcomes[].note：auth_failed=凭据无效，" +
					"unreachable=端口不通/主机不可达，unsupported=该协议未实现验证器。"
			}
			if aborted != "" {
				res["aborted"] = aborted
			}
			return jsonResult(res)
		},
	)
}

// matrixCredentials 解析要用的凭据集合。
// 显式 id 时逐个取（并校验任务可见性）；否则取任务范围内全部凭据并去重。
func (t *ToolSet) matrixCredentials(ids []int64) ([]db.CredentialSecret, error) {
	store := t.as.Credentials()
	var out []db.CredentialSecret
	seen := map[int64]bool{}
	if len(ids) > 0 {
		for _, id := range ids {
			if id <= 0 || seen[id] {
				continue
			}
			seen[id] = true
			c, err := store.SecretByID(t.taskID, id)
			if err != nil {
				continue // 不可见/不存在的 id 直接跳过，不中断整批
			}
			out = append(out, *c)
		}
		return out, nil
	}
	rows, err := store.ListForTask(t.taskID, "", "", 0, 500, 0)
	if err != nil {
		return nil, fmt.Errorf("读取凭据失败: %w", err)
	}
	for _, r := range rows {
		if r.ID <= 0 || seen[r.ID] || !r.HasSecret {
			continue
		}
		seen[r.ID] = true
		c, err := store.SecretByID(t.taskID, r.ID)
		if err != nil {
			continue
		}
		out = append(out, *c)
	}
	return out, nil
}

// matrixEndpoint 是某资产支持的一个可验证入口。
type matrixEndpoint struct {
	protocol string
	port     int
}

// matrixProtocolsForAsset 按端口/服务名/URL 推断资产的可用验证协议。
//
// 判定顺序：先看端口（最可靠），再看 service_name（ssh/smb/mysql…），最后看 URL。
// 同一资产可有多个入口（既开 22 又开 445）。
func matrixProtocolsForAsset(a *db.Asset) []matrixEndpoint {
	var out []matrixEndpoint
	add := func(proto string, port int) {
		for _, e := range out {
			if e.protocol == proto {
				return
			}
		}
		out = append(out, matrixEndpoint{protocol: proto, port: port})
	}
	port := 0
	if a.Port != nil {
		port = *a.Port
	}
	switch port {
	case 22:
		add("ssh", 22)
	case 445:
		add("smb", 445)
	case 3306:
		add("mysql", 3306)
	case 5432:
		add("postgres", 5432)
	case 6379:
		add("redis", 6379)
	}
	switch strings.ToLower(strings.TrimSpace(a.ServiceName)) {
	case "ssh":
		add("ssh", 22)
	case "smb", "microsoft-ds", "netbios-ssn":
		add("smb", 445)
	case "mysql":
		add("mysql", 3306)
	case "postgres", "postgresql":
		add("postgres", 5432)
	case "redis":
		add("redis", 6379)
	case "http", "https", "http-proxy":
		add("http", port)
	}
	if strings.HasPrefix(strings.ToLower(a.URL), "http") {
		add("http", port)
	}
	// 连端口都没有但开了 80/443 的服务资产，按 Web 处理。
	if len(out) == 0 && (port == 80 || port == 443) {
		add("http", port)
	}
	return out
}

// matrixCredentialFits 判断凭据形态是否适用于某协议。
//
// 关键取舍：token / cookie 型凭据只对 HTTP 有意义——把它们喂给 ssh_check 只会
// 产生一堆无意义的认证失败，还会把账号失败计数推高（触发防锁定熔断）。
// 用户名留空的凭据只适用于 http（如纯 Cookie 会话），ssh/smb/db 需要账号。
func matrixCredentialFits(c *db.CredentialSecret, protocol string) bool {
	if c == nil || strings.TrimSpace(c.Secret) == "" {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(c.CredType))
	isToken := strings.Contains(kind, "token") || strings.Contains(kind, "cookie") ||
		strings.Contains(kind, "session") || strings.Contains(kind, "jwt") ||
		strings.Contains(kind, "bearer") || strings.Contains(kind, "key")
	if protocol == "http" {
		return true // token 与账号密码都能用于 Web 登录验证
	}
	if isToken {
		return false
	}
	return strings.TrimSpace(c.Username) != ""
}

// matrixAssetHost 取资产的主机地址（优先 IP，其次域名）。
func matrixAssetHost(a *db.Asset) string {
	if ip := strings.TrimSpace(a.IP); ip != "" {
		return ip
	}
	return strings.TrimSpace(a.Domain)
}

// matrixAssetLabel 是返回结果里给人看的目标标识。
func matrixAssetLabel(a *db.Asset) string {
	host := matrixAssetHost(a)
	if a.Port != nil && *a.Port > 0 {
		return fmt.Sprintf("%s:%d", host, *a.Port)
	}
	if u := strings.TrimSpace(a.URL); u != "" {
		return u
	}
	return host
}

// matrixAssetURL 是 Web 登录验证的登录页地址。
func matrixAssetURL(a *db.Asset) string {
	if u := strings.TrimSpace(a.URL); strings.HasPrefix(strings.ToLower(u), "http") {
		return u
	}
	host := matrixAssetHost(a)
	if host == "" {
		return ""
	}
	if a.Port != nil && *a.Port > 0 && *a.Port != 80 && *a.Port != 443 {
		return fmt.Sprintf("http://%s:%d/", host, *a.Port)
	}
	return "https://" + host + "/"
}

// runMatrixProbe 执行一条尝试：调用对应验证器，把结果归一成 ok / failed / ... 判定。
func (t *ToolSet) runMatrixProbe(ctx context.Context, p credMatrixProbe) credMatrixOutcome {
	oc := credMatrixOutcome{
		CredentialID: p.credID,
		Username:     p.cred.Username,
		AssetID:      p.assetID,
		Asset:        p.assetLabel,
		Protocol:     p.protocol,
	}

	var (
		tool    actool.CoreTool
		payload map[string]any
	)
	switch p.protocol {
	case "ssh":
		cred := map[string]any{"username": p.cred.Username}
		if strings.Contains(strings.ToLower(p.cred.CredType), "key") {
			cred["private_key"] = p.cred.Secret
		} else {
			cred["password"] = p.cred.Secret
		}
		tool = t.sshCheck()
		payload = map[string]any{"host": p.host, "port": p.port, "credentials": []any{cred}}
	case "smb":
		tool = t.smbCheck()
		payload = map[string]any{
			"host": p.host,
			"port": p.port,
			"credentials": []any{map[string]any{
				"domain":   p.cred.Domain,
				"username": p.cred.Username,
				"password": p.cred.Secret,
			}},
		}
	case "mysql", "postgres", "redis":
		tool = t.dbCheck()
		payload = map[string]any{
			"host":   p.host,
			"engine": p.protocol,
			"port":   p.port,
			"credentials": []any{map[string]any{
				"username": p.cred.Username,
				"password": p.cred.Secret,
			}},
		}
	case "http":
		u := p.url
		if u == "" {
			oc.Verdict = "unsupported"
			oc.Note = "资产没有可用 URL，无法做 Web 登录验证"
			return oc
		}
		tool = t.httpLoginCheck()
		payload = map[string]any{
			"url":       u,
			"users":     []string{p.cred.Username},
			"passwords": []string{p.cred.Secret},
			// pairs 模式保证只做 1 次配对，不做笛卡尔积。
			"mode": "pairs",
		}
	default:
		oc.Verdict = "unsupported"
		oc.Note = "该协议没有对应的验证器"
		return oc
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		oc.Verdict = "error"
		oc.Note = "构造参数失败: " + err.Error()
		return oc
	}
	res, err := tool.Call(ctx, raw, nil)
	if err != nil {
		oc.Verdict = "error"
		oc.Note = "调用验证器失败: " + err.Error()
		return oc
	}
	text := res.Flatten()
	if res.IsError {
		oc.Verdict = "error"
		oc.Note = matrixFirstLine(text)
		return oc
	}

	var env probeResultEnvelope
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		oc.Verdict = "error"
		oc.Note = "验证器返回无法解析: " + matrixFirstLine(text)
		return oc
	}
	if env.Locked {
		oc.Verdict = "locked"
		oc.Note = "目标返回锁定/限流信号"
		return oc
	}
	if len(env.Results) == 0 {
		oc.Verdict = "error"
		oc.Note = "验证器没有返回任何组合结果"
		return oc
	}
	r := env.Results[0]
	oc.Verdict = normalizeMatrixVerdict(r.Verdict)
	oc.Evidence = strings.TrimSpace(r.Evidence)
	if oc.Evidence == "" {
		oc.Evidence = strings.TrimSpace(r.Detail)
	}
	if oc.Verdict == "ok" {
		// 证据要能直接支撑「横向成功」这个结论，不能是空串。
		if oc.Evidence == "" {
			oc.Evidence = fmt.Sprintf("%s 认证成功（%s@%s）", p.protocol, p.cred.Username, p.assetLabel)
		}
		oc.Evidence = fmt.Sprintf("[credential_reuse_matrix] %s: %s", p.protocol, oc.Evidence)
	} else if oc.Verdict != "failed" {
		oc.Note = strings.TrimSpace(r.Detail + " " + r.Evidence)
	}
	return oc
}

// normalizeMatrixVerdict 把四个验证器各自的成功/失败词统一成一套判定。
//
// ssh/smb/db 用 ok / wrong_password / no_such_user / ...；web 用 success / possible /
// failed。矩阵里只需要四类：ok（实证可用）、failed（确定不可用）、
// locked（触发防护）、other（需人工看）。
func normalizeMatrixVerdict(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ok", "success":
		return "ok"
	case "failed", "auth_failed", "wrong_password", "no_such_user", "denied":
		return "failed"
	case "locked", "locked_out", "disabled", "account_disabled", "account_locked_out":
		return "locked"
	case "possible":
		return "possible"
	case "error", "unreachable", "skipped":
		return v
	}
	return "other"
}

// matrixFirstLine 取文本首行并截断，用于错误提示。
func matrixFirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
