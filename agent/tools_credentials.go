// tools_credentials.go：资产凭据库的读写工具。
//
// 主要函数：
//   - recordCredential：登记「在某资产上发现」的凭据（凭据身份 + discovered 关系）。
//   - markCredentialVerified：标记凭据在目标资产上「认证成功」（verified 关系）。
//   - listCredentials：跨资产盘点任务范围内（或内网段）的凭据关系，不含 secret。
//
// ## 为什么需要这三个工具（而不是继续用 insert_assets 的 auth 字段）
//
// v0.4.81 之前凭据只有一个存储位置：assets.auth（JSONB[]）。它有三个硬伤：
//  1. 同一条凭据在 A/B 两台机器上各存一份，改密码要改 N 处，且没有唯一键去重——
//     模型横向复用时无法判断「这条我是不是已经试过了」。
//  2. 「发现」与「认证成功」是两种不同的事实，挤在一列里只能靠 description
//     自由文本表达，无法结构化查询「哪些凭据已验证、在哪些资产上验证成功」。
//  3. 跨资产盘点（"我现在手上到底有哪些账号"）需要 JOIN assets 做索引化查询，
//     JSONB[] 做不到，模型只能把 list_assets 整个读进上下文自己归纳。
//
// ## 语义纪律（与 db/credentials.go 的约束一一对应）
//
//   - 发现与认证分离：A 主机上发现、B 主机上验证成功，是两条关系，互不覆盖。
//     mark_credential_verified 绝不移动或删除原资产的 discovered 记录。
//   - secret 不回显：三个工具的所有返回体都不含 secret 字段。要看凭据能不能用，
//     用 credential_reuse_matrix（自动试）或 auth_request（组一条命令）。
//   - 范围校验：asset_id 必须在当前任务范围内；credential_id 必须与当前任务有关联，
//     否则拒绝——防止按全局 ID 读写别的任务的凭据。

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/db"
)

// recordCredential 是 worker 的 record_credential 工具：把在【当前任务范围内】某
// 资产上发现的凭据登记入库（凭据身份 + 该资产的 discovered 关系）。
func (t *ToolSet) recordCredential() actool.CoreTool {
	return writeTool(
		"record_credential",
		"登记在指定资产上【发现】的凭据（来自文件、配置、内存、流量、数据库导出等）。\n"+
			"asset_id 是凭据的发现资产，必须在当前任务范围内（可先 list_assets 拿到 id）。\n"+
			"同一凭据重复登记会自动去重并刷新 last_seen；认证成功请改用 mark_credential_verified，"+
			"不要用本工具重复登记来表达认证。\n"+
			"返回：{credential_id, asset_id, relation:\"discovered\"}，不回显 secret。\n"+
			"拿到 credential_id 后：credential_reuse_matrix 可批量验证它能在哪些资产上用，"+
			"auth_request 可拿它组一条带认证的命令。",
		obj(map[string]any{
			"asset_id":  intp("凭据的发现资产 id（必填，须在任务范围内）"),
			"cred_type": str("凭据类型，如 password/hash/token/key/cookie/ssh_key（必填）"),
			"username":  str("账号名（可选）"),
			"domain":    str("账号所属域/租户，如 CORP（可选）"),
			"secret":    str("凭据本体：密码/哈希/token/私钥等（必填，仅用于写入与去重，不会在任何读取中回显）"),
			"target":    str("该凭据适用的协议/服务，如 smb/rdp/ssh/mysql（可选）"),
			"source":    str("发现来源，如 文件路径/配置项/内存区域/流量会话（可选，建议填写）"),
			"extra": map[string]any{
				"type":        "object",
				"description": "附加结构化信息（可选，如 hash 类型、过期时间、来源主机）",
			},
		}, "asset_id", "cred_type", "secret"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("record_credential 未启用: AssetStore 未初始化"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("record_credential 需要任务上下文(当前无 task)"), nil
			}
			var a struct {
				AssetID  int64          `json:"asset_id"`
				CredType string         `json:"cred_type"`
				Username string         `json:"username"`
				Domain   string         `json:"domain"`
				Secret   string         `json:"secret"`
				Target   string         `json:"target"`
				Source   string         `json:"source"`
				Extra    map[string]any `json:"extra"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			if a.AssetID <= 0 {
				return actool.Errorf("asset_id 不能为空"), nil
			}
			if strings.TrimSpace(a.CredType) == "" {
				return actool.Errorf("cred_type 不能为空"), nil
			}
			if strings.TrimSpace(a.Secret) == "" {
				return actool.Errorf("secret 不能为空"), nil
			}
			// 发现资产必须位于当前任务（含直接来源任务）范围内。
			assets, err := t.as.GetByIDsInScope(t.taskID, []int64{a.AssetID})
			if err != nil {
				return actool.Errorf("校验资产范围失败: " + err.Error()), nil
			}
			if len(assets) == 0 {
				return actool.Errorf(fmt.Sprintf("asset_id=%d 不在当前任务范围内，拒绝登记（请确认资产归属或先用 list_assets 查询）", a.AssetID)), nil
			}
			credentialID, err := t.as.Credentials().UpsertDiscovered(db.CredentialInput{
				CredType: a.CredType,
				Username: a.Username,
				Domain:   a.Domain,
				Secret:   a.Secret,
				Extra:    a.Extra,
			}, db.CredentialLinkInput{
				AssetID: a.AssetID,
				Target:  a.Target,
				Source:  a.Source,
			})
			if err != nil {
				return actool.Errorf("登记凭据失败: " + err.Error()), nil
			}
			t.writes.Assets++
			t.anchorOwner(a.AssetID)
			return jsonResult(map[string]any{
				"credential_id": credentialID,
				"asset_id":      a.AssetID,
				"relation":      db.CredentialRelationDiscovered,
			})
		},
	)
}

// markCredentialVerified 是 worker 的 mark_credential_verified 工具：把已发现的
// 凭据标记为在某台【任务范围内】资产上认证成功（写该资产的 verified 关系）。
// 认证资产可以是发现本机，也可以是另一台主机；发现关系保持不动。
func (t *ToolSet) markCredentialVerified() actool.CoreTool {
	return writeTool(
		"mark_credential_verified",
		"标记凭据在指定资产上【认证成功】。\n"+
			"credential_id 来自 record_credential 的返回或 list_credentials 的 id 字段。\n"+
			"asset_id 是【实际认证成功】的资产：可以是发现本机，也可以是另一台主机（横向移动验证），"+
			"但都必须在当前任务范围内。\n"+
			"evidence 必填：记录认证成功的关键证据（如 命令输出片段/返回码/会话建立信息）。\n"+
			"本工具只增加目标资产的 verified 关系，不会移动或删除原资产的发现记录。\n"+
			"注意：credential_reuse_matrix 已自动把验证成功的结果写库，不需要再手工补一次。\n"+
			"返回：{credential_id, asset_id, relation:\"verified\"}。",
		obj(map[string]any{
			"credential_id": intp("凭据 id（必填，来自 record_credential 返回或 list_credentials）"),
			"asset_id":      intp("实际认证成功的资产 id（必填，须在任务范围内；可与发现资产不同）"),
			"target":        str("认证成功的协议/服务，如 smb/rdp/ssh/URL（可选，建议填写）"),
			"evidence":      str("认证成功的关键证据（必填）：命令输出片段、返回码、会话信息等"),
		}, "credential_id", "asset_id", "evidence"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("mark_credential_verified 未启用: AssetStore 未初始化"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("mark_credential_verified 需要任务上下文(当前无 task)"), nil
			}
			var a struct {
				CredentialID int64  `json:"credential_id"`
				AssetID      int64  `json:"asset_id"`
				Target       string `json:"target"`
				Evidence     string `json:"evidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			if a.CredentialID <= 0 {
				return actool.Errorf("credential_id 不能为空"), nil
			}
			if a.AssetID <= 0 {
				return actool.Errorf("asset_id 不能为空"), nil
			}
			if strings.TrimSpace(a.Evidence) == "" {
				return actool.Errorf("evidence 不能为空：请记录认证成功的关键证据（命令输出片段/返回码/会话信息等）"), nil
			}
			creds := t.as.Credentials()
			// 凭据必须对当前任务可见（其关联资产在任务范围内），防止按全局 ID 修改无关凭据。
			visible, err := creds.IsVisibleForTask(t.taskID, a.CredentialID)
			if err != nil {
				return actool.Errorf("校验凭据可见性失败: " + err.Error()), nil
			}
			if !visible {
				return actool.Errorf(fmt.Sprintf("credential_id=%d 与当前任务无关（其关联资产不在任务范围内），拒绝标记", a.CredentialID)), nil
			}
			// 认证目标资产必须位于当前任务（含直接来源任务）范围内。
			assets, err := t.as.GetByIDsInScope(t.taskID, []int64{a.AssetID})
			if err != nil {
				return actool.Errorf("校验资产范围失败: " + err.Error()), nil
			}
			if len(assets) == 0 {
				return actool.Errorf(fmt.Sprintf("asset_id=%d 不在当前任务范围内，拒绝标记认证（请确认资产归属）", a.AssetID)), nil
			}
			if err := creds.MarkVerified(a.CredentialID, a.AssetID, a.Target, a.Evidence); err != nil {
				return actool.Errorf("标记认证失败: " + err.Error()), nil
			}
			t.writes.Assets++
			t.anchorOwner(a.AssetID)
			return jsonResult(map[string]any{
				"credential_id": a.CredentialID,
				"asset_id":      a.AssetID,
				"relation":      db.CredentialRelationVerified,
			})
		},
	)
}

// listCredentials 是跨资产凭据盘点工具（只读）。
//
// 与 list_assets 的区别：list_assets 把凭据嵌在资产 JSON 的 auth 字段里，模型要
// 自己从几十个资产里挑；本工具直接给一张「凭据 × 资产 × 关系」的平表，并可按
// relation / cred_type / 是否内网过滤，是横向移动前「清点弹药」的入口。
func (t *ToolSet) listCredentials() actool.CoreTool {
	return readTool(
		"list_credentials",
		"盘点当前任务范围内的全部凭据（凭据 × 资产 × 关系），用于横向移动前清点弹药。\n"+
			"每行包含：id（凭据 id，供 credential_reuse_matrix / auth_request 使用）、"+
			"type、username、domain、relation（discovered=发现 / verified=已认证成功）、"+
			"target（协议）、description（来源或认证证据）、has_secret、asset_id/asset_ip/asset_url。\n"+
			"**不返回 secret 本身**。\n"+
			"relation=\"verified\" 表示这条凭据在该资产上验证过，可直接拿来复用；"+
			"relation=\"discovered\" 只表示被发现，能不能用未知——交给 credential_reuse_matrix 判定。\n"+
			"过滤参数：relation / cred_type / intranet_only（只看资产 IP 在 RFC1918 的条目）。",
		obj(map[string]any{
			"relation":      str("只返回该关系：discovered 或 verified（可选）"),
			"cred_type":     str("只返回该凭据类型，如 password/hash/token（可选）"),
			"intranet_only": map[string]any{"type": "boolean", "description": "只返回内网段（10/8、172.16/12、192.168/16）资产上的凭据（可选）"},
			"limit":         intp("最多返回多少条，默认 100，上限 500"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_credentials 未启用: AssetStore 未初始化"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("list_credentials 需要任务上下文(当前无 task)"), nil
			}
			var a struct {
				Relation     string `json:"relation"`
				CredType     string `json:"cred_type"`
				IntranetOnly bool   `json:"intranet_only"`
				Limit        int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 100
			}
			if limit > 500 {
				limit = 500
			}
			if r := strings.TrimSpace(a.Relation); r != "" &&
				r != db.CredentialRelationDiscovered && r != db.CredentialRelationVerified {
				return actool.Errorf("relation 只能是 discovered 或 verified"), nil
			}
			creds := t.as.Credentials()
			var rows []db.CredentialRow
			var err error
			if a.IntranetOnly {
				// 内网口径按企业维度聚合，这里再用任务范围收一遍，避免拿到别的任务的资产。
				rows, err = creds.ListForTask(t.taskID, a.Relation, a.CredType, 0, 500, 0)
				if err != nil {
					return actool.Errorf("盘点凭据失败: " + err.Error()), nil
				}
				filtered := make([]db.CredentialRow, 0, len(rows))
				for _, r := range rows {
					if isPrivateIPv4(r.AssetIP) {
						filtered = append(filtered, r)
					}
				}
				rows = filtered
			} else {
				rows, err = creds.ListForTask(t.taskID, a.Relation, a.CredType, 0, limit, 0)
				if err != nil {
					return actool.Errorf("盘点凭据失败: " + err.Error()), nil
				}
			}
			if len(rows) > limit {
				rows = rows[:limit]
			}
			out := make([]map[string]any, 0, len(rows))
			verified := 0
			for _, r := range rows {
				if r.Relation == db.CredentialRelationVerified {
					verified++
				}
				desc := r.Source
				if r.Relation == db.CredentialRelationVerified {
					desc = r.Evidence
				}
				out = append(out, map[string]any{
					"id":           r.ID,
					"type":         r.CredType,
					"username":     r.Username,
					"domain":       r.Domain,
					"relation":     r.Relation,
					"target":       r.Target,
					"description":  desc,
					"has_secret":   r.HasSecret,
					"asset_id":     r.AssetID,
					"asset_type":   r.AssetType,
					"asset_ip":     r.AssetIP,
					"asset_domain": r.AssetDomain,
					"asset_url":    r.AssetURL,
					"company_id":   r.CompanyID,
					"company_name": r.CompanyName,
					"last_seen":    r.LastSeen,
				})
			}
			return jsonResult(map[string]any{
				"total":    len(out),
				"verified": verified,
				"items":    out,
				"note": "secret 不回显。要验证这些凭据能在哪些资产上用，调用 credential_reuse_matrix；" +
					"要拿某一条组一条带认证的命令，调用 auth_request 并传 credential_id。",
			})
		},
	)
}

// isPrivateIPv4 判断字符串 IP 是否落在 RFC1918 私网段。
// 只做字面判定（不做 DNS 解析）：资产上的 ip 字段本来就是字面量。
func isPrivateIPv4(raw string) bool {
	ip := parseIPv4(raw)
	if ip == nil {
		return false
	}
	switch {
	case ip[0] == 10:
		return true
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		return true
	case ip[0] == 192 && ip[1] == 168:
		return true
	}
	return false
}

// parseIPv4 是极简的字面 IPv4 解析（避免为一次判定引入 net 依赖差异）。
func parseIPv4(raw string) []byte {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return nil
	}
	out := make([]byte, 4)
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return nil
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return nil
		}
		out[i] = byte(n)
	}
	return out
}
