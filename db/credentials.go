// credentials.go：资产凭据身份与「发现 / 认证成功」关系的存储。
//
// 主要函数/类型：
//   - CredentialStore：asset_credentials（凭据身份）+ asset_credential_links（资产关系）的存储入口。
//   - CredentialInput / CredentialLinkInput：写入输入（含 secret，绝不用于读取投影）。
//   - CredentialView：脱敏读取视图（刻意没有 Secret 字段）。
//   - UpsertDiscovered / MarkVerified：发现关系写入与认证关系标记。
//   - AggregateAuth / PopulateAuth：按资产批量聚合脱敏凭据并回填 Asset.Auth。
//   - SecretByID：唯一的 secret 读取入口，仅供 auth_request 组命令。
//   - ListForTask / QueryIntranet：任务内与内网台账两种盘点口径。
//   - IsVisibleForTask / PruneOrphaned：任务可见性校验与孤儿凭据清理。
//
// 语义约束（承自 artex-ld dev/assets-credentials-clues-plan.md）：
//   - 凭据身份只表达「这个凭据是什么」，认证状态是资产相关的，只能由
//     links.relation='verified' 表达；asset_credentials 上没有全局 verified 字段。
//   - A 发现、B 认证：A 保留 discovered，B 增加 verified；绝不移动或删除 A 的来源。
//   - secret 只进入 asset_credentials 用于写入与唯一键去重；除 SecretByID 外的
//     所有 SELECT 投影一律不取 secret 列。
//
// 与上游的差异：RedAI 的 assets.auth 是 JSONB[] 且已有读路径（list_assets /
// auth_request），因此本层不改旧读路径，而是**双写**——新工具写新表，同时由
// backfillAuthCredentials 在启动时把存量 assets.auth 灌进新表，保证两套口径
// 看到的是同一批凭据。

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// 关系类型常量。
const (
	CredentialRelationDiscovered = "discovered"
	CredentialRelationVerified   = "verified"
)

// CredentialInput 是凭据身份的写入输入。
type CredentialInput struct {
	CredType string // 为空时落库为 'unknown'
	Username string
	Domain   string
	Secret   string // 只用于写入与唯一键去重，任何读取路径不得回填
	Extra    map[string]any
}

// CredentialLinkInput 是凭据与资产关系的写入输入。
type CredentialLinkInput struct {
	AssetID  int64
	Relation string // discovered | verified
	Target   string // 认证协议/服务，如 smb/rdp/ssh/URL
	Source   string // discovered：文件、配置、内存等来源
	Evidence string // verified：认证成功的关键证据
}

// CredentialView 是凭据的脱敏读取视图：刻意没有 Secret 字段，避免被误序列化。
type CredentialView struct {
	ID       int64          `json:"id"`
	CredType string         `json:"type"`
	Username string         `json:"username"`
	Domain   string         `json:"domain"`
	Relation string         `json:"relation"`
	Target   string         `json:"target"`
	Source   string         `json:"source"`
	Evidence string         `json:"evidence"`
	Extra    map[string]any `json:"extra,omitempty"`
	// HasSecret 只报告「这条身份带凭据本体」，不回显值本身。用于让模型判断
	// 这条凭据能不能直接拿去复用（空 secret 的空口令账号也合法，但需要显式知道）。
	HasSecret bool   `json:"has_secret"`
	CreatedAt string `json:"created_at"`
	LastSeen  string `json:"last_seen"`
}

// CredentialStore operates on asset_credentials + asset_credential_links.
// 与 AssetStore 一样支持 tx 复用：从带事务的 AssetStore 派生时，写入落在同一事务里。
type CredentialStore struct {
	db *DB
	tx *sql.Tx
}

// Credentials returns the credential store derived from this asset store,
// sharing its db handle and (when present) its open transaction.
func (s *AssetStore) Credentials() *CredentialStore {
	return &CredentialStore{db: s.db, tx: s.tx}
}

// DB 级入口：给没有 AssetStore 的场景（server 装配、后台任务）用。
func (d *DB) Credentials() *CredentialStore { return &CredentialStore{db: d} }

// credentialQuerier 抽象 *db.DB / *sql.Tx 的公共查询面。
type credentialQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func (s *CredentialStore) querier() credentialQuerier {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

// withTx 保证写入落在单事务里：已有事务直接复用，否则新开一个。
func (s *CredentialStore) withTx(fn func(tx *sql.Tx) error) error {
	if s.tx != nil {
		return fn(s.tx)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// upsertCredentialIdentity 按唯一键 (cred_type,username,domain,secret) Upsert
// 凭据身份：冲突时更新 last_seen 并返回已有 ID。
func upsertCredentialIdentity(tx *sql.Tx, c CredentialInput) (int64, error) {
	credType := strings.TrimSpace(c.CredType)
	if credType == "" {
		credType = "unknown"
	}
	extra := "{}"
	if len(c.Extra) > 0 {
		raw, err := json.Marshal(c.Extra)
		if err != nil {
			return 0, err
		}
		extra = string(raw)
	}
	var id int64
	err := tx.QueryRow(`
INSERT INTO asset_credentials(cred_type, username, domain, secret, extra)
VALUES ($1, $2, $3, $4, $5::jsonb)
ON CONFLICT (cred_type, username, domain, secret) DO UPDATE SET last_seen = now()
RETURNING id`,
		credType, c.Username, c.Domain, c.Secret, extra,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// upsertCredentialLink 写入 (credential_id, asset_id, relation) 关系：冲突时只更新
// 非空 target/source/evidence 与 last_seen，不重复插行。
func upsertCredentialLink(tx *sql.Tx, credentialID int64, link CredentialLinkInput) error {
	_, err := tx.Exec(`
INSERT INTO asset_credential_links(credential_id, asset_id, relation, target, source, evidence)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (credential_id, asset_id, relation) DO UPDATE SET
    target    = COALESCE(NULLIF(EXCLUDED.target, ''),   asset_credential_links.target),
    source    = COALESCE(NULLIF(EXCLUDED.source, ''),   asset_credential_links.source),
    evidence  = COALESCE(NULLIF(EXCLUDED.evidence, ''), asset_credential_links.evidence),
    last_seen = now()`,
		credentialID, link.AssetID, link.Relation, link.Target, link.Source, link.Evidence,
	)
	return err
}

// SyncAuthDiscoveries 把某个资产上的一组 auth 条目登记为 discovered 关系，
// 返回写入条数。转换规则与启动回填完全一致（同一 credentialInputFromAuthItem），
// 差别只在于作用域：只处理指定资产，供「资产写入时就地入账」使用。
//
// 为什么需要它：回填只在进程启动时跑一次，且靠 flag 幂等。若只依赖回填，
// 运行期通过 insert_assets / 资产 API 写进来的凭据要等下次重启才进台账——
// 期间 credential_reuse_matrix 盘点不到，等于「刚采到却用不上」。
//
// 失败不会影响资产本身（资产已落库，这里只是补登记），调用方决定是告警还是忽略。
func (s *CredentialStore) SyncAuthDiscoveries(assetID int64, target, source string, auth []map[string]any) (int, error) {
	if assetID <= 0 || len(auth) == 0 {
		return 0, nil
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "资产 auth 字段（写入时同步）"
	}
	written := 0
	err := s.withTx(func(tx *sql.Tx) error {
		for _, item := range auth {
			input, description, ok := credentialInputFromAuthItem(item)
			if !ok {
				continue // 只有用户名没有 secret 的条目不是凭据
			}
			src := source
			if d := strings.TrimSpace(description); d != "" {
				src = d + "（" + source + "）"
			}
			credID, err := upsertCredentialIdentity(tx, input)
			if err != nil {
				return err
			}
			if err := upsertCredentialLink(tx, credID, CredentialLinkInput{
				AssetID:  assetID,
				Relation: CredentialRelationDiscovered,
				Target:   target,
				Source:   src,
			}); err != nil {
				return err
			}
			written++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// UpsertDiscovered 在一个数据库事务内 Upsert 凭据身份，再写 link.AssetID 指向
// 资产的 discovered 关系。身份冲突更新 last_seen 并返回已有 ID；关系冲突更新
// 非空 target/source 与 last_seen，不重复插行。
func (s *CredentialStore) UpsertDiscovered(c CredentialInput, link CredentialLinkInput) (int64, error) {
	if link.AssetID <= 0 {
		return 0, fmt.Errorf("asset_id is required")
	}
	link.Relation = CredentialRelationDiscovered
	link.Evidence = "" // discovered 关系不携带认证证据
	var id int64
	err := s.withTx(func(tx *sql.Tx) error {
		credID, err := upsertCredentialIdentity(tx, c)
		if err != nil {
			return err
		}
		if err := upsertCredentialLink(tx, credID, link); err != nil {
			return err
		}
		id = credID
		return nil
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// MarkVerified 只新增或更新指定资产的 verified 关系：凭据不存在或证据为空时
// 返回错误；绝不修改任何 discovered 关系。
func (s *CredentialStore) MarkVerified(credentialID, assetID int64, target, evidence string) error {
	if credentialID <= 0 {
		return fmt.Errorf("credential_id is required")
	}
	if assetID <= 0 {
		return fmt.Errorf("asset_id is required")
	}
	if strings.TrimSpace(evidence) == "" {
		return fmt.Errorf("evidence is required")
	}
	return s.withTx(func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM asset_credentials WHERE id=$1)`, credentialID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("credential %d not found", credentialID)
		}
		return upsertCredentialLink(tx, credentialID, CredentialLinkInput{
			AssetID:  assetID,
			Relation: CredentialRelationVerified,
			Target:   target,
			Evidence: evidence,
		})
	})
}

// CredentialVerifiedItem 是一条「某凭据在某资产上认证成功」的批量写入项。
type CredentialVerifiedItem struct {
	CredentialID int64
	AssetID      int64
	Target       string
	Evidence     string
}

// MarkVerifiedBatch 在一个事务里批量标记 verified（凭据复用矩阵逐行判定后调用，
// 避免 N 次独立事务）。空 evidence 的条目直接跳过而不是报错——矩阵里失败的行
// 不需要落库。返回实际写入条数。
func (s *CredentialStore) MarkVerifiedBatch(items []CredentialVerifiedItem) (int, error) {
	written := 0
	err := s.withTx(func(tx *sql.Tx) error {
		for _, it := range items {
			if it.CredentialID <= 0 || it.AssetID <= 0 || strings.TrimSpace(it.Evidence) == "" {
				continue
			}
			var exists bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM asset_credentials WHERE id=$1)`, it.CredentialID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				continue
			}
			if err := upsertCredentialLink(tx, it.CredentialID, CredentialLinkInput{
				AssetID:  it.AssetID,
				Relation: CredentialRelationVerified,
				Target:   it.Target,
				Evidence: it.Evidence,
			}); err != nil {
				return err
			}
			written++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// CredentialSecret 是一次「带认证请求」所需的完整凭据。
// 只在 auth_request 组命令时短暂存在，不得写入日志/事实/报告。
type CredentialSecret struct {
	ID       int64
	CredType string
	Username string
	Domain   string
	Secret   string
	Extra    map[string]any
}

// SecretByID 是本包唯一读取 secret 的入口。
//
// 调用方必须先用 IsVisibleForTask 校验凭据对该任务可见，否则就是按全局 ID
// 越权读取别的任务的凭据。这里额外接受 taskID 并在 SQL 里再校验一次，避免
// 调用方漏做而静默泄露；taskID<=0 表示不校验（仅供 server 内部使用）。
func (s *CredentialStore) SecretByID(taskID, credentialID int64) (*CredentialSecret, error) {
	if credentialID <= 0 {
		return nil, fmt.Errorf("credential_id is required")
	}
	q := `
SELECT c.id, c.cred_type, c.username, c.domain, c.secret, c.extra
FROM asset_credentials c
WHERE c.id=$1`
	args := []any{credentialID}
	if taskID > 0 {
		q = `
WITH ` + scopeTargetCTE + `
SELECT c.id, c.cred_type, c.username, c.domain, c.secret, c.extra
FROM asset_credentials c
JOIN asset_credential_links l ON l.credential_id = c.id
JOIN target ON target.id = l.asset_id
WHERE c.id=$2`
		args = []any{taskID, credentialID}
	}
	var out CredentialSecret
	var extraRaw []byte
	if err := s.querier().QueryRow(q, args...).Scan(
		&out.ID, &out.CredType, &out.Username, &out.Domain, &out.Secret, &extraRaw,
	); err != nil {
		if err == sql.ErrNoRows {
			if taskID > 0 {
				return nil, fmt.Errorf("凭据 %d 与当前任务无关（其关联资产不在任务范围内）", credentialID)
			}
			return nil, fmt.Errorf("凭据 %d 不存在", credentialID)
		}
		return nil, err
	}
	if len(extraRaw) > 0 {
		_ = json.Unmarshal(extraRaw, &out.Extra)
	}
	return &out, nil
}

// AggregateAuth 一次查询 asset_credential_links JOIN asset_credentials，同时取回
// 每个资产的 discovered 与 verified 关系。SELECT 列表刻意不包含 secret。
// 返回的每项形状与 Asset.Auth 回填一致。
func (s *CredentialStore) AggregateAuth(assetIDs []int64) (map[int64][]map[string]any, error) {
	out := map[int64][]map[string]any{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(assetIDs))
	args := make([]any, len(assetIDs))
	for i, id := range assetIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	rows, err := s.querier().Query(`
SELECT l.asset_id, c.id, c.cred_type, c.username, c.domain,
       l.relation, l.target, l.source, l.evidence, c.extra,
       (c.secret <> '') AS has_secret,
       to_char(l.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       to_char(l.last_seen  AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
FROM asset_credential_links l
JOIN asset_credentials c ON c.id = l.credential_id
WHERE l.asset_id IN (`+strings.Join(placeholders, ",")+`)
ORDER BY l.asset_id, l.relation, l.last_seen DESC, c.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var assetID int64
		var view CredentialView
		var extraRaw []byte
		if err := rows.Scan(
			&assetID, &view.ID, &view.CredType, &view.Username, &view.Domain,
			&view.Relation, &view.Target, &view.Source, &view.Evidence, &extraRaw,
			&view.HasSecret, &view.CreatedAt, &view.LastSeen,
		); err != nil {
			return nil, err
		}
		if len(extraRaw) > 0 {
			_ = json.Unmarshal(extraRaw, &view.Extra)
		}
		description := view.Source
		if view.Relation == CredentialRelationVerified {
			description = view.Evidence
		}
		item := map[string]any{
			"id":          view.ID,
			"type":        view.CredType,
			"username":    view.Username,
			"domain":      view.Domain,
			"relation":    view.Relation,
			"target":      view.Target,
			"description": description,
			"has_secret":  view.HasSecret,
			"created_at":  view.CreatedAt,
			"last_seen":   view.LastSeen,
		}
		out[assetID] = append(out[assetID], item)
	}
	return out, rows.Err()
}

// PopulateAuth 批量回填 assets 的 Auth 字段（脱敏）。空数组直接返回；聚合失败
// 向调用方返回错误，绝不把数据库异常当作「资产没有凭据」。
func (s *CredentialStore) PopulateAuth(assets []*Asset) error {
	if len(assets) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(assets))
	seen := map[int64]bool{}
	for _, a := range assets {
		if a == nil || a.ID <= 0 || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		ids = append(ids, a.ID)
	}
	grouped, err := s.AggregateAuth(ids)
	if err != nil {
		return err
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		if items, ok := grouped[a.ID]; ok {
			a.Auth = items
		} else {
			a.Auth = nil
		}
	}
	return nil
}

// CredentialRow 是盘点表的一行：脱敏凭据关系 + 所在资产/企业投影。
type CredentialRow struct {
	CredentialView
	AssetID     int64  `json:"asset_id"`
	AssetType   string `json:"asset_type,omitempty"`
	AssetIP     string `json:"asset_ip,omitempty"`
	AssetDomain string `json:"asset_domain,omitempty"`
	AssetURL    string `json:"asset_url,omitempty"`
	CompanyID   int64  `json:"company_id,omitempty"`
	CompanyName string `json:"company_name,omitempty"`
}

// credentialRowFrom 是盘点投影的公共 FROM/JOIN 段。单独拆出来是为了让
// count(*) 与取数两条语句共用同一段连接，避免两边条件写歪导致分页总数不准。
const credentialRowFrom = `
FROM asset_credential_links l
JOIN asset_credentials c ON c.id = l.credential_id
JOIN assets a ON a.id = l.asset_id
LEFT JOIN companies co ON co.id = a.company_id`

// credentialRowCols 是 CredentialRow 投影的公共列（不含 secret）。
const credentialRowCols = `
SELECT c.id, c.cred_type, c.username, c.domain,
       l.relation, l.target, l.source, l.evidence, c.extra,
       (c.secret <> '') AS has_secret,
       to_char(l.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       to_char(l.last_seen  AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       a.id, COALESCE(a.type,''), COALESCE(a.ip,''), COALESCE(a.domain,''), COALESCE(a.url,''),
       COALESCE(a.company_id, 0), COALESCE(co.name, '')` + credentialRowFrom

func scanCredentialRows(rows *sql.Rows) ([]CredentialRow, error) {
	defer rows.Close()
	out := []CredentialRow{}
	for rows.Next() {
		var row CredentialRow
		var extraRaw []byte
		if err := rows.Scan(
			&row.ID, &row.CredType, &row.Username, &row.Domain,
			&row.Relation, &row.Target, &row.Source, &row.Evidence, &extraRaw,
			&row.HasSecret, &row.CreatedAt, &row.LastSeen,
			&row.AssetID, &row.AssetType, &row.AssetIP, &row.AssetDomain, &row.AssetURL,
			&row.CompanyID, &row.CompanyName,
		); err != nil {
			return nil, err
		}
		if len(extraRaw) > 0 {
			_ = json.Unmarshal(extraRaw, &row.Extra)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ListForTask 列出「关联资产位于该任务（含直接来源任务）范围内」的全部凭据关系。
// relation / credType / companyID 为空或 0 时不过滤；limit<=0 不分页。
func (s *CredentialStore) ListForTask(taskID int64, relation, credType string, companyID int64, limit, offset int) ([]CredentialRow, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("taskID is required")
	}
	where := `
WHERE l.asset_id IN (SELECT id FROM target)
  AND ($2 = '' OR l.relation = $2)
  AND ($3 = '' OR c.cred_type = $3)
  AND ($4 <= 0 OR a.company_id = $4)`
	args := []any{taskID, strings.TrimSpace(relation), strings.TrimSpace(credType), companyID}
	q := `WITH ` + scopeTargetCTE + credentialRowCols + where + ` ORDER BY l.last_seen DESC, c.id`
	if limit > 0 {
		q += ` LIMIT $5 OFFSET $6`
		args = append(args, limit, offset)
	}
	rows, err := s.querier().Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanCredentialRows(rows)
}

// intranetCredentialFilter 是内网凭据查询的公共 WHERE：资产 IP 落在 RFC1918
// 私网段（10/8、172.16/12、192.168/16），companyID=0 不按企业过滤。try_inet
// 容忍脏 IP：非法值返回 NULL 被自然排除。
const intranetCredentialFilter = `
WHERE (try_inet(a.ip) <<= '10.0.0.0/8'::inet
    OR try_inet(a.ip) <<= '172.16.0.0/12'::inet
    OR try_inet(a.ip) <<= '192.168.0.0/16'::inet)
  AND ($1 <= 0 OR a.company_id = $1)`

// QueryIntranet 分页返回内网资产上的 discovered/verified 凭据关系（脱敏，无
// secret）。limit<=0 不分页；同时返回符合条件的总行数供分页展示。
func (s *CredentialStore) QueryIntranet(companyID int64, limit, offset int) ([]CredentialRow, int, error) {
	total := 0
	countRows, err := s.querier().Query(`SELECT count(*) FROM asset_credential_links l
JOIN asset_credentials c ON c.id = l.credential_id
JOIN assets a ON a.id = l.asset_id`+intranetCredentialFilter, companyID)
	if err != nil {
		return nil, 0, err
	}
	if countRows.Next() {
		if err := countRows.Scan(&total); err != nil {
			countRows.Close()
			return nil, 0, err
		}
	}
	if err := countRows.Close(); err != nil {
		return nil, 0, err
	}
	if total == 0 || offset >= total {
		return []CredentialRow{}, total, nil
	}
	q := credentialRowCols + intranetCredentialFilter + ` ORDER BY l.last_seen DESC, c.id`
	args := []any{companyID}
	if limit > 0 {
		q += ` LIMIT $2 OFFSET $3`
		args = append(args, limit, offset)
	}
	rows, err := s.querier().Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := scanCredentialRows(rows)
	return out, total, err
}

// CredentialListFilter 是全局凭据台账的筛选条件。零值表示不过滤。
// 与 ListForTask 的区别：这里不限定任务范围，是「平台已知的全部凭据」视图，
// 供管理端点使用（agent 侧仍走任务范围版本，避免跨任务越权）。
type CredentialListFilter struct {
	Relation     string // discovered | verified
	CredType     string
	Query        string // 用户名 / 域 / 目标 / 资产 ip / 域名 / 服务名 模糊匹配
	CompanyID    int64
	IntranetOnly bool
	Limit        int
	Offset       int
}

// where 依据筛选条件拼出 WHERE 子句与参数。占位符按参数实际序号生成，
// 不用 $1 固定位——条件是可选的，写死序号是这类动态查询最常见的错源。
func (f CredentialListFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if v := strings.TrimSpace(f.Relation); v != "" {
		add("l.relation = $%d", v)
	}
	if v := strings.TrimSpace(f.CredType); v != "" {
		add("c.cred_type = $%d", v)
	}
	if v := strings.TrimSpace(f.Query); v != "" {
		args = append(args, "%"+strings.ToLower(v)+"%")
		n := len(args)
		conds = append(conds, fmt.Sprintf(
			`(lower(c.username) LIKE $%d OR lower(c.domain) LIKE $%d OR lower(l.target) LIKE $%d
   OR lower(COALESCE(a.ip,'')) LIKE $%d OR lower(COALESCE(a.domain,'')) LIKE $%d
   OR lower(COALESCE(a.service_name,'')) LIKE $%d)`, n, n, n, n, n, n))
	}
	if f.CompanyID > 0 {
		add("a.company_id = $%d", f.CompanyID)
	}
	if f.IntranetOnly {
		conds = append(conds, `(try_inet(a.ip) <<= '10.0.0.0/8'::inet
    OR try_inet(a.ip) <<= '172.16.0.0/12'::inet
    OR try_inet(a.ip) <<= '192.168.0.0/16'::inet)`)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return "\nWHERE " + strings.Join(conds, "\n  AND "), args
}

// ListAll 分页返回全平台凭据关系（脱敏，无 secret），并返回筛选后的总行数。
func (s *CredentialStore) ListAll(f CredentialListFilter) ([]CredentialRow, int, error) {
	where, args := f.where()
	var total int
	if err := s.querier().QueryRow(`SELECT count(*)`+credentialRowFrom+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 || (f.Limit > 0 && f.Offset >= total) {
		return []CredentialRow{}, total, nil
	}
	q := credentialRowCols + where + ` ORDER BY l.relation DESC, l.last_seen DESC, c.id`
	full := append([]any{}, args...)
	if f.Limit > 0 {
		q += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(full)+1, len(full)+2)
		full = append(full, f.Limit, f.Offset)
	}
	rows, err := s.querier().Query(q, full...)
	if err != nil {
		return nil, 0, err
	}
	out, err := scanCredentialRows(rows)
	return out, total, err
}

// CredentialStats 是台账页头部的汇总数字。intranet 口径与 QueryIntranet 一致。
type CredentialStats struct {
	Identities     int `json:"identities"`
	Links          int `json:"links"`
	Discovered     int `json:"discovered"`
	Verified       int `json:"verified"`
	IntranetLinks  int `json:"intranet_links"`
	VerifiedIntra  int `json:"verified_intranet"`
	WithSecret     int `json:"with_secret"`
	DistinctTypes  int `json:"distinct_types"`
	CompaniesCount int `json:"companies"`
}

func (s *CredentialStore) Stats() (*CredentialStats, error) {
	var out CredentialStats
	err := s.querier().QueryRow(`
SELECT
  (SELECT count(*) FROM asset_credentials),
  (SELECT count(*) FROM asset_credential_links),
  (SELECT count(*) FROM asset_credential_links WHERE relation='discovered'),
  (SELECT count(*) FROM asset_credential_links WHERE relation='verified'),
  (SELECT count(*) FROM asset_credential_links l JOIN assets a ON a.id=l.asset_id
     WHERE try_inet(a.ip) <<= '10.0.0.0/8'::inet
        OR try_inet(a.ip) <<= '172.16.0.0/12'::inet
        OR try_inet(a.ip) <<= '192.168.0.0/16'::inet),
  (SELECT count(*) FROM asset_credential_links l JOIN assets a ON a.id=l.asset_id
     WHERE l.relation='verified' AND (try_inet(a.ip) <<= '10.0.0.0/8'::inet
        OR try_inet(a.ip) <<= '172.16.0.0/12'::inet
        OR try_inet(a.ip) <<= '192.168.0.0/16'::inet)),
  (SELECT count(*) FROM asset_credentials WHERE secret <> ''),
  (SELECT count(DISTINCT cred_type) FROM asset_credentials),
  (SELECT count(DISTINCT a.company_id) FROM asset_credential_links l
     JOIN assets a ON a.id=l.asset_id WHERE a.company_id IS NOT NULL)`).Scan(
		&out.Identities, &out.Links, &out.Discovered, &out.Verified,
		&out.IntranetLinks, &out.VerifiedIntra, &out.WithSecret, &out.DistinctTypes, &out.CompaniesCount)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete 删除一条凭据身份（关系随 FK 级联删除）。返回是否真的删到了行——
// 端点据此区分 404 与 200，避免「删了不存在的东西也报成功」。
func (s *CredentialStore) Delete(credentialID int64) (bool, error) {
	if credentialID <= 0 {
		return false, fmt.Errorf("credential_id is required")
	}
	res, err := s.querier().Exec(`DELETE FROM asset_credentials WHERE id=$1`, credentialID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// IsVisibleForTask 仅当凭据已有关联资产位于当前任务（或直接来源任务）范围内时
// 返回 true。供 worker 工具校验，防止按全局 ID 修改无关凭据。
func (s *CredentialStore) IsVisibleForTask(taskID, credentialID int64) (bool, error) {
	if taskID <= 0 || credentialID <= 0 {
		return false, nil
	}
	var visible bool
	err := s.querier().QueryRow(`WITH `+scopeTargetCTE+`
SELECT EXISTS(
    SELECT 1 FROM asset_credential_links l
    JOIN target ON target.id = l.asset_id
    WHERE l.credential_id = $2
)`, taskID, credentialID).Scan(&visible)
	if err != nil {
		return false, err
	}
	return visible, nil
}

// PruneOrphaned 删除已无任何资产关系的孤儿凭据，避免留下不可见的 secret。
// 在资产删除路径（级联删除关系之后）调用；返回删除行数。
func (s *CredentialStore) PruneOrphaned() (int64, error) {
	res, err := s.querier().Exec(`
DELETE FROM asset_credentials c
WHERE NOT EXISTS (SELECT 1 FROM asset_credential_links l WHERE l.credential_id = c.id)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// credentialInputFromAuthItem 把存量/兼容入口的 auth 条目转换为凭据写入输入。
// password 为空但 token 非空时使用 token；两者都为空时返回 false（跳过，不生成
// 可用凭据）。
func credentialInputFromAuthItem(item map[string]any) (CredentialInput, string, bool) {
	str := func(key string) string {
		v, _ := item[key].(string)
		return strings.TrimSpace(v)
	}
	raw := func(key string) string {
		v, _ := item[key].(string)
		return v
	}
	secret := raw("password")
	if strings.TrimSpace(secret) == "" {
		secret = raw("token")
	}
	if strings.TrimSpace(secret) == "" {
		return CredentialInput{}, "", false
	}
	return CredentialInput{
		CredType: str("type"),
		Username: str("username"),
		Domain:   str("domain"),
		Secret:   secret,
	}, str("description"), true
}
