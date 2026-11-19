// credentials_backfill.go：把存量 assets.auth（JSONB[]）灌进新的凭据库两表。
//
// 为什么需要：v0.4.81 之前凭据只存在 assets.auth 这一列里，新工具（record_credential /
// mark_credential_verified / list_credentials / credential_reuse_matrix）读的是
// asset_credentials + asset_credential_links。不做回填的话，升级后模型用新工具盘点
// 会得到「零凭据」，而 list_assets 明明列着一堆——两套口径打架比没有功能更糟。
//
// 幂等性：UpsertDiscovered 的唯一键是 (cred_type,username,domain,secret) 与
// (credential_id,asset_id,relation)，重复执行只会刷新 last_seen，不会产生重复行。
// 因此即使中途失败、下次启动重跑也是安全的；flag 只是省掉重复扫描的开销。
//
// 方向性：只做 assets.auth → 凭据库，**不反向写回**。旧读路径（list_assets /
// auth_request）继续读 assets.auth，行为不变；新工具写新表。两边看到的凭据集合
// 在回填后一致。

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

const credentialsBackfillFlag = "credentials_backfill_v1"

// migrateAuthCredentials 把存量 assets.auth 逐条登记为 discovered 关系。
// 只在首次启动时全量扫描；之后由 flag 短路。
func (d *DB) migrateAuthCredentials() error {
	if v, _, _ := d.GetSetting(credentialsBackfillFlag); v == "done" {
		return nil
	}

	rows, err := d.Query(`
SELECT id, COALESCE(service_name,''), array_to_json(auth)::text
FROM assets
WHERE auth IS NOT NULL AND array_length(auth, 1) > 0`)
	if err != nil {
		return fmt.Errorf("scan assets.auth: %w", err)
	}

	type pending struct {
		assetID int64
		target  string
		auth    []map[string]any
	}
	var batch []pending
	for rows.Next() {
		var p pending
		var raw string
		if err := rows.Scan(&p.assetID, &p.target, &raw); err != nil {
			rows.Close()
			return fmt.Errorf("scan assets.auth row: %w", err)
		}
		if raw == "" || raw == "null" {
			continue
		}
		if err := json.Unmarshal([]byte(raw), &p.auth); err != nil {
			// 单行脏数据不该拖垮整个启动流程：跳过并继续，其余资产照常回填。
			continue
		}
		batch = append(batch, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate assets.auth: %w", err)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(batch) == 0 {
		return d.SetSetting(credentialsBackfillFlag, "done")
	}

	creds := d.Credentials()
	err = creds.withTx(func(tx *sql.Tx) error {
		for _, p := range batch {
			for _, item := range p.auth {
				input, description, ok := credentialInputFromAuthItem(item)
				if !ok {
					continue // 没有可用 secret 的条目不是凭据
				}
				// 来源标注回填来源，让人一眼看出这条不是本次任务采集的；
				// 原 description 有内容时保留，别把采集线索吞掉。
				source := "assets.auth 回填（历史凭据）"
				if s := strings.TrimSpace(description); s != "" {
					source = s + "（assets.auth 回填）"
				}
				credID, err := upsertCredentialIdentity(tx, input)
				if err != nil {
					return err
				}
				if err := upsertCredentialLink(tx, credID, CredentialLinkInput{
					AssetID:  p.assetID,
					Relation: CredentialRelationDiscovered,
					Target:   p.target,
					Source:   source,
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("backfill credentials: %w", err)
	}
	return d.SetSetting(credentialsBackfillFlag, "done")
}
