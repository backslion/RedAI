package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// 这组测试是凭据库的**集成**测试：需要真实 PostgreSQL（无 DSN 时跳过）。
// 单元测试只能验判据函数，验不了这里真正容易出错的地方——唯一键去重、
// discovered/verified 并存、读取投影是否漏了 secret、任务范围 CTE 的
// 占位符对齐、级联删除与孤儿清理。

// seedCredentialAsset 插入一条带 auth 的 service 资产，返回 id。
func seedCredentialAsset(t *testing.T, d *DB, name, ip string, authJSON string) int64 {
	t.Helper()
	var id int64
	err := d.QueryRow(`INSERT INTO assets(type, ip, port, service_name, auth)
VALUES ('service', $1, 22, $2, ARRAY[$3::jsonb]) RETURNING id`, ip, name, authJSON).Scan(&id)
	if err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func cleanCredentialTestData(t *testing.T, d *DB) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM asset_credential_links`,
		`DELETE FROM asset_credentials`,
		`DELETE FROM assets WHERE service_name LIKE 'credtest-%'`,
		`DELETE FROM task_scope WHERE task_id IN (SELECT id FROM tasks WHERE name LIKE 'credtest-%')`,
		`DELETE FROM tasks WHERE name LIKE 'credtest-%'`,
		`DELETE FROM explorations WHERE goal LIKE 'credtest-%'`,
		`DELETE FROM settings WHERE key='` + credentialsBackfillFlag + `'`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("cleanup %q: %v", q, err)
		}
	}
}

// TestCredentialBackfillDedupes 验证存量 assets.auth 回填：
// 两台上同一组凭据必须收敛成一条身份 + 两条 discovered 关系，而不是两条身份。
func TestCredentialBackfillDedupes(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	const auth = `{"username":"root","password":"Passw0rd!","type":"ssh","description":"取自 /etc/ssh/sshd_config"}`
	a := seedCredentialAsset(t, d, "credtest-a", "10.0.0.5", auth)
	b := seedCredentialAsset(t, d, "credtest-b", "10.0.0.6", auth)

	// 重跑迁移（flag 已被 cleanup 删掉），模拟升级后首次启动。
	if err := d.migrateAuthCredentials(); err != nil {
		t.Fatalf("migrateAuthCredentials: %v", err)
	}

	var identities, links int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credentials`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links WHERE relation='discovered'`).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if identities != 1 {
		t.Errorf("同一凭据应去重为 1 条身份，实际 %d", identities)
	}
	if links != 2 {
		t.Errorf("两台资产应各留一条 discovered 关系，实际 %d", links)
	}

	var source string
	if err := d.QueryRow(`SELECT source FROM asset_credential_links WHERE asset_id=$1`, a).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, "回填") {
		t.Errorf("回填来源应可辨识，实际 %q", source)
	}
	if !strings.Contains(source, "sshd_config") {
		t.Errorf("原 description 线索不应被吞掉，实际 %q", source)
	}

	// 幂等：再跑一次不应新增关系。
	if err := d.migrateAuthCredentials(); err != nil {
		t.Fatalf("migrateAuthCredentials (2nd): %v", err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links`).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 2 {
		t.Errorf("重跑迁移产生了重复关系，实际 %d", links)
	}

	_ = b
}

// TestCredentialRelationsCoexist 验证「A 发现、B 认证成功」是两条关系：
// 标记 B 为 verified 不得覆盖或移除 A 的 discovered 来源。
func TestCredentialRelationsCoexist(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	creds := d.Credentials()
	a := seedCredentialAsset(t, d, "credtest-a", "10.0.1.5", `{"username":"root","password":"Passw0rd!","type":"ssh"}`)
	b := seedCredentialAsset(t, d, "credtest-b", "10.0.1.6", `{"username":"root","password":"Passw0rd!","type":"ssh"}`)

	credID, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "ssh", Username: "root", Secret: "Passw0rd!"},
		CredentialLinkInput{AssetID: a, Relation: CredentialRelationDiscovered, Target: "ssh", Source: "credtest"})
	if err != nil {
		t.Fatalf("UpsertDiscovered: %v", err)
	}
	if _, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "ssh", Username: "root", Secret: "Passw0rd!"},
		CredentialLinkInput{AssetID: b, Relation: CredentialRelationDiscovered, Target: "ssh", Source: "credtest"}); err != nil {
		t.Fatalf("UpsertDiscovered(2): %v", err)
	}
	if err := creds.MarkVerified(credID, b, "ssh", "ssh_check: auth ok (uid=0)"); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	// 重复标记必须幂等（PK 含 relation）。
	if err := creds.MarkVerified(credID, b, "ssh", "ssh_check: auth ok (uid=0)"); err != nil {
		t.Fatalf("MarkVerified (2nd): %v", err)
	}

	agg, err := creds.AggregateAuth([]int64{a, b})
	if err != nil {
		t.Fatalf("AggregateAuth: %v", err)
	}
	if rels := relationSetOf(agg[a]); rels["verified"] {
		t.Error("A 只被『发现』，不应出现 verified 关系")
	}
	if rels := relationSetOf(agg[a]); !rels["discovered"] {
		t.Error("A 的 discovered 来源丢失")
	}
	if rels := relationSetOf(agg[b]); !rels["verified"] || !rels["discovered"] {
		t.Errorf("B 应同时持有 discovered 与 verified，实际 %v", rels)
	}

	// 读取投影绝不能带出 secret。
	raw, err := json.Marshal(agg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Passw0rd!") {
		t.Error("AggregateAuth 输出了明文 secret——凭据会进 LLM 上下文")
	}

	var verifiedRows int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links WHERE relation='verified'`).Scan(&verifiedRows); err != nil {
		t.Fatal(err)
	}
	if verifiedRows != 1 {
		t.Errorf("重复标记不应产生重复行，实际 %d", verifiedRows)
	}
}

// TestCredentialScopeGuard 验证按任务读取 secret 的守卫：范围不命中的任务
// 既看不到凭据，也读不到 secret；同时校验 scopeTargetCTE 的占位符对齐。
func TestCredentialScopeGuard(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	creds := d.Credentials()
	assetID := seedCredentialAsset(t, d, "credtest-scope", "10.0.0.5", `{"username":"root","password":"Passw0rd!","type":"ssh"}`)
	credID, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "ssh", Username: "root", Secret: "Passw0rd!"},
		CredentialLinkInput{AssetID: assetID, Relation: CredentialRelationDiscovered, Target: "ssh", Source: "credtest"})
	if err != nil {
		t.Fatalf("UpsertDiscovered: %v", err)
	}

	mkTask := func(name, cidr string) int64 {
		var expID, taskID int64
		if err := d.QueryRow(`INSERT INTO explorations(goal) VALUES ('credtest-'||$1) RETURNING id`, name).Scan(&expID); err != nil {
			t.Fatalf("seed exploration: %v", err)
		}
		if err := d.QueryRow(`INSERT INTO tasks(description, goal, exploration_id, name)
VALUES ('credtest','credtest',$1,$2) RETURNING id`, expID, "credtest-"+name).Scan(&taskID); err != nil {
			t.Fatalf("seed task: %v", err)
		}
		if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, net) VALUES ($1,'cidr',$2)`, taskID, cidr); err != nil {
			t.Fatalf("seed scope: %v", err)
		}
		return taskID
	}
	inScope := mkTask("in", "10.0.0.0/24")
	outScope := mkTask("out", "192.168.99.0/24")

	visible, err := creds.IsVisibleForTask(inScope, credID)
	if err != nil {
		t.Fatalf("IsVisibleForTask(in): %v", err)
	}
	if !visible {
		t.Error("范围命中的任务应可见该凭据")
	}
	if visible, err = creds.IsVisibleForTask(outScope, credID); err != nil {
		t.Fatalf("IsVisibleForTask(out): %v", err)
	}
	if visible {
		t.Error("范围不命中的任务不应看到该凭据")
	}

	sec, err := creds.SecretByID(inScope, credID)
	if err != nil {
		t.Fatalf("SecretByID(in): %v", err)
	}
	if sec.Secret != "Passw0rd!" {
		t.Error("SecretByID 未取回正确 secret")
	}
	if _, err := creds.SecretByID(outScope, credID); err == nil {
		t.Error("范围不命中的任务居然读到了 secret——这是越权")
	}

	rows, err := creds.ListForTask(inScope, "", "", 0, 100, 0)
	if err != nil {
		t.Fatalf("ListForTask(in): %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("任务内应看到 1 条凭据关系，实际 %d", len(rows))
	}
	if out, err := creds.ListForTask(outScope, "", "", 0, 100, 0); err != nil {
		t.Fatalf("ListForTask(out): %v", err)
	} else if len(out) != 0 {
		t.Errorf("任务外不应看到任何凭据，实际 %d", len(out))
	}

	// 投影同样不能带 secret。
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "Passw0rd!") {
		t.Error("ListForTask 投影包含明文 secret")
	}
}

// TestCredentialPruneOrphaned 验证资产删除后（关系级联消失）孤儿身份被清理，
// 否则不可见的 secret 会永久留在库里。
func TestCredentialPruneOrphaned(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	creds := d.Credentials()
	assetID := seedCredentialAsset(t, d, "credtest-orphan", "10.0.2.5", `{"username":"orphan","password":"only-on-this-asset","type":"ssh"}`)
	if _, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "ssh", Username: "orphan", Secret: "only-on-this-asset"},
		CredentialLinkInput{AssetID: assetID, Relation: CredentialRelationDiscovered, Target: "ssh", Source: "credtest"}); err != nil {
		t.Fatalf("UpsertDiscovered: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM assets WHERE id=$1`, assetID); err != nil {
		t.Fatalf("delete asset: %v", err)
	}

	pruned, err := creds.PruneOrphaned()
	if err != nil {
		t.Fatalf("PruneOrphaned: %v", err)
	}
	if pruned != 1 {
		t.Errorf("应清理 1 条孤儿身份，实际 %d", pruned)
	}
	var left int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credentials WHERE username='orphan'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("孤儿身份未被清理，剩余 %d", left)
	}
}

func relationSetOf(items []map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, it := range items {
		if r, ok := it["relation"].(string); ok {
			out[r] = true
		}
	}
	return out
}

// TestCredentialListAllFilters 验证台账页依赖的筛选/分页/汇总/删除：
// 分页总数必须与筛选条件一致（页脚「共 N 条」就靠它），删除必须真实生效。
func TestCredentialListAllFilters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	creds := d.Credentials()
	// 内网 SSH（认证成功）+ 公网 MySQL（仅发现）+ 内网 Redis（仅发现）
	inner := seedCredentialAsset(t, d, "credtest-inner", "10.9.0.11", `{"username":"root","password":"Aa1!","type":"ssh"}`)
	outer := seedCredentialAsset(t, d, "credtest-outer", "203.0.113.9", `{"username":"dbuser","password":"Bb2!","type":"mysql"}`)
	if _, err := d.Exec(`UPDATE assets SET domain='db.example.com' WHERE id=$1`, outer); err != nil {
		t.Fatal(err)
	}

	sshID, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "ssh", Username: "root", Secret: "Aa1!"},
		CredentialLinkInput{AssetID: inner, Relation: CredentialRelationDiscovered, Target: "ssh", Source: "credtest"})
	if err != nil {
		t.Fatalf("UpsertDiscovered(ssh): %v", err)
	}
	if err := creds.MarkVerified(sshID, inner, "ssh", "ssh_check: auth ok"); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if _, err := creds.UpsertDiscovered(
		CredentialInput{CredType: "mysql", Username: "dbuser", Secret: "Bb2!"},
		CredentialLinkInput{AssetID: outer, Relation: CredentialRelationDiscovered, Target: "mysql", Source: "credtest"}); err != nil {
		t.Fatalf("UpsertDiscovered(mysql): %v", err)
	}

	// 全部：ssh 两条关系（discovered+verified）+ mysql 一条。
	all, total, err := creds.ListAll(CredentialListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Errorf("全部关系应为 3 条，实际 total=%d len=%d", total, len(all))
	}

	// 关系筛选
	verified, vTotal, err := creds.ListAll(CredentialListFilter{Relation: "verified"})
	if err != nil {
		t.Fatalf("ListAll(verified): %v", err)
	}
	if vTotal != 1 || len(verified) != 1 || verified[0].Relation != "verified" {
		t.Errorf("verified 筛选应只返回 1 条认证关系，实际 total=%d len=%d", vTotal, len(verified))
	}

	// 类型筛选
	mysql, mTotal, err := creds.ListAll(CredentialListFilter{CredType: "mysql"})
	if err != nil {
		t.Fatalf("ListAll(mysql): %v", err)
	}
	if mTotal != 1 || len(mysql) != 1 || mysql[0].Username != "dbuser" {
		t.Errorf("mysql 筛选结果不对，实际 total=%d", mTotal)
	}

	// 关键词：域名命中
	byDomain, dTotal, err := creds.ListAll(CredentialListFilter{Query: "db.example.com"})
	if err != nil {
		t.Fatalf("ListAll(q=domain): %v", err)
	}
	if dTotal != 1 || len(byDomain) != 1 {
		t.Errorf("按域名搜索应命中 1 条，实际 total=%d", dTotal)
	}

	// 关键词：用户名命中（大小写不敏感）
	_, uTotal, err := creds.ListAll(CredentialListFilter{Query: "DBUSER"})
	if err != nil {
		t.Fatalf("ListAll(q=user): %v", err)
	}
	if uTotal != 1 {
		t.Errorf("用户名搜索应大小写不敏感命中 1 条，实际 %d", uTotal)
	}

	// 仅内网：只保留 10.9.0.11 上的两条
	intra, iTotal, err := creds.ListAll(CredentialListFilter{IntranetOnly: true})
	if err != nil {
		t.Fatalf("ListAll(intranet): %v", err)
	}
	if iTotal != 2 || len(intra) != 2 {
		t.Errorf("内网筛选应命中 2 条，实际 total=%d len=%d", iTotal, len(intra))
	}
	for _, r := range intra {
		if r.AssetIP != "10.9.0.11" {
			t.Errorf("内网筛选混入了公网资产 %s", r.AssetIP)
		}
	}

	// 分页：total 是筛选后的总数，不随 limit 变
	page1, pTotal, err := creds.ListAll(CredentialListFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("ListAll(page1): %v", err)
	}
	if pTotal != 3 || len(page1) != 2 {
		t.Errorf("第一页应返回 2 条且 total=3，实际 len=%d total=%d", len(page1), pTotal)
	}
	page2, _, err := creds.ListAll(CredentialListFilter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("ListAll(page2): %v", err)
	}
	if len(page2) != 1 {
		t.Errorf("第二页应剩 1 条，实际 %d", len(page2))
	}
	// 越界页不报错，返回空集
	page3, _, err := creds.ListAll(CredentialListFilter{Limit: 2, Offset: 99})
	if err != nil {
		t.Fatalf("ListAll(offset beyond): %v", err)
	}
	if len(page3) != 0 {
		t.Errorf("越界页应为空，实际 %d", len(page3))
	}

	// 汇总口径
	st, err := creds.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Identities != 2 || st.Links != 3 || st.Verified != 1 || st.Discovered != 2 {
		t.Errorf("汇总数字不对: %+v", st)
	}
	if st.IntranetLinks != 2 || st.VerifiedIntra != 1 {
		t.Errorf("内网口径不对: %+v", st)
	}
	if st.WithSecret != 2 || st.DistinctTypes != 2 {
		t.Errorf("secret/类型口径不对: %+v", st)
	}

	// 删除：关系级联消失、身份消失、不存在时返回 false
	ok, err := creds.Delete(sshID)
	if err != nil || !ok {
		t.Fatalf("Delete: ok=%v err=%v", ok, err)
	}
	var links int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links WHERE credential_id=$1`, sshID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 0 {
		t.Errorf("删除凭据后关系应级联清除，实际剩 %d", links)
	}
	if ok, err := creds.Delete(sshID); err != nil || ok {
		t.Errorf("重复删除应返回 ok=false（用于 404），实际 ok=%v err=%v", ok, err)
	}
}

// TestSyncAuthDiscoveries 验证「资产写入时就地入账」：新插入的资产带 auth，
// 不必等进程重启（回填）就能出现在台账里；重复同步不产生重复关系。
func TestSyncAuthDiscoveries(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	cleanCredentialTestData(t, d)
	defer cleanCredentialTestData(t, d)

	creds := d.Credentials()
	assetID := seedCredentialAsset(t, d, "credtest-sync", "10.3.3.3", "{}")
	auth := []map[string]any{
		{"type": "ssh", "username": "root", "password": "Sync1!", "description": "取自 /root/.ssh/id_rsa.bak"},
		{"type": "ssh", "username": "nopass"}, // 无 secret：不是凭据，应被跳过
	}

	n, err := creds.SyncAuthDiscoveries(assetID, "10.3.3.3:22 ssh", "insert_assets 登记", auth)
	if err != nil {
		t.Fatalf("SyncAuthDiscoveries: %v", err)
	}
	if n != 1 {
		t.Errorf("只应登记 1 条（无 secret 的跳过），实际 %d", n)
	}
	var links int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links WHERE asset_id=$1 AND relation='discovered'`, assetID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("discovered 关系应为 1 条，实际 %d", links)
	}
	var source string
	if err := d.QueryRow(`SELECT source FROM asset_credential_links WHERE asset_id=$1`, assetID).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, "insert_assets 登记") || !strings.Contains(source, "id_rsa.bak") {
		t.Errorf("来源应同时含登记渠道与原描述，实际 %q", source)
	}

	// 幂等：同一批再同步一次，关系数不变，身份数不变。
	if _, err := creds.SyncAuthDiscoveries(assetID, "10.3.3.3:22 ssh", "insert_assets 登记", auth); err != nil {
		t.Fatalf("SyncAuthDiscoveries (2nd): %v", err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM asset_credential_links WHERE asset_id=$1`, assetID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("重复同步产生了重复关系，实际 %d", links)
	}
	var identities int
	if err := d.QueryRow(`SELECT count(*) FROM asset_credentials`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 1 {
		t.Errorf("重复同步产生了重复身份，实际 %d", identities)
	}

	// 空输入与非法 assetID 都是无操作，不报错。
	if n, err := creds.SyncAuthDiscoveries(0, "", "", auth); err != nil || n != 0 {
		t.Errorf("assetID=0 应无操作，实际 n=%d err=%v", n, err)
	}
	if n, err := creds.SyncAuthDiscoveries(assetID, "", "", nil); err != nil || n != 0 {
		t.Errorf("空 auth 应无操作，实际 n=%d err=%v", n, err)
	}
}
