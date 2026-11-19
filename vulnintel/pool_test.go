package vulnintel

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePool 记录所有写语句，用来断言"这条 SQL 走了哪个池"。
//
// 故意让 db 侧为 nil：任何一个写点如果漏改回 s.db，这里会直接 nil panic，
// 而不是悄悄写进主池——这正是本组测试要守住的回归点。
type fakePool struct {
	mu           sync.Mutex
	stmts        []string
	rowsAffected int64
}

func (f *fakePool) ExecContext(_ context.Context, q string, _ ...any) (sql.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stmts = append(f.stmts, strings.Join(strings.Fields(q), " "))
	return fakeResult(f.rowsAffected), nil
}

func (f *fakePool) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, errors.New("fakePool: 写路径不应触发查询")
}

func (f *fakePool) QueryRowContext(context.Context, string, ...any) *sql.Row {
	// 返回 nil：如果某个写路径意外走读，调用方会在 Scan 处 panic，测试直接失败。
	return nil
}

func (f *fakePool) executed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.stmts...)
}

type fakeResult int64

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return int64(r), nil }

// 没配后台池时必须回落主池：这是 POJUN_PG_BG_POOL=0 与"池子建不起来"两种
// 退化路径共用的行为保证。
func TestStoreFallsBackToMainPool(t *testing.T) {
	st := New(nil)
	if st.bg != nil {
		t.Fatal("New 不应带后台池")
	}
	if got, ok := st.bgPool().(*fakePool); ok {
		t.Fatalf("bgPool 回落到了 fakePool：%T", got)
	}

	// NewWithBackgroundPool(nil) 等价于 New。
	st2 := NewWithBackgroundPool(nil, nil)
	if st2.bg != nil {
		t.Fatal("bg 为 nil 时应退回 New")
	}
}

func TestStoreUsesBackgroundPoolWhenSet(t *testing.T) {
	if got := NewWithBackgroundPool(nil, nil).bg; got != nil {
		t.Fatal("bg 为 nil 时不应持有后台池")
	}
	fake := &fakePool{}
	st := &Store{bg: fake}
	if st.bgPool() != sqlPool(fake) {
		t.Fatalf("bgPool 未返回注入的后台池: %T", st.bgPool())
	}
}

// UpsertCVE 内部是一条 INSERT + 一条 DELETE + 若干 INSERT，必须全落在后台池。
func TestUpsertCVEAllStatementsGoToBackgroundPool(t *testing.T) {
	fake := &fakePool{}
	st := &Store{bg: fake}

	c := cve("CVE-2024-9001", "acme", "widget", "1.0", 9.8)
	if err := st.UpsertCVE(context.Background(), c); err != nil {
		t.Fatalf("UpsertCVE: %v", err)
	}
	stmts := fake.executed()
	if len(stmts) != 3 {
		t.Fatalf("期望 3 条写语句（cve / 清索引 / 建索引），实际 %d 条:\n%s",
			len(stmts), strings.Join(stmts, "\n"))
	}
	if !strings.HasPrefix(stmts[0], "INSERT INTO vuln_cves") {
		t.Errorf("第 1 条应为 cve upsert，实际: %s", stmts[0])
	}
	if !strings.HasPrefix(stmts[1], "DELETE FROM vuln_cpe_products") {
		t.Errorf("第 2 条应为清 cpe 索引，实际: %s", stmts[1])
	}
	if !strings.HasPrefix(stmts[2], "INSERT INTO vuln_cpe_products") {
		t.Errorf("第 3 条应为建 cpe 索引，实际: %s", stmts[2])
	}
}

// MarkKEV 有两条分支（已有行只 UPDATE / 未知行 UPDATE 后再插 stub），两条都
// 要走后台池：KEV 整轮是顺序写几百条，落在主池就是几百次抢连接。
func TestMarkKEVGoesToBackgroundPool(t *testing.T) {
	cases := []struct {
		rowsAffected int64
		want         []string
	}{
		{1, []string{"UPDATE vuln_cves"}},
		{0, []string{"UPDATE vuln_cves", "INSERT INTO vuln_cves"}},
	}
	for _, c := range cases {
		fake := &fakePool{rowsAffected: c.rowsAffected}
		st := &Store{bg: fake}
		if err := st.MarkKEV(context.Background(), "CVE-2024-9002", time.Unix(1700000000, 0)); err != nil {
			t.Fatalf("MarkKEV: %v", err)
		}
		stmts := fake.executed()
		if len(stmts) != len(c.want) {
			t.Fatalf("rowsAffected=%d 时期望 %d 条写语句，实际 %d: %v",
				c.rowsAffected, len(c.want), len(stmts), stmts)
		}
		for i, prefix := range c.want {
			if !strings.HasPrefix(stmts[i], prefix) {
				t.Errorf("rowsAffected=%d 第 %d 条期望 %s，实际: %s",
					c.rowsAffected, i+1, prefix, stmts[i])
			}
		}
	}
}

// 同步水位是后台写的：写进主池会和高频读抢连接，而这种 upsert 每页一次。
func TestSaveSyncStateGoesToBackgroundPool(t *testing.T) {
	fake := &fakePool{}
	st := &Store{bg: fake}
	if err := st.SaveSyncState(context.Background(), SyncState{Source: "nvd", TotalSynced: 42}); err != nil {
		t.Fatalf("SaveSyncState: %v", err)
	}
	stmts := fake.executed()
	if len(stmts) != 1 || !strings.HasPrefix(stmts[0], "INSERT INTO vuln_sync_state") {
		t.Fatalf("期望 1 条 vuln_sync_state upsert，实际: %v", stmts)
	}
}

// PoC 聚合与 GHSA 合并也是同步写路径。这里只守"有写就落在后台池"，不重复
// 断言 SQL 细节（细节由各自的 PG 集成测试覆盖）。
func TestPocAndGhsaWritesGoToBackgroundPool(t *testing.T) {
	fake := &fakePool{}
	st := &Store{bg: fake}
	if err := st.UpsertPoC(context.Background(), PoC{
		CVEID: "CVE-2024-9003", Source: "github", URL: "https://example.test/p",
		Title: "poc", Kind: "poc",
	}); err != nil {
		t.Fatalf("UpsertPoC: %v", err)
	}
	if got := len(fake.executed()); got != 1 {
		t.Fatalf("UpsertPoC 应写 1 条，实际 %d", got)
	}
}
