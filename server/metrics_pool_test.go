package server

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	pgdb "github.com/chu0119/pojun/db"
)

// stubConnector 让我们能在不连 PG 的前提下拿到一个真实的 *sql.DB：只用于读
// Stats()（纯内存计数器），Connect 永不被调用。
type stubConnector struct{}

func (stubConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("stub connector: 不应真正建连")
}
func (stubConnector) Driver() driver.Driver { return stubDriver{} }

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("stub driver: 不应真正建连")
}

func stubPool(t *testing.T) *sql.DB {
	t.Helper()
	db := sql.OpenDB(stubConnector{})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// 主池序列必须始终存在；后台池序列只在独立池真的建起来时输出——"没有这条
// 序列"就是"当前回落到主池"的可观测信号，比一条恒为 0 的序列诚实。
func TestDBPoolMetricsSeries(t *testing.T) {
	mainPool := stubPool(t)

	render := func(s *Server) string {
		var b bytes.Buffer
		writeDBPoolMetrics(&b, s)
		return b.String()
	}

	// 只有主池。
	s := &Server{m: &Manager{pg: &pgdb.DB{DB: mainPool}}}
	out := render(s)
	for _, want := range []string{
		`pojun_db_pool_open{pool="main"} 0`,
		`pojun_db_pool_in_use{pool="main"} 0`,
		`pojun_db_pool_idle{pool="main"} 0`,
		`pojun_db_pool_max_open{pool="main"} 0`,
		`pojun_db_pool_wait_total{pool="main"} 0`,
		`pojun_db_pool_wait_seconds_total{pool="main"} 0`,
		`# TYPE pojun_db_pool_wait_total counter`,
		`# TYPE pojun_db_pool_open gauge`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `pool="intel"`) {
		t.Errorf("没配后台池时不该有 intel 序列:\n%s", out)
	}

	// 加上后台池。
	intelPool := stubPool(t)
	s.m.intelPool = intelPool
	out = render(s)
	if !strings.Contains(out, `pojun_db_pool_open{pool="intel"} 0`) {
		t.Errorf("缺 intel 序列:\n%s", out)
	}
	// 两个池都要出现，不能因为加了 intel 就把 main 顶掉。
	if !strings.Contains(out, `pojun_db_pool_open{pool="main"} 0`) {
		t.Errorf("intel 出现后 main 序列消失:\n%s", out)
	}
}

// 每个 family 的 # TYPE 只能出现一次，否则抓取方会丢弃整段 exposition。
func TestDBPoolMetricsDeclaresEachFamilyOnce(t *testing.T) {
	s := &Server{m: &Manager{pg: &pgdb.DB{DB: stubPool(t)}, intelPool: stubPool(t)}}
	var b bytes.Buffer
	writeDBPoolMetrics(&b, s)

	for _, name := range []string{
		"pojun_db_pool_open",
		"pojun_db_pool_in_use",
		"pojun_db_pool_idle",
		"pojun_db_pool_max_open",
		"pojun_db_pool_wait_total",
		"pojun_db_pool_wait_seconds_total",
	} {
		if n := strings.Count(b.String(), "# TYPE "+name+" "); n != 1 {
			t.Errorf("%s 的 # TYPE 出现 %d 次，应为 1", name, n)
		}
		if n := strings.Count(b.String(), "# HELP "+name+" "); n != 1 {
			t.Errorf("%s 的 # HELP 出现 %d 次，应为 1", name, n)
		}
	}
}

// 装配残缺时（Manager 有但 pg 没接上）不能 panic——/api/metrics 是旁路端点。
func TestDBPoolMetricsNilSafety(t *testing.T) {
	for _, s := range []*Server{
		nil,
		{},
		{m: &Manager{}},
	} {
		var b bytes.Buffer
		writeDBPoolMetrics(&b, s) // 不 panic 即通过
	}
}
