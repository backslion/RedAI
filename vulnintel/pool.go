package vulnintel

import (
	"context"
	"database/sql"

	"github.com/backslion/RedAI/db"
)

// Store 持有一份 CVE/KEV/GHSA/PoC 情报库的读写入口。
//
// 两个池的分工是本包唯一的结构约定：
//   - db：**在线读**（agent 的 search_vulns/get_vuln、状态页、快通道查询）。
//     这些查询走主池，和任务其余查询共享同一批连接。
//   - bg：**后台批处理**（NVD/KEV/GHSA/PoC 同步写库、同步期的重查询、同步后
//     的资产联动）。走独立的连接池，见 db.OpenBackgroundPool 的说明。
//
// 两个池连的是同一个库，写下去的数据对另一侧立即可见（autocommit + read
// committed），所以这里不存在"读到旧数据"的一致性问题。唯一的约束是**同一
// 逻辑写操作不要跨池拆开**——单条 upsert 内的多条语句要落在同一个池上，否则
// 同一条记录会同时占两条连接，反而放大争用。
type Store struct {
	db *db.DB
	bg sqlPool // 后台批处理池；nil = 回落主池
}

// New 用主池构造 Store：读写都走主池，等价于引入后台池之前的行为。
func New(d *db.DB) *Store { return &Store{db: d} }

// NewWithBackgroundPool 用独立后台池承载批处理作业。bg 为 nil 时退回 New，
// 所以调用方不需要自己判断池子有没有建起来。
func NewWithBackgroundPool(d *db.DB, bg *sql.DB) *Store {
	if bg == nil {
		return New(d)
	}
	return &Store{db: d, bg: bg}
}

// sqlPool 是 Store 用到的全部数据库能力。*sql.DB 直接满足；*db.DB 通过内嵌
// 的 *sql.DB 也满足，所以 bgPool 可以在两者之间切换而调用点无感。
type sqlPool interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// bgPool 返回后台批处理该用的池。没配独立池时回落主池——这条回落路径是
// POJUN_PG_BG_POOL=0 与"池子建不起来"两种情况共用的行为保证。
func (s *Store) bgPool() sqlPool {
	if s.bg != nil {
		return s.bg
	}
	return s.db
}
