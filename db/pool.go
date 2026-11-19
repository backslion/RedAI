package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// 后台作业连接池（POJUN_PG_BG_POOL）。
//
// 主池（maxOpenConns=32）由所有在线路径共享：每个任务的资产/探索图查询、
// SSE 轮询、引擎心跳。漏洞情报同步是唯一会长时间、大批量压库的后台作业——
// 全量 NVD 回溯一轮要写几十万条，每轮同步结束后还要跑两条重查询：
//
//   - syncPoCs 的候选池：`ORDER BY kev DESC, 分数 DESC` 取 400 条；
//   - LinkAssetsToVulns 的候选 CVE：`WHERE kev OR modified_at > $1`（modified_at
//     没有索引，等于对 vuln_cves 全表扫）再 JOIN vuln_cpe_products。
//
// 这两条在百万级行数下会长时间占住一条连接，而且和任务查询排同一个队——
// 任务侧看到的只是"慢了一下"，很难归因到情报同步。
//
// 所以给后台作业单独开一条小池：**上限硬隔离**（后台最多占 N 条，永远抢不到
// 任务侧的连接），**下限保留**（主池 32 条仍然全部留给在线路径）。另外带上
// application_name，pg_stat_activity 里能一眼分开这两批连接。
const (
	// defaultBackgroundPoolSize 是后台池默认大小。取值依据：情报同步的并发度
	// 很低（主同步一轮串行写、快通道每 30 分钟一轮、资产联动一轮一次），
	// 3 条就够跑满；留到 6 是给"同步 + 快通道 + 联动"同时发生的峰值余量。
	defaultBackgroundPoolSize = 6
)

// BackgroundPoolSize 解析后台池大小。未设置时用默认值；POJUN_PG_BG_POOL=0
// 显式关闭独立池（后台作业回落到主池，等价于旧行为）；非法值回落到默认值，
// 超过主池上限的按主池上限封顶——后台池不该比主池还大。
func BackgroundPoolSize() int {
	raw := strings.TrimSpace(os.Getenv("POJUN_PG_BG_POOL"))
	if raw == "" {
		return defaultBackgroundPoolSize
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return defaultBackgroundPoolSize
	}
	if n > maxOpenConns {
		return maxOpenConns
	}
	return n
}

// OpenBackgroundPool 打开后台作业专用连接池。
//
// 与 Open 的区别只有两点，都是刻意的：
//   - **不跑迁移**。schema 与 seed 由主池的 Open 负责，这里连的已经是初始化过
//     的库；再跑一遍既慢又会和主池抢 schema advisory lock。
//   - **连接数小得多**。见上面 BackgroundPoolSize 的说明。
//
// appName 会写进 DSN 的 application_name，出现在 pg_stat_activity / pg_stat_
// statements 里，便于把一个慢查询归到具体是哪批连接发出的。
func OpenBackgroundPool(dsn, appName string, maxOpen int) (*sql.DB, error) {
	if maxOpen <= 0 {
		return nil, fmt.Errorf("background pool size must be > 0, got %d", maxOpen)
	}
	if appName != "" {
		dsn = WithApplicationName(dsn, appName)
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxOpen)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	// 这里必须 Ping：sql.Open 是惰性的，不 Ping 的话"池子建好了但连不上"
	// 要到第一次同步写库才暴露，而那时错误会被记进 vuln_sync_state，看起来
	// 像情报源的问题而不是配置问题。
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connect postgres background pool: %w", err)
	}
	return sqlDB, nil
}

// WithApplicationName 给 DSN 加上 application_name。
//
// 两种 DSN 形态都要支持：URL 形态（`postgres://user@host/db?sslmode=disable`，
// 配置文件构造出来的都是这种）和 keyword 形态（`host=... user=...`，环境变量
// 里手写时常见）。URL 形态已经带了同名参数就不覆盖——调用方显式写在 DSN 里的
// 值优先于这里的默认命名。
func WithApplicationName(dsn, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return dsn
	}
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
		q := u.Query()
		if q.Get("application_name") != "" {
			return dsn
		}
		q.Set("application_name", name)
		u.RawQuery = q.Encode()
		return u.String()
	}
	if strings.Contains(dsn, "application_name=") {
		return dsn
	}
	return dsn + " application_name=" + name
}
