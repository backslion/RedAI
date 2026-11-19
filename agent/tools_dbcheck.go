package agent

// 数据库凭据验证与未授权检测（YCode 二开 · 内网纵深）：db_check 是 ssh_check 的
// 数据库对应物——对 redis/mysql/postgres 逐个验证【用户+口令】组合(每组合一次，≤5)，
// redis 同时检测未授权访问（无 requirepass 即高危）。与凭据复用矩阵的数据库入口
// 一一对应。定位=验证器不是爆破器。协议：redis 手写 RESP；postgres 复用平台 pgx；
// mysql 用 go-sql-driver(纯 Go)。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	actool "github.com/Autumn-27/norma/tool"
)

// redisExchange 手写 RESP：发送命令数组，读取回复（简单类型+bulk+error）。
func redisExchange(conn net.Conn, timeout time.Duration, args ...string) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var req []byte
	req = fmt.Appendf(req, "*%d\r\n", len(args))
	for _, a := range args {
		req = fmt.Appendf(req, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// redisProbe 连接 redis 并判定：未授权 / 密码有效 / 需要密码 / 认证失败。
// 返回 (verdict, detail, version, err)。
func redisProbe(addr, password string, timeout time.Duration) (string, string, string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = conn.Close() }()

	if resp, err := redisExchange(conn, timeout, "PING"); err == nil && strings.HasPrefix(resp, "+PONG") {
		info, _ := redisExchange(conn, timeout, "INFO", "server")
		ver := ""
		for _, line := range strings.Split(info, "\r\n") {
			if strings.HasPrefix(line, "redis_version:") {
				ver = strings.TrimPrefix(line, "redis_version:")
			}
		}
		// 未授权：还能拿 CONFIG 就更进一步确认写面
		cfg, cfgErr := redisExchange(conn, timeout, "CONFIG", "GET", "requirepass")
		note := "未授权访问：无需口令即可执行命令"
		if cfgErr == nil && strings.HasPrefix(cfg, "*") {
			note += "，且 CONFIG 可读（历史上 CONFIG SET dir/dbfilename + SAVE 可写文件）"
		}
		return "unauthorized", note, ver, nil
	}
	if password == "" {
		return "auth_required", "需要密码(NOAUTH/ERR)", "", nil
	}
	resp, err := redisExchange(conn, timeout, "AUTH", password)
	if err == nil && strings.HasPrefix(resp, "+OK") {
		info, _ := redisExchange(conn, timeout, "INFO", "server")
		ver := ""
		for _, line := range strings.Split(info, "\r\n") {
			if strings.HasPrefix(line, "redis_version:") {
				ver = strings.TrimPrefix(line, "redis_version:")
			}
		}
		return "ok", "凭据有效", ver, nil
	}
	return "auth_failed", "认证失败(" + strings.TrimSpace(resp) + ")", "", nil
}

func (t *ToolSet) dbCheck() actool.CoreTool {
	return readTool("db_check",
		"(内网纵深)数据库凭据验证与未授权检测：对 redis/mysql/postgres 逐个验证【用户+口令】组合(每组合一次，≤5)。redis 额外检测未授权访问(无 requirepass 即可直接执行命令=高危，历史上 CONFIG SET 写文件是常用利用面)。与 credential-reuse 矩阵的数据库入口对应：SQL 注入脱库的口令、配置文件里的连接串、弱口令候选都在这里验证。验证器不是爆破器，每组合一次、失败即停该组合。成功后 record_intelligence + 试常用库/表(SELECT 只读)。",
		obj(map[string]any{
			"host": map[string]any{
				"type": "string", "description": "目标主机(IP 或域名)。",
			},
			"engine": map[string]any{
				"type": "string", "enum": []string{"redis", "mysql", "postgres"},
				"description": "数据库类型。",
			},
			"port": map[string]any{
				"type": "integer", "description": "端口；留空按引擎默认(redis 6379/mysql 3306/postgres 5432)。",
			},
			"credentials": map[string]any{
				"type":        "array",
				"description": "凭据组合(≤5)：[{\"username\":\"root\",\"password\":\"...\"}]；redis 的 username 留空；组合留空+engine=redis 时只做未授权检测。",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"username": map[string]any{"type": "string"},
						"password": map[string]any{"type": "string"},
					},
				},
			},
			"database": map[string]any{
				"type": "string", "description": "连接的数据库名(mysql 默认无；postgres 默认 postgres)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 5000, "description": "单连接超时毫秒(2000..15000)。",
			},
		}, "host", "engine"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Host        string `json:"host"`
				Engine      string `json:"engine"`
				Port        int    `json:"port"`
				Credentials []struct {
					Username string `json:"username"`
					Password string `json:"password"`
				} `json:"credentials"`
				Database  string `json:"database"`
				TimeoutMs int    `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			host := strings.TrimSpace(p.Host)
			engine := strings.ToLower(strings.TrimSpace(p.Engine))
			if host == "" {
				return actool.Errorf("host 不能为空"), nil
			}
			if engine != "redis" && engine != "mysql" && engine != "postgres" {
				return actool.Errorf("engine 仅支持 redis/mysql/postgres"), nil
			}
			if p.Port <= 0 {
				switch engine {
				case "redis":
					p.Port = 6379
				case "mysql":
					p.Port = 3306
				default:
					p.Port = 5432
				}
			}
			if len(p.Credentials) > 5 {
				return actool.Errorf("凭据组合过多(>5)：验证器不是爆破器，请分批"), nil
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			if timeout > 15*time.Second {
				timeout = 15 * time.Second
			}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.Port))
			out := map[string]any{"host": host, "engine": engine, "port": p.Port}

			// ---- redis ----
			if engine == "redis" {
				verdict, detail, ver, err := redisProbe(addr, "", timeout)
				if err != nil {
					return actool.Errorf("Redis 不可达: " + err.Error()), nil
				}
				entry := map[string]any{"username": "", "password": "", "verdict": verdict, "detail": detail}
				if ver != "" {
					entry["version"] = ver
				}
				out["results"] = []map[string]any{entry}
				// 组合逐个验证（未授权命中就不再试口令）
				if verdict != "unauthorized" {
					for _, c := range p.Credentials {
						v2, d2, _, e2 := redisProbe(addr, c.Password, timeout)
						if e2 != nil {
							out["results"] = append(out["results"].([]map[string]any), map[string]any{"username": c.Username, "password": "***", "verdict": "error", "detail": e2.Error()})
							continue
						}
						out["results"] = append(out["results"].([]map[string]any), map[string]any{"username": c.Username, "password": "***", "verdict": v2, "detail": d2})
						if v2 == "ok" {
							break
						}
					}
				}
				if out["results"].([]map[string]any)[0]["verdict"] == "unauthorized" {
					out["verdict"] = "Redis 未授权访问——高危：可直接读写数据，CONFIG SET 写文件面待验证"
				} else if anyOK(out["results"].([]map[string]any)) {
					out["verdict"] = "Redis 凭据有效——实证数据库访问，record_intelligence + 评估数据面"
				} else {
					out["verdict"] = "Redis 需要凭据且本次组合均未命中"
				}
				return jsonResult(out)
			}

			// ---- mysql / postgres ----
			type credResult struct {
				Username  string   `json:"username"`
				Verdict   string   `json:"verdict"` // ok / auth_failed / error
				Detail    string   `json:"detail,omitempty"`
				Version   string   `json:"version,omitempty"`
				Databases []string `json:"databases,omitempty"`
			}
			results := []credResult{}
			anySuccess := false
			for _, c := range p.Credentials {
				r := credResult{Username: strings.TrimSpace(c.Username)}
				if r.Username == "" {
					r.Username = defaultDBUser(engine)
				}
				var dsn string
				if engine == "mysql" {
					dsn = fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=%ds&readTimeout=%ds", r.Username, c.Password, addr, strings.TrimSpace(p.Database), int(timeout.Seconds()), int(timeout.Seconds()))
				} else {
					dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable connect_timeout=%d",
						host, p.Port, r.Username, c.Password, strings.TrimSpace(dbStrOrDefault(p.Database, "postgres")), int(timeout.Seconds()))
				}
				db, err := sql.Open(engine, dsn)
				if err != nil {
					r.Verdict, r.Detail = "error", err.Error()
					results = append(results, r)
					continue
				}
				db.SetConnMaxLifetime(timeout)
				db.SetMaxOpenConns(1)
				pingCtx, cancel := context.WithTimeout(ctx, timeout)
				if err := db.PingContext(pingCtx); err != nil {
					cancel()
					_ = db.Close()
					msg := err.Error()
					if strings.Contains(msg, "Access denied") || strings.Contains(msg, "password authentication failed") || strings.Contains(msg, "28P01") {
						r.Verdict, r.Detail = "auth_failed", "认证拒绝"
					} else if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "dial") {
						r.Verdict, r.Detail = "error", "不可达: "+msg
					} else {
						r.Verdict, r.Detail = "auth_failed", msg
					}
					results = append(results, r)
					continue
				}
				cancel()
				r.Verdict = "ok"
				// 版本 + 库清单（只读）
				var ver string
				_ = db.QueryRowContext(ctx, "SELECT version()").Scan(&ver)
				r.Version = dbFirstLine(ver)
				if rows, qerr := db.QueryContext(ctx, enginesDBListSQL(engine)); qerr == nil {
					for rows.Next() {
						var name string
						if _ = rows.Scan(&name); name != "" {
							r.Databases = append(r.Databases, name)
						}
					}
					_ = rows.Close()
				}
				_ = db.Close()
				anySuccess = true
				results = append(results, r)
			}
			if len(results) == 0 {
				return actool.Errorf("mysql/postgres 至少需要一组凭据(username+password)"), nil
			}
			// 全部组合都是网络层失败 → 目标不可达（错误结论而非"凭据不对"）
			allError := true
			for _, r := range results {
				if r.Verdict != "error" {
					allError = false
					break
				}
			}
			if allError {
				return actool.Errorf("数据库不可达：全部组合连接失败，样例：" + results[0].Detail), nil
			}
			out["results"] = results
			if anySuccess {
				out["verdict"] = "数据库凭据有效——实证访问，立即 record_intelligence + 库/表盘点(只读)"
			} else {
				out["verdict"] = "本次组合均未命中(认证拒绝或不可达)"
			}
			return jsonResult(out)
		})
}

func defaultDBUser(engine string) string {
	if engine == "mysql" {
		return "root"
	}
	return "postgres"
}

func dbStrOrDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func dbFirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func anyOK(results []map[string]any) bool {
	for _, r := range results {
		if r["verdict"] == "ok" {
			return true
		}
	}
	return false
}

func enginesDBListSQL(engine string) string {
	if engine == "mysql" {
		return "SHOW DATABASES"
	}
	return "SELECT datname FROM pg_database WHERE datistemplate = false"
}
