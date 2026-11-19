package agent

// LDAP 域枚举工具（YCode 二开 · Windows 域纵深）：ldap_enum 用已得域凭据（或匿名）
// 连域控 LDAP(389/636) 拉取域内核心侦察面：用户清单（含 UAC 标志——DONT_REQ_PREAUTH
// 的账号直接喂 asrep_roast 烤、DISABLED/LOCKOUT 标注）、域管等高价值组成员、机器账号、
// 域功能级别。这是「凭据→域内地图」的核心一跳。依赖 go-ldap/ldap/v3（纯 Go）。
// 只读操作（search），绝不写目录。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	actool "github.com/Autumn-27/norma/tool"
)

// uacFlags AD userAccountControl 关键标志位。
const (
	uacAccountDisable     = 0x0002
	uacLockout            = 0x0010
	uacDontReqPreauth     = 0x400000 // 不需要 Kerberos 预认证 → AS-REP 可烤
	uacPasswordExpired    = 0x800000
	uacTrustedForDeleg    = 0x80000
	uacDontExpirePasswd   = 0x10000
	uacServerTrustAccount = 0x2000 // 域控机器账号
	uacWorkstationAccount = 0x1000
)

func uacNotes(v int64) []string {
	var out []string
	if v&uacAccountDisable != 0 {
		out = append(out, "disabled")
	}
	if v&uacLockout != 0 {
		out = append(out, "locked_out")
	}
	if v&uacDontReqPreauth != 0 {
		out = append(out, "DONT_REQ_PREAUTH(可AS-REP烤)")
	}
	if v&uacPasswordExpired != 0 {
		out = append(out, "password_expired")
	}
	if v&uacDontExpirePasswd != 0 {
		out = append(out, "password_never_expires(高价值服务账号)")
	}
	if v&uacTrustedForDeleg != 0 {
		out = append(out, "trusted_for_delegation")
	}
	if v&uacServerTrustAccount != 0 {
		out = append(out, "domain_controller")
	}
	return out
}

func (t *ToolSet) ldapEnum() actool.CoreTool {
	return readTool("ldap_enum",
		"(域纵深)LDAP 域枚举：用已得域凭据(或匿名绑定)连域控 389(TCP)/636(LDAPS) 只读检索——①全部用户清单(含 userAccountControl 标志：DONT_REQ_PREAUTH 的账号直接喂 asrep_roast、disabled/locked 标注、密码永不过期=高价值服务账号)②指定组(默认 Domain Admins/Administrators)成员③机器账号列表④域功能级别与根 DN。产出即域内地图：普通用户→弱口令/凭据复用候选，服务账号→高价值目标，DC 机器账号→下一步目标。只读不写。凭据优先复用已有(credential-reuse 矩阵)，匿名绑定失败再要求凭据。",
		obj(map[string]any{
			"host": map[string]any{
				"type": "string", "description": "域控地址(IP 或域名)。",
			},
			"port": map[string]any{
				"type": "integer", "default": 389, "description": "LDAP 端口：389(明文/StartTLS) 或 636(LDAPS)。",
			},
			"username": map[string]any{
				"type": "string", "description": "绑定 DN 或 user@realm(可空=匿名绑定)。",
			},
			"password": map[string]any{
				"type": "string", "description": "绑定口令(可空=匿名)。",
			},
			"realm": map[string]any{
				"type": "string", "description": "域名(如 CORP.LOCAL)；空则从根 DSE 自动获取默认命名上下文。",
			},
			"groups": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "要枚举成员的组(默认 Domain Admins + Administrators)。",
			},
			"limit": map[string]any{
				"type": "integer", "default": 500, "description": "各清单返回上限(50..2000)。",
			},
			"timeout_ms": map[string]any{
				"type": "integer", "default": 8000, "description": "连接/检索超时毫秒(3000..20000)。",
			},
		}, "host"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Host      string   `json:"host"`
				Port      int      `json:"port"`
				Username  string   `json:"username"`
				Password  string   `json:"password"`
				Realm     string   `json:"realm"`
				Groups    []string `json:"groups"`
				Limit     int      `json:"limit"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			host := strings.TrimSpace(p.Host)
			if host == "" {
				return actool.Errorf("host 不能为空"), nil
			}
			if p.Port <= 0 {
				p.Port = 389
			}
			if p.Limit <= 0 {
				p.Limit = 500
			}
			if p.Limit > 2000 {
				p.Limit = 2000
			}
			timeout := time.Duration(p.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 8 * time.Second
			}
			if timeout > 20*time.Second {
				timeout = 20 * time.Second
			}
			addr := fmt.Sprintf("%s:%d", host, p.Port)

			var conn *ldap.Conn
			var err error
			dialer := &net.Dialer{Timeout: timeout}
			if p.Port == 636 {
				conn, err = ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}), ldap.DialWithDialer(dialer)) //nolint:gosec // 域内自签常见
			} else {
				conn, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
			}
			if err != nil {
				return actool.Errorf("LDAP 连接失败: " + err.Error()), nil
			}
			defer func() { _ = conn.Close() }()
			conn.SetTimeout(timeout)

			// ---- 绑定 ----
			// bindDN 接受 DN 形式(CN=..,DC=..) 或 UPN 形式(user@REALM)，go-ldap 均可直绑
			bindDN := strings.TrimSpace(p.Username)
			if err := conn.Bind(bindDN, p.Password); err != nil {
				if bindDN == "" {
					return actool.Errorf("匿名绑定被拒(" + err.Error() + ")：请传 username/password(可用 credential-reuse 矩阵里已验证的域凭据，格式 user@REALM)"), nil
				}
				return actool.Errorf("LDAP 绑定失败(凭据无效或格式不对): " + err.Error()), nil
			}

			// ---- 根 DSE：默认命名上下文 ----
			namingCtx := ""
			if strings.TrimSpace(p.Realm) != "" {
				namingCtx = "DC=" + strings.Join(strings.Split(strings.ToUpper(strings.TrimSpace(p.Realm)), "."), ",DC=")
			} else {
				dse, derr := conn.Search(&ldap.SearchRequest{
					BaseDN:       "",
					Scope:        ldap.ScopeBaseObject,
					Filter:       "(objectClass=*)",
					Attributes:   []string{"defaultNamingContext", "domainFunctionality"},
					SizeLimit:    1,
					DerefAliases: ldap.NeverDerefAliases,
				})
				if derr == nil && len(dse.Entries) > 0 {
					namingCtx = dse.Entries[0].GetAttributeValue("defaultNamingContext")
				}
				if namingCtx == "" {
					return actool.Errorf("无法确定根 DN(realm 未传且根 DSE 不可读)：请显式传 realm，如 CORP.LOCAL"), nil
				}
			}

			limit := p.Limit
			out := map[string]any{"host": host, "port": p.Port, "base_dn": namingCtx}

			// ---- ① 用户清单 ----
			userSearch := ldap.NewSearchRequest(namingCtx, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(timeout.Seconds()), false,
				"(&(objectClass=user)(objectCategory=person))",
				[]string{"sAMAccountName", "userAccountControl", "displayName", "mail", "description", "pwdLastSet", "lastLogonTimestamp"}, nil)
			users, err := conn.Search(userSearch)
			if err != nil {
				return actool.Errorf("用户检索失败(权限或过滤): " + err.Error()), nil
			}
			type userRow struct {
				Username string   `json:"username"`
				Display  string   `json:"display_name,omitempty"`
				Mail     string   `json:"mail,omitempty"`
				Desc     string   `json:"description,omitempty"`
				UAC      int64    `json:"uac"`
				Flags    []string `json:"flags,omitempty"`
			}
			var all []userRow
			for _, e := range users.Entries {
				uac, _ := strconv.ParseInt(e.GetAttributeValue("userAccountControl"), 10, 64)
				row := userRow{
					Username: e.GetAttributeValue("sAMAccountName"),
					Display:  e.GetAttributeValue("displayName"),
					Mail:     e.GetAttributeValue("mail"),
					Desc:     e.GetAttributeValue("description"),
					UAC:      uac,
					Flags:    uacNotes(uac),
				}
				if row.Username != "" {
					all = append(all, row)
				}
			}
			// 可烤账号置顶，其余按名排序
			roastable, normal := []userRow{}, []userRow{}
			for _, u := range all {
				if u.UAC&uacDontReqPreauth != 0 {
					roastable = append(roastable, u)
				} else {
					normal = append(normal, u)
				}
			}
			sort.Slice(normal, func(i, j int) bool { return normal[i].Username < normal[j].Username })
			truncated := len(all) > limit
			out["user_count"] = len(all)
			out["asrep_candidates"] = roastable
			out["users"] = append(append([]userRow{}, roastable...), normal...)
			out["users_truncated"] = truncated

			// ---- ② 组成员 ----
			groups := p.Groups
			if len(groups) == 0 {
				groups = []string{"Domain Admins", "Administrators"}
			}
			type groupResult struct {
				Group   string   `json:"group"`
				Members []string `json:"members"`
				Error   string   `json:"error,omitempty"`
			}
			var groupOut []groupResult
			for _, g := range groups {
				gr := groupResult{Group: g}
				res, gerr := conn.Search(ldap.NewSearchRequest(namingCtx, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(timeout.Seconds()), false,
					fmt.Sprintf("(&(objectClass=group)(sAMAccountName=%s))", ldap.EscapeFilter(g)),
					[]string{"member"}, nil))
				if gerr != nil || len(res.Entries) == 0 {
					gr.Error = "组未找到或不可读"
					groupOut = append(groupOut, gr)
					continue
				}
				members := res.Entries[0].GetAttributeValues("member")
				for _, m := range members {
					cn := m
					if i := strings.Index(m, "CN="); i >= 0 {
						cn = m[3:]
						if j := strings.Index(cn, ","); j >= 0 {
							cn = cn[:j]
						}
					}
					gr.Members = append(gr.Members, cn)
				}
				groupOut = append(groupOut, gr)
			}
			out["groups"] = groupOut

			// ---- ③ 机器账号 ----
			machines, merr := conn.Search(ldap.NewSearchRequest(namingCtx, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(timeout.Seconds()), false,
				"(objectClass=computer)",
				[]string{"sAMAccountName", "operatingSystem", "dNSHostName"}, nil))
			if merr == nil {
				type machineRow struct {
					Name string `json:"name"`
					OS   string `json:"os,omitempty"`
					DNS  string `json:"dns,omitempty"`
				}
				var ms []machineRow
				for _, e := range machines.Entries {
					name := strings.TrimSuffix(e.GetAttributeValue("sAMAccountName"), "$")
					if name == "" {
						continue
					}
					ms = append(ms, machineRow{Name: name, OS: e.GetAttributeValue("operatingSystem"), DNS: e.GetAttributeValue("dNSHostName")})
				}
				sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
				if len(ms) > limit {
					ms = ms[:limit]
				}
				out["machine_count"] = len(machines.Entries)
				out["machines"] = ms
			}

			verdict := fmt.Sprintf("域枚举成功：用户 %d 个(可烤 %d)、机器 %d 台", len(all), len(roastable), len(machines.Entries))
			if len(roastable) > 0 {
				verdict += fmt.Sprintf("——%d 个 DONT_REQ_PREAUTH 账号立即用 asrep_roast 烤", len(roastable))
			}
			verdict += "；用户名清单是弱口令/凭据复用矩阵的候选集(http_login_check/ssh_check/smb_check)"
			out["verdict"] = verdict
			return jsonResult(out)
		})
}
