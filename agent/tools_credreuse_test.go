package agent

import (
	"testing"

	"github.com/chu0119/pojun/db"
)

// 协议推断决定「凭据会被喂给哪个验证器」。判错方向的代价很实在：把 token 当
// 口令丢给 ssh_check，会白白消耗该账号的失败额度，触发防锁定熔断。
func TestMatrixProtocolsForAsset(t *testing.T) {
	port := func(n int) *int { return &n }
	cases := []struct {
		name string
		a    *db.Asset
		want []string
	}{
		{"22 端口 → ssh", &db.Asset{IP: "10.0.0.1", Port: port(22)}, []string{"ssh"}},
		{"445 端口 → smb", &db.Asset{IP: "10.0.0.2", Port: port(445)}, []string{"smb"}},
		{"3306 → mysql", &db.Asset{IP: "10.0.0.3", Port: port(3306)}, []string{"mysql"}},
		{"5432 → postgres", &db.Asset{IP: "10.0.0.4", Port: port(5432)}, []string{"postgres"}},
		{"6379 → redis", &db.Asset{IP: "10.0.0.5", Port: port(6379)}, []string{"redis"}},
		{"URL 资产 → http", &db.Asset{URL: "https://a.example.com/login"}, []string{"http"}},
		{"443 无 URL → http", &db.Asset{IP: "10.0.0.6", Port: port(443)}, []string{"http"}},
		{"service_name 兜底 → ssh", &db.Asset{IP: "10.0.0.7", ServiceName: "ssh"}, []string{"ssh"}},
		{"无端口无服务 → 空", &db.Asset{IP: "10.0.0.8"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matrixProtocolsForAsset(c.a)
			if len(got) != len(c.want) {
				t.Fatalf("协议数不符: got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i].protocol != c.want[i] {
					t.Errorf("第 %d 个协议: got %s want %s", i, got[i].protocol, c.want[i])
				}
			}
		})
	}
}

// token 型凭据只对 HTTP 有意义；把这条规则写死，避免"宽松匹配"退化成
// 拿 Bearer token 去试 SSH。
func TestMatrixCredentialFits(t *testing.T) {
	cases := []struct {
		name     string
		cred     *db.CredentialSecret
		protocol string
		want     bool
	}{
		{"账号密码 → ssh", &db.CredentialSecret{CredType: "password", Username: "root", Secret: "x"}, "ssh", true},
		{"账号密码 → smb", &db.CredentialSecret{CredType: "password", Username: "admin", Secret: "x"}, "smb", true},
		{"token → ssh 拒绝", &db.CredentialSecret{CredType: "token", Username: "u", Secret: "x"}, "ssh", false},
		{"cookie → smb 拒绝", &db.CredentialSecret{CredType: "cookie", Username: "u", Secret: "x"}, "smb", false},
		{"token → http 允许", &db.CredentialSecret{CredType: "token", Username: "u", Secret: "x"}, "http", true},
		{"无用户名 → ssh 拒绝", &db.CredentialSecret{CredType: "password", Secret: "x"}, "ssh", false},
		{"无用户名 → http 允许（纯 Cookie 会话）", &db.CredentialSecret{CredType: "cookie", Secret: "x"}, "http", true},
		{"空 secret → 全拒", &db.CredentialSecret{CredType: "password", Username: "u"}, "http", false},
		{"nil 凭据 → 拒绝", nil, "ssh", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matrixCredentialFits(c.cred, c.protocol); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

// 四个验证器的判定词不统一（ssh/smb/db 用 ok，web 用 success），矩阵必须归一，
// 否则"验证成功"会被当成未知结果、既不入库也不进 success_list。
func TestNormalizeMatrixVerdict(t *testing.T) {
	cases := map[string]string{
		"ok":             "ok",
		"success":        "ok",
		"OK":             "ok",
		"failed":         "failed",
		"auth_failed":    "failed",
		"wrong_password": "failed",
		"no_such_user":   "failed",
		"denied":         "failed",
		"locked":         "locked",
		"locked_out":     "locked",
		"disabled":       "locked",
		"possible":       "possible",
		"error":          "error",
		"skipped":        "skipped",
		"whatever":       "other",
	}
	for in, want := range cases {
		if got := normalizeMatrixVerdict(in); got != want {
			t.Errorf("normalizeMatrixVerdict(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsPrivateIPv4(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":       true,
		"172.16.0.1":     true,
		"172.31.255.254": true,
		"172.32.0.1":     false,
		"192.168.1.1":    true,
		"8.8.8.8":        false,
		"":               false,
		"not-an-ip":      false,
		"256.1.1.1":      false,
		"1.2.3":          false,
	}
	for in, want := range cases {
		if got := isPrivateIPv4(in); got != want {
			t.Errorf("isPrivateIPv4(%q)=%v want %v", in, got, want)
		}
	}
}
