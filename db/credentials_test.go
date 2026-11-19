package db

import (
	"os"
	"strings"
	"testing"
)

// credentialInputFromAuthItem 是「存量 assets.auth → 凭据库」的唯一转换点。
// 它判错的后果是静默丢凭据：回填时把有效条目不当作凭据，升级后凭据库就是空的，
// 而 assets.auth 明明有值——排查这种"看起来迁移了其实没有"的问题非常费时。
func TestCredentialInputFromAuthItem(t *testing.T) {
	cases := []struct {
		name       string
		item       map[string]any
		wantOK     bool
		wantSecret string
		wantUser   string
		wantType   string
		wantDomain string
		wantDesc   string
	}{
		{
			name:       "password 优先",
			item:       map[string]any{"type": "password", "username": "root", "password": "p@ss", "token": "t"},
			wantOK:     true,
			wantSecret: "p@ss",
			wantUser:   "root",
			wantType:   "password",
			wantDesc:   "",
		},
		{
			name:       "无 password 时用 token",
			item:       map[string]any{"type": "token", "token": "abc", "description": "来自浏览器"},
			wantOK:     true,
			wantSecret: "abc",
			wantType:   "token",
			wantDesc:   "来自浏览器",
		},
		{
			name:       "带 domain",
			item:       map[string]any{"username": "admin", "password": "x", "domain": "CORP"},
			wantOK:     true,
			wantSecret: "x",
			wantUser:   "admin",
			wantDomain: "CORP",
		},
		{
			name:   "只有用户名 → 不是凭据",
			item:   map[string]any{"username": "admin"},
			wantOK: false,
		},
		{
			name:   "空对象 → 不是凭据",
			item:   map[string]any{},
			wantOK: false,
		},
		{
			name:   "password 为纯空白 → 不是凭据",
			item:   map[string]any{"username": "u", "password": "   "},
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, desc, ok := credentialInputFromAuthItem(c.item)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if got.Secret != c.wantSecret {
				t.Errorf("secret=%q want %q", got.Secret, c.wantSecret)
			}
			if got.Username != c.wantUser {
				t.Errorf("username=%q want %q", got.Username, c.wantUser)
			}
			if got.CredType != c.wantType {
				t.Errorf("type=%q want %q", got.CredType, c.wantType)
			}
			if got.Domain != c.wantDomain {
				t.Errorf("domain=%q want %q", got.Domain, c.wantDomain)
			}
			if desc != c.wantDesc {
				t.Errorf("description=%q want %q", desc, c.wantDesc)
			}
		})
	}
}

// 凭据两表必须是「可重复执行」的 DDL：schema.sql 每次启动都会整体 Exec，
// 写成 CREATE TABLE 不带 IF NOT EXISTS 会让第二次启动直接失败。
func TestSchemaHasCredentialTables(t *testing.T) {
	raw, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatalf("读取 schema.sql: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS asset_credentials",
		"CREATE TABLE IF NOT EXISTS asset_credential_links",
		"UNIQUE (cred_type, username, domain, secret)",
		"CHECK (relation IN ('discovered', 'verified'))",
		"idx_asset_credential_links_asset",
		"idx_asset_credential_links_cred",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("schema.sql 缺少 %q——凭据库建表不完整或不可幂等", want)
		}
	}
}
