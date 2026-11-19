package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 移植能力的绑定守卫（v0.5.x）：这些工具来自其他 ARTEX 分支（YCode / ymh /
// reArtex），一旦被误删、改名或漏绑到某个角色，实战里表现为「agent 不会用」，
// 很难在代码评审时发现。这里把「谁必须有」写成断言，让回归在 CI 里立刻炸。
func TestPortedToolsBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := make(map[string]bool, len(tools))
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}

	worker := names(ts.WorkerTools())
	for _, n := range []string{
		"waf_probe", "ssrf_probe", "http_login_check",
		"expand_cidr", "tcp_probe", "nbns_probe", "subdomain_probe", "dir_probe",
		"ssh_check", "smb_check", "db_check", "asrep_roast", "ldap_enum",
		"honeypot_check", "import_assets_from_file",
		// 凭据库（v0.5.x）：worker 是唯一真正采集凭据的角色，四个都必须在。
		"record_credential", "mark_credential_verified", "list_credentials", "credential_reuse_matrix",
	} {
		if !worker[n] {
			t.Errorf("worker 未绑定移植工具 %s——执行侧用不上，等于没移植", n)
		}
	}

	planner := names(ts.PlannerTools())
	for _, n := range []string{"honeypot_check", "expand_cidr", "tcp_probe", "subdomain_probe", "dir_probe",
		"list_credentials", "credential_reuse_matrix"} {
		if !planner[n] {
			t.Errorf("planner 未绑定 %s——规划阶段摸不了局面，只能凭想象派意图", n)
		}
	}

	main := names(ts.MainAgentTools())
	for _, n := range []string{"waf_probe", "honeypot_check", "import_assets_from_file", "tcp_probe",
		"record_credential", "mark_credential_verified", "list_credentials", "credential_reuse_matrix"} {
		if !main[n] {
			t.Errorf("mainagent 未绑定 %s——人在环路上手动要不到这个能力", n)
		}
	}
}

// AllDomainTools 被 server 用来给 Auto / 自定义 agent 注入领域工具，重名会让
// 注册表里出现两个同名工具（行为取决于遍历顺序，极难排查）。
func TestAllDomainToolsNoDuplicateNames(t *testing.T) {
	ts := NewToolSet(nil, "")
	seen := map[string]bool{}
	for _, tl := range ts.AllDomainTools() {
		if seen[tl.Name()] {
			t.Errorf("AllDomainTools 出现重名工具 %s——注册表会被后者覆盖，行为不确定", tl.Name())
		}
		seen[tl.Name()] = true
	}
}
