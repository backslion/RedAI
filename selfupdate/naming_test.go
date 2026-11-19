package selfupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 发布包命名有三重耦合，任何一处漂移都只在用户点「一键更新」时才暴露：
//
//	build.sh 产出 redai-<ver>-<os>-<arch>.zip 且包内有 redai / redai-hostd
//	AssetName        去 Release 里按这个名字找资产   → 错了报「没有可用资产」
//	extractBinary    从 zip 里按基名取主程序         → 错了报「发布包里没有找到」
//	hostd 自我换装   从 zip 里取助手                 → 错了报「发布包里没有」
//
// 这里把 build.sh 当作契约来源：改名时只改它和 BinaryName，测试会替你把两边锁住。
func TestReleaseNamingMatchesBuildScript(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "build.sh"))
	if err != nil {
		t.Fatalf("读取 build.sh: %v", err)
	}
	script := string(raw)

	wants := []struct {
		needle string
		why    string
	}{
		{`package_name="` + BinaryName + `-`, "build.sh 的发布包名前缀必须等于 selfupdate.BinaryName"},
		{`binary_name="` + BinaryName + `"`, "build.sh 的主程序名必须等于 selfupdate.BinaryName"},
		{`./cmd/` + BinaryName + "\n", "主程序入口目录"},
		{`./cmd/` + HelperName + "\n", "助手入口目录"},
		{`$(dirname "$binary")/` + HelperName, "包内助手文件名必须等于 selfupdate.HelperName"},
		{`$(dirname "$binary")/` + BinaryName + "-maint", "包内维护工具名"},
	}
	for _, w := range wants {
		if !strings.Contains(script, w.needle) {
			t.Errorf("build.sh 缺少 %q（%s）", w.needle, w.why)
		}
	}

	// 助手自我换装必须用常量而不是字面量，否则又是一份会漂移的副本。
	up, err := os.ReadFile(filepath.Join("..", "hostd", "selfupgrade.go"))
	if err != nil {
		t.Fatalf("读取 hostd/selfupgrade.go: %v", err)
	}
	if !strings.Contains(string(up), "selfupdate.HelperName") {
		t.Error("hostd/selfupgrade.go 应使用 selfupdate.HelperName，不要写字面量文件名")
	}
}

// AssetName 的前缀必须就是 BinaryName —— 顺手把「有人改了常量却忘了前缀」
// 这类低级错误也挡住。
func TestAssetNameUsesBinaryName(t *testing.T) {
	got := AssetName("v9.9.9", "linux", "arm64")
	want := BinaryName + "-9.9.9-linux-arm64.zip"
	if got != want {
		t.Errorf("AssetName = %q, want %q", got, want)
	}
}
