package db

import (
	"net/url"
	"strings"
	"testing"
)

// 未设置环境变量时用默认值——这是绝大多数部署的实际取值。
func TestBackgroundPoolSizeDefault(t *testing.T) {
	t.Setenv("POJUN_PG_BG_POOL", "")
	if got := BackgroundPoolSize(); got != defaultBackgroundPoolSize {
		t.Errorf("未设置时应为默认值 %d，实际 %d", defaultBackgroundPoolSize, got)
	}
}

func TestBackgroundPoolSizeFromEnv(t *testing.T) {
	cases := []struct {
		raw  string
		want int
		why  string
	}{
		{"12", 12, "正常取值"},
		{"1", 1, "下界（只留一条连接也能跑串行同步）"},
		{"0", 0, "显式关闭 → 后台作业回落主池"},
		{"-3", defaultBackgroundPoolSize, "负数非法 → 回落默认值，不能变成" +
			"「负数上限」把池子锁死"},
		{"abc", defaultBackgroundPoolSize, "非数字 → 回落默认值"},
		{" 8 ", 8, "两侧空白被裁剪"},
		{"999", maxOpenConns, "超过主池上限时按主池封顶：后台池不该比主池还大"},
	}
	for _, c := range cases {
		t.Setenv("POJUN_PG_BG_POOL", c.raw)
		if got := BackgroundPoolSize(); got != c.want {
			t.Errorf("POJUN_PG_BG_POOL=%q → %d，期望 %d（%s）", c.raw, got, c.want, c.why)
		}
	}
}

// DSN 的两种形态都要能加上 application_name，否则 pg_stat_activity 里分不出
// 哪条连接属于后台批处理。
func TestWithApplicationName(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "URL 形态",
			dsn:  "postgres://u:p@127.0.0.1:5432/pojun?sslmode=disable",
			want: "pojun-intel",
		},
		{
			name: "keyword 形态",
			dsn:  "host=127.0.0.1 user=pojun dbname=pojun",
			want: "pojun-intel",
		},
	}
	for _, c := range cases {
		got := WithApplicationName(c.dsn, c.want)
		if c.dsn == got {
			t.Fatalf("%s: DSN 未被改写: %s", c.name, got)
		}
		if u, err := url.Parse(got); err == nil && u.Scheme != "" {
			if v := u.Query().Get("application_name"); v != c.want {
				t.Errorf("%s: application_name=%q，期望 %q", c.name, v, c.want)
			}
			// 改写不能吃掉原有参数。
			if c.dsn == "postgres://u:p@127.0.0.1:5432/pojun?sslmode=disable" &&
				u.Query().Get("sslmode") != "disable" {
				t.Errorf("%s: 原有 sslmode 丢失: %s", c.name, got)
			}
			continue
		}
		if want := "application_name=" + c.want; !strings.Contains(got, want) {
			t.Errorf("%s: 缺少 %q: %s", c.name, want, got)
		}
	}
}

// DSN 里显式写的 application_name 优先于这里的默认命名：调用方比我们更清楚
// 这条连接该叫什么。
func TestWithApplicationNameRespectsExplicit(t *testing.T) {
	dsn := "postgres://u@h/db?application_name=explicit"
	if got := WithApplicationName(dsn, "pojun-intel"); got != dsn {
		t.Errorf("显式值被覆盖: %s", got)
	}
	kw := "host=h application_name=explicit dbname=db"
	if got := WithApplicationName(kw, "pojun-intel"); got != kw {
		t.Errorf("keyword 形态的显式值被覆盖: %s", got)
	}
}

func TestWithApplicationNameEmptyNameIsNoop(t *testing.T) {
	dsn := "postgres://u@h/db"
	if got := WithApplicationName(dsn, "  "); got != dsn {
		t.Errorf("空名字不应改写 DSN: %s", got)
	}
}

// 池大小 <= 0 是调用方的编程错误，直接拒绝——静默建一个"0 连接"的池会让所有
// 后台写库在第一次同步时才失败，错误位置离原因太远。
func TestOpenBackgroundPoolRejectsNonPositiveSize(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := OpenBackgroundPool("postgres://u@h/db", "pojun-intel", n); err == nil {
			t.Errorf("size=%d 应报错", n)
		}
	}
}

// 连不上要立刻返回错误（而不是交出一个惰性的、第一次同步才炸的池子）。
func TestOpenBackgroundPoolFailsFastOnBadDSN(t *testing.T) {
	if _, err := OpenBackgroundPool("::not-a-dsn::", "pojun-intel", 2); err == nil {
		t.Fatal("非法 DSN 应返回错误")
	}
}
