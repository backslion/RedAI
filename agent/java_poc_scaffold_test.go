package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func javaPocTool(t *testing.T) (string, func(t *testing.T, class, target string, extra map[string]any) string) {
	t.Helper()
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.javaPocScaffold()
	return dir, func(t *testing.T, class, target string, extra map[string]any) string {
		t.Helper()
		in := map[string]any{"vulnclass": class, "target": target}
		for k, v := range extra {
			in[k] = v
		}
		raw, _ := json.Marshal(in)
		res, err := tool.Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatalf("Call(%s) 失败: %v", class, err)
		}
		var meta struct {
			Path      string `json:"path"`
			VulnClass string `json:"vulnclass"`
			RunWith   string `json:"run_with_bash"`
		}
		if jerr := json.Unmarshal([]byte(res.Flatten()), &meta); jerr != nil {
			t.Fatalf("返回不是 JSON: %v\n%s", jerr, res.Flatten())
		}
		if meta.VulnClass != class {
			t.Errorf("vulnclass=%q, want %q", meta.VulnClass, class)
		}
		if !strings.HasSuffix(meta.Path, ".py") {
			t.Errorf("脚本路径异常: %q", meta.Path)
		}
		if _, statErr := os.Stat(meta.Path); statErr != nil {
			t.Fatalf("脚本未落盘: %v", statErr)
		}
		if !strings.Contains(meta.RunWith, "python3") {
			t.Errorf("run_with_bash 缺少 python3: %q", meta.RunWith)
		}
		return meta.Path
	}
}

// 四类骨架都必须真的能落盘、能通过 Python 语法检查；否则 worker 拿到路径也跑不起来，
// 最后又会退回手写 curl。
func TestJavaPocScaffoldClasses(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("无 python3，跳过脚本语法检查")
	}
	_, gen := javaPocTool(t)
	cases := []struct {
		class string
		want  []string
	}{
		{"shiro550", []string{"rememberMe", "deleteMe", "AES", "shiro-key"}},
		{"fastjson", []string{"@type", "Inet4Address", "oast", "fastjson-sink"}},
		{"log4j2", []string{"${jndi:", "User-Agent", "log4j2-oast"}},
		{"deser", []string{"\\xac\\xed\\x00\\x05", "unserialize()", "deser-sink"}},
	}
	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			path := gen(t, tc.class, "http://127.0.0.1:9/test", nil)
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("读取失败: %v", rerr)
			}
			text := string(src)
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Errorf("%s 骨架缺少 %q", tc.class, want)
				}
			}
			cmd := exec.Command(py, "-m", "py_compile", path)
			if out, cerr := cmd.CombinedOutput(); cerr != nil {
				t.Fatalf("%s 骨架语法错误: %v\n%s", tc.class, cerr, out)
			}
		})
	}
}

func runJavaPoc(t *testing.T, path string, args ...string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("无 python3，跳过骨架实跑")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, append([]string{path}, args...)...)
	raw, rerr := cmd.CombinedOutput()
	if rerr != nil {
		t.Fatalf("骨架执行失败: %v\n%s", rerr, raw)
	}
	return string(raw)
}

// Shiro 指纹：靶场对无效 rememberMe 回 deleteMe，骨架必须敢报 MATCH shiro-fingerprint，
// 但不能把它升级成 “key 命中/RCE”。
func TestJavaPocScaffoldShiroFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "rememberMe=") {
			w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
		}
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer srv.Close()

	_, gen := javaPocTool(t)
	path := gen(t, "shiro550", srv.URL+"/login", nil)
	out := runJavaPoc(t, path, srv.URL+"/login")
	if !strings.Contains(out, "MATCH shiro-fingerprint") {
		t.Errorf("应判出 Shiro 指纹:\n%s", out)
	}
	if strings.Contains(out, "MATCH shiro-key") {
		t.Errorf("没有 payload 时不应报 key 命中:\n%s", out)
	}
}

// Fastjson：靶场返回 autoType 错误特征时，骨架应报 sink，且不改写为 RCE。
func TestJavaPocScaffoldFastjsonSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"autoType is not support. ClassNotFoundException com.sun.rowset.JdbcRowSetImpl"}`))
	}))
	defer srv.Close()

	_, gen := javaPocTool(t)
	path := gen(t, "fastjson", srv.URL+"/api/import", nil)
	out := runJavaPoc(t, path, srv.URL+"/api/import")
	if !strings.Contains(out, "MATCH fastjson-sink") {
		t.Errorf("应判出 fastjson 解析 sink:\n%s", out)
	}
	if strings.Contains(out, "RCE 成功") {
		t.Errorf("错误特征不能写成 RCE 成功:\n%s", out)
	}
}

// Log4j2：至少要把 ${jndi:...} 真的放进请求头；没有回调检查时不能报 MATCH。
func TestJavaPocScaffoldLog4jSendsHeader(t *testing.T) {
	var sawJNDI bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.Header.Values("User-Agent") {
			if strings.Contains(v, "${jndi:") {
				sawJNDI = true
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, gen := javaPocTool(t)
	path := gen(t, "log4j2", srv.URL+"/", map[string]any{"oast": "demo.dnslog.cn"})
	out := runJavaPoc(t, path, srv.URL+"/", "--oast", "demo.dnslog.cn", "--header", "User-Agent")
	if !sawJNDI {
		t.Errorf("骨架没有把 JNDI payload 放进 User-Agent:\n%s", out)
	}
	if strings.Contains(out, "MATCH log4j2") {
		t.Errorf("没有 oast_check_url 时不应报 MATCH:\n%s", out)
	}
}

// 反序列化：靶场返回 Java 反序列化错误特征时，骨架应报 sink；错误特征不是利用成功。
func TestJavaPocScaffoldDeserSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("java.io.InvalidClassException: failed to deserialize; serialVersionUID mismatch"))
	}))
	defer srv.Close()

	_, gen := javaPocTool(t)
	path := gen(t, "deser", srv.URL+"/api/deserialize", map[string]any{"param": "data"})
	out := runJavaPoc(t, path, srv.URL+"/api/deserialize", "data")
	if !strings.Contains(out, "MATCH deser-sink") {
		t.Errorf("应判出反序列化 sink:\n%s", out)
	}
	if strings.Contains(out, "RCE 成功") || strings.Contains(out, "MATCH deser-rce") {
		t.Errorf("错误特征不能写成利用成功:\n%s", out)
	}
}

// 回调证据链：只有 OAST 日志里真的出现 token 才允许 MATCH；否则不允许拿状态码冒充。
func TestJavaPocScaffoldFastjsonOASTMatch(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	oast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("seen " + r.URL.Query().Get("token")))
	}))
	defer oast.Close()

	_, gen := javaPocTool(t)
	check := oast.URL + "/oast?token={token}"
	path := gen(t, "fastjson", target.URL+"/api", map[string]any{
		"oast":           "demo.dnslog.cn",
		"oast_check_url": check,
	})
	out := runJavaPoc(t, path, target.URL+"/api", "--oast", "demo.dnslog.cn", "--oast-check", check)
	if !strings.Contains(out, "MATCH fastjson-oast") {
		t.Errorf("OAST 日志出现 token 时应判回调命中:\n%s", out)
	}
}

func TestJavaPocScaffoldRejectsUnknownClass(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(t.TempDir())
	tool := ts.javaPocScaffold()
	in, _ := json.Marshal(map[string]any{"vulnclass": "shiro721", "target": "http://x/"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if !strings.Contains(res.Flatten(), "不支持的类别") {
		t.Errorf("未知类别应给出可用列表，实际:\n%s", res.Flatten())
	}
}

// 绑定守卫：执行侧、人在环路、独立渗透 agent 都必须拿得到；planner 不需要。
func TestJavaPocScaffoldBoundToRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := map[string]bool{}
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	for _, role := range []struct {
		name  string
		tools []actool.CoreTool
	}{
		{"worker", ts.WorkerTools()},
		{"mainagent", ts.MainAgentTools()},
		{"pentest", builtinToolsByAgent()["pentest"]},
	} {
		if !names(role.tools)["java_poc_scaffold"] {
			t.Errorf("%s 未绑定 java_poc_scaffold——组件级验证没有入口", role.name)
		}
	}
}
