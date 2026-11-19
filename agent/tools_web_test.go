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
)

// 攻击链第一段（信息收集）的可用性守卫：dir_probe 必须能从真实 HTTP 响应里
// 挑出「存在但受限」与「信息泄露」，且不能把 404 兜底页当命中。
//
// 这不是接口形状测试——它起真 httptest 服务，走真实并发 GET，用来挡住
// 「路径字典还在、探测逻辑写坏了却没人发现」这类回归。
func TestDirProbeFindsRealHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusMovedPermanently)
			w.Header().Set("Location", "/admin/login")
			_, _ = w.Write([]byte(`<html><title>后台登录</title></html>`))
		case "/admin/login":
			_, _ = w.Write([]byte(`<html><title>管理后台</title><form></form></html>`))
		case "/.git/config":
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@x:a.git\n"))
		case "/upload/":
			// 403 在 dir_probe 的语义里是「存在但受限」，必须算命中。
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "worker")
	tool := ts.dirProbe()
	in, _ := json.Marshal(map[string]any{
		"base_url": srv.URL,
		"preset":   "none",
		"paths":    []string{"/admin/", "/admin/login", "/.git/config", "/upload/", "/nope123"},
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	out := res.Flatten()

	for _, want := range []string{"/admin/", "/.git/config", "/upload/"} {
		if !strings.Contains(out, want) {
			t.Errorf("应命中 %s，实际输出:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/nope123") {
		t.Errorf("404 路径不应算命中:\n%s", out)
	}
}

// 攻击链第二段（Web 漏洞 → getshell）的桥梁：poc_scaffold 必须能按类别产出
// 可运行骨架并落进任务共享目录。upload 类别是 getshell 主路径，单独盯住它
// 的「只判上传成功、不判执行」这条边界——骨架一旦擅自宣称 getshell 成功，
// 上层 agent 就会把「传上去了」写成「拿到了」，这正是要防的误报来源。
func TestPocScaffoldUploadSkeleton(t *testing.T) {
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)

	tool := ts.pocScaffold()
	in, _ := json.Marshal(map[string]any{
		"vulnclass": "upload",
		"target":    "http://10.0.0.5/upload.php",
		"param":     "file",
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	out := res.Flatten()

	// 返回是 JSON：path 必须指向真实落盘文件，否则 run_script 无脚本可跑。
	var meta struct {
		Path      string `json:"path"`
		VulnClass string `json:"vulnclass"`
		RunWith   string `json:"run_with_bash"`
	}
	if jerr := json.Unmarshal([]byte(out), &meta); jerr != nil {
		t.Fatalf("返回不是预期 JSON: %v\n%s", jerr, out)
	}
	if meta.VulnClass != "upload" {
		t.Errorf("vulnclass = %q", meta.VulnClass)
	}
	if !strings.Contains(meta.Path, "upload") || !strings.HasSuffix(meta.Path, ".py") {
		t.Errorf("脚本路径异常: %q", meta.Path)
	}
	if !strings.Contains(meta.RunWith, "python3") {
		t.Errorf("应给出可执行命令，实际: %q", meta.RunWith)
	}
	scriptPath := meta.Path
	body, rerr := os.ReadFile(scriptPath)
	if rerr != nil {
		t.Fatalf("骨架未落盘(%s): %v", scriptPath, rerr)
	}
	src := string(body)

	for _, want := range []string{"poc.php", "multipart/form-data", "MATCH upload"} {
		if !strings.Contains(src, want) {
			t.Errorf("上传骨架缺少 %q", want)
		}
	}
	// 边界守卫：骨架只判「上传成功」，把执行验证留给下一步。
	if !strings.Contains(src, "确认回显") && !strings.Contains(src, "解析执行") {
		t.Error("上传骨架应显式提示「下一步确认回显/解析执行」，否则会被误读成 getshell 成功")
	}
}

// 端到端：poc_scaffold 生成的 upload 骨架必须能真的跑起来、真的判出「上传成功」。
//
// 为什么值得花一个测试：骨架的判据（状态码 + 正则）一旦写错，agent 会拿到
// 「没命中」的假否定，从而放弃一条真实可利用上传点——这种损失是静默的。
// 这里起真 httptest 靶场收 multipart，真执行 python3 骨架，只看它敢不敢报 MATCH。
func TestPocScaffoldUploadSkeletonActuallyRuns(t *testing.T) {
	py := "python3"
	if _, err := exec.LookPath(py); err != nil {
		t.Skip("无 python3，跳过骨架实跑")
	}

	var sawPHP, sawHtaccess bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.MultipartForm == nil {
			http.Error(w, "no form", http.StatusBadRequest)
			return
		}
		for name := range r.MultipartForm.File {
			fhs := r.MultipartForm.File[name]
			for _, fh := range fhs {
				if strings.HasSuffix(fh.Filename, ".php") {
					sawPHP = true
				}
				if strings.HasSuffix(fh.Filename, ".htaccess") {
					sawHtaccess = true
				}
			}
		}
		_, _ = w.Write([]byte(`{"status":"success","msg":"upload success"}`))
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(t.TempDir())
	tool := ts.pocScaffold()
	in, _ := json.Marshal(map[string]any{
		"vulnclass": "upload",
		"target":    srv.URL + "/upload.php",
		"param":     "file",
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	var meta struct {
		Path string `json:"path"`
	}
	if jerr := json.Unmarshal([]byte(res.Flatten()), &meta); jerr != nil {
		t.Fatalf("返回解析失败: %v", jerr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, meta.Path, srv.URL+"/upload.php", "file")
	raw, rerr := cmd.CombinedOutput()
	if rerr != nil {
		t.Fatalf("骨架执行失败: %v\n%s", rerr, raw)
	}
	out := string(raw)
	if !strings.Contains(out, "MATCH upload") {
		t.Errorf("靶场明确返回 success，骨架却没判出 MATCH:/n%s", out)
	}
	if !sawPHP {
		t.Errorf("骨架没有真的把 .php 文件发出去:\n%s", out)
	}
	_ = sawHtaccess
}
