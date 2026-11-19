package server

// WebShell 会话的 HTTP 装配与 API。
//
// 与 agent 侧 webshell_* 工具共用同一个 Manager：网页上登记的会话 worker 立刻
// 能用，worker 落地的马网页上也能看到、能执行、能清理。这与 pivot 的取舍一致——
// 入口是平台资源，不是某一次对话的私有状态；但每条都带 TaskID，跨任务不可见。
//
// 与上游 artex-full 的差异：
//   - 会话库随平台数据目录走（s.dataDir/webshells.json），不再写死 /opt/artex；
//   - 多任务隔离（TaskID），上游是单实例全局库；
//   - 不需要 Python MCP 那一侧——Pojun 的工具是 norma 原生 CoreTool，协议只保留
//     Go 一份实现，不存在「两边改了协议对不上」的问题。
//
// 参数名（param）永不出现在任何列表/详情响应里：它等价于马的钥匙，泄漏了等于
// 把入口交出去。前端编辑时留空 = 保持原样。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/webshell"
)

// initWebShell 建 manager、接审计钩子、注入 agent 工具集。
// 失败只记日志（降级为无会话管理），不拖垮启动。
func (s *Server) initWebShell() {
	m, err := webshell.NewManager(s.dataDir)
	if err != nil {
		log.Printf("[webshell] disabled: %v", err)
		return
	}
	m.OnEvent = s.recordWebShellEvent
	s.webshells = m
	agent.SetWebShellManager(m)
	// WebShell 隧道台账：复用同一会话库取出口代理，进程内资源，退出时全关。
	tm := webshell.NewTunnelManager(m)
	tm.OnEvent = s.recordWebShellTunnelEvent
	s.wsTunnels = tm
	agent.SetWebShellTunnelManager(tm)
	log.Printf("[webshell] 会话库已就绪: %s（上限 %d 条）", m.Dir(), webshell.MaxSessions)
	if d := webshell.PayloadDir(); d != "" {
		log.Printf("[webshell] 自备载荷库: %s", d)
	} else {
		log.Printf("[webshell] 使用内置最小载荷模板（自备库请设 %s）", webshell.PayloadDirEnv)
	}
}

// recordWebShellTunnelEvent 把隧道开/关/到期写进归属任务的活动记录。
// 与 pivot 的审计口径一致：开隧道是对内网的长期入口，必须可追溯。
func (s *Server) recordWebShellTunnelEvent(ev webshell.TunnelEvent) {
	summary := fmt.Sprintf("webshell_tunnel %s: %s (%s)", ev.Kind, ev.ID, ev.Label)
	log.Printf("[webshell-tunnel] task=%d %s", ev.TaskID, summary)
	if ev.TaskID <= 0 || s.m == nil || s.m.pg == nil {
		return
	}
	t, err := s.m.pg.GetTask(ev.TaskID)
	if err != nil || t == nil || t.ExplorationID <= 0 {
		return
	}
	_, _ = s.m.pg.Exploration(t.ExplorationID).AppendActivity(db.Activity{
		Worker: "system", Kind: "text", Tool: "webshell_pivot_" + ev.Kind,
		Summary: summary,
		Detail:  fmt.Sprintf("id=%s label=%s target=%s detail=%s", ev.ID, ev.Label, ev.Target, ev.Detail),
	})
}

// recordWebShellEvent 把登记/摘登记/清理写进归属任务的活动记录。
// 不含 exec：执行频率高，逐条记会把真正的关键动作淹掉（exec 本身由拦截规则
// 的审批记录覆盖）。
func (s *Server) recordWebShellEvent(ev webshell.Event) {
	summary := fmt.Sprintf("webshell %s: %s (%s %s)", ev.Kind, ev.Name, ev.Type, ev.URL)
	if ev.Kind == "purge" {
		summary = fmt.Sprintf("webshell purge: %s 远端清理后摘登记（%s）", ev.Name, ev.Detail)
	}
	log.Printf("[webshell] task=%d %s", ev.TaskID, summary)
	if ev.TaskID <= 0 || s.m == nil || s.m.pg == nil {
		return
	}
	t, err := s.m.pg.GetTask(ev.TaskID)
	if err != nil || t == nil || t.ExplorationID <= 0 {
		return // 任务句柄已不在（结束/删除），日志已留
	}
	if _, err := s.m.pg.Exploration(t.ExplorationID).AppendActivity(db.Activity{
		Worker: "system", Kind: "text", Tool: "webshell_" + ev.Kind,
		Summary: summary,
		Detail:  fmt.Sprintf("name=%s type=%s url=%s remote_touched=%v detail=%s", ev.Name, ev.Type, ev.URL, ev.Remote, ev.Detail),
	}); err != nil {
		log.Printf("[webshell] activity 写入失败(task=%d): %v", ev.TaskID, err)
	}
}

// wsBadRequest 让 API 能区分「参数问题(400)」与「不存在(404)」。
type wsBadRequest struct{ msg string }

func (e wsBadRequest) Error() string { return e.msg }

func wsErr(msg string) error { return wsBadRequest{msg} }

// wsErrStatus 把 webshell 包的哨兵错误映射成 HTTP 状态码。
func wsErrStatus(err error) (int, string) {
	if err == nil {
		return 200, ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, webshell.ErrNotFound.Error()):
		return 404, msg
	case strings.Contains(msg, webshell.ErrInvalid.Error()):
		return 400, msg
	default:
		return 400, msg // 校验类错误占绝对多数，500 会把「填错了」伪装成「平台坏了」
	}
}

// wsTaskID 从 query 解析 task_id。0 表示「全部」（仅管理端视图用）。
func wsTaskID(r *http.Request) int64 {
	if v := r.URL.Query().Get("task_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

// webshellListAll 列出会话。?task_id=N 只看该任务；不传=全部。
func (s *Server) webshellListAll(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	items := s.webshells.List(wsTaskID(r))
	writeJSON(w, 200, map[string]any{
		"items":           items,
		"count":           len(items),
		"total":           s.webshells.Count(),
		"max_sessions":    webshell.MaxSessions,
		"payload_dir":     webshell.PayloadDir(),
		"types":           webshell.ValidTypes,
		"max_upload":      webshell.UploadMax,
		"max_download":    webshell.DownloadMax,
		"chunk_default":   webshell.ChunkDefault,
		"default_timeout": int(webshell.DefaultTimeout / time.Second),
	})
}

// webshellAddReq 是登记请求。param 只写不读。
type webshellAddReq struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Type        string            `json:"type"`
	Param       string            `json:"param"`
	Method      string            `json:"method"`
	Header      map[string]string `json:"header"`
	Note        string            `json:"note"`
	TaskID      int64             `json:"task_id"`
	RemotePath  string            `json:"remote_path"`
	Proxy       string            `json:"proxy"`
	UserAgent   string            `json:"user_agent"`
	ProxyRotate bool              `json:"proxy_rotate"`
	Overwrite   bool              `json:"overwrite"`
}

// webshellAdd 登记一条会话。
func (s *Server) webshellAdd(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	var req webshellAddReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if err := webshell.ValidateProxy(req.Proxy); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.TaskID > 0 {
		if t, _ := s.m.pg.GetTask(req.TaskID); t == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
	}
	v, err := s.webshells.Add(webshell.AddOptions{
		Name: req.Name, URL: req.URL, Type: req.Type, Param: req.Param, Method: req.Method,
		Header: req.Header, Note: req.Note, TaskID: req.TaskID, RemotePath: req.RemotePath,
		Proxy: req.Proxy, UserAgent: req.UserAgent, ProxyRotate: req.ProxyRotate,
		Overwrite: req.Overwrite,
	})
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"session": v})
}

// webshellUpdate 局部更新（param 留空=保持原样）。
func (s *Server) webshellUpdate(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	var req webshellAddReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if req.Proxy != "" {
		if err := webshell.ValidateProxy(req.Proxy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	v, err := s.webshells.Update(name, func(sess *webshell.Session) {
		if req.URL != "" {
			sess.URL = strings.TrimSpace(req.URL)
		}
		if req.Type != "" {
			sess.Type = strings.TrimSpace(req.Type)
		}
		if req.Param != "" {
			sess.Param = strings.TrimSpace(req.Param)
		}
		if req.Method != "" {
			sess.Method = req.Method
		}
		if req.Note != "" {
			sess.Note = strings.TrimSpace(req.Note)
		}
		if req.RemotePath != "" {
			sess.RemotePath = strings.TrimSpace(req.RemotePath)
		}
		if req.Proxy != "" {
			sess.Proxy = strings.TrimSpace(req.Proxy)
		}
		if req.UserAgent != "" {
			sess.UserAgent = strings.TrimSpace(req.UserAgent)
		}
		if req.Header != nil {
			sess.Header = req.Header
		}
		sess.ProxyRotate = req.ProxyRotate
	})
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"session": v})
}

// webshellExec 执行命令。
func (s *Server) webshellExec(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	var req struct {
		Command        string   `json:"command"`
		Commands       []string `json:"commands"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if len(req.Commands) > 0 {
		results, err := s.webshells.ExecBatch(r.Context(), name, "", req.Commands, timeout)
		if err != nil {
			code, msg := wsErrStatus(err)
			writeErr(w, code, msg)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok": true, "batch": true, "results": results, "count": len(results),
		})
		return
	}
	res, err := s.webshells.Exec(r.Context(), name, req.Command, timeout)
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{
		"output": res.Output, "mode": res.Mode, "egress": res.Egress, "truncated": res.Truncated,
	})
}

// webshellUpload 上传文件（content_b64 或 local_path）。
func (s *Server) webshellUpload(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	var req struct {
		RemotePath string `json:"remote_path"`
		ContentB64 string `json:"content_b64"`
		LocalPath  string `json:"local_path"`
		ChunkSize  int    `json:"chunk_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if strings.TrimSpace(req.ContentB64) == "" && strings.TrimSpace(req.LocalPath) == "" {
		writeErr(w, 400, "要给 content_b64 或 local_path 其中之一")
		return
	}
	if strings.TrimSpace(req.ContentB64) != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.ContentB64))
		if err != nil {
			writeErr(w, 400, "content_b64 不是合法 base64: "+err.Error())
			return
		}
		res, err := s.webshells.Upload(r.Context(), name, req.RemotePath, raw, req.ChunkSize, 0)
		if err != nil {
			code, msg := wsErrStatus(err)
			writeErr(w, code, msg)
			return
		}
		writeJSON(w, 200, map[string]any{"result": res})
		return
	}
	// local_path 走 agent 侧的同一实现需要 os 读文件；这里只接受 b64，避免把
	// 「服务端任意文件读取」开成一个 API。local_path 仅留给模型在 worker 上下文用。
	writeErr(w, 400, "网页上传请用 content_b64（local_path 只在 agent 工具里可用）")
}

// webshellDownload 读远端文件。?path=&max_bytes=
func (s *Server) webshellDownload(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	remotePath := strings.TrimSpace(r.URL.Query().Get("path"))
	if remotePath == "" {
		writeErr(w, 400, "缺少 path 参数")
		return
	}
	maxBytes := 0
	if v := r.URL.Query().Get("max_bytes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxBytes = n
		}
	}
	res, err := s.webshells.Download(r.Context(), name, remotePath, maxBytes, 0)
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	body := map[string]any{
		"remote_path": res.RemotePath, "bytes": res.Bytes, "remote_size": res.RemoteSize,
		"truncated": res.Truncated, "text": res.Text, "mode": res.Mode, "egress": res.Egress,
	}
	if res.Text {
		body["content"] = string(res.Data)
	} else {
		body["content_b64"] = base64.StdEncoding.EncodeToString(res.Data)
	}
	writeJSON(w, 200, body)
}

// webshellProbe 巡检一条或全部。
func (s *Server) webshellProbe(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	var req struct {
		Name   string `json:"name"`
		TaskID int64  `json:"task_id"`
		Deep   bool   `json:"deep"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // 空 body 等价于巡检全部
	if strings.TrimSpace(req.Name) != "" {
		res, err := s.webshells.Probe(r.Context(), req.Name, req.Deep, 0)
		if err != nil {
			code, msg := wsErrStatus(err)
			writeErr(w, code, msg)
			return
		}
		writeJSON(w, 200, map[string]any{"item": res})
		return
	}
	items := s.webshells.ProbeAll(r.Context(), req.TaskID, req.Deep, 0)
	alive := 0
	for _, it := range items {
		if it.Alive {
			alive++
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "alive": alive, "failed": len(items) - alive})
}

// webshellDelete 清理会话（默认只摘登记）。
func (s *Server) webshellDelete(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	var req struct {
		RemoveRemote bool `json:"remove_remote"`
		Force        bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	res, err := s.webshells.Purge(r.Context(), name, webshell.PurgeOptions{
		RemoveRemote: req.RemoveRemote,
		Force:        req.Force,
	})
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"result": res})
}

// webshellSummary 概览。
func (s *Server) webshellSummary(w http.ResponseWriter, r *http.Request) {
	if s.webshells == nil {
		writeErr(w, 503, "WebShell 会话管理未启用")
		return
	}
	items := s.webshells.List(wsTaskID(r))
	byType := map[string]int{}
	direct := 0
	for _, it := range items {
		byType[it.Type]++
		if it.Egress == "直连" {
			direct++
		}
	}
	writeJSON(w, 200, map[string]any{
		"count": len(items), "total": s.webshells.Count(),
		"by_type": byType, "egress_direct": direct,
		"max_sessions": webshell.MaxSessions,
	})
}

// webshellPayloads 列出载荷（不含全文）。
func (s *Server) webshellPayloads(w http.ResponseWriter, r *http.Request) {
	items := webshell.ListTemplates()
	if v := r.URL.Query().Get("type"); v != "" {
		out := items[:0]
		for _, it := range items {
			if it.Type == v {
				out = append(out, it)
			}
		}
		items = out
	}
	writeJSON(w, 200, map[string]any{
		"items": items, "payload_dir": webshell.PayloadDir(),
		"placeholder": webshell.ParamPlaceholder,
	})
}

// webshellPayloadDetail 取一份载荷的全文（已按 param 渲染）。
// 载荷名走 ?name=（它可能含 /，不放进路径段）。
func (s *Server) webshellPayloadDetail(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, 400, "缺少 name 参数")
		return
	}
	tp, err := webshell.GetTemplate(name)
	if err != nil {
		code, msg := wsErrStatus(err)
		writeErr(w, code, msg)
		return
	}
	param := strings.TrimSpace(r.URL.Query().Get("param"))
	if param == "" {
		param = "pass"
	}
	writeJSON(w, 200, map[string]any{
		"name": tp.Name, "type": tp.Type, "param": param,
		"content": tp.Render(param), "summary": tp.Summary,
	})
}

// webshellShutdown 进程退出时的收尾：只打日志，不做任何网络动作。
//
// 刻意不自动清理会话（那意味着退出时对每个目标再发一轮请求，且可能把演练中
// 还要用的入口删掉）。会话库留在磁盘上，下次启动照样能读回来。
func (s *Server) webshellShutdown() {
	if s.webshells == nil {
		return
	}
	if n := s.webshells.Count(); n > 0 {
		log.Printf("webshell: 进程退出，会话库保留 %d 条（%s）", n, s.webshells.Dir())
	}
}
