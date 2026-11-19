package server

// WebShell 隧道的 HTTP 装配：列表 / 概览 / 开 / 关。
//
// 与 agent 工具共用同一个 TunnelManager；页面上开的隧道 worker 立刻能用。
// 每条带 TaskID，?task_id=N 过滤（管理端「全部」视图用 0）。
// token 不进任何响应：它只在 open 请求里进一次，之后只活在 manager 内部。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/webshell"
)

// webshellTunnelsList 列出隧道。?task_id=N 只看该任务，?recent=N 附最近连接记录。
func (s *Server) webshellTunnelsList(w http.ResponseWriter, r *http.Request) {
	if s.wsTunnels == nil {
		writeErr(w, 503, "WebShell 隧道未启用")
		return
	}
	recent := 3
	if v := r.URL.Query().Get("recent"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 20 {
			recent = n
		}
	}
	items := make([]webshell.TunnelView, 0)
	for _, t := range s.wsTunnels.List(wsTaskID(r)) {
		items = append(items, t.View(recent))
	}
	writeJSON(w, 200, map[string]any{
		"items": items, "count": len(items), "stats": s.wsTunnels.Stats(),
		"max_per_task": webshell.MaxPerTask,
	})
}

// webshellTunnelsSummary 概览。
func (s *Server) webshellTunnelsSummary(w http.ResponseWriter, r *http.Request) {
	if s.wsTunnels == nil {
		writeErr(w, 503, "WebShell 隧道未启用")
		return
	}
	writeJSON(w, 200, s.wsTunnels.Stats())
}

// webshellTunnelOpenReq 是开隧道请求。token 只在这里进一次，不回传。
type webshellTunnelOpenReq struct {
	TaskID    int64  `json:"task_id"`
	Name      string `json:"name"`
	TunnelURL string `json:"tunnel_url"`
	Token     string `json:"token"`
	Mode      string `json:"mode"`
	Target    string `json:"target"`
	Label     string `json:"label"`
	TTLMin    int    `json:"ttl_minutes"`
	SocksUser string `json:"socks_user"`
	SocksPass string `json:"socks_pass"`
	BindHost  string `json:"bind_host"`
}

// webshellTunnelOpen 开一条隧道。非回环绑定强制认证（Manager 内已兜底，这里再校验一次给清晰错误）。
func (s *Server) webshellTunnelOpen(w http.ResponseWriter, r *http.Request) {
	if s.wsTunnels == nil || s.webshells == nil {
		writeErr(w, 503, "WebShell 隧道未启用")
		return
	}
	var req webshellTunnelOpenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	bind := strings.TrimSpace(req.BindHost)
	if bind == "" {
		bind = "127.0.0.1"
	}
	if bind != "127.0.0.1" && bind != "localhost" && req.SocksUser == "" && req.SocksPass == "" {
		writeErr(w, 400, "绑定非回环地址必须设置 socks_user / socks_pass")
		return
	}
	if req.TaskID > 0 {
		if t, _ := s.m.pg.GetTask(req.TaskID); t == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
	}
	ttl := time.Duration(req.TTLMin) * time.Minute
	if ttl <= 0 {
		ttl = webshell.DefaultTTL
	}
	tun, err := s.wsTunnels.Open(r.Context(), webshell.TunnelOptions{
		TaskID: req.TaskID, Session: req.Name, TunnelURL: req.TunnelURL, Token: req.Token,
		Mode: req.Mode, Target: req.Target, Label: req.Label, TTL: ttl,
		BindHost: bind, SocksUser: req.SocksUser, SocksPass: req.SocksPass,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tunnel": tun.View(0)})
}

// webshellTunnelClose 关闭一条隧道。?task_id=N 给定时跨任务关闭被拒。
func (s *Server) webshellTunnelClose(w http.ResponseWriter, r *http.Request) {
	if s.wsTunnels == nil {
		writeErr(w, 503, "WebShell 隧道未启用")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, 400, "缺少隧道 id")
		return
	}
	tun, ok := s.wsTunnels.Get(id)
	if !ok {
		writeErr(w, 404, "隧道不存在")
		return
	}
	if taskID := wsTaskID(r); taskID > 0 && tun.TaskID != taskID {
		writeErr(w, 403, "跨任务不能关闭隧道")
		return
	}
	if err := s.wsTunnels.Close(id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"closed": id})
}
