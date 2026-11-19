package server

// 内网穿透（pivot）的 HTTP 装配与 API。
//
// 与 agent 侧 pivot_* 工具共用同一个 Manager：网页上开的隧道，worker 立刻能
// 在 pivot_list 里看到并用；worker 开的隧道，网页上能关。这是刻意的——隧道
// 是平台资源，不是某一次对话的私有状态。
//
// 凭据仍然收口：API 只接受 credential_id（或人工显式填入的一次性凭据），
// 返回体里永远没有 secret。

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/backslion/RedAI/agent"
	"github.com/backslion/RedAI/pivot"
)

// initPivot 建 manager 并注入 agent 工具集。
func (s *Server) initPivot() {
	s.pivots = pivot.NewManager()
	agent.SetPivotManager(s.pivots)
}

// pivotHopReq 是 API 的跳板输入。password/private_key 只写不读。
type pivotHopReq struct {
	Addr         string `json:"addr"`
	CredentialID int64  `json:"credential_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	PrivateKey   string `json:"private_key"`
	Passphrase   string `json:"passphrase"`
	Label        string `json:"label"`
}

type pivotOpenReq struct {
	TaskID     int64         `json:"task_id"`
	Label      string        `json:"label"`
	Mode       string        `json:"mode"`
	Hops       []pivotHopReq `json:"hops"`
	Target     string        `json:"target"`
	TTLMinutes int           `json:"ttl_minutes"`
	SocksUser  string        `json:"socks_user"`
	SocksPass  string        `json:"socks_pass"`
	BindHost   string        `json:"bind_host"`
}

// buildHops 把请求转成 pivot.Hop。credential_id 走凭据库（带任务范围校验）。
func (s *Server) buildHops(taskID int64, in []pivotHopReq) ([]pivot.Hop, error) {
	out := make([]pivot.Hop, 0, len(in))
	for _, h := range in {
		hop := pivot.Hop{Addr: strings.TrimSpace(h.Addr), User: strings.TrimSpace(h.Username), Label: strings.TrimSpace(h.Label)}
		if h.CredentialID > 0 {
			if s.m == nil || s.m.pg == nil {
				return nil, errBadRequest("凭据库不可用，无法按 credential_id 取凭据")
			}
			sec, err := s.m.pg.Credentials().SecretByID(taskID, h.CredentialID)
			if err != nil {
				return nil, errBadRequest(err.Error())
			}
			if hop.User == "" {
				hop.User = sec.Username
			}
			if strings.Contains(sec.Secret, "PRIVATE KEY") || sec.CredType == "key" {
				hop.PrivateKey = []byte(sec.Secret)
			} else {
				hop.Password = sec.Secret
			}
		} else {
			if strings.TrimSpace(h.PrivateKey) != "" {
				hop.PrivateKey = []byte(h.PrivateKey)
				hop.Passphrase = []byte(h.Passphrase)
			} else {
				hop.Password = h.Password
			}
		}
		out = append(out, hop)
	}
	return out, nil
}

// errBadRequest 让 API 层能区分「参数/凭据问题(400)」与「网络问题(502)」。
type pivotBadRequest struct{ msg string }

func (e pivotBadRequest) Error() string { return e.msg }

func errBadRequest(msg string) error { return pivotBadRequest{msg: msg} }

// pivotOpen 建隧道。
func (s *Server) pivotOpen(w http.ResponseWriter, r *http.Request) {
	if s.pivots == nil {
		writeErr(w, 503, "内网穿透未启用")
		return
	}
	var req pivotOpenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if len(req.Hops) == 0 {
		writeErr(w, 400, "hops 不能为空")
		return
	}
	if req.TaskID > 0 {
		if t, _ := s.m.pg.GetTask(req.TaskID); t == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
	}
	hops, err := s.buildHops(req.TaskID, req.Hops)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	tun, err := s.pivots.Open(r.Context(), pivot.OpenOptions{
		TaskID:    req.TaskID,
		Label:     req.Label,
		Mode:      req.Mode,
		Hops:      hops,
		Target:    req.Target,
		TTL:       ttl,
		BindHost:  req.BindHost,
		SocksUser: req.SocksUser,
		SocksPass: req.SocksPass,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"tunnel": tun.View(0),
		"usage":  pivotUsageText(tun),
	})
}

// pivotListAll 列出隧道。?task_id=N 只看该任务；?all=1 看全部。
func (s *Server) pivotListAll(w http.ResponseWriter, r *http.Request) {
	if s.pivots == nil {
		writeErr(w, 503, "内网穿透未启用")
		return
	}
	var taskID int64
	if v := r.URL.Query().Get("task_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			taskID = n
		}
	}
	if r.URL.Query().Get("all") == "1" {
		taskID = 0
	}
	list := s.pivots.List(taskID)
	items := make([]pivot.TunnelView, 0, len(list))
	for _, t := range list {
		items = append(items, t.View(5))
	}
	writeJSON(w, 200, map[string]any{
		"items":               items,
		"stats":               s.pivots.Stats(),
		"max_hops":            pivot.MaxHops,
		"max_per_task":        pivot.MaxPerTask,
		"default_ttl_minutes": int(pivot.DefaultTTL / time.Minute),
		"max_ttl_minutes":     int(pivot.MaxTTL / time.Minute),
	})
}

// pivotSummary 概览。
func (s *Server) pivotSummary(w http.ResponseWriter, r *http.Request) {
	if s.pivots == nil {
		writeErr(w, 503, "内网穿透未启用")
		return
	}
	writeJSON(w, 200, map[string]any{
		"stats":        s.pivots.Stats(),
		"max_hops":     pivot.MaxHops,
		"max_per_task": pivot.MaxPerTask,
	})
}

// pivotDelete 关闭隧道。
func (s *Server) pivotDelete(w http.ResponseWriter, r *http.Request) {
	if s.pivots == nil {
		writeErr(w, 503, "内网穿透未启用")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, 400, "缺少隧道 id")
		return
	}
	if err := s.pivots.Close(id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// pivotUsageText 与 agent 侧 pivotUsage 同一份说明。两端文案必须一致：
// 人在页面上看到的用法与模型看到的不一样，就会互相打架。
func pivotUsageText(t *pivot.Tunnel) string {
	if t.Mode == pivot.ModeSocks {
		return "SOCKS5 入口 " + t.Listen + "。curl 用 --socks5-hostname " + t.Listen +
			"（不要用 --socks5：域名会在本机解析，内网域名解析不到）；" +
			"nmap 不走 SOCKS5，端口探测用 pivot_probe；用完在页面上关闭或让它到期。"
	}
	return "端口转发 " + t.Listen + " → " + t.Target + "，直接连本机 " + t.Listen + " 即可。"
}

// pivotShutdown 关闭全部隧道（进程退出时调用）。
func (s *Server) pivotShutdown() {
	if s.pivots == nil {
		return
	}
	n := 0
	for range s.pivots.List(0) {
		n++
	}
	s.pivots.CloseAll()
	if n > 0 {
		log.Printf("pivot: 进程退出，已关闭 %d 条隧道", n)
	}
}
