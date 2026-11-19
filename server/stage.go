package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/backslion/RedAI/db"
	stagepkg "github.com/backslion/RedAI/stage"
)

// 受管文件投递（移植自 artex-ymh 的 F13；stage 包语义见 stage/stage.go 头注释）。
// 本文件做三件事：
//  1. 装配：创建 stage.Manager，把记账事件写进归属任务的 activity（无任务上下文只打日志）；
//  2. 下载路由 GET /s/{token}/{name}（root mux，JWT 之外——目标机器没有 token；
//     requireAuth 对 /s/ 前缀放行）；
//  3. 管理 API（POST/GET/DELETE /api/stage*，在 JWT 之后）。
//
// 与上游的差异：
//   - TaskID 用 int64（RedAI 的任务 id 本来就是整数，activity 记账可以直接用，
//     不必再在字符串与整数之间来回转）；
//   - 新增单条 256 MiB 上限（暂存目录在平台数据盘上，不设限等于给 agent 一个把
//     磁盘写满的静默入口）；
//   - 基址优先取 POJUN_STAGE_BASE_URL，否则由 main 用监听地址推（0.0.0.0/空主机
//     回落 127.0.0.1 占位，目标实际可达地址由模型按部署替换主机部分）。

// initStage 创建进程内暂存管理器并接好记账。失败只记日志（降级为无暂存服务），
// 不拖垮启动。
func (s *Server) initStage() {
	m, err := stagepkg.New(s.ctx, filepath.Join(s.dataDir, "stage"))
	if err != nil {
		log.Printf("[stage] disabled: %v", err)
		return
	}
	m.OnEvent = s.recordStageEvent
	s.stageSvc = m
	log.Printf("[stage] 受管暂存服务已就绪: GET /s/<token>/<name> (TTL 默认 %v, 上限 %v, 单条上限 %d MiB)",
		stagepkg.DefaultTTL, stagepkg.MaxTTL, stagepkg.MaxSize>>20)
	log.Printf("[stage] 注意：该下载路径免 JWT，安全性依赖随机 token + TTL + 限速；" +
		"如需关闭，设置 POJUN_STAGE_DISABLED=1 后重启")
}

// stageDisabledByEnv 让不需要投递能力的部署（例如只在公网做纯扫描）彻底关掉
// 这条免鉴权路径——把「是否存在一个无鉴权下载口」变成部署方可控的开关。
func stageDisabledByEnv() bool {
	v := strings.TrimSpace(os.Getenv("POJUN_STAGE_DISABLED"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
}

// SetStageBaseURL 设置拼进暂存 URL 的对外基址（通常是主监听地址）。目标机器能
// 用哪个地址回连平台取决于部署，这里只是给工具返回一个可直接用的绝对 URL。
func (s *Server) SetStageBaseURL(addr string) {
	if s.stageSvc == nil {
		return
	}
	if v := strings.TrimSpace(os.Getenv("POJUN_STAGE_BASE_URL")); v != "" {
		s.stageSvc.SetBaseURL(v)
		return
	}
	host := strings.TrimSpace(addr)
	if host == "" || strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host // ":8787" → "127.0.0.1:8787"
	} else if strings.HasPrefix(host, "0.0.0.0") {
		host = strings.Replace(host, "0.0.0.0", "127.0.0.1", 1)
	} else if strings.HasPrefix(host, "[::]") {
		host = strings.Replace(host, "[::]", "127.0.0.1", 1)
	}
	s.stageSvc.SetBaseURL("http://" + host)
}

// recordStageEvent 把 stage 记账事件写进归属任务的 activity；任务已结束、无任务
// 上下文或库不可用时至少留服务端日志（投递是外部可见动作，日志是最后的凭据）。
func (s *Server) recordStageEvent(ev stagepkg.Event) {
	e := ev.Entry
	summary := fmt.Sprintf("stage %s: %s (token=%s… size=%d bytes, expires %s)",
		ev.Kind, e.Name, shortToken(e.Token), e.Size, e.ExpiresAt.Format(time.RFC3339))
	if ev.Kind == stagepkg.EventDownload {
		summary = fmt.Sprintf("stage download: %s 被 %s 拉取 %d/%d 字节（累计完整命中 %d 次）",
			e.Name, ev.Remote, ev.Bytes, e.Size, e.Hits)
	}
	log.Printf("[stage] task=%d %s", e.TaskID, summary)
	if e.TaskID <= 0 || s.m == nil || s.m.pg == nil {
		return
	}
	t, err := s.m.pg.GetTask(e.TaskID)
	if err != nil || t == nil || t.ExplorationID <= 0 {
		return // 任务句柄已不在（结束/删除），日志已留
	}
	if _, err := s.m.pg.Exploration(t.ExplorationID).AppendActivity(db.Activity{
		Worker: "system", Kind: "text", Tool: "stage_share",
		Summary: summary,
		Detail: fmt.Sprintf("token=%s name=%s size=%d one_shot=%v expires_at=%s remote=%s bytes=%d hits=%d",
			e.Token, e.Name, e.Size, e.OneShot, e.ExpiresAt.Format(time.RFC3339), ev.Remote, ev.Bytes, e.Hits),
	}); err != nil {
		log.Printf("[stage] activity 写入失败(task=%d): %v", e.TaskID, err)
	}
}

// shortToken 只取 token 前 8 位进日志：日志会被贴进工单/报告，完整 token 等于
// 在有效期内把下载能力一起泄出去。
func shortToken(tok string) string {
	if len(tok) <= 8 {
		return tok
	}
	return tok[:8]
}

// stageDownload 服务下载。挂 root mux（JWT 之外）；防枚举的一致性 404 与限速
// 都在 stage.Manager.Download 里。
func (s *Server) stageDownload(w http.ResponseWriter, r *http.Request) {
	if s.stageSvc == nil {
		http.NotFound(w, r)
		return
	}
	s.stageSvc.Download(w, r, r.PathValue("token"), r.PathValue("name"))
}

// --- 管理 API（JWT 之后，供 worker 工具与 UI 使用） ---

type stageCreateReq struct {
	Path          string `json:"path"`           // 平台侧已有文件（与 content_base64 二选一）
	Name          string `json:"name"`           // content 模式必填
	ContentBase64 string `json:"content_base64"` // content 模式
	TTLMinutes    int    `json:"ttl_minutes"`    // 0 = 默认 15 分钟，上限 120
	OneShot       bool   `json:"one_shot"`       // 首次成功完整下载后即焚
	TaskID        int64  `json:"task_id"`        // 归属任务（activity 记账）
}

func (s *Server) stageCreate(w http.ResponseWriter, r *http.Request) {
	if s.stageSvc == nil {
		writeErr(w, 503, "stage service disabled")
		return
	}
	var req stageCreateReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	opts := stagepkg.PutOpts{
		TTL:     time.Duration(req.TTLMinutes) * time.Minute,
		OneShot: req.OneShot,
		TaskID:  req.TaskID,
	}
	var e *stagepkg.Entry
	var err error
	switch {
	case strings.TrimSpace(req.Path) != "":
		e, err = s.stageSvc.PutFile(strings.TrimSpace(req.Path), opts)
	case req.ContentBase64 != "":
		data, derr := base64.StdEncoding.DecodeString(req.ContentBase64)
		if derr != nil {
			writeErr(w, 400, "content_base64 解码失败: "+derr.Error())
			return
		}
		e, err = s.stageSvc.PutContent(req.Name, data, opts)
	default:
		writeErr(w, 400, "path 与 content_base64 至少提供一个")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, e)
}

func (s *Server) stageList(w http.ResponseWriter, r *http.Request) {
	if s.stageSvc == nil {
		writeJSON(w, 200, map[string]any{"items": []stagepkg.Entry{}, "max_ttl_minutes": int(stagepkg.MaxTTL.Minutes())})
		return
	}
	items := s.stageSvc.List()
	writeJSON(w, 200, map[string]any{
		"items":           items,
		"max_ttl_minutes": int(stagepkg.MaxTTL.Minutes()),
		"max_size_mb":     int(stagepkg.MaxSize >> 20),
	})
}

func (s *Server) stageDelete(w http.ResponseWriter, r *http.Request) {
	if s.stageSvc == nil {
		writeErr(w, 503, "stage service disabled")
		return
	}
	token := r.PathValue("token")
	if !s.stageSvc.Delete(token) {
		writeErr(w, 404, "stage entry not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": token})
}

// stageSummary 给页面顶部卡片用：条目数、总字节、最早过期时间。
func (s *Server) stageSummary(w http.ResponseWriter, r *http.Request) {
	if s.stageSvc == nil {
		writeJSON(w, 200, map[string]any{"entries": 0, "bytes": 0, "one_shot": 0, "enabled": false})
		return
	}
	items := s.stageSvc.List()
	var bytes int64
	oneShot := 0
	var soonest time.Time
	for _, it := range items {
		bytes += it.Size
		if it.OneShot {
			oneShot++
		}
		if soonest.IsZero() || it.ExpiresAt.Before(soonest) {
			soonest = it.ExpiresAt
		}
	}
	out := map[string]any{
		"entries": len(items), "bytes": bytes, "one_shot": oneShot, "enabled": true,
		"max_size_mb": int(stagepkg.MaxSize >> 20),
	}
	if !soonest.IsZero() {
		out["next_expiry"] = soonest.Format(time.RFC3339)
	}
	writeJSON(w, 200, out)
}
