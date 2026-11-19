package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/backslion/RedAI/stage"

	actool "github.com/Autumn-27/norma/tool"
)

// 受管文件投递工具（红队杀伤链的「送工具」环节，移植自 artex-ymh 的 stage_share）。
//
// 与 listener_* 是一对反向能力：
//   - listener_*：目标 → 平台（接住回连，自己起端口）；
//   - stage_share：平台 → 目标（平台给出随机 token 下载口，目标 curl/wget 拉）。
//
// 设计边界（与 stage 包注释一致）：只用于**向外投递**工具/payload。战利品、凭据、
// 证据一律走会话读取 / evidence——暂存服务即使被打穿也没有敏感数据可泄。
// 因此本工具不需要 ask 审批：它不执行任何命令、不接触目标，只是把工作区里已有的
// 文件复制到平台自有目录并向模型返回一个短期 URL。

// SetStageManager wires the process-wide managed-staging service (nil = disabled).
func SetStageManager(m *stage.Manager) {
	setDefaultRuntime(func(r *Runtime) { r.Stage = m })
}

func (t *ToolSet) stageUnavailable() (actool.Result, bool) {
	if t.rtStage() == nil {
		return actool.Errorf("受管暂存服务未启用（POJUN_STAGE_DISABLED 生效或初始化失败），无法投递文件"), true
	}
	return actool.Result{}, false
}

// stageShare 把工作区里的文件交给受管暂存服务，返回 token 下载 URL。
func (t *ToolSet) stageShare() actool.CoreTool {
	return writeTool(
		"stage_share",
		"把工作区里已生成的文件（自编译工具、payload、脚本）交给平台【受管暂存服务】，返回一个随机 token 下载 URL（/s/<token>/<name>，无法列举目录）与过期时间，供目标机用 curl/wget 拉取。"+
			"硬 TTL 默认 15 分钟（ttl_minutes 可调，上限 120），到期自动销毁；one_shot=true 时目标首次**完整**下载后立即即焚（适合一次性 payload）。"+
			"【只用于向目标投递工具/payload】——不要用它传战利品、凭据或证据（那些走会话读取 / evidence）。"+
			"返回的 URL 主机是平台自身监听地址；目标不可达该地址时，按目标可达的平台地址替换主机部分（路径与 token 不变）。",
		obj(map[string]any{
			"path":        str("要投递的本地文件绝对路径（工作区里已生成的工具/payload）"),
			"ttl_minutes": intp("存活分钟数，默认 15，上限 120"),
			"one_shot":    map[string]any{"type": "boolean", "description": "true = 目标首次成功完整下载后立即销毁（默认 false）"},
		}, "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := t.stageUnavailable(); un {
				return r, nil
			}
			var a struct {
				Path       string `json:"path"`
				TTLMinutes int    `json:"ttl_minutes"`
				OneShot    bool   `json:"one_shot"`
			}
			_ = json.Unmarshal(in, &a)
			path := strings.TrimSpace(a.Path)
			if path == "" {
				return actool.Errorf("path 为必填参数"), nil
			}
			// 任务归属从运行时权威注入，不接受模型传 task_id（否则可把投递记到别人的
			// 任务账上，审计链就断了）。
			taskID := RunInfoFrom(ctx).TaskID
			e, err := t.rtStage().PutFile(path, stage.PutOpts{
				TTL:     time.Duration(a.TTLMinutes) * time.Minute,
				OneShot: a.OneShot,
				TaskID:  taskID,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			note := "目标机用 curl/wget 拉取该 URL；到期或（开启 one_shot 时）首次完整下载后自动销毁。" +
				"URL 主机为平台监听地址，目标不可达时按目标可达地址替换主机部分，路径与 token 不变。"
			if t.rtStage() != nil && !strings.HasPrefix(e.URL, "http") {
				note = "当前未配置对外基址（POJUN_STAGE_BASE_URL 或启动 -addr），返回的是相对路径；" +
					"拼上目标可达的平台地址后即可使用。" + note
			}
			return jsonResult(map[string]any{
				"url":        e.URL,
				"name":       e.Name,
				"expires_at": e.ExpiresAt.Format(time.RFC3339),
				"one_shot":   e.OneShot,
				"size":       e.Size,
				"task_id":    e.TaskID,
				"note":       note,
			})
		},
	)
}

// stageListTool 看当前存活条目（只读）：投递之后确认 token 还在、还剩多久、
// 目标是否已经拉过。执行侧常需要它来判断「是不是该重新投一次」。
func (t *ToolSet) stageListTool() actool.CoreTool {
	return readTool(
		"stage_list",
		"列出当前存活的受管暂存条目（token、文件名、大小、过期时间、已完整下载次数、已写出字节）。用于确认投递的 URL 是否仍有效、目标是否已拉取；只想看自己任务的条目时传 task_only=true。",
		obj(map[string]any{
			"task_only": map[string]any{"type": "boolean", "description": "true = 只看本任务投递的条目（默认 false：全部条目）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := t.stageUnavailable(); un {
				return r, nil
			}
			var a struct {
				TaskOnly bool `json:"task_only"`
			}
			_ = json.Unmarshal(in, &a)
			taskID := RunInfoFrom(ctx).TaskID
			items := t.rtStage().List()
			out := make([]map[string]any, 0, len(items))
			for _, it := range items {
				if a.TaskOnly && it.TaskID != taskID {
					continue
				}
				out = append(out, map[string]any{
					"token":        it.Token,
					"name":         it.Name,
					"size":         it.Size,
					"url":          it.URL,
					"expires_at":   it.ExpiresAt.Format(time.RFC3339),
					"one_shot":     it.OneShot,
					"hits":         it.Hits,
					"bytes_served": it.Bytes,
					"task_id":      it.TaskID,
				})
			}
			return jsonResult(map[string]any{"count": len(out), "items": out})
		},
	)
}
