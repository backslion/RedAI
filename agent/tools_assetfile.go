package agent

// 表格文件批量导资产（移植自 reArtex 的 E2-5 能力）。
//
// 甲方场景的常态是「给一份资产清单 xlsx」而不是一个个域名让人敲：把文件内容
// 解析成 host/IP，逐条走 db 层 Upsert（域名合法性校验在 db 层兜底），并自动
// 关联到当前任务——这样「文件里的资产」有正规通路，不会出现把文件名
// `baidu-src.xlsx` 当成域名塞进 insert_assets 的事故。

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/chu0119/pojun/db"

	actool "github.com/Autumn-27/norma/tool"
)

// importAssetsFromFile 从工作区的 xlsx/csv 文件提取真实资产并入库。
// 解析器见 assetfile.go（零第三方依赖）。
func (t *ToolSet) importAssetsFromFile() actool.CoreTool {
	return writeTool("import_assets_from_file",
		"从 xlsx/csv 文件提取资产（域名/IP/URL）并登记到当前任务。传文件的工作区绝对路径（上传文件在 <工作区>/uploads/ 下）。"+
			"文件名本身不是资产——本工具解析文件【内容】；解析出的每条都会过域名校验。返回 imported/skipped 计数与样例。\n"+
			"何时用：甲方给了资产清单/备案表/子域导出，或你从 ScopeSentry 等功能导出了表格时——别手工逐条 insert_assets。",
		obj(map[string]any{
			"path": str("xlsx/csv 文件的工作区绝对路径"),
		}, "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			path := strings.TrimSpace(a.Path)
			if path == "" {
				return actool.Errorf("path 不能为空"), nil
			}
			if t.as == nil {
				return actool.Errorf("资产存储不可用"), nil
			}
			hits, err := ParseTabularHosts(path)
			if err != nil {
				return actool.Errorf("解析失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return actool.Errorf("文件里没有解析出任何域名/IP——确认列里是资产本身而不是描述文字"), nil
			}
			imported, skipped := 0, 0
			sample := []string{}
			skippedNotes := []string{}
			for _, h := range hits {
				switch h.Kind {
				case "ip":
					if _, err := t.as.UpsertIP(db.UpsertIPReq{IP: h.Host, TaskID: t.taskID}); err != nil {
						skipped++
						if len(skippedNotes) < 5 {
							skippedNotes = append(skippedNotes, h.Host+": "+err.Error())
						}
						continue
					}
				default: // domain | url → subdomain（副作用自动建根域，域名校验在 db 层）
					if _, err := t.as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: h.Host, TaskID: t.taskID}); err != nil {
						skipped++
						if len(skippedNotes) < 5 {
							skippedNotes = append(skippedNotes, h.Host+": "+err.Error())
						}
						continue
					}
				}
				imported++
				if len(sample) < 10 {
					sample = append(sample, h.Host)
				}
			}
			t.writes.Assets += imported
			return jsonResult(map[string]any{
				"imported": imported, "skipped": skipped, "sample": sample, "skipped_notes": skippedNotes,
				"note": "已关联当前任务；根域名由子域名副作用自动补建",
			})
		})
}
