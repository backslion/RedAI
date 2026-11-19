package server

// 访问门控的配置接口。
//
// 单独成文件而不是塞进 routes_ops.go：门控是安全边界，读写逻辑要能一眼看完。
// 两个端点都走 requireAuth（在 /api/ mux 下），配置本身也需要登录才能改。

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// gateView 是回传给界面的配置投影，**不含任何口令材料**。
type gateView struct {
	Enabled  bool   `json:"enabled"`
	User     string `json:"user"`
	HasPass  bool   `json:"has_pass"`
	Source   string `json:"source"` // db / env / off
	HintText string `json:"hint_text,omitempty"`
}

func (s *Server) getGate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	view := gateView{}
	if v, ok, err := pg.GetSetting(gateEnabledKey); err == nil && ok {
		view.Enabled = v == "1" || v == "true"
	}
	if v, ok, err := pg.GetSetting(gateUserKey); err == nil && ok {
		view.User = v
	}
	if v, ok, err := pg.GetSetting(gatePassHashKey); err == nil && ok && v != "" {
		view.HasPass = true
	}
	view.Source = "db"
	if view.Enabled {
		view.HintText = "已开启：未通过门控的请求只会看到 nginx 404 页"
	} else {
		view.HintText = "未开启：登录页对所有访问者可见"
	}
	writeJSON(w, 200, view)
}

// putGate 保存门控配置。
//
// 语义刻意做成「整份覆盖」而不是部分更新：门控是安全开关，允许只改一半
// （比如只改密码忘了改开关）比要求全量提交更容易配错。
//
// password 为空表示「保持原密码不变」——界面上通常不回显密码，用户只改用户名
// 或开关时不该被迫重输。
func (s *Server) putGate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		Enabled  bool   `json:"enabled"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "参数解析失败: "+err.Error())
		return
	}
	if in.Enabled {
		if in.User == "" {
			// 允许沿用库里已有的用户名。
			if v, ok, _ := pg.GetSetting(gateUserKey); !ok || v == "" {
				writeErr(w, 400, "开启门控必须设置用户名")
				return
			}
		}
		hasPass := false
		if v, ok, _ := pg.GetSetting(gatePassHashKey); ok && v != "" {
			hasPass = true
		}
		if !hasPass && in.Password == "" {
			writeErr(w, 400, "首次开启门控必须设置密码（或设置环境变量 POJUN_GATE_USER/POJUN_GATE_PASS）")
			return
		}
	}
	if in.Password != "" {
		// bcrypt 硬限制 72 字节，超长会被静默截断，这里显式拒绝。
		if len(in.Password) > 72 {
			writeErr(w, 400, "密码超过 72 字节（bcrypt 上限）")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "口令哈希失败: "+err.Error())
			return
		}
		if err := pg.SetSetting(gatePassHashKey, string(hash)); err != nil {
			writeErr(w, 500, "保存口令失败: "+err.Error())
			return
		}
	}
	if in.User != "" {
		if err := pg.SetSetting(gateUserKey, in.User); err != nil {
			writeErr(w, 500, "保存用户名失败: "+err.Error())
			return
		}
	}
	enabled := "0"
	if in.Enabled {
		enabled = "1"
	}
	if err := pg.SetSetting(gateEnabledKey, enabled); err != nil {
		writeErr(w, 500, "保存门控开关失败: "+err.Error())
		return
	}
	// 立刻生效，不等 TTL。
	s.gate.invalidate()
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": in.Enabled})
}
