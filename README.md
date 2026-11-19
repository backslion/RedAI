<div align="center">

<img src="screenshots/redai-logo.png" width="96" alt="RedAI"/>

# REDAI

**AI 自主渗透测试平台,基于Pojun项目的二次开发 · 从一句话目标到可交付漏洞报告**

> REDAI，北斗第七星，主杀伐、主变局。<br/>
> 找到防线的破口，并把破口证明给你看。

[![Release](https://img.shields.io/github/v/release/backslion/RedAI?label=%E7%89%88%E6%9C%AC&color=red)](https://github.com/backslion/RedAI/releases)
[![CI](https://github.com/backslion/RedAI/actions/workflows/ci.yml/badge.svg)](https://github.com/backslion/RedAI/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-lightgrey)
![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white)

**Go 单体后端** · **Next.js 内嵌前端** · **PostgreSQL** · **多 Agent 自主推进** · **全程证据留痕**

📦 [一条命令安装](#快速开始)

</div>

---

## 快速开始

> 依赖 **PostgreSQL**（安装脚本/Compose 自动处理）；探索需在 UI 里配置 **LLM**
> （Anthropic / OpenAI / 任意兼容网关，多通道轮询）。详细安装方式、系统选择、
> 公网部署与升级 → [安装详解](#安装详解)。

**Linux（Debian / Ubuntu / RHEL / Kali 等，root 执行，全自动交互安装）：**

```bash
curl -fsSL https://github.com/backslion/RedAI/releases/latest/download/install.sh | sudo bash
```

**macOS 13+（Apple Silicon / Intel，一条命令，不需要 sudo）：**

```bash
curl -fsSL https://github.com/backslion/RedAI/releases/latest/download/install.sh | bash
```

自动完成：Homebrew 检测（没有就装）→ PostgreSQL 16 安装与服务化 → 下载并
校验 darwin 包 → 生成 config.json → 注册 launchd 用户级服务（开机自启 +
崩溃自动拉起）→ 健康检查。渗透工具与 LibreOffice 等 `brew install` 按需装
（缺失工具在「宿主环境」页如实显示），详见[安装详解](#安装详解)。

**Windows / 已有 Docker（工具链全在镜像里，宿主机零安装）：**

```bash
git clone --depth 1 https://github.com/backslion/RedAI.git redai && cd redai
cp .env.example .env    # Windows 用 copy；至少改 POSTGRES_PASSWORD
# Windows（Docker Desktop，WSL2 后端）：
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
# macOS（Docker Desktop / OrbStack）：
docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d
# Linux / 其他：
docker compose up -d
# → http://localhost:8787
```

**装好之后（3 分钟上手）：**

1. 浏览器打开 `http://<host>:8787` → 初始化管理员密码（≥8 位）
2. 「LLM 配置」页配模型通道（≥2 个通道 + 开启轮询 = 实战推荐）；Anthropic/OpenAI/
   DeepSeek 等 OpenAI 兼容端点直接填 base_url + key + model（如 DeepSeek：
   `https://api.deepseek.com` + `deepseek-chat`/`deepseek-reasoner`）
3. 「宿主环境」页一键装齐工具（Docker 镜像已内置全部 66 件，可跳过）
4. 新建任务，给一句话目标

---

## 目录

| | |
|---|---|
| **🚀 部署** | [安装详解](#安装详解) · [配置速查](#配置速查) |
| **📸 产品** | [界面速览](#界面速览) · [核心能力](#核心能力) · [系统架构](#系统架构) · [与同类项目的差异](#与同类项目的差异) |
| **🧰 资产与纪律** | [内置资产清单：技能 / MCP / 工具](#内置资产清单技能--mcp--工具) · [实战纪律与安全边界](#实战纪律与安全边界) |
| **👥 参与** | [开发与贡献](#开发与贡献) · [文档索引](#文档索引) · [来源声明](#来源声明) · [许可与免责声明](#许可与免责声明) |

---

## 这是什么

RedAI 是一套 **LLM 多 Agent 自主渗透测试平台**：给一句话目标，它自动完成
「目标拆解 → 侦察 → 漏洞挖掘 → 利用 → 后渗透 → 报告」全流程，人随时可以插手纠偏。

它不是一个「包一层 API 的扫描器」。RedAI 的核心设计是**让 AI 像一个守纪律的渗透测试工程师一样干活**：

- **目标闸门**——每个目标必须带可核验的验收标准（如「未授权接口不带凭据返回 200 且
  含业务数据」「越权请求能读取到非本人对象的完整字段」），
  全部目标经证明达成才允许任务收官；未完成就标「未完成」，报告里如实呈现，绝不假装跑完了。
- **证据闸门**——critical/high 漏洞必须附可机械复现的证据（HTTP 状态码、命令命中输出、
  流量对比），纯版本匹配的「可能存在」进不了交付报告。
- **自主续跳**——确认漏洞 ≠ 完成意图。发现 high/critical 只到「漏洞存在」时，平台自动派发
  下一跳利用链意图（凭据→横向、注入→dump→登录、上传→webshell），推进到 L4 数据/资金影响层。
- **全程留痕**——所有 HTTP/S 流量过 MITM 代理逐请求留存，发现绑定流量证据，
  每一步 activity 可回放，「这个结论是怎么得出的」全程可回溯。

单机实测基线（真实授权项目数据，Kali 部署）：12 个任务、56,000+ 次工具调用、
**295 个确认漏洞**（严重 28 / 高危 140）、2,752 个资产节点，全程无人值守。

---

## 界面速览

> 以下截图来自真实运行实例，目标域名、企业名称、IP 与漏洞细节均已脱敏。

**全局态势**

| 控制台登录：首次启动初始化管理员，防爆破锁定 | 总览：任务 / 发现 / 资产 / Token 全局态势与趋势 |
| :---: | :---: |
| ![登录](screenshots/redai-login.png) | ![总览](screenshots/redai-dashboard.png) |

**任务执行**

| 任务列表：目标进度与漏洞分布一屏可见 | 任务详情：多 Agent 会话，planner 态势研判实时可见 |
| :---: | :---: |
| ![任务列表](screenshots/redai-tasks.png) | ![任务详情](screenshots/redai-task-detail.png) |

| 任务总览：目标逐条带验收标准，达成状态诚实呈现 |
| :---: |
| ![任务总览](screenshots/redai-task-overview.png) |

| 目标管理与操作约束：目标逐条勾选达成，allow/deny 约束直接约束 planner 派单 |
| :---: |
| ![目标管理与操作约束](screenshots/redai-task-goals.png) |

**发现与证据**

| 发现：跨任务漏洞汇总，按严重度统计 | 漏洞详情：摘要 + 复测命令 + 证据 PoC + 状态卡 |
| :---: | :---: |
| ![发现](screenshots/redai-findings.png) | ![漏洞详情](screenshots/redai-finding-detail.png) |

| 资产台账：企业 → 根域名/IP/子域/服务/接口 全量登记 | 资产覆盖图：力导向布局，已测节点高亮 |
| :---: | :---: |
| ![资产](screenshots/redai-assets.png) | ![资产覆盖图](screenshots/redai-assets-graph.png) |

| 全局流量代理：所有 HTTP/S 往来逐请求留存 |
| :---: |
| ![流量](screenshots/redai-traffic.png) |

**平台配置**

| 漏洞情报运营：42 万 CVE / KEV 在野利用 / PoC 仓库持续同步 | 技能库：22 个内置方法论技能，按需加载 |
| :---: | :---: |
| ![漏洞情报](screenshots/redai-vulnintel.png) | ![技能库](screenshots/redai-skills.png) |

| MCP 预设：FOFA 测绘 / Playwright / Burp 等一键接入 | Agent 角色：按角色配模型与可见性 |
| :---: | :---: |
| ![MCP](screenshots/redai-mcp.png) | ![Agent](screenshots/redai-agents.png) |

| LLM 配置：多通道轮询 / 熔断 / 故障转移 | 宿主环境：66 件工具体检 + 一键装齐 |
| :---: | :---: |
| ![LLM](screenshots/redai-llm.png) | ![宿主环境](screenshots/redai-hostenv.png) |

| 监听器 / C2：反弹 shell 回连接收与出口管理 | 对话工作台：跨 Agent 对话与工具触发回放 |
| :---: | :---: |
| ![C2](screenshots/redai-c2.png) | ![对话](screenshots/redai-chat.png) |

| 系统设置：目标收尾 / 写回守卫 / 跨任务去重等开关 | 领域工具：agent 可调用的平台工具清单与开关 |
| :---: | :---: |
| ![设置](screenshots/redai-settings.png) | ![工具](screenshots/redai-tools.png) |

---

## 核心能力

### 1. 多 Agent 自主推进

```mermaid
sequenceDiagram
  autonumber
  participant EV as 图变更(800ms 防抖)
  participant P as planner（每轮新会话）
  participant FR as frontier 意图队列
  participant W as worker ×N
  EV-->>P: 唤醒（边沿/心跳）
  P->>FR: add_intent 派 0..4 个意图（带锚定资产）
  W->>FR: CAS 领取意图
  W->>W: 真实工具执行（全部过 MITM 留痕）
  W->>EV: 写回 fact/asset/finding + 每步 activity
  EV-->>P: 图变更 → 下一轮（闭环）
```

- **planner** 是唯一意图生成者，持有一份跨唤醒共享的 todolist——串行利用链
  （注入点→凭据→横向）记录一次、按依赖逐步派发，不重复不错序。
- **worker** 做完一条意图即停；结果写回双图后自动唤醒 planner。
- **mainagent** 接管对话、报告补写、工具触发的即时任务（如复测提醒）。
- **人在环路**：对话纠偏 / 意图暂停取消 / 人工审批 / `steer_work` 实时纠偏，
  每步 activity 在 UI 内联可见。
- 多层韧性：空转收场（nudge 3 轮 + prevent 5 轮 + 取消原因落库）/ 拆解墙钟 /
  规划轮超时 / 瞬时故障自动重跑——免费限流通道也能稳定跑完任务。

### 2. 目标管理：完成判定不可被绕过

- `set_goals` 支持每条目标带 `criteria`（可核验验收标准），目标拆解提示词强制
  产出 criteria（如「未授权接口匿名返回 200 且含业务字段」「越权对照能稳定
  读到非授权对象」），禁止把「发现/验证漏洞」这类过程写成最终目标。
- **`goal_met` 闸门**：还有目标未 `met` 时，整体收官直接被拒绝（附未达成目标 id）。
- **诚实终态**：只有全部目标达成才落 `done`；有未达成目标时，无论超时 / 自动空转 /
  覆盖度收尾，终态一律 `timeout`（未完成），列表/详情/报告三处如实标注 `x/y 目标`。
- Word/Markdown 报告新增「目标达成情况」小节，逐条列出已达成/未达成及验收标准。

### 3. 执行面：原生执行器 + 会话复用 + 后台作业

| 能力 | 说明 |
|---|---|
| `http_request` | 原生 HTTP 执行器：方法/头/体/重定向/超时可控，自动过 MITM 留痕 |
| `session_login` | 五形态登录（表单/JSON/Basic/Bearer/自定义），任务级 cookie jar 与 curl 互通 |
| 会话复用 | `http_request(session=同名)` 自动带登录态；双身份对照做越权零成本 |
| `poc_scaffold` | 按类别（sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race）生成可运行 Python 验证骨架 |
| `java_poc_scaffold` | 组件专用骨架：Shiro-550（deleteMe/AES/key）、Fastjson（@type）、Log4j2（${jndi:...}）、反序列化（Java/PHP/Pickle magic）；回调需 `oast_check_url`，错误特征不写成 RCE |
| `job_start/status/output/stop` | 后台作业：长扫描/爆破放后台跑，run 结束进程继续，结果随时取回 |
| `save_script` / `run_script` | 任务级共享脚本目录：一次编写，全任务复用 |

### 4. 攻击链续跳：确认漏洞之后继续走

- `report_finding` 回执带 `chain_intent_id`——平台按漏洞类别自动派发继任意图：
  - SQL 注入 → 数据外带验证 → 登录态获取 → 后台横向
  - 文件上传 → 落地验证 → webshell 能力边界确认
  - 未授权接口 → 越权对照 → 数据面影响评估
- worker 纪律（代码注入提示，不受前端词表编辑影响）：确认漏洞 ≠ 完成意图；
  按影响层级 L1 信息 → L2 认证/越权 → L3 控制 → L4 数据/资金 推进；
  判「不可利用」前必须换过 ≥2 种本质不同手段并留下失败输出。
- **续跳对 11 个维度全覆盖**：`recon→authz`、`data-export→lateral`、
  `lateral→privesc` 之前是断点——「横向移动成功」这条最高价值的高危 finding
  恰好没有下一跳，内网纵深打完第一层就停。`data-export→lateral` 的目标文案
  带终止条件（无内网入口则记录并结束），避免纯 Web 任务为空转的横向意图烧预算。

### 5. 漏洞去重与合并：一份漏洞一份真相

- **多键去重**：每条 finding 带 cve / root / endpoint / param 强键 +
  asset_class / name 弱键，新上报自动命中合并目标，`merge_count` 计数、
  来源 finding 收进 `finding_updates` 时间线，证据与资产锚点保留并集。
- **跨任务去重**：同资产同漏洞在别的任务已报过时，默认不重复打扰（可关）。

### 6. 写回守卫：范围越界的硬防线

- `record_fact` / `report_finding` 锚定非本任务自有范围的资产时直接拒绝
  （own / source / foreign 三分类，来源任务范围只读共享）。
- planner 侧配套「复核优先」硬尾巴：跨域名归属结论必须先双域取证复核，
  复核不过立即放弃该链——防止一次误报的关联导致整条链跑偏。

### 7. 漏洞情报运营（持续，不是静态知识库）

多数同类产品的情报是「按组件查」；RedAI 做的是「**按时间流**」——
**最近 7 天爆了什么 → 匹配我的资产 → 排进任务**：

- NVD 全量/增量（实测库 42 万+）+ **CISA KEV 在野利用** + GitHub Advisory
  + GitHub PoC 聚合（实测库 1,400+）
- **近期高危快通道**：按发布时间每 30 分钟拉 CVSS≥9.0 或 KEV，几十分钟进库
- **资产指纹→CVE 反向匹配**：同步的 CVE 自动匹配资产 technologies 指纹，
  命中即向任务挂 hint
- **版本区间精确判定**：`search_vulns` 返回 `version_in_range` 三态；
  NVD 不填区间时 GHSA 补（保守判定：解析不出→「可能受影响」）

### 8. 红队作战能力

- **回连接收器**：接住反弹 shell / OOB 回连，逐会话记录来源、时间、捕获内容；
  REST + agent 工具双入口；启停走人工审批。
- **C2 出口三形态**：direct（本机可达）/ SSH 中继托管（无公网+公网中转机，
  断线自动重连）/ manual（已有手工转发）。`listener_start` 返回解析后的
  回连地址，agent 直接填 payload，无需自行判断网络形态。
- **后渗透方法论**：redteam-ops skill 六阶段（落地稳定化→提权→权限保持→凭据
  获取→横向移动→数据获取回传→收尾）+ 证据纪律。
- **凭据台账与复用**：凭据按「身份 × 资产 × 关系」落库，`discovered`（在某处发现）
  与 `verified`（在该资产认证成功）是两条独立关系，跨资产可盘点、内网可单列。
  `credential_reuse_matrix` 自动按端口/URL 选协议验证可达性并回写认证结果，
  防锁定纪律（每组合 1 次、同账号失败 2 次熔断、遇 locked 立即中止）硬编码不可关。
  「功能 → 凭据」页可人工核对与删除；接口只出脱敏投影，明文凭据不下发到浏览器。
- **知识库（两层 RAG）**：甲方文档、历史报告、内部规范、现场取回的配置与日志按
  「全局库 / 任务库」两层入库，分块后由 `knowledge_search` 检索（中文按二元组 +
  词频逆文档频率打分，配了向量模型再加语义重排），报告里能追到出处。任务之间
  互相不可见；全局库只允许 planner 与人类主控写入，避免单任务现场资料污染全局。
  「功能 → 知识库」页可导入、检索、查看原文与配置向量模型。
- **内网拓扑**（任务详情「内网拓扑」页签）：任务范围内的 IP 资产按 `/24` 归成
  网段、同 IP 的多条服务资产合为一个主机节点（端口并集），并标出「已授权 /
  已测 / 实测」。实测边来自运行中隧道**成功**的拨号记录——失败的尝试不画，
  那是「试过但不通」。库存与可达刻意分层：一边是「我知道它存在」，一边是
  「我确实拨通过」，混起来复盘就分不清哪条是猜的。隧道是进程内状态，
  实测边只在本次服务运行期间有效。
- **后渗透工具**：impacket / netexec / evil-winrm / chisel / ligolo-ng /
  proxychains / socat / linpeas / pspy / responder / sqlmap / hydra / hashcat /
  nuclei / ffuf … 66 件在「宿主环境」页一键装齐（特权助手 pojun-hostd 串行排队）。

### 9. 审批与拦截：三层闸门

| 层 | 语义 | 内置规则 |
|---|---|---|
| 明令禁止 `deny` | 任何语境都不可逆且无合法渗透用途——不调模型直接拒 | 10 条 |
| 交 Agent 研判 `judge` | 作用对象取决于上下文（删测试表 vs 删生产表）——命中后走模型裁决 | 13 条 |
| 人工确认 `ask` | 平台能力边界变更（如开监听端口、开内网隧道）——转人工审批 | 5 条 |

- 规则级 timeout 真生效（研判类 90s/allow，硬禁类 30s/deny）；
- 模型裁决**严格 JSON 解析**（解析失败走失败策略，绝不猜）；
- 反注入边界：裁判输入刻意收窄（仅工具名+参数+工作目录），历史不进裁判视野；
- **写回范围守卫**（见 §6）在数据层再兜一道。

### 9.1 访问门控与反测绘（默认关闭）

部署在公网或客户内网时，登录页本身就是一个明确的指纹。门控默认关闭，开启后：

- 未通过的浏览器请求返回 `401` + `Basic realm="nginx"`；扫描器/脚本一律拿到
  **逐字节固定**的 nginx 404 页（连 `Server: nginx` 头都有），认不出这是什么平台；
- 通过一次 Basic 认证后种 HMAC cookie，后续（含静态资源）凭 cookie 放行；
- **只作用于前端页面**：`/api`（Bearer）与 `/s`（capability URL）不受影响；
- 启用：`PUT /api/system/gate {"enabled":true,"user":"…","password":"…"}`；
- 忘密码时的救急通道：设 `POJUN_GATE_USER` / `POJUN_GATE_PASS` 环境变量重启。

反 AI 蜜罐侧同时开了两处收敛：`http_request` 的默认 UA 改为按目标 hash 选取的
真实浏览器 UA 池（同一目标稳定、跨目标分散，但**骗不过 TLS 指纹**）；`honeypot_check`
判定 ≥0.6 的目标会被登记，后续 HTTP 访问逐步减速，累计 8 次熔断。

### 9.2 网段扩权审批（默认关闭）

`task_scope` 原本只是「资产入库的范围判定」，工具调用本身不受它约束——授权范围
退化成统计口径。开启后它变成真正的边界：

- 工具调用的目标 IP 落在任务基线网段之外 → 进入 `ask` 人工审批（与 §9 共用同一
  套审批队列与历史）；
- **批准即扩权**：把该目标所在 `/24`（IPv6 `/48`）写入 `task_scope`
  （`source=manual`），后续同类目标自动放行。按网段而非单主机授权——逐主机授权
  会变成几百次点击，没人会认真看，等于把审批变成走过场；
- **只判 IP/CIDR，不判域名**：agent 正常侦察必须访问搜索与 CDN，按域名卡会误杀；
  任务没有显式网段范围时一律不干预，存量任务零影响；
- 开关 `scope_gate_enabled`（系统设置页 / `PUT /api/settings`）。**默认关**：
  开着会卡住无人值守的任务，单次审批 30 分钟无响应按拒绝收口。

### 10. 全程证据链与交付

- **MITM 记录代理**：worker 的全部 HTTP/S 流量逐请求留存（CA 签发留痕）；
- **发现绑定流量**：finding 绑定 baseline / proof / verification / supporting
  四类流量证据，快照版本化（sha256），报告引用可验证；
- **证据附件**：截图 + Word/Excel/PPT/PDF 取样自动转图归档，任务内隔离、可归属漏洞；
- **报告导出**：专业级 Word（封面·目录·页眉页脚·严重度着色·复测记录·流量证据·
  修复路线图，手写 OOXML 零依赖）+ Markdown + 批量「一漏洞一 docx」zip；
- **对抗式自检**：换身份/换参数顺序/换客户端复现——「确认了才报」。

### 11. 成本与模型路由

- **LLM 三通道轮询**：熔断 + 故障转移 + 用量归因，免费限流通道也能跑完任务
  （实测 2,725M token，缓存命中率 93%）；按角色配模型：planner 强推理 /
  worker 中推理 / judge 便宜档。
- **worker 态势瘦身**：规划专用字段不进 worker 对话；**未测资产按簇排序**
  静态沉底；**http_probe 批量探活**一次往返替代逐条 curl。

### 12. 可观测性：`/api/metrics`

`GET /api/metrics` 输出 Prometheus 文本格式（`text/plain; version=0.0.4`），
手写实现、零第三方依赖。走常规 JWT 鉴权（指标里带工具名与任务规模，属于部署指纹）。

| 指标 | 说明 |
|---|---|
| `pojun_tool_calls_total{tool,result}` | 工具调用次数，result = ok / error / panic |
| `pojun_tool_duration_seconds{tool}` | 工具墙钟耗时直方图（5ms → 60s） |
| `pojun_llm_requests_total{agent,result}` | 模型调用次数，agent = planner / worker / mainagent |
| `pojun_llm_duration_seconds{agent}` | 模型调用耗时直方图（0.5s → 300s） |
| `pojun_llm_first_event_seconds{agent}` | 流式首事件延迟（体感指标） |
| `pojun_tasks{state}` | 任务数（running / paused / done / failed / timeout / queued） |
| `pojun_db_pool_{open,in_use,idle,max_open}{pool}` | 连接池水位；pool = main / intel |
| `pojun_db_pool_wait_{total,seconds_total}{pool}` | 池满排队次数与累计等待时长 |
| `pojun_process_*` | uptime、goroutine 数、堆与 GC |

**两套连接池**：主池（32 连接）承载所有在线路径；漏洞情报的后台批处理（NVD/KEV/
GHSA/PoC 同步写库、同步期重查询、资产联动）走独立池，上限由 `POJUN_PG_BG_POOL`
控制（默认 6，`0` = 关闭隔离、回落主池）。后台池连接带 `application_name=pojun-intel`，
在 `pg_stat_activity` 里可直接区分。`pool="intel"` 序列只在独立池真的建起来时输出——
**没有这条序列就是"当前回落主池"**。建池失败只记一行日志，不影响启动。

埋点只落在两处既有收口上：`guardedTool.Call`（覆盖 domain / SDK / MCP / skill
全部工具）与 `taskLLMRuntime.Stream/Complete`（所有任务 agent 的模型调用）——
只记录、不改变任何返回值。抓取示例：

```yaml
scrape_configs:
  - job_name: pojun
    scheme: http
    authorization: { type: Bearer, credentials_file: /etc/pojun-token }
    static_configs: [{ targets: ["127.0.0.1:8787"] }]
```


---

## 系统架构

### 双图架构：资产图 × 探索图

渗透测试的全部状态拆成两张独立、由锚点缝合的图：

- **资产图**（全局共享）：`root_domain / subdomain / ip / service / app / endpoint`
  六类节点的真值库，跨任务复用；公司归属 + 授权边界（task_scope）挂在这里。
- **探索图**（每任务一份）：`goal → intent → fact / finding` 的推进链，五种边
  （spawns / derived_from / yields / proves / covers）构成**血缘**——「这个发现
  是从哪条线索推出来的」全程可回溯，这是**报告可信度的根基**。

```mermaid
flowchart LR
  subgraph EG["探索图（每任务 · 推进链）"]
    direction TB
    G["goal"] -->|spawns| I1["intent A"]
    I1 -->|yields| F["fact"]
    F -->|derived_from| I2["intent B"]
    I2 -->|yields| FD["finding 漏洞"]
  end
  subgraph AG["资产图（全局 · 真值库）"]
    direction TB
    RD["root_domain"] --> SD["subdomain"] --> SV["service"] --> EP["endpoint"]
  end
  I1 -.->|anchor| SD
  FD -.->|anchor| EP
```

### 一次任务的完整生命周期

```mermaid
flowchart TB
  T["新建任务（一句话目标 + 范围）"] --> GD["目标拆解：LLM 产出 goals + criteria"]
  GD --> LOOP{引擎闭环}
  LOOP -->|"planner 派意图"| FR["frontier 意图队列"]
  FR -->|"CAS 领取"| W["worker ×N 执行"]
  W -->|"fact / asset / finding"| LOOP
  W -->|"high/critical 确认"| CH["攻击链续跳：自动派继任意图"]
  CH --> LOOP
  W -->|"同类漏洞命中"| DD["多键去重：合并进既有 finding"]
  DD --> LOOP
  LOOP -->|"全部目标 met"| DONE["done（可交付）"]
  LOOP -->|"目标未全达 + 触发收尾"| TO["timeout（未完成，如实标注）"]
  DONE --> REP["Word / Markdown 报告 + 目标达成情况 + 复测入口"]
```

---

## 安装详解

> 快速上手用上面的[快速开始](#快速开始)就够了；本节是系统选择、四种安装方式、
> 公网部署与升级的完整参考。依赖 **PostgreSQL**；探索需配置 **LLM**（UI 里配，
> 支持 Anthropic / OpenAI / 任意 OpenAI 兼容网关，多通道轮询 + 故障转移）。

### 系统选择与配置要求

| 系统 | 结论 |
|---|---|
| **Debian 12 (bookworm)** | ✅ **首选**：稳定、systemd、PostgreSQL 15 源内、LibreOffice/poppler/uv 齐全 |
| **Ubuntu 22.04 / 24.04 LTS** | ✅ **首选**：与 Debian 同源，长期支持 |
| **Windows 10/11（Docker Desktop）** | ✅ **支持**：WSL2 后端跑 Linux 容器，工具链全在镜像里，见[方式二](#方式二docker-compose-直跑ghcr-已发布镜像)的 Windows 说明 |
| **macOS 13+（Apple Silicon / Intel）** | ✅ **支持**：一条命令安装（install.sh 自动走 brew + launchd，不需要 sudo），见[快速开始](#快速开始)；工具链不全时「宿主环境」页如实显示缺失 |
| Kali | ⚠️ 可用（开箱全套工具），但滚动更新有升级风险，生产环境不建议 |
| RHEL / Rocky / CentOS Stream | ⚠️ 支持（dnf 路径），但 ffuf/sqlmap 新版等工具覆盖少，按需自装 |
| Windows 原生（exe 直跑） | ❌ 不支持：特权助手/工具链/守护脚本均为 Linux 体系，请用 Docker Desktop 或 WSL2 |

**硬件**：最低 2 核 4G / 20G 磁盘（不含工具）；**推荐 4 核 8G / 60G**（含 SecLists
约 2.5G、nuclei 模板、Playwright chromium、LibreOffice）。
**网络**：安装期需访问 GitHub 与 LLM 网关；受限环境用 `--install-proxy`。
**Python**：内置 FOFA MCP 需要 Python ≥ 3.10（不影响主服务）；`uv` 由安装脚本自动准备。

### 方式一：一条命令，全自动交互安装（推荐 · 仅 Linux）

在**全新 Linux 服务器**（Debian/Ubuntu/CentOS/RHEL/Kali 等）上以 root 执行：

```bash
curl -fsSL https://github.com/backslion/RedAI/releases/latest/download/install.sh | sudo bash
```

脚本会交互式问你（直接回车用默认值）：

1. **部署形态**：二进制（推荐，systemd + 系统 PostgreSQL）或 Docker；
2. **出网代理**（可选）：apt / GitHub 下载受限时填 `http://host:port`；
3. 然后自动完成：装依赖（PostgreSQL / LibreOffice / poppler / ImageMagick / 字体等）
   → 建运行用户与目录 → 初始化数据库 → 装 systemd 服务
   → 首次启动 → 打印访问地址与初始账号。

常用非交互姿势：

```bash
# 全默认（二进制、直连）
curl -fsSL https://github.com/backslion/RedAI/releases/latest/download/install.sh | sudo bash -s -- -y
# 带代理 + 顺装常用渗透工具
curl -fsSL .../install.sh | sudo bash -s -- --install-proxy=http://10.0.0.14:7897 --with-tools
# Docker 形态
curl -fsSL .../install.sh | sudo bash -s -- --mode=docker
```

幂等：重复执行 = 原地升级；`config.json` / `jwt.key` / 数据 / 数据库不动。
卸载：`systemctl disable --now pojun pojun-hostd && rm -rf /opt/pojun`。

### 方式二：Docker Compose 直跑（ghcr 已发布镜像）

已经会用 Docker 的话，不需要 install.sh：

```bash
git clone --depth 1 https://github.com/backslion/RedAI.git redai && cd redai
cp .env.example .env      # 至少改 POSTGRES_PASSWORD；POJUN_TAG 可钉到具体版本（如 v0.4.64）
docker compose up -d      # → http://localhost:8787
```

**Windows（Docker Desktop，WSL2 后端）**：

```powershell
git clone --depth 1 https://github.com/backslion/RedAI.git redai; cd redai
copy .env.example .env    # 至少改 POSTGRES_PASSWORD
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
# → http://localhost:8787
```

- Windows 加 `-f docker-compose.windows.yml` 的原因：data 卷改为 named volume
  （NTFS bind mount 的小文件 I/O 实测慢约两个数量级，流量/证据写入会明显变卡），
  并预映射回连端口 4444-4450；
- **回连接收器**：容器内 direct 模式解析出的 LHOST 是容器网段 IP，外部目标连不到——
  在「监听器 / C2」页把出口形态设为 **manual**、地址填 Windows 宿主机的局域网 IP
  （`ipconfig` 查看），监听端口与映射端口 1:1 对应；Windows 防火墙放行对应端口；
- 数据备份：`docker run --rm -v <项目名>_pojun-data:/data -v "%cd%:/backup" alpine tar czf /backup/pojun-data.tgz -C /data .`；
- 其余与 Linux 相同：镜像内置全部渗透工具 / LibreOffice / Playwright，无需在
  Windows 宿主机安装任何工具链。建议 Docker Desktop 分配 ≥8G 内存。

- 镜像 `ghcr.io/backslion/redai`，amd64/arm64 双架构，`POJUN_TAG` 默认 `latest`；
  渗透工具随镜像内置（与二进制 `--with-tools` 同一套）：nmap / masscan /
  sqlmap / hydra / whatweb / nikto / ffuf / john / impacket / socat /
  proxychains / nuclei / httpx / subfinder / naabu / dnsx / katana / tlsx /
  notify / interactsh / gitleaks / chisel / amass / dalfox / feroxbuster /
  gobuster / wafw00f / semgrep / pwntools / SecLists 字典 /
  Playwright + chromium / LibreOffice / poppler / ImageMagick / 公文字体；
- 数据落 `./data`（宿主机可直接查看/备份），数据库在 `pgdata` 卷；
- 升级：`docker compose pull && docker compose up -d`；卸载：`docker compose down -v`；
- 回连端口映射示例见 `docker-compose.yml` 注释（reverse shell 需放开对应端口）。

### 方式三：下载预编译包（Linux / macOS，amd64 与 arm64）

到 [Releases](https://github.com/backslion/RedAI/releases) 下载对应平台包
`pojun-<版本>-<平台>-<架构>.zip`（附 SHA256SUMS），解压后：

```bash
cp config.example.json config.json   # 填好 database 连接
./start.sh                           # → http://localhost:8787
```

> 用 `start.sh` 启动而非直接跑二进制——它是守护脚本，「一键更新」靠它完成换装
> （macOS 上的页面一键更新同样可用，按平台自动匹配发布包）。

**macOS 补充说明：**

macOS 也可以用 install.sh 一条命令安装（见[快速开始](#快速开始)）——脚本自动走
Homebrew + launchd，与 Linux 同款体验；下面的手动方式适合不想装 Homebrew 或
想精细控制各依赖的场景。

- 依赖自装：`brew install postgresql@16 libheif poppler libreoffice` 并启动 PostgreSQL；
  Node ≥ 20（Playwright MCP）与 `uv`（FOFA MCP）按需安装；
- 渗透工具链（nmap/sqlmap/nuclei 等）用 `brew install` 按需装，没有的工具
  「宿主环境」页会如实显示缺失——agent 会绕开缺失工具改用可用的；
- 特权助手 `pojun-hostd` 与批量装工具是 Linux 体系，macOS 上不可用（影响：
  「一键装齐」按钮不可用，其余功能完整）；
- `masscan`/`nmap -sS` 等特权扫描需要 root/sudo，与 Linux 同理。

### 方式四：从源码编译

```bash
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o pojun ./cmd/redai
CGO_ENABLED=0 go build -o pojun-hostd ./cmd/redai-hostd   # 可选：特权安装助手（Linux）
./start.sh
# 交叉编译其他平台示例（macOS Apple Silicon）：
# CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags embedui -o pojun-darwin-arm64 ./cmd/redai
```

### 公网部署

内置公网部署安全基线（登录防爆破、探活去指纹、改密吊销会话、认证面无产品名）。
必须：HTTPS 反代 + 覆写 `X-Forwarded-For`。完整基线见
[docs/公网部署安全加固-2026-10-29.md](docs/公网部署安全加固-2026-10-29.md)。

### 升级

**页面一键更新**（系统配置 → 版本与更新）：下载 → SHA256 校验 → 冒烟测试 →
原子换装 → 失败自动回滚到上一版。升级只换程序不动数据，schema 幂等迁移。

---

## 配置速查

**数据库**（`config.json` 或 `POJUN_PG_DSN`）：

```json
{ "database": { "host": "127.0.0.1", "port": 5432, "user": "pojun",
                "password": "…", "dbname": "pojun", "sslmode": "disable" } }
```

**LLM**：环境变量 `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` 可兜底，UI「LLM 配置」页
配多通道 + 开启「LLM 轮询」。常用参数：`./start.sh -addr :8787 -proxy :8788`。

**C2 出口**（可选）：`PUT /api/c2/config` 配 `mode=direct|ssh|manual` +
中转机地址/SSH 凭据——`listener_start` 自动返回解析后的回连地址。

**反向代理（HTTPS）**：前端和 API/SSE 同源，反代必须关缓冲。Nginx 示例：

```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 限流依赖
        proxy_buffering off; proxy_read_timeout 3600s;               # SSE 必需
        proxy_http_version 1.1; proxy_set_header Connection "";
    }
}
```

---

## 内置资产清单：技能 / MCP / 工具

**25 个内置技能**（按意图场景自动路由，默认绑定到对应角色）：

| 领域 | 技能 |
|---|---|
| 综合方法论 | vuln-hunting（未知面挖掘）/ attack-surface-recon（侦察）/ pentest-output-standards（报告规范） |
| Web 与 API | web-attack-methods / api-security-testing / api-recon |
| 内网与凭据 | intranet-pivot（OOMA 纵深 SOP + 4 个纯 Python 脚本）/ credential-reuse（凭据复用矩阵） |
| 专项 | cloud-security / windows-ad / source-code-audit / llm-security / mobile-reverse / apk-reverse / contract-audit / wireless |
| 红队后渗透 | redteam-ops（六阶段方法论）/ opsec |
| SRC 知识库 | src-hunting（48 篇测试知识 + 11 篇流程规则，按需加载） |

**内置工具补充（v0.5.x 跨分支移植，纯 Go 零外部二进制）**：

- **打点绕防**：`waf_probe`（WAF 指纹 + 变形穿透差分）/ `ssrf_probe` / `http_login_check`
- **技术栈指纹**：`web_fingerprint`（响应头 + Cookie + meta generator + 静态资源路径 + 默认错误页 + 8 条身份确认路径，产出 CPE 风格的 product/vendor/version 与拼好的 `search_vulns` 调用；附 favicon 的 mmh3 icon_hash，可直接拿去 FOFA/Shodan 反查同族资产）。8 条路径探针带随机基线 + 响应体特征词双重校验，SPA / 软 404 兜底站点不会全站误报）
- **内网纵深**：`expand_cidr` / `tcp_probe` / `nbns_probe` / `subdomain_probe` / `dir_probe`
- **凭据与域**：`ssh_check` / `smb_check`（SMB2+NTLMv2 手写）/ `db_check`（Redis·MySQL·PostgreSQL）/ `asrep_roast`（Kerberos DER 手写）/ `ldap_enum`
- **凭据库**：`record_credential`（登记发现）/ `mark_credential_verified`（标记认证成功）/ `list_credentials`（凭据 × 资产平表盘点）/ `credential_reuse_matrix`（自动选协议批量验证并把成功结果回写 `verified`，内置防锁定熔断）
- **反蜜罐**：`honeypot_check`（Cowrie / OpenCanary / Kippo / HFish 等签名库打分）
- **批量导资产**：`import_assets_from_file`（xlsx / csv 直读）
- **知识库**：`knowledge_search`（全局 + 本任务混合检索）/ `knowledge_add`（原文入库，或给 URL 由服务端抓取去标签）/ `knowledge_list`（盘点可见文档）
- **受管投递**：`stage_share`（把工作区里编译好的工具/payload 换成随机 token 下载链接，硬 TTL 默认 15 分钟、可设一次性即焚）/ `stage_list`（确认链接是否还有效、目标是否已拉取）
- **内网穿透**：`pivot_open`（用已控主机的 SSH 建 SOCKS5 / 端口转发通道，支持最多 4 跳跳板链，目标机不落任何二进制）/ `pivot_probe`（经跳板机代拨探测内网端口，nmap 不走 SOCKS5）/ `pivot_list` / `pivot_close`
- **WebShell 通道**：`webshell_payload_list` / `webshell_payload_get`（内置 4 个最小载荷 + 自备库覆盖，可按参数名渲染）/ `webshell_add`（登记已落地的马）/ `webshell_list` / `webshell_exec`（自动识别 eval / base64 两种载荷模式）/ `webshell_upload` / `webshell_download`（PHP 分块、带回执）/ `webshell_probe`（区分「连不上」与「不是我的马」）/ `webshell_remove`（默认只摘登记，`remove_remote` 才动远端，删后复查）

> 凭据分 `discovered`（发现）与 `verified`（认证成功）两种关系，存于
> `asset_credentials` / `asset_credential_links` 两表；secret 不出现在任何读取投影里，
> 唯一读取入口是 `auth_request` 组命令时。升级时 `assets.auth` 会被自动回填。

> 知识库存于 `knowledge_docs` / `knowledge_chunks` 两表，`task_id` 为空即全局库。
> 向量以 JSONB 存放、余弦在 Go 里算，**不依赖 pgvector**；没配向量模型时自动退化为
> 纯关键词检索，中英文都能命中。

> 内网穿透走 SSH 的 `direct-tcpip` 通道，**不在目标机落 chisel/suo5 二进制**：多跳时第 N+1
> 跳的连接建在第 N 跳的通道上，中间主机不需要出网也不需要装客户端。入口默认只绑
> `127.0.0.1`（只有本平台能用），要对外开放必须同时设 SOCKS5 用户名口令（后端强制）。
> curl 打内网用 `--socks5-hostname`（`--socks5` 会本地解析域名）+ `--noproxy ""`
> （环境里的 `NO_PROXY=127.0.0.1` 会让请求看起来通了其实没走隧道）。
> 隧道有硬 TTL（默认 2 小时、上限 8 小时），`pivot_list` 能看到每条连接的目标、字节与
> 失败原因；收尾必须 `pivot_close`——留着就是一条对内网的长期入口。

> WebShell 通道管的是「目标上那把马」：登记、执行、传文件、查活、清理。会话库落在平台
> 数据目录（`webshells.json`，0600）并**按任务隔离**——跨任务看不到也执行不了。参数名与
> 请求头值不进任何读取投影（它们等价于马的钥匙），执行时才从库里取。删除默认**只摘登记**，
> `remove_remote=true` 才动远端，顺序是「先删上传物 → 最后自删马 → 再请求一次确认打不通 →
> 才摘登记」；远端没清干净会报错并保留登记，要丢弃必须显式 `force`。
> 内置载荷只用于验证链路，**不负责免杀**：要过目标 WAF/EDR 请把自备马放进
> `POJUN_WEBSHELL_PAYLOAD_DIR` 下的 `php/jsp/aspx` 子目录。出口可用 `proxy` 指向
> SOCKS5/HTTP 代理（支持代理池），避免目标日志里直接出现平台 IP——页面上「直连」是
> 一个会被显式标出来的状态，不是默认。
> 平台**不做 OS 层持久化**（cron/systemd/计划任务）：权限维持的立场仍是「演示可行、
> 不部署长期后门」（见 `skills/redteam-ops`），WebShell 通道只负责 Web 层这条通道本身。

> 受管投递的下载路径 `GET /s/<token>/<name>` **免 JWT**——目标机拉 payload 时没有 token，
> 能力 URL 本身就是凭据：24 字节 `crypto/rand`、硬 TTL（15min，上限 2h）、禁目录列举、
> 单 token / 单 IP 双维度限速、错误 token 与过期响应逐字节一致，单条上限 256 MiB。
> 只用于【向外投递工具】，战利品/证据走会话读取。不需要这条口子时设
> `POJUN_STAGE_DISABLED=1` 彻底关闭（`/s/` 一律 404）；对外地址用
> `POJUN_STAGE_BASE_URL` 指定（NAT / 域名场景）。

**10 个 MCP 预设**（一键填充配置）：FOFA 资产测绘（含 one-fox 通道）/ Playwright
浏览器 / Chrome DevTools / Burp Suite / Fetch 网页抓取 / Sequential Thinking /
Memory 知识库 / Filesystem / HexStrike 工具桥（150+ 安全工具桥接）/ Context7 文档检索。

**66 件宿主工具**（体检 + 一键装齐）：网络与主机（nmap/masscan/naabu/tlsx…）、
子域与 DNS（subfinder/dig/amass…）、Web 与 API（httpx/katana/ffuf/dalfox…）、
注入与利用（sqlmap/hydra/hashcat/john…）、后渗透（impacket/netexec/evil-winrm/
chisel/ligolo-ng/socat/proxychains/linpeas/pspy/responder…）、
语料（SecLists 字典 / nuclei 模板）。

---

## 与同类项目的差异

| 维度 | 常见同类 | RedAI |
|---|---|---|
| 完成判定 | LLM 自评「任务完成」即可收官 | 目标 + 验收标准 + `goal_met` 闸门，未全达成强制记未完成 |
| 漏洞可信度 | 扫描器输出直接入库 | 机械验证凭据闸门 + L1-L4 证据分级 + 对抗式自检，critical/high 必须 L3+ |
| 漏洞重复 | 按标题/URL 简单去重 | 多键去重（cve/root/endpoint/param 强键）+ 合并时间线 + 跨任务去重 |
| 深度利用 | 确认漏洞即结束 | 攻击链自动续跳（维度→下一跳），L1→L4 影响层级推进纪律 |
| 长任务 | 单轮超时即丢 | 后台作业 + 任务级共享脚本 + 会话复用，run 结束作业继续跑 |
| 流量证据 | 无或截图 | MITM 逐请求留存 + 四类证据绑定 + sha256 版本化 + 报告引用 |
| 情报 | 静态知识库 | NVD/KEV/GHSA/PoC 时间流 + 资产指纹反向匹配 + 高危快通道 |
| 交付 | Markdown | 公文级 Word（封面/目录/复测/流量证据/修复路线图）+ 一漏洞一 docx |
| 成本 | 单通道 | 多通道轮询 + 熔断 + 角色路由 + 缓存命中（实测 93%） |

---

## 实战纪律与安全边界

- **授权优先**：任务创建即声明范围（域名/IP/公司主体），资产图按范围登记，
  写回守卫在数据层拦截越界。
- **最小伤害验证**：SQL 注入探测默认 level 2 / risk 1（只读）；文件上传只验证
  能力不落地后门；登录面 ≤5 组默认口令失败即停；禁止大字典爆破生产系统。
- **审批门**：破坏性命令三层闸门（deny/judge/ask），平台能力边界变更转人工。
- **复测纯手动**：平台不自动触发任何复测动作。
- **凭据卫生**：LLM key / FOFA key 只进运行时配置，不入仓库不入报告。

## 开发与贡献

```bash
./dev.sh    # 后端(:8787) + 流量代理(:8788) + 前端 next dev(:5173)
go test ./...   # 连 PG 跑全量（CI 用 -p 1 串行防跨包死锁）
cd web && npx tsc --noEmit && NEXT_EXPORT=1 npx next build
```

- 后端：`go run ./cmd/redai`（`-tags embedui` 内嵌前端）
- 前端：`cd web && npm run dev`（`/api` 反代热更新）
- Mock 预览：`cd web && NEXT_PUBLIC_MOCK=1 npm run dev`

项目结构：

```
cmd/            程序入口（redai 主服务 / redai-hostd 特权助手 / redai-maint 维护工具）
agent/          多 Agent 层：planner / worker / mainagent / 领域工具（tools_*.go）
db/             PostgreSQL 唯一存储：schema.sql（幂等迁移）+ 全部表 Store
server/         HTTP 服务：路由 / 引擎调度 / Manager / 会话 / 报告 / 更新
intercept/      拦截引擎：规则匹配 → LLM 研判 → allow/ask/deny
guard/          工具调用审批门（把裁决接进 agent 执行链）
listener/       回连接收器：接住反弹 shell / OOB 回连并留证
traffic/        MITM 流量记录代理 + 出口代理池
vulnintel/      漏洞情报：NVD/KEV/GHSA/PoC/快通道/资产联动/限速闸门
hosttools/      宿主工具目录（66 件，按攻击面分类）
hostd/          特权助手：root 常驻 unix socket，装工具/特权操作
llmpool/        LLM 多通道轮询池：熔断/故障转移
llmrec/         LLM 请求录制与 token 计量
report/         报告生成：Word 导出（手写 OOXML 零依赖）
notify/         通知推送：钉钉/飞书/企业微信等
evidence/       发现的证据留存与版本化
enrich/         资产自动补全：DNS / HTTP 探测
selfupdate/     一键自更新：查 Release → 校验 → 换装
skills/         内置 skill：vuln-hunting / redteam-ops / api-recon / …
web/            Next.js 前端（静态导出后 go:embed 内嵌）
docs/           设计文档 / 部署手册 / 能力对照
```

### 发版

版本号只由 tag 决定，不需要改代码里的版本常量。

```bash
# 1. 在 CHANGELOG.md 顶部加一段（CI 找不到这段会拒绝发布）
#    ## [0.4.85] - 2026-11-20
# 2. 提交
git commit -am "feat: ..."
# 3. 一键发版：校验 CHANGELOG / 工作区 / tag 后，打 tag 并推送
./scripts/release.sh 0.4.85
```

推送 tag 即触发 `.github/workflows/release.yml`：交叉编译 linux/darwin ×
amd64/arm64、生成 `SHA256SUMS`、创建 GitHub Release、推送镜像
`ghcr.io/backslion/redai`。Release 说明取自 CHANGELOG 对应版本段；安装命令与镜像
地址按**实际仓库**注入（`${{ github.repository }}`），fork 到别的账号无需改任何文件。

自更新源同理，由 `build.sh` 的 `POJUN_REPO` 在构建期注入。手工构建时没传就用默认值
`backslion/RedAI`——二开成别的仓库时**必须**传，否则你的产物会去上游拉更新，
且因为上游包的 SHA256 校验能过，替换过程不会报任何错。

欢迎 Issue 与 PR：修 bug / 补文档直接提；新功能建议先开 Issue 讨论场景与边界。

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/AI-交接指南.md](docs/AI-交接指南.md) | 机制→代码位置地图、发版流程、测试纪律、已知问题与未决方向 |
| [docs/跨分支能力移植.md](docs/跨分支能力移植.md) | 以 RedAI 为母版吸收其他 ARTEX 分支：差集、改造点、未移植项与验证方式 |
| [docs/01-双图架构.md](docs/01-双图架构.md) | 资产图/探索图、锚点、schema 迁移设计、不变量清单 |
| [docs/02-引擎与调度闭环.md](docs/02-引擎与调度闭环.md) | planner/worker 编排与生命周期 |
| [docs/03-LLM接入层.md](docs/03-LLM接入层.md) | 通道选路、轮询池、熔断、录制计量 |
| [docs/04-审批与拦截.md](docs/04-审批与拦截.md) | 三层规则与裁决链路、反注入边界 |
| [docs/部署手册.md](docs/部署手册.md) | 部署 / 升级 / 排障（实测踩坑全记录） |
| [docs/公网部署安全加固-2026-10-29.md](docs/公网部署安全加固-2026-10-29.md) | 公网部署安全基线 |
| [docs/红队能力建设-2026-10-30.md](docs/红队能力建设-2026-10-30.md) | 杀伤链能力矩阵 / 竞品对照 / 路线图 |
| [docs/漏洞挖掘能力对比.md](docs/漏洞挖掘能力对比.md) | 与开源同类逐项对比 |
| [docs/深度优化方案-2026-10-31.md](docs/深度优化方案-2026-10-31.md) | 报告质感 × Agent 认知 × 攻击链 |
| [docs/模型路由策略.md](docs/模型路由策略.md) | 按角色配模型：planner 强推理/worker 中推理/judge 便宜档 |
| [docs/同行对比分析-2026-11.md](docs/同行对比分析-2026-11.md) | 12+ 同行项目代码级调研与借鉴落地清单 |
| [CHANGELOG.md](CHANGELOG.md) | 逐版本功能更新记录 |

## 来源声明

本项目最初 fork 自己删除的原作者项目
[Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)（百度“Agent+”攻防挑战赛
冠军项目）的最终定版 v0.3.15，原作者代码保留在 git 历史里作为起点。

- **保留**：双图架构、planner/worker 编排、MITM 流量代理、审批门框架、基础
  工具集——原作者的架构设计是优秀的，git 历史向其致意；
- **重建**：全部设计文档、CI 门禁、依赖解耦（norma SDK fork）、Docker 源；
- **独立演进**：v0.3.16 以来 700+ 提交、约 5 万行新增由本仓库维护者完成，
  覆盖情报运营 / 目标闸门 / 攻击链 / 执行面 / 去重合并 / 证据链 / 技能体系等
  整条能力线，与原项目已无代码级关联。

## 许可与免责声明

### 开源协议

**AGPL-3.0**——衍生作品（含网络服务）须同样开源。完整条款见 [LICENSE](LICENSE)。

### 使用限制

**本工具仅供个人学习、代码研究与本地技术验证使用，不得用于对任何线上系统或
网站发起实际测试。** 允许范围：阅读学习源码、本地隔离环境验证。严禁：对任何
线上系统发起扫描/探测/利用（无论是否授权）、实际渗透对抗、生产环境使用、
非法入侵与数据窃取。

使用者须自行遵守所在国家/地区全部法律法规（含《网络安全法》《数据安全法》
《个人信息保护法》等）。**因使用本工具产生的一切法律责任由使用者自行承担。**

本项目按“现状”提供，不附带任何担保。下载、安装或使用即表示已阅读并同意
上述全部条款。

---

## 参考

- [norma](https://github.com/Autumn-27/norma) — agent harness SDK（本平台多 Agent 引擎）
- [SecLists](https://github.com/danielmiessler/SecLists) / [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — 语料与模板
- [FOFA](https://fofa.info) — 资产测绘（内置 MCP 预设）

<div align="center">

**REDAI · RedAI** — 找到防线的破口，并把破口证明给你看。

</div>
