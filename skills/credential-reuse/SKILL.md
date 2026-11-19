---
name: credential-reuse
description: 横向凭据复用一条龙：拿到任何一个凭据（口令/哈希/私钥/token）后，先 record_credential 入库，再用 credential_reuse_matrix 按「凭据 × 入口」在授权资产上系统性验证复用（SSH/SMB/Web/数据库/Redis 自动选协议），命中自动写回 verified 关系，即实证横向移动。涉及弱口令验证、凭据扩散、防锁定纪律时调用本 skill。
---

# Credential Reuse（凭据横向复用一条龙）

**前提**：仅对已授权范围内的资产做凭据验证。操作约束（allow/deny）优先于本 skill 的一切建议。

核心心法：**拿到一个凭据 ≠ 拿到一台机器；在全部入口上验证它才是横向的开始。**
内网里口令复用率极高——一个凭据命中第二台主机，就是最实证、最省步数的横向移动（比新漏洞利用快且稳）。

> 本平台把「凭据」做成了一等公民：凭据存 `asset_credentials` + `asset_credential_links` 两表，
> 关系分 `discovered`（发现）与 `verified`（在该资产上认证成功）。
> **报横向移动类漏洞必须以 `verified` 为依据**，`discovered` 只说明你在某处看到了它。

## 标准流程（Orient → Verify → Spread）

### ① 凭据盘点（Orient）

先用 `list_credentials` 看手上已有什么（按 `relation` / `cred_type` / 仅内网过滤），
再补齐遗漏的凭据源：

- 本机 harvest：`~/.ssh/`、配置文件、`.bash_history`、进程环境、数据库连接串
- 注入/脱库所得：SQL 注入脱出的用户表（用户名 + 哈希 + 明文列）
- 泄露文件：备份包、`.env`、git 仓库、导出文件
- 域环境：`ldap_enum` 拉到账号清单 → `asrep_roast` 出可破解哈希

每发现一条，立刻 `record_credential` 登记（`asset_id` = 发现它的资产，
`cred_type` 写清 password / hash / token / ssh_key，`source` 写清来源）。
**不要只把凭据贴在 fact 里**——不登记就进不了矩阵、也无法盘点。

### ② 复用矩阵（Verify）——每条凭据 × 每类入口

**首选 `credential_reuse_matrix`**：给它 `asset_ids`（必须显式给，不会替你扫全任务），
它按资产端口/URL 自动选协议并逐个验证，把成功组合自动写回 `verified`。

第一次先 `dry_run=true` 看计划范围，确认后再真跑。

| 入口类型 | 底层验证器 | 说明 |
|---|---|---|
| SSH | `ssh_check` | 用户名按目标惯用名展开（ubuntu/root/admin/主机名） |
| SMB/Windows | `smb_check` | 445/TCP；顺带探共享（SYSVOL/NETLOGON 可读=域成员）；状态码 oracle 可枚举账号状态 |
| Web 登录/控制台 | `http_login_check` | 管理后台、OA、数据库管理页；显式 `success_contains` 更稳 |
| 数据库 | `db_check` | mysql / postgres / redis，含 Redis 未授权检测 |
| Kerberos | `asrep_roast` | 88/TCP KDC；未启用预认证账号的哈希离线破解出明文口令 → 回矩阵 |

需要精细控制（自定义私有键、只测单个账号）时，单独调对应验证器，
验证成功后再用 `mark_credential_verified` 手工补写关系（带 `evidence`）。

- **口令变形优先试**：命中过的口令 P，对其它用户先试 {P, P+123, 用户名=P, 用户名+P}——内网常见「一套口令走天下」。
  变形后的凭据要作为新凭据 `record_credential` 登记（不同 secret 是不同身份）。
- **结果对称记录**：成功与失败都 `record_fact`；成功由矩阵自动写 `verified`，
  再对拿下的主机做权限/信息收集、有漏洞则 `report_finding`。
- **跨资产对照用 `auth_request(credential_id=...)`**：凭据登记在 A、要拿它去 B 验证越权时，
  传 `credential_id` 而不是在 B 上重复登记一份。

### ③ 扩散（Spread）

每次命中产生的新立足点 → 回到 intranet-pivot ①（本机 harvest 拿新凭据）→ 新凭据回到本 skill ②。
凭据矩阵随资产增长滚动重验：新增 service 资产后，把已有 `verified` 凭据对它过一遍（成本低、命中即赚）。

## 防锁定纪律（红线）

- `credential_reuse_matrix` 已内置且**不可关闭**：每条凭据在每个目标上只试 1 次、
  同账号累计失败 ≥2 次整体熔断、遇 locked/disabled/429 立即中止、单次上限 40 组合、串行 300ms。
- 单独调验证器时自行遵守同样标准：单次 ≤10 组合（SMB/DB ≤5）；同一账号失败 ≥2 次立即停。
- 出现锁定关键词/429 就停下等冷却或换入口，**不要换工具硬闯**。
- 温和节奏：串行 + 间隔；避开业务高峰；绝不做过载爆破。

## 证据标准

「复用成功」的结论必须带可复核证据：登录后的会话标识（cookie/输出片段）、
执行的一条无害命令回显、或数据库的一条查询结果。仅凭「没报错」不算命中。
`credential_reuse_matrix` 写回的 `verified` 关系里已带验证器原始判定文本，可直接引用。

深入细节（判定标准、反例、域环境）见 `reference.md`。
