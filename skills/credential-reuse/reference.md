# Credential Reuse 深度参考（凭据横向复用 · YCode）

配合 `SKILL.md` 使用：正文给流程，这里给判定标准、展开策略与反例。
一切以授权范围与操作约束（allow/deny）为最高优先。

## 1. 凭据来源→验证入口 对照

| 凭据来源 | 拿到什么 | 第一验证动作 |
|---|---|---|
| SSH 私钥 | id_rsa 等 | `ssh_check` 多用户名试 key（root/ubuntu/admin/deploy + 目标主机名） |
| 配置文件/.env | 明文口令 + 对应服务 | 先打原服务确认有效，再横向到矩阵其它入口 |
| SQL 注入脱库 | 用户名+哈希(+盐) | 常见弱口令本地比对（不在线爆破）；比对出明文再进矩阵 |
| 备份压缩包 | 全套配置/数据库 | 逐条抽凭据进矩阵，别只报「存在备份」 |
| 报错回显/日志 | 偶发凭据 | 置信度低，先在原入口验证，失败不扩散 |
| 内存/环境变量 | API key/token | 对应控制台/接口验证（token 复用不走本 skill 的表单流程） |

## 2. 用户名展开策略（SSH/登录通用）

对每个命中口令 P，目标主机上值得试的用户名集合（按命中率排序）：
1. 原用户名本身（跨主机同账号）
2. 目标主机惯用名：root / ubuntu / admin / test / deploy / git / nginx / mysql
3. 主机名本身（内网常见 hostname=账号）
4. 公司/项目名缩写

## 3. http_login_check 判定细节

- **优先给 success_contains**：登录成功页的稳定串（欢迎语/退出按钮文字/token 字段名）比自动判定可靠。
- **possible 结论必复核**：长度差异/关键词消失只算疑似——换一条路径（登录后独有页面）独立确认。
- **JSON 接口**：content_type=json + 显式字段名；很多接口失败也回 200，此时 success_contains 或状态码差异是唯一依据。
- **验证码/CSSM**：extra_params 里带抓包拿到的 token；验证码挡路时换无验证码的入口或 API。

## 4. 防锁定计算

设目标锁定阈值未知：默认按「最多 2 次失败/账号/窗口」执行。
- http_login_check 单次 ≤10 组合、自动锁定中止 → 已内置
- ssh_check 单账号失败 ≥3 自动 skip → 已内置
- 手工验证（数据库等）自行遵守：每账号每窗口 ≤2 次失败

## 5. 反例（不算命中的情形）

- 登录接口对任何输入都回 200+同一 JSON 结构（未看 data 字段）→ 不算
- SSH 返回 banner 但认证失败样例含 "password expired" → 账号存在，口令需换，不算命中但记 fact（账号枚举结论）
- Redis PING 返回 PONG 但 INFO 被 rename → 未授权只算部分成立，写利用要另行实证

## 6. 域环境（Windows）补充

有 impacket/工具环境时：哈希不落地比对，直接
- SMB：PtH（secretsdump 所得 NTLM）
- WinRM：PtH / 密码
- Kerberos：AS-REP roasting（无预授权账号）→ 离线破解 → 回矩阵
域内拿到任何域账号 → 优先试「同口令域管理员」，命中率意外地高。

## 7. 产出落库映射

| 动作 | 工具/字段 |
|---|---|
| 凭据登记 | `record_credential`（发现）；`mark_credential_verified` / `credential_reuse_matrix`（认证成功→verified） |
| 服务资产挂凭据 | 优先 `record_credential`（凭据库）；`insert_assets` 的 `auth` 字段保留兼容 |
| 横向结论 | record_fact（含证据 + 已试清单） |
| 高危定性 | report_finding（弱口令/未授权/凭据复用，severity 按入口价值定） |
