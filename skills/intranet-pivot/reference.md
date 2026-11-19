# Intranet Pivot 深度参考（内网纵深 · YCode）

配合 `SKILL.md` 使用：正文给链路，这里给细节、判断标准与反例。**一切以授权范围与操作约束（allow/deny）为最高优先。**

## 1. 网段发现：从哪里拿到"要打的内网段"

| 来源 | 命令/方法 | 可信度 |
|---|---|---|
| 立足点路由表 | `ip r` / `route print` | 高——直接给可达网段 |
| 立足点接口 | `ip a` / `ipconfig /all` | 高——本段 + 规划的静态段 |
| ARP 缓存 | `cat /proc/net/arp` / `arp -a` | 高（仅本段，但确定存活） |
| DHCP/租约 | `cat /var/lib/dhcp/*.leases` | 中 |
| DNS 反查区域 | `nslookup`、AXFR 尝试（授权内 DNS） | 中 |
| 配置文件 | 防火墙/负载均衡/备份配置里的网段 | 中 |
| 端口 500/4500/1723/1194 开放 | IPSec/PPTP/OpenVPN 网关迹象 | 低（提示存在 VPN 段） |

反例：只扫了 `/24` 就停——路由表里的 `<IP>`、`<IP>` 段常被遗漏。网段要**从多来源汇总去重**，展开前先 `expand_cidr` 看规模，超过 8192 分段。

## 2. 存活判断标准（减少误判）

- TCP 判活用**多端口并探**（22/135/445/3389/80/443），任一连通即活；只 ping 会漏掉禁 ICMP 的 Windows。
- 全部超时 ≠ 主机不存在：可能只开了非常规端口。高价值目标（域控/数据库段）可用 `port_scan.py --preset top100` 直接扫段代替判活。
- 记录时把"判活方式"写进 fact（如 `tcp:445 连通`），别只写"存活"。

## 3. 服务优先级与"值得马上看"的迹象

**打分模型**（决定先派哪条意图）：
- 88/389/445/636 + 主机名像 DC → 域控，最高价值（但最敏感，动作要最轻）。
- 3389/5985 + 管理员凭据 → 直接立足点。
- 数据库端口 + 配置文件里捞到的连接串 → 凭据复用第一现场。
- 管理面板（Jenkins/WebLogic/Druid/Swagger/Nacos/Grafana…）→ 未授权/弱口令高频区，`service_probe.py` 的 `panel_hints` 直接给指纹。
- 6379/11211/27017/9200 未授权 → `service_probe.py` 会直接标出。

**版本 ≠ 漏洞**：banner 里的版本只用于排序优先级；"该版本有 CVE"不构成 finding，必须实际触发才可上报（与全局上报纪律一致）。

## 4. 凭据复用的矩阵打法

拿到的每个凭据 × 授权范围内每类入口 = 验证矩阵。执行顺序按行列成本：
1. 先试**来源最匹配**的入口（数据库连库串→同类型数据库；Windows 本地凭据→SMB/WinRM）。
2. 再跨类型试（同一口令 → SSH/SMB/Web 控制台）——内网口令复用率极高。
3. 哈希类（NTLM）走 Pass-the-Hash 场景的验证（SMB），有专用工具时用工具。
4. 失败 ≥3 次即停该账号（锁定风险）；把"已验证失败"的组合记 fact，别让别人重复试。

## 5. 权限提升枚举清单（只读枚举 → 记录 → 按授权利用）

**Linux**：SUID+GTFOBins 匹配、`sudo -l` 规则、cron 可写脚本/PATH、capability（`getcap -r /`）、内核版本 vs 公开本地提权面（枚举即止，实际利用按授权与操作约束）。
**Windows**：`whoami /priv`（SeImpersonate/SeAssignPrimaryToken/SeBackup/SeLoadDriver 为高危）、未加引号服务路径+可写目录、AlwaysInstallElevated、可写服务 binPath、unquoted service、令牌模拟面。
**域内**：Kerberoastable SPN 清单（`setspn -Q */*` 只读）、AS-REP 无预认证用户、约束委派配置、GPO 里的本地管理员口令、AD ACL 异常（GenericAll 等）——以上全是**枚举与记录**，涉及请求服务票据/提取哈希的实际动作，仅在授权明确覆盖且操作约束允许时执行。

## 6. 隧道与接入（把授权内网接进 ARTEX 测试面）

| 手段 | 适用 | 纪律 |
|---|---|---|
| `ssh -N -D 1080 user@hop` | 有 SSH 立足点 | 只转发授权段；记录进程，收尾 kill |
| `ssh -N -L 本地端口:目标:端口 user@hop` | 只需探个别服务 | 同上 |
| HTTP 隧道/SSRF 链 | 仅 Web 立足点 | 属利用链范畴，走各自流程 |
| 第三方隧道工具 | 用户自带并授权 | 不由本 skill 引入 |

每建一条隧道立即 record_fact（协议/端口/对应授权段）；**收尾时逐条关闭**是硬要求。

## 7. 记录与资产化对照表

| 产出 | 写哪里 | 要点 |
|---|---|---|
| 新网段 | fact（inferred）+ 待展开 | 写来源（路由表/ARP/配置） |
| 存活 IP | insert_assets(type=ip) | props 带判活方式 |
| 开放端口/服务 | insert_assets(type=service) | banner/版本进 props |
| 面板/中间件指纹 | 资产 props + fact | 指纹只排序，不当漏洞 |
| 凭据 | `record_credential`（凭据库） | 必须带来源；验证成功的用 `verified` 关系表达 |
| 凭据复用成功 | fact(observed) + report_finding(如构成漏洞) | 登录成功的请求/会话证据 |
| 未授权访问迹象 | fact + 按流程上报 | service_probe 结论要可复现 |

## 8. 红线速查

- 范围外网段/主机：不扫、不连、不解析进入意图。
- 破坏性（删改数据/停服务/重启/加密）：一律禁止。
- 持久化/后门/新账号：一律禁止。
- 爆破：默认不做；授权允许的低速验证也限 单账号失败≥3 即停。
- 流量洪峰：一次 tcp_probe/preset 控制在工具内置上限内；不用脚本打全 65535。
- 锁定风险（域环境尤其）：任何登录尝试前先想锁定策略。

## 9. 脚本用法速查

```bash
# 网段展开（也可直接用内置工具 expand_cidr）
python3 scripts/cidr_expand.py <IP> --limit 512

# 存活摸底（TCP 多端口判活）
python3 scripts/sweep_alive.py --targets <IP> -t 1 | tee alive.jsonl

# 端口扫描 + banner
python3 scripts/port_scan.py --hosts file:hosts.txt --preset db --banner -t 1.5

# 高价值服务只读核查
python3 scripts/service_probe.py --hosts file:hosts.txt
```

脚本都输出 JSON 行（最后一行 summary），可直接读入后再批量 insert_assets。
