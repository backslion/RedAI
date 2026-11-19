---
name: intranet-pivot
description: 内网渗透/横向移动/后渗透/纵深一条龙时调用该 skill。涉及内网网段探测、存活与端口扫描、凭据收集与复用、横向验证、立足点信息收集、权限提升枚举、内网穿透/隧道代理（pivot_open 建 SOCKS5 或端口转发、pivot_probe 经跳板探端口、多跳跳板链）等场景使用。
---

# Intranet Pivot（内网纵深一条龙 · YCode）

**前提**：仅对已授权范围内的内网网段与主机操作。范围外目标一律不碰；操作约束（allow/deny）优先于本 skill 的一切建议。

本 skill 提供**从边界立足点到内网纵深**的标准作战流程（OOMA 循环：Observe → Orient → Move → Ascend），以及不依赖外部工具的配套脚本（纯 Python3 标准库，位于本 skill 的 `scripts/`）。

---

## 总体链路（一条龙）

```
①立足点信息收集 → ②网段发现与存活摸底 → ③服务识别与攻击面清点
→ ④凭据获取（本机 harvest + 服务弱配置） → ⑤凭据复用/横向验证
→ ⑥新立足点权限提升 → ⑦回到 ②（下一跳纵深） …
```

每一跳的产出（新网段 / 新凭据 / 新权限）就是下一跳的输入。**不要跳步**：没有完成 ②③ 就去 ⑤ 只会瞎打；拿到一个凭据不去 ⑤ 验证就等于没拿。

## ① 立足点信息收集（拿到任一 shell/执行点后立即做）

**Linux 立足点**（在立足点 shell 里执行，均只读）：
- 网络：`ip a` / `ifconfig`、`ip r` / `route -n`、`cat /proc/net/arp`、`cat /etc/hosts`、`ping -b -c1 <网段广播>`（谨慎）
- 凭据线索：`ls -la ~/.ssh/`、`cat ~/.ssh/config ~/.bash_history`、`find / -maxdepth 4 \( -name "*.conf" -o -name "*.env" -o -name "config.php" -o -name "*.yml" \) 2>/dev/null | head -50`、`env`、`cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|secret|token|key'`
- 提权面：`sudo -l`、`find / -perm -4000 -type f 2>/dev/null`、`cat /etc/crontab; ls -la /etc/cron.*`、`getcap -r / 2>/dev/null`

**Windows 立足点**：
- 网络：`ipconfig /all`、`route print`、`arp -a`、`net view /domain`
- 凭据线索：`cmdkey /list`、`dir %USERPROFILE%\Desktop /s /b`、`findstr /si password *.txt *.ini *.cfg *.xml`、`reg query HKLM /f password /t REG_SZ /s`（量大时限定子键）
- 域信息：`whoami /all`、`net user /domain`、`net group "domain admins" /domain`、`nltest /dclist:%USERDOMAIN%`
- 提权面：`whoami /priv`（SeImpersonate/SeBackup 等高价值特权）、`systeminfo`（补丁面）、`qwinsta`、服务路径：`wmic service get name,pathname,startmode | findstr /i "Auto"`

产出：每条新网段 → `scripts/cidr_expand.py` 展开；每条凭据 → 立即登记（凭据资产/情报），再进 ⑤。

## ② 网段发现与存活摸底（在 ARTEX 侧执行）

优先用内置工具 `expand_cidr` + `tcp_probe`（无脚本依赖）。脚本方式：

```bash
python3 scripts/cidr_expand.py <IP> <IP>-<IP>     # 展开网段
python3 scripts/sweep_alive.py --targets <IP> --probe-ports 22,135,445,3389,80,443 -t 1
```

- ARP 表里出现的同段 IP 是**确定存活**；路由表给出可达网段，ARP 不覆盖的段用 TCP 探测判活（ICMP 常被禁）。
- 存活主机立即 `insert_assets(type=ip)`；同段可结合 DNS/PTR 反查主机名。

## ③ 服务识别与攻击面清点

```bash
python3 scripts/port_scan.py --hosts file:alive.txt --preset top100 --banner -t 1.5
python3 scripts/service_probe.py --hosts <ip> --ports 6379,27017,11211,9200   # 未授权/弱配置面核查(只读探测)
```

- 优先用内置工具：`subdomain_probe`（domain 枚举，内网场景 resolver 指向内网 DNS 可解内部域名）、`dir_probe`（Web 根的敏感路径/管理面摸底，默认走录制代理留痕）。
- 每台主机的开放端口 → `insert_assets(type=service)`，banner 里的版本信息写 props；子域命中 → `insert_assets(type=subdomain)`。
- **内网高价值服务清单**（按优先级）：域控(88/389/445/636) → 数据库(3306/1433/5432/1521/27017/6379/11211) → 远程执行(22/445/5985/3389) → 管理 panel(7001/4848/8080/9200/5601/15672) → 文件共享(445/2049/21)。
- `service_probe.py` 只做**只读协议级核查**（Redis PING/INFO、memcached stats、MongoDB hello、HTTP 标题/头），发现未授权访问记录为事实并按流程处置，不做写入/利用。

## ④ 凭据获取

三个来源按性价比排序：
1. **配置文件/历史记录**（①已覆盖）：应用连库串、`.env`、部署脚本、`~/.bash_history`、运维 wiki/工单（若有 Web 门户）。
2. **服务弱配置**：未授权（③已探测）、默认口令（仅对授权范围内服务做**低速率**验证：单服务 ≤5 个常见组合，避免锁定——已存在专用字典/爆破工具的，用工具并同样限速）。
3. **已有漏洞的产出**：如 SQL 注入读用户表、任意文件读取读配置——这些走各自的漏洞利用流程，本 skill 只负责把拿到的凭据接入 ⑤。

每条凭据必须用 `record_credential` 登记（`asset_id` = 发现它的资产，`source` 写清哪台主机/哪个文件/哪个服务）；
登记后它才进得了 `credential_reuse_matrix` 的盘点范围。

## ⑤ 凭据复用与横向验证（内网最快的一条路）

- 对授权范围内每类入口逐一验证：SSH(22) / SMB(445) / WinRM(5985) / RDP(3389) / 数据库 / Web 控制台登录。
- **一次成功登录 = 实证横向移动**，登记 fact（observed）+ 新凭据与新立足点资产；失败也要记录（避免重复尝试）。
- 口令喷射纪律：单账号失败 ≥3 次即停（防锁定）；优先"同口令跨服务"而非"单账号试多口令"。
- 成功即进入 ⑥，该主机成为新立足点，回到 ①。
- **SSH 验证成功先建通道**：`pivot_open(hops=[{addr:"<该主机>:22", credential_id:<凭据 id>}])`
  ——之后打它背后的网段全部走这条通道（见 ⑦），不用每台目标都单独登一次。

## ⑥ 权限提升枚举（新立足点上，只读枚举为主）

- Linux：SUID/GTFOBins 类、sudo 规则、cron 任务与可写脚本、capability、内核版本对应公开提权面。
- Windows：`whoami /priv` 高价值特权（SeImpersonate → Potato 系）、未加引号服务路径、AlwaysInstallElevated、可写服务 DLL、令牌枚举。
- 域内：Kerberoastable SPN（只读枚举 `setspn -Q */*`）、AS-REP roastable 用户、GPO/ACL 异常——枚举结论记录 fact，实际利用按授权与约束执行。

## ⑦ 隧道/代理接入（用平台工具，别手工起 ssh -D）

拿到可登录的 SSH 凭据后，**用 `pivot_open` 建隧道**，不要自己 `ssh -N -D`：
手工起的隧道没有台账、没有 TTL、进程退出就变成孤儿进程，收尾时也容易被忘掉。

```
ssh_check 验证凭据可登录
  → pivot_open(hops=[{addr, credential_id}], mode=socks)     # 拿到 127.0.0.1:<port>
  → pivot_probe(pivot_id, hosts=[...], ports=[...])          # 经隧道探端口（nmap 不走 SOCKS5）
  → curl --noproxy "" --socks5-hostname 127.0.0.1:<port> ... # 打内网 HTTP
  → pivot_close(id)                                          # 收尾必关
```

要点：
- **凭据用 `credential_id`**（`list_credentials` 查），不要手打口令——手打在工具参数里
  会留在对话记录与日志里。平台从凭据库取出后只用于握手，不回传。
- **多跳**：`hops` 按顺序给，第 2 跳的连接建在第 1 跳的通道上，中间主机不需要装任何
  工具、不需要出网。四跳足够覆盖「入口 → DMZ → 办公 → 核心」。
- **curl 必须用 `--socks5-hostname`**（`--socks5` 会在本机解析域名，内网域名解析不到），
  并且要加 `--noproxy ""`——环境变量里常有 `NO_PROXY=127.0.0.1`，会把目标为回环地址的
  请求直接放过去，看起来"通了"其实没走隧道。
- **端口扫描用 `pivot_probe`**：nmap 不走 SOCKS5（除非装 proxychains，部署环境未必有）。
  `pivot_probe` 的连接由跳板机代拨（SSH direct-tcpip），通道打开即证明端口可达。
- **`portfwd` 模式**给不支持 SOCKS 的工具用（固定映射一个 host:port）；要打多个目标就
  用 `socks`。
- **纪律**：隧道只转发授权网段流量；`pivot_list` 能看到每条隧道的连接记录（目标、
  字节、失败原因），收尾逐条 `pivot_close`——默认 TTL 2 小时，但不能靠它兜底。
- 打不通时先看 `pivot_list` 里隧道的 `last_error` 与 `recent[].error`：`refused` 是端口
  关闭（主机活着）、`timeout` 是被过滤或网段不通、`administratively prohibited` 是跳板机
  sshd 禁止转发（`AllowTcpForwarding no`，只能换跳板）。

## 记录纪律（贯穿）

- 每个产出**立即**写回：新网段/存活 IP/服务 → 资产图；结论与证据 → record_fact（observed/inferred 如实标注）；凭据 → 情报/凭据资产。
- 串行链的中间结论（"<IP> 的 445 可匿名枚举共享"）都是后续意图的输入，别只记最后战果。
- **红线**：不删改数据、不停止/重启服务、不留后门与持久化、不做加密勒索、不做过载爆破、范围外不碰。隧道用完即撤。

## 脚本清单（scripts/，均纯 Python3 标准库）

| 脚本 | 用途 |
|---|---|
| `cidr_expand.py` | CIDR/范围/单 IP → IP 列表（支持 limit） |
| `sweep_alive.py` | TCP 多端口并探测活（输出 JSON 行） |
| `port_scan.py` | 并发端口扫描 + banner 抓取（预设 top100/web/db/win/nix） |
| `service_probe.py` | 高价值服务只读核查（Redis/memcached/MongoDB/HTTP 指纹） |

脚本默认从 ARTEX 侧发起；`--help` 看参数。更多细节、边界与反例见 `reference.md`。
