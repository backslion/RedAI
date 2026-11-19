"use client";

import * as React from "react";

import { CopyIcon, Loader2Icon, NetworkIcon, PlusIcon, RefreshCwIcon, ShieldAlertIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { CredentialRow, PivotHopInput, PivotStats, PivotTunnel } from "@/lib/types";
import { copyText as writeClipboard, safeUUID } from "@/lib/utils";

// 内网横向穿透（pivot）管理页。
//
// 这一页对应的是「平台 → 目标内网」方向：拿一台已控主机的 SSH 凭据，在平台
// 回环上开一个 SOCKS5 或端口转发入口，之后 curl / worker / pivot_probe 都
// 可以借它打进去。
//
// 与 stage 页的对称性：stage 是目标来拉（平台开下载口），pivot 是平台去打
// （平台开出口）。两者都是「对外通道」，所以都只活在本进程内存里、都有硬 TTL。
//
// 刻意不做的事：
//   - 不回显凭据。跳板凭据只能从凭据库选（credential_id）或当场手填，填完即发，
//     页面上再也读不到。
//   - 不默认绑 0.0.0.0。入口只在回环上，只有本平台能用；要对外开放必须同时设
//     SOCKS5 用户名口令（后端强制，前端只是提前拦一道）。

const TTL_PRESETS = [30, 60, 120, 240, 480];

type HopDraft = {
  /** 行身份：用随机值而不是数组下标——增删中间行时下标会串，输入内容会跳错行。 */
  key: string;
  addr: string;
  credId: string;
  username: string;
  password: string;
  label: string;
};

function emptyHop(): HopDraft {
  return { key: safeUUID(), addr: "", credId: "", username: "", password: "", label: "" };
}

function fmtBytes(n: number) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

function remainText(expires: string, now: number) {
  const t = new Date(expires).getTime();
  if (Number.isNaN(t)) return "—";
  const left = Math.floor((t - now) / 1000);
  if (left <= 0) return "已到期";
  const h = Math.floor(left / 3600);
  const m = Math.floor((left % 3600) / 60);
  const s = left % 60;
  if (h > 0) return `${h}时${String(m).padStart(2, "0")}分`;
  return `${m}分${String(s).padStart(2, "0")}秒`;
}

function fmtTime(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}

function StatTile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card className="gap-1 p-3">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className="font-semibold text-2xl tabular-nums">{value}</div>
      {hint ? <div className="text-muted-foreground text-xs">{hint}</div> : null}
    </Card>
  );
}

export default function PivotPage() {
  const [items, setItems] = React.useState<PivotTunnel[]>([]);
  const [stats, setStats] = React.useState<PivotStats | null>(null);
  const [maxHops, setMaxHops] = React.useState(4);
  const [maxTTL, setMaxTTL] = React.useState(480);
  const [defaultTTL, setDefaultTTL] = React.useState(120);
  const [creds, setCreds] = React.useState<CredentialRow[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [now, setNow] = React.useState(() => Date.now());
  const [expanded, setExpanded] = React.useState<string | null>(null);

  // 表单状态
  const [label, setLabel] = React.useState("");
  const [mode, setMode] = React.useState<"socks" | "portfwd">("socks");
  const [hops, setHops] = React.useState<HopDraft[]>([emptyHop()]);
  const [target, setTarget] = React.useState("");
  const [ttl, setTtl] = React.useState(120);
  const [socksUser, setSocksUser] = React.useState("");
  const [socksPass, setSocksPass] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  const [pendingDelete, setPendingDelete] = React.useState<PivotTunnel | null>(null);

  const load = React.useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const r = await api.pivots();
      setItems(r.items);
      setStats(r.stats);
      setMaxHops(r.max_hops);
      setMaxTTL(r.max_ttl_minutes);
      setDefaultTTL(r.default_ttl_minutes);
      setTtl((cur) => (cur > r.max_ttl_minutes ? r.default_ttl_minutes : cur));
    } catch {
      if (!silent) toast.error("加载隧道列表失败");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    // 凭据下拉：只要已验证的（discovered 也允许——验证是加分项不是前提，
    // 但排在后面反而干扰选择，这里取最近 200 条由用户自己判断）。
    api
      .credentials({ limit: 200 })
      .then((r) => setCreds(r.items))
      .catch(() => setCreds([]));
  }, [load]);

  React.useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  // 存活/流量会变，30 秒静默刷一次（含被 TTL 或心跳关掉的隧道）。
  React.useEffect(() => {
    const t = window.setInterval(() => void load(true), 30_000);
    return () => window.clearInterval(t);
  }, [load]);

  function patchHop(i: number, patch: Partial<HopDraft>) {
    setHops((cur) => cur.map((h, idx) => (idx === i ? { ...h, ...patch } : h)));
  }

  async function submit() {
    if (hops.some((h) => !h.addr.trim())) {
      toast.error("每一跳都要填地址");
      return;
    }
    if (hops.some((h) => !h.credId && (!h.username.trim() || !h.password))) {
      toast.error("每一跳都要选凭据，或填用户名 + 口令");
      return;
    }
    if (mode === "portfwd" && !target.trim()) {
      toast.error("端口转发模式必须填内网目标 host:port");
      return;
    }
    const hopInputs: PivotHopInput[] = hops.map((h) =>
      h.credId
        ? { addr: h.addr.trim(), credential_id: Number(h.credId), label: h.label.trim() || undefined }
        : {
            addr: h.addr.trim(),
            username: h.username.trim(),
            password: h.password,
            label: h.label.trim() || undefined,
          },
    );
    setCreating(true);
    try {
      const r = await api.openPivot({
        label: label.trim() || undefined,
        mode,
        hops: hopInputs,
        target: mode === "portfwd" ? target.trim() : undefined,
        ttl_minutes: ttl,
        socks_user: socksUser.trim() || undefined,
        socks_pass: socksPass || undefined,
      });
      toast.success("隧道已建立", { description: r.usage });
      setLabel("");
      setHops([emptyHop()]);
      setTarget("");
      await load(true);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "开隧道失败");
    } finally {
      setCreating(false);
    }
  }

  async function closePivot(t: PivotTunnel) {
    try {
      await api.closePivot(t.id);
      toast.success("隧道已关闭");
      setPendingDelete(null);
      await load(true);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "关闭失败");
    }
  }

  async function copyText(text: string, what: string) {
    if (await writeClipboard(text)) {
      toast.success(`已复制${what}`);
    } else {
      toast.error("复制失败——浏览器拒绝访问剪贴板");
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-lg">
            <NetworkIcon className="size-5" /> 内网横向穿透
          </h1>
          <p className="text-muted-foreground text-xs">
            用已控主机的 SSH 建 SOCKS5 / 端口转发通道。隧道只在平台回环上监听，有硬 TTL，
            到期自动关闭；结束后请手动关掉，不要留着当长期入口。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          刷新
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatTile label="隧道" value={String(stats?.tunnels ?? 0)} hint={`存活 ${stats?.alive ?? 0}`} />
        <StatTile label="SOCKS5" value={String(stats?.socks ?? 0)} hint="任意内网目标" />
        <StatTile label="端口转发" value={String(stats?.portfwd ?? 0)} hint="固定目标" />
        <StatTile
          label="连接"
          value={String(stats?.conns ?? 0)}
          hint={`失败 ${stats?.fails ?? 0}｜并发 ${stats?.active_now ?? 0}`}
        />
        <StatTile
          label="流量"
          value={fmtBytes((stats?.bytes_up ?? 0) + (stats?.bytes_down ?? 0))}
          hint={`↑ ${fmtBytes(stats?.bytes_up ?? 0)} ↓ ${fmtBytes(stats?.bytes_down ?? 0)}`}
        />
      </div>

      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="font-medium text-sm">开隧道</div>
          <div className="ml-auto flex gap-1">
            <Button size="sm" variant={mode === "socks" ? "default" : "outline"} onClick={() => setMode("socks")}>
              SOCKS5（任意目标）
            </Button>
            <Button size="sm" variant={mode === "portfwd" ? "default" : "outline"} onClick={() => setMode("portfwd")}>
              端口转发（单目标）
            </Button>
          </div>
        </div>

        <div className="grid gap-2 md:grid-cols-3">
          <div className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">标注（可选）</span>
            <Input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="如：办公网出口-01"
              className="h-8"
            />
          </div>
          {mode === "portfwd" ? (
            <div className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">内网目标 host:port</span>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="10.20.3.15:3306"
                className="h-8"
              />
            </div>
          ) : null}
          <div className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">存活时长（分钟，上限 {maxTTL}）</span>
            <div className="flex gap-1">
              <Input
                type="number"
                min={1}
                max={maxTTL}
                value={ttl}
                onChange={(e) => setTtl(Math.min(maxTTL, Math.max(1, Number(e.target.value) || defaultTTL)))}
                className="h-8"
              />
              {TTL_PRESETS.filter((m) => m <= maxTTL).map((m) => (
                <Button key={m} size="sm" variant="outline" className="h-8 px-2" onClick={() => setTtl(m)}>
                  {m >= 60 ? `${m / 60}h` : `${m}m`}
                </Button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground">跳板链（按顺序，最多 {maxHops} 跳）</span>
            {hops.length < maxHops ? (
              <Button size="sm" variant="ghost" className="h-7" onClick={() => setHops((c) => [...c, emptyHop()])}>
                <PlusIcon className="size-3.5" /> 加一跳
              </Button>
            ) : null}
          </div>
          {hops.map((h, i) => (
            <div key={h.key} className="grid items-end gap-2 rounded-md border p-2 md:grid-cols-12">
              <div className="text-muted-foreground text-xs md:col-span-1">第 {i + 1} 跳</div>
              <div className="flex flex-col gap-1 text-xs md:col-span-3">
                <span className="text-muted-foreground">地址 host:port</span>
                <Input
                  value={h.addr}
                  onChange={(e) => patchHop(i, { addr: e.target.value })}
                  placeholder="10.0.0.5:22"
                  className="h-8"
                />
              </div>
              <div className="flex flex-col gap-1 text-xs md:col-span-4">
                <span className="text-muted-foreground">从凭据库选（推荐）</span>
                <select
                  value={h.credId}
                  onChange={(e) => patchHop(i, { credId: e.target.value })}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                >
                  <option value="">— 手填账号口令 —</option>
                  {creds.map((c) => (
                    <option key={c.id} value={String(c.id)}>
                      #{c.id} {c.domain ? `${c.domain}\\` : ""}
                      {c.username || "(无用户名)"} · {c.type} · {c.target || "无资产"}
                    </option>
                  ))}
                </select>
              </div>
              {h.credId ? (
                <div className="text-muted-foreground text-xs md:col-span-4">
                  口令由平台从凭据库取出，不经过浏览器。
                </div>
              ) : (
                <>
                  <div className="flex flex-col gap-1 text-xs md:col-span-2">
                    <span className="text-muted-foreground">用户名</span>
                    <Input
                      value={h.username}
                      onChange={(e) => patchHop(i, { username: e.target.value })}
                      className="h-8"
                    />
                  </div>
                  <div className="flex flex-col gap-1 text-xs md:col-span-2">
                    <span className="text-muted-foreground">口令</span>
                    <Input
                      type="password"
                      value={h.password}
                      onChange={(e) => patchHop(i, { password: e.target.value })}
                      className="h-8"
                    />
                  </div>
                </>
              )}
              {hops.length > 1 ? (
                <Button
                  size="sm"
                  variant="ghost"
                  className="md:col-span-1"
                  onClick={() => setHops((c) => c.filter((_, idx) => idx !== i))}
                >
                  <Trash2Icon className="size-4" />
                </Button>
              ) : null}
            </div>
          ))}
        </div>

        <div className="grid gap-2 md:grid-cols-2">
          <div className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">SOCKS5 用户名（可选，绑定非回环时必填）</span>
            <Input value={socksUser} onChange={(e) => setSocksUser(e.target.value)} className="h-8" />
          </div>
          <div className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">SOCKS5 口令</span>
            <Input type="password" value={socksPass} onChange={(e) => setSocksPass(e.target.value)} className="h-8" />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button onClick={() => void submit()} disabled={creating}>
            {creating ? <Loader2Icon className="size-4 animate-spin" /> : <NetworkIcon className="size-4" />}
            建立隧道
          </Button>
          <span className="flex items-center gap-1 text-muted-foreground text-xs">
            <ShieldAlertIcon className="size-3.5" />
            开隧道会走人工审批（agent 侧）；本页由已登录人员直接操作，同样会计入活动流。
          </span>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>标注 / 模式</TableHead>
              <TableHead>入口</TableHead>
              <TableHead>跳板链</TableHead>
              <TableHead>剩余</TableHead>
              <TableHead className="text-right">连接</TableHead>
              <TableHead className="text-right">流量</TableHead>
              <TableHead>状态</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="py-8 text-center text-muted-foreground text-sm">
                  {loading ? "加载中…" : "还没有隧道。先用 ssh_check 验证一台主机的凭据，再在上面建隧道。"}
                </TableCell>
              </TableRow>
            ) : (
              items.map((t) => (
                <React.Fragment key={t.id}>
                  <TableRow>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm">{t.label || "(未标注)"}</span>
                        <Badge variant={t.mode === "socks" ? "secondary" : "outline"} className="w-fit text-xs">
                          {t.mode === "socks" ? "SOCKS5" : `转发 → ${t.target || "?"}`}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <button
                        type="button"
                        className="font-mono text-xs hover:underline"
                        onClick={() =>
                          void copyText(t.mode === "socks" ? (t.socks_url ?? t.listen) : t.listen, "入口地址")
                        }
                      >
                        {t.listen}
                      </button>
                      {t.has_auth ? <div className="text-muted-foreground text-xs">需认证</div> : null}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5 text-xs">
                        {t.hops.map((h, i) => (
                          <span key={`${t.id}-${h.addr}`} className="truncate font-mono">
                            {i + 1}. {h.label || h.addr} ({h.user})
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums">{remainText(t.expires_at, now)}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      {t.conns}
                      {t.fails > 0 ? <span className="text-destructive"> / 败 {t.fails}</span> : null}
                      {t.active_now > 0 ? <div className="text-muted-foreground">并发 {t.active_now}</div> : null}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      <div>↑ {fmtBytes(t.bytes_up)}</div>
                      <div>↓ {fmtBytes(t.bytes_down)}</div>
                    </TableCell>
                    <TableCell>
                      {t.alive ? (
                        <Badge variant="secondary" className="text-xs">
                          存活
                        </Badge>
                      ) : (
                        <div className="flex flex-col gap-0.5">
                          <Badge variant="destructive" className="w-fit text-xs">
                            已断开
                          </Badge>
                          {t.last_error ? (
                            <span className="max-w-[220px] truncate text-muted-foreground text-xs" title={t.last_error}>
                              {t.last_error}
                            </span>
                          ) : null}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setExpanded(expanded === t.id ? null : t.id)}
                          title="最近连接"
                        >
                          明细
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            void copyText(t.mode === "socks" ? (t.socks_url ?? t.listen) : t.listen, "入口地址")
                          }
                        >
                          <CopyIcon className="size-4" />
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setPendingDelete(t)}>
                          <Trash2Icon className="size-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  {expanded === t.id ? (
                    <TableRow>
                      <TableCell colSpan={8} className="bg-muted/40">
                        <div className="flex flex-col gap-2 text-xs">
                          <div className="flex flex-wrap gap-x-6 gap-y-1">
                            <span>
                              主机密钥：<span className="font-mono">{t.host_key || "—"}</span>
                            </span>
                            <span>建立于 {fmtTime(t.created_at)}</span>
                            <span>
                              到期 {fmtTime(t.expires_at)}（{remainText(t.expires_at, now)}）
                            </span>
                          </div>
                          <div className="text-muted-foreground">
                            核对主机密钥：与目标机{" "}
                            <span className="font-mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>{" "}
                            的输出比对。指纹不符说明链路上有中间人。
                          </div>
                          <div>
                            <div className="mb-1 font-medium">最近连接</div>
                            {(t.recent ?? []).length === 0 ? (
                              <div className="text-muted-foreground">
                                还没有连接。curl 用 --socks5-hostname {t.listen}。
                              </div>
                            ) : (
                              <div className="flex flex-col gap-0.5 font-mono">
                                {(t.recent ?? [])
                                  .slice()
                                  .reverse()
                                  .map((c) => (
                                    <div key={`${t.id}-${c.at}-${c.target}`} className="flex flex-wrap gap-x-3">
                                      <span>{fmtTime(c.at)}</span>
                                      <span className={c.ok ? "text-foreground" : "text-destructive"}>
                                        {c.ok ? "OK " : "FAIL"}
                                      </span>
                                      <span>{c.target}</span>
                                      {c.ok ? (
                                        <span className="text-muted-foreground">
                                          ↑{fmtBytes(c.up)} ↓{fmtBytes(c.down)}
                                        </span>
                                      ) : (
                                        <span className="text-muted-foreground">{c.err}</span>
                                      )}
                                    </div>
                                  ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : null}
                </React.Fragment>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      <AlertDialog open={!!pendingDelete} onOpenChange={(v) => !v && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>关闭这条隧道？</AlertDialogTitle>
            <AlertDialogDescription>
              关闭后，正在经它进行的连接会立刻断开，依赖它的 worker 会拿不到内网目标。
              {pendingDelete ? `入口 ${pendingDelete.listen} 将不再监听。` : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={() => pendingDelete && void closePivot(pendingDelete)}>
              关闭隧道
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
