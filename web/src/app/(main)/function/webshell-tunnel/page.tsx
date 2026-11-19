"use client";

// WebShell 隧道管理页：把「只有一句话马、没开 22」的目标变成 SOCKS5 内网出口。
// 与 pivot 页并列但不是替代：pivot 走 SSH，本页走 WebShell HTTP 隧道。
// 三步流程在页面顶部说明：拿脚本+token（找 agent）→ 落地脚本 → 在这里开隧道。

import * as React from "react";
import { CopyIcon, Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon, WaypointsIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import type { WebShellSession, WebShellTunnel } from "@/lib/types";
import { copyText as writeClipboard } from "@/lib/utils";

export default function WebShellTunnelPage() {
  const [items, setItems] = React.useState<WebShellTunnel[]>([]);
  const [sessions, setSessions] = React.useState<WebShellSession[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const [draft, setDraft] = React.useState({
    name: "",
    tunnel_url: "",
    token: "",
    mode: "socks",
    target: "",
    label: "",
    ttl_minutes: 120,
    socks_user: "",
    socks_pass: "",
    bind_host: "127.0.0.1",
  });

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      const [t, s] = await Promise.all([api.webshellTunnels(undefined, 5), api.webshells()]);
      setItems(t.items);
      setSessions(s.items);
    } catch (e) {
      toast.error(`加载失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const submit = async () => {
    if (!draft.name || !draft.tunnel_url || !draft.token) {
      toast.error("会话、脚本 URL、token 都要填");
      return;
    }
    setBusy("open");
    try {
      await api.openWebshellTunnel({
        name: draft.name,
        tunnel_url: draft.tunnel_url,
        token: draft.token,
        mode: draft.mode,
        target: draft.mode === "portfwd" ? draft.target : undefined,
        label: draft.label || undefined,
        ttl_minutes: draft.ttl_minutes,
        socks_user: draft.socks_user || undefined,
        socks_pass: draft.socks_pass || undefined,
        bind_host: draft.bind_host,
      });
      toast.success("隧道已开启");
      setOpen(false);
      await refresh();
    } catch (e) {
      toast.error(`开隧道失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy("");
    }
  };

  const close = async (t: WebShellTunnel) => {
    setBusy(t.id);
    try {
      await api.closeWebshellTunnel(t.id);
      toast.success("隧道已关闭");
      await refresh();
    } catch (e) {
      toast.error(`关闭失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy("");
    }
  };

  const copy = (text: string) => {
    void writeClipboard(text).then((ok) => {
      if (ok) toast.success("已复制");
      else toast.error("复制失败——浏览器拒绝访问剪贴板");
    });
  };

  const fmtBytes = (n: number) =>
    n < 1024 ? `${n}B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)}KB` : `${(n / 1024 / 1024).toFixed(1)}MB`;

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl">
            <WaypointsIcon className="size-5" />
            WebShell 隧道
          </h1>
          <p className="mt-1 text-muted-foreground text-sm">
            只有一句话马、目标没开 22 时，经 WebShell 开 SOCKS5 内网出口。三步：让 agent 用
            <code className="mx-1 rounded bg-muted px-1">webshell_tunnel_script</code>
            生成脚本+token → 把脚本落地到目标 Web 目录 → 在这里填 URL 与 token 开隧道。
          </p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void refresh()} disabled={loading}>
            <RefreshCwIcon className={`size-4 ${loading ? "animate-spin" : ""}`} />
            刷新
          </Button>
          <Button size="sm" onClick={() => setOpen(true)}>
            <PlusIcon className="size-4" />
            开隧道
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">隧道总数</div>
          <div className="mt-1 font-semibold text-2xl">{items.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">存活</div>
          <div className="mt-1 font-semibold text-2xl">{items.filter((t) => t.alive).length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">SOCKS5 入口</div>
          <div className="mt-1 font-semibold text-2xl">{items.filter((t) => t.mode === "socks").length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">累计连接</div>
          <div className="mt-1 font-semibold text-2xl">{items.reduce((a, t) => a + t.conns, 0)}</div>
        </Card>
      </div>

      <div className="space-y-3">
        {items.length === 0 && (
          <Card className="p-8 text-center text-muted-foreground text-sm">
            还没有隧道。让 agent 生成脚本并落地后，点「开隧道」。
          </Card>
        )}
        {items.map((t) => (
          <Card className="p-4" key={t.id}>
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{t.label || t.session}</span>
                  <Badge variant={t.alive ? "default" : "secondary"}>{t.alive ? "存活" : "已断"}</Badge>
                  <Badge variant="outline">{t.mode}</Badge>
                  {t.has_auth && <Badge variant="outline">认证</Badge>}
                </div>
                {t.socks_url && (
                  <div className="flex items-center gap-2 text-sm">
                    <code className="truncate rounded bg-muted px-2 py-1 text-xs">{t.socks_url}</code>
                    <Button size="icon" variant="ghost" className="size-7" onClick={() => copy(t.socks_url ?? "")}>
                      <CopyIcon className="size-3.5" />
                    </Button>
                  </div>
                )}
                <div className="text-muted-foreground text-xs">
                  会话 {t.session} · 出口 {t.egress} · 连接 {t.conns}（失败 {t.fails}）· ↑{fmtBytes(t.bytes_up)} ↓
                  {fmtBytes(t.bytes_down)} · 剩余 {Math.floor(t.ttl_sec / 60)} 分钟
                </div>
                {t.last_error && <div className="text-amber-600 text-xs">⚠ {t.last_error}</div>}
              </div>
              <Button
                size="sm"
                variant="destructive"
                disabled={busy === t.id}
                onClick={() => void close(t)}
              >
                {busy === t.id ? <Loader2Icon className="size-4 animate-spin" /> : <Trash2Icon className="size-4" />}
                关闭
              </Button>
            </div>
          </Card>
        ))}
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>开一条 WebShell 隧道</DialogTitle>
            <DialogDescription>
              token 来自 agent 的 webshell_tunnel_script；必须与落到目标上的脚本一致，否则建连失败。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>WebShell 会话</Label>
              <Select value={draft.name} onValueChange={(v) => setDraft({ ...draft, name: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="选一条已登记的会话" />
                </SelectTrigger>
                <SelectContent>
                  {sessions.map((s) => (
                    <SelectItem key={s.name} value={s.name}>
                      {s.name} — {s.url}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>脚本 URL</Label>
              <Input
                placeholder="http://10.0.0.5/uploads/tunnel_xxx.php"
                value={draft.tunnel_url}
                onChange={(e) => setDraft({ ...draft, tunnel_url: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>token</Label>
              <Input
                placeholder="脚本里的 $T 值"
                value={draft.token}
                onChange={(e) => setDraft({ ...draft, token: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>模式</Label>
                <Select value={draft.mode} onValueChange={(v) => setDraft({ ...draft, mode: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="socks">SOCKS5（任意内网目标）</SelectItem>
                    <SelectItem value="portfwd">端口转发（固定单目标）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>TTL（分钟）</Label>
                <Input
                  type="number"
                  value={draft.ttl_minutes}
                  onChange={(e) => setDraft({ ...draft, ttl_minutes: Number(e.target.value) })}
                />
              </div>
            </div>
            {draft.mode === "portfwd" && (
              <div className="space-y-1">
                <Label>目标 host:port</Label>
                <Input
                  placeholder="10.0.0.9:3389"
                  value={draft.target}
                  onChange={(e) => setDraft({ ...draft, target: e.target.value })}
                />
              </div>
            )}
            <div className="space-y-1">
              <Label>标注（可选）</Label>
              <Input
                placeholder="DMZ 内网出口"
                value={draft.label}
                onChange={(e) => setDraft({ ...draft, label: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1">
                <Label>绑定地址</Label>
                <Input value={draft.bind_host} onChange={(e) => setDraft({ ...draft, bind_host: e.target.value })} />
              </div>
              <div className="space-y-1">
                <Label>SOCKS 用户</Label>
                <Input value={draft.socks_user} onChange={(e) => setDraft({ ...draft, socks_user: e.target.value })} />
              </div>
              <div className="space-y-1">
                <Label>SOCKS 口令</Label>
                <Input
                  type="password"
                  value={draft.socks_pass}
                  onChange={(e) => setDraft({ ...draft, socks_pass: e.target.value })}
                />
              </div>
            </div>
            <p className="text-muted-foreground text-xs">
              绑定非回环地址（如 0.0.0.0）必须同时填 SOCKS 用户与口令，否则会被拒绝。
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void submit()} disabled={busy === "open"}>
              {busy === "open" && <Loader2Icon className="size-4 animate-spin" />}
              开隧道
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
