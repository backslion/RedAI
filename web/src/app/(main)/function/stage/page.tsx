"use client";

import * as React from "react";

import { CopyIcon, Loader2Icon, PackageOpenIcon, RefreshCwIcon, Trash2Icon, UploadCloudIcon } from "lucide-react";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { StageEntry, StageSummary } from "@/lib/types";
import { copyText as writeClipboard } from "@/lib/utils";

// 受管文件投递（stage）管理页。
//
// 这一页对应的是「平台 → 目标」方向：worker 编译好 payload，通过暂存服务换一个
// 随机 token 的下载 URL，目标机 curl/wget 拉取。下载路径免 JWT——目标机没有
// token，所以安全性建立在「token 不可猜 + 硬 TTL + 禁列举 + 限速」上，页面上
// 能看到的就是审计所需的全部信息（谁投的、多大、还剩多久、被拉过几次）。
//
// 刻意不做的事：不提供上传任意本机文件以外的入口（path 只能是平台侧已有文件），
// 也不展示历史条目——台账只活在本进程内存里，重启即作废。

const TTL_PRESETS = [5, 15, 30, 60, 120];

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
  if (left <= 0) return "已过期";
  const m = Math.floor(left / 60);
  const s = left % 60;
  return m > 0 ? `${m}分${String(s).padStart(2, "0")}秒` : `${s}秒`;
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

export default function StagePage() {
  const [items, setItems] = React.useState<StageEntry[]>([]);
  const [summary, setSummary] = React.useState<StageSummary | null>(null);
  const [maxTTL, setMaxTTL] = React.useState(120);
  const [loading, setLoading] = React.useState(true);
  const [now, setNow] = React.useState(() => Date.now());

  const [path, setPath] = React.useState("");
  const [ttl, setTtl] = React.useState(15);
  const [oneShot, setOneShot] = React.useState(false);
  const [creating, setCreating] = React.useState(false);
  const [pendingDelete, setPendingDelete] = React.useState<StageEntry | null>(null);

  const load = React.useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [list, sum] = await Promise.all([api.stageList(), api.stageSummary()]);
      setItems(list.items);
      setMaxTTL(list.max_ttl_minutes);
      setSummary(sum);
    } catch {
      if (!silent) toast.error("加载暂存条目失败");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    // 条目 TTL 是分钟级，10 秒刷新一次足够；倒计时用本地时钟每秒走。
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    const poll = window.setInterval(() => void load(true), 10000);
    return () => {
      window.clearInterval(tick);
      window.clearInterval(poll);
    };
  }, [load]);

  async function onCreate() {
    const p = path.trim();
    if (!p) {
      toast.error("请填写平台侧文件路径");
      return;
    }
    setCreating(true);
    try {
      const e = await api.createStage({ path: p, ttl_minutes: ttl, one_shot: oneShot });
      toast.success(`已投递 ${e.name}，${remainText(e.expires_at, Date.now())} 后失效`);
      setPath("");
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "投递失败");
    } finally {
      setCreating(false);
    }
  }

  async function onDelete(entry: StageEntry) {
    try {
      await api.deleteStage(entry.token);
      toast.success(`已销毁 ${entry.name}`);
      setPendingDelete(null);
      await load(true);
    } catch {
      toast.error("销毁失败——可能已过期");
    }
  }

  async function onCopy(entry: StageEntry) {
    const url = entry.url.startsWith("http") ? entry.url : `${window.location.origin}${entry.url}`;
    if (await writeClipboard(url)) {
      toast.success("下载链接已复制（目标机不可达该主机时需替换主机部分）");
    } else {
      toast.error("复制失败，请手动选择链接");
    }
  }

  const disabled = summary?.enabled === false;

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl">
            <PackageOpenIcon className="size-5" />
            受管暂存
          </h1>
          <p className="mt-1 max-w-3xl text-muted-foreground text-sm">
            把工作区里编译好的工具 / payload 交给平台，换一个随机 token 的下载链接，供目标机 curl / wget
            拉取。链接免登录，靠 token 不可猜 + 硬 TTL + 禁目录列举 + 限速保护；到期或一次性下载后自动销毁。只用于
            <span className="text-foreground"> 向外投递</span>，战利品与证据一律走会话读取。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          刷新
        </Button>
      </div>

      {disabled ? (
        <Card className="border-amber-500/40 bg-amber-500/5 p-3 text-sm">
          暂存服务未启用（<code className="font-mono">POJUN_STAGE_DISABLED</code> 生效或初始化失败）。 此时{" "}
          <code className="font-mono">/s/</code> 一律 404，agent 的 <code className="font-mono">stage_share</code>{" "}
          会明确报「未启用」。
        </Card>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="存活条目" value={String(summary?.entries ?? 0)} hint="只统计本进程，重启即清空" />
        <StatTile
          label="占用空间"
          value={fmtBytes(summary?.bytes ?? 0)}
          hint={`单条上限 ${summary?.max_size_mb ?? 256} MB`}
        />
        <StatTile label="一次性投递" value={String(summary?.one_shot ?? 0)} hint="首次完整下载后即焚" />
        <StatTile
          label="最近过期"
          value={summary?.next_expiry ? remainText(summary.next_expiry, now) : "—"}
          hint={summary?.next_expiry ? "最快要失效的条目" : "当前无条目"}
        />
      </div>

      <Card className="gap-3 p-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <UploadCloudIcon className="size-4" />
          手工投递
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <div className="flex min-w-[280px] flex-1 flex-col gap-1">
            <label className="text-muted-foreground text-xs" htmlFor="stage-path">
              平台侧文件路径
            </label>
            <Input
              id="stage-path"
              placeholder="/app/data/sessions/xxx/agent.bin"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
          <div className="flex w-28 flex-col gap-1">
            <label className="text-muted-foreground text-xs" htmlFor="stage-ttl">
              TTL（分钟）
            </label>
            <Input
              id="stage-ttl"
              type="number"
              min={1}
              max={maxTTL}
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value) || 15)}
            />
          </div>
          <div className="flex items-center gap-2 pb-2">
            <Checkbox id="stage-oneshot" checked={oneShot} onCheckedChange={(v) => setOneShot(v === true)} />
            <label className="text-sm" htmlFor="stage-oneshot">
              一次性
            </label>
          </div>
          <Button onClick={() => void onCreate()} disabled={creating || disabled} className="mb-0.5">
            {creating ? <Loader2Icon className="size-4 animate-spin" /> : <UploadCloudIcon className="size-4" />}
            投递
          </Button>
        </div>
        <div className="flex flex-wrap gap-1">
          {TTL_PRESETS.map((m) => (
            <Button key={m} size="sm" variant="ghost" className="h-6 px-2 text-xs" onClick={() => setTtl(m)}>
              {m} 分钟
            </Button>
          ))}
        </div>
      </Card>

      <Card className="overflow-hidden p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>文件名</TableHead>
              <TableHead>下载路径</TableHead>
              <TableHead>归属任务</TableHead>
              <TableHead className="text-right">大小</TableHead>
              <TableHead>剩余</TableHead>
              <TableHead className="text-right">下载</TableHead>
              <TableHead className="w-24 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center text-muted-foreground text-sm">
                  <Loader2Icon className="mx-auto mb-2 size-4 animate-spin" />
                  加载中
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center text-muted-foreground text-sm">
                  暂无条目。agent 用 <code className="font-mono">stage_share</code> 投递后会出现在这里。
                </TableCell>
              </TableRow>
            ) : (
              items.map((it) => {
                const expired = new Date(it.expires_at).getTime() <= now;
                return (
                  <TableRow key={it.token}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        {it.name}
                        {it.one_shot ? (
                          <Badge variant="outline" className="text-[11px]">
                            一次性
                          </Badge>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[280px] truncate font-mono text-xs" title={it.url}>
                      {it.url}
                    </TableCell>
                    <TableCell className="text-xs">{it.task_id ? `#${it.task_id}` : "—"}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{fmtBytes(it.size)}</TableCell>
                    <TableCell className={expired ? "text-red-600 text-xs dark:text-red-400" : "text-xs"}>
                      {remainText(it.expires_at, now)}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      {it.hits} 次<div className="text-muted-foreground">{fmtBytes(it.bytes_served)}</div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-7"
                          title="复制链接"
                          onClick={() => void onCopy(it)}
                        >
                          <CopyIcon className="size-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-7 text-red-600 dark:text-red-400"
                          title="立即销毁"
                          onClick={() => setPendingDelete(it)}
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </Card>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>销毁暂存条目？</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete ? `${pendingDelete.name} 的下载链接会立即失效，目标机此刻正在下载也会中断。` : ""}
              该操作不可撤销，但可以重新投递一次。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={() => pendingDelete && void onDelete(pendingDelete)}>销毁</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
