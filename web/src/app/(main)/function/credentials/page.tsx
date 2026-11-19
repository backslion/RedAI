"use client";

import * as React from "react";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  KeyRoundIcon,
  Loader2Icon,
  RefreshCwIcon,
  SearchIcon,
  ShieldCheckIcon,
  Trash2Icon,
} from "lucide-react";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { CredentialRow, CredentialStats } from "@/lib/types";
import { cn } from "@/lib/utils";

// 凭据台账页。
//
// 这一页刻意只呈现脱敏信息：后端 projection 里没有 secret 列，这里也不可能
// 显示明文。需要「拿这条凭据去访问某个 URL」时走 agent 的 auth_request
// （credential_id=...），由执行侧组装命令——不给浏览器留明文凭据的下发口。

const PAGE_SIZES = [25, 50, 100];
const RELATIONS = [
  { value: "all", label: "全部关系" },
  { value: "verified", label: "已认证" },
  { value: "discovered", label: "仅发现" },
];
const TYPES = [
  { value: "all", label: "全部类型" },
  { value: "ssh", label: "ssh" },
  { value: "rdp", label: "rdp" },
  { value: "smb", label: "smb" },
  { value: "mysql", label: "mysql" },
  { value: "postgres", label: "postgres" },
  { value: "redis", label: "redis" },
  { value: "http", label: "http" },
  { value: "token", label: "token" },
  { value: "unknown", label: "unknown" },
];

function fmtTime(ts: string) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// assetLabel 给出「人怎么指代这台机器」：ip 优先，其次域名，再退回资产类型+id。
function firstNonEmpty(...vals: (string | undefined)[]): string {
  for (const v of vals) {
    if (v && v.trim() !== "") return v;
  }
  return "";
}

function assetLabel(r: CredentialRow) {
  return firstNonEmpty(r.asset_ip, r.asset_domain, r.asset_url) || `资产#${r.asset_id}`;
}

function assetSub(r: CredentialRow) {
  const bits: string[] = [];
  if (r.asset_ip && r.asset_domain) bits.push(r.asset_domain);
  if (r.asset_type) bits.push(r.asset_type);
  if (r.company_name) bits.push(r.company_name);
  return bits.join(" · ");
}

// credentialLabel 是报告里可以安全写入的指代方式（不含 secret）。
function credentialLabel(r: CredentialRow) {
  const who = r.domain ? `${r.domain}\\${r.username || "?"}` : r.username || "空用户名";
  return `${r.type || "unknown"}:${who}`;
}

export default function CredentialsPage() {
  const [items, setItems] = React.useState<CredentialRow[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<CredentialStats | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [relation, setRelation] = React.useState("all");
  const [type, setType] = React.useState("all");
  const [intranet, setIntranet] = React.useState(false);
  const [size, setSize] = React.useState(50);
  const [page, setPage] = React.useState(0);

  const [selected, setSelected] = React.useState<CredentialRow | null>(null);
  const [pendingDelete, setPendingDelete] = React.useState<CredentialRow | null>(null);
  const [reloadKey, setReloadKey] = React.useState(0); // 手动刷新触发器（仅用于强制重跑下面的 effect）

  // 搜索防抖：输入停顿 300ms 才落成查询条件。
  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: 任一筛选条件变化都应回到第一页。
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, relation, type, intranet, size]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reloadKey 只是「刷新」按钮的强制重跑开关
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .credentials({
        relation,
        type,
        q: queryQ,
        intranet,
        limit: size,
        offset: page * size,
      })
      .then((r) => {
        if (!alive) return;
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => {
        if (!alive) return;
        setItems([]);
        setTotal(0);
        toast.error("加载凭据台账失败");
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [relation, type, queryQ, intranet, size, page, reloadKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: 同上，reloadKey 是刷新触发器
  React.useEffect(() => {
    let alive = true;
    api
      .credentialStats()
      .then((s) => alive && setStats(s))
      .catch(() => alive && setStats(null));
    return () => {
      alive = false;
    };
  }, [reloadKey]);

  const maxPage = Math.max(0, Math.ceil(total / size) - 1);
  const reload = () => setReloadKey((k) => k + 1);

  async function confirmDelete() {
    const row = pendingDelete;
    if (!row) return;
    setPendingDelete(null);
    try {
      await api.deleteCredential(row.id);
      toast.success(`已删除凭据 ${credentialLabel(row)}`);
      setSelected((cur) => (cur && cur.id === row.id ? null : cur));
      reload();
    } catch {
      toast.error("删除失败——凭据可能已被其他操作移除");
      reload();
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <KeyRoundIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">凭据台账</h1>
          <Badge variant="secondary">{total}</Badge>
        </div>
        <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          刷新
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile label="凭据身份" value={stats?.identities ?? 0} hint={`${stats?.distinct_types ?? 0} 种类型`} />
        <StatTile label="已认证关系" value={stats?.verified ?? 0} hint={`共 ${stats?.links ?? 0} 条关系`} tone="risk" />
        <StatTile
          label="内网可用"
          value={stats?.verified_intranet ?? 0}
          hint={`内网关系 ${stats?.intranet_links ?? 0} 条`}
          tone="risk"
        />
        <StatTile label="带凭据本体" value={stats?.with_secret ?? 0} hint={`覆盖 ${stats?.companies ?? 0} 家企业`} />
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="搜索用户名 / 域 / 目标 / 资产 IP / 域名..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 pl-8"
          />
        </div>
        <Select value={relation} onValueChange={setRelation}>
          <SelectTrigger size="sm" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RELATIONS.map((r) => (
              <SelectItem key={r.value} value={r.value}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={type} onValueChange={setType}>
          <SelectTrigger size="sm" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="flex h-8 items-center gap-2 rounded-md border border-input px-2.5 text-muted-foreground text-xs">
          <Checkbox
            id="cred-intranet-only"
            checked={intranet}
            onCheckedChange={(v) => setIntranet(v === true)}
            aria-label="仅内网资产"
          />
          <label htmlFor="cred-intranet-only" className="cursor-pointer">
            仅内网资产
          </label>
        </div>
        <Select value={String(size)} onValueChange={(v) => setSize(Number(v))}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} / 页
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="min-h-0 flex-1 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead className="min-w-52">凭据</TableHead>
                <TableHead className="min-w-40">所在资产</TableHead>
                <TableHead className="w-24">关系</TableHead>
                <TableHead className="w-28">目标</TableHead>
                <TableHead className="min-w-56">来源 / 证据</TableHead>
                <TableHead className="w-24">最近</TableHead>
                <TableHead className="w-20 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={7} className="py-12 text-center text-muted-foreground text-sm">
                    没有匹配的凭据。凭据由 agent 在执行中登记（record_credential）， 或在升级时从存量资产的 auth
                    字段自动回填。
                  </TableCell>
                </TableRow>
              )}
              {items.map((r) => (
                <TableRow
                  key={`${r.id}-${r.asset_id}-${r.relation}`}
                  className="cursor-pointer"
                  onClick={() => setSelected(r)}
                >
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[11px]">
                        {r.type || "unknown"}
                      </Badge>
                      <span className="truncate font-mono text-xs">
                        {credentialLabel(r).split(":").slice(1).join(":")}
                      </span>
                      {r.has_secret ? (
                        <Badge variant="secondary" className="text-[10px]">
                          有本体
                        </Badge>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="truncate font-mono text-xs">{assetLabel(r)}</div>
                    <div className="truncate text-muted-foreground text-xs">{assetSub(r)}</div>
                  </TableCell>
                  <TableCell>
                    <RelationBadge relation={r.relation} />
                  </TableCell>
                  <TableCell className="truncate font-mono text-muted-foreground text-xs">{r.target || "—"}</TableCell>
                  <TableCell>
                    <div className="truncate text-xs">{r.evidence || r.source || "—"}</div>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{fmtTime(r.last_seen)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7 text-muted-foreground hover:text-destructive"
                      onClick={(e) => {
                        e.stopPropagation();
                        setPendingDelete(r);
                      }}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between gap-2 border-t px-3 py-2 text-muted-foreground text-xs">
          <span>
            共 {total} 条 · 第 {page + 1} / {maxPage + 1} 页
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              disabled={page <= 0}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeftIcon className="size-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              disabled={page >= maxPage}
              onClick={() => setPage((p) => p + 1)}
            >
              <ChevronRightIcon className="size-4" />
            </Button>
          </div>
        </div>
      </Card>

      {/* Detail sheet */}
      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full sm:max-w-lg">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="font-mono text-base">{credentialLabel(selected)}</SheetTitle>
                <SheetDescription>
                  凭据 ID #{selected.id} ·{" "}
                  {selected.relation === "verified" ? "已在该资产上认证成功" : "仅在来源处被发现，可用性未知"}
                </SheetDescription>
              </SheetHeader>
              <div className="flex flex-col gap-3 px-4 pb-6 text-sm">
                <Field label="所在资产">
                  <span className="font-mono">{assetLabel(selected)}</span>
                  {assetSub(selected) ? <span className="text-muted-foreground">（{assetSub(selected)}）</span> : null}
                </Field>
                <Field label="关系">
                  <RelationBadge relation={selected.relation} />
                </Field>
                <Field label="目标/协议">
                  <span className="font-mono">{selected.target || "—"}</span>
                </Field>
                <Field label="来源">
                  <span className="break-all">{selected.source || "—"}</span>
                </Field>
                <Field label="证据">
                  <span className="break-all">{selected.evidence || "—"}</span>
                </Field>
                <Field label="首次登记">
                  <span>{fmtTime(selected.created_at)}</span>
                </Field>
                <Field label="最近出现">
                  <span>{fmtTime(selected.last_seen)}</span>
                </Field>
                {selected.extra && Object.keys(selected.extra).length > 0 ? (
                  <Field label="扩展属性">
                    <pre className="max-h-40 overflow-auto rounded-md bg-muted p-2 text-xs">
                      {JSON.stringify(selected.extra, null, 2)}
                    </pre>
                  </Field>
                ) : null}
                <div className="mt-2 rounded-md border border-dashed p-3 text-muted-foreground text-xs">
                  本页不显示明文凭据。需要用它访问目标时，让 agent 调用{" "}
                  <code className="font-mono">auth_request(credential_id={selected.id})</code> —— 命令由执行侧组装，
                  凭据不会进入对话与报告。
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  className="self-start"
                  onClick={() => setPendingDelete(selected)}
                >
                  <Trash2Icon className="size-4" />
                  删除该凭据
                </Button>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      {/* Delete confirm */}
      <AlertDialog open={!!pendingDelete} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除这条凭据？</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete ? credentialLabel(pendingDelete) : ""} 将被移出台账，其所有资产关联一并删除，
              且不可恢复。若只是某台资产上不再可用，可保留身份、删除对应关系即可（后续版本支持）。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDelete}>确认删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function StatTile({ label, value, hint, tone }: { label: string; value: number; hint?: string; tone?: "risk" }) {
  return (
    <Card className="gap-1 p-3">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div
        className={cn(
          "font-semibold text-2xl tabular-nums",
          tone === "risk" && value > 0 && "text-red-600 dark:text-red-400",
        )}
      >
        {value}
      </div>
      {hint ? <div className="text-muted-foreground text-xs">{hint}</div> : null}
    </Card>
  );
}

function RelationBadge({ relation }: { relation: string }) {
  // 已认证 = 真的能进，按风险色突出；仅发现 = 中性。
  if (relation === "verified") {
    return (
      <Badge variant="destructive" className="gap-1 text-[11px]">
        <ShieldCheckIcon className="size-3" />
        已认证
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-[11px]">
      仅发现
    </Badge>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-muted-foreground text-xs">{label}</span>
      <div className="text-sm">{children}</div>
    </div>
  );
}
