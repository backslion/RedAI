"use client";

import * as React from "react";

import {
  BookOpenIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  DatabaseIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  Settings2Icon,
  SparklesIcon,
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  KnowledgeConfig,
  KnowledgeDocRow,
  KnowledgeHit,
  KnowledgeSearchResult,
  KnowledgeStats,
} from "@/lib/types";
import { cn } from "@/lib/utils";

// 知识库页（v0.5.x）。
//
// 这一页解决的是「资料没有归宿」：甲方给的文档、历史报告、内部规范、现场取回的
// 配置与日志，过去只能塞进 fact 或干脆不读。现在它们以文档形式入库、被分块索引，
// agent 用 knowledge_search 检索，报告里能带出处。
//
// 两种作用域要分清：
//   - 全局库（scope=global）：跨任务可读，放方法论/规范/历史报告。
//   - 任务库（scope=task）：只属于某个任务，放客户现场资料。
// 页面上必须显式选择，避免把客户资料误写成全局资料。

const PAGE_SIZES = [25, 50, 100];
const SCOPES = [
  { value: "all", label: "全部来源" },
  { value: "global", label: "全局库" },
  { value: "task", label: "任务库" },
];

function fmtTime(ts: string) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function scopeLabel(taskId: number) {
  return taskId === 0 ? "全局" : `任务 #${taskId}`;
}

function fmtScore(v: number) {
  return (Math.round(v * 100) / 100).toFixed(2);
}

export default function KnowledgePage() {
  const [docs, setDocs] = React.useState<KnowledgeDocRow[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<KnowledgeStats | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [scope, setScope] = React.useState("all");
  const [category, setCategory] = React.useState("all");
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [size, setSize] = React.useState(50);
  const [page, setPage] = React.useState(0);
  const [reloadKey, setReloadKey] = React.useState(0);

  // 检索态：与列表分离——检索是「问一句」，列表是「盘点」。
  const [searchQ, setSearchQ] = React.useState("");
  const [searching, setSearching] = React.useState(false);
  const [searchRes, setSearchRes] = React.useState<KnowledgeSearchResult | null>(null);

  const [selected, setSelected] = React.useState<KnowledgeDocRow | null>(null);
  const [selectedContent, setSelectedContent] = React.useState("");
  const [contentLoading, setContentLoading] = React.useState(false);
  const [pendingDelete, setPendingDelete] = React.useState<KnowledgeDocRow | null>(null);

  const [importOpen, setImportOpen] = React.useState(false);
  const [configOpen, setConfigOpen] = React.useState(false);

  // 搜索输入防抖 300ms，避免每敲一个字打一次库。
  React.useEffect(() => {
    const t = window.setTimeout(() => {
      setQueryQ(query.trim());
      setPage(0);
    }, 300);
    return () => window.clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reloadKey 是刷新触发器
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .knowledgeDocs({
        scope: scope as "all" | "global" | "task",
        category,
        q: queryQ,
        limit: size,
        offset: page * size,
      })
      .then((r) => {
        if (!alive) return;
        setDocs(r.items);
        setTotal(r.total);
      })
      .catch(() => alive && setDocs([]))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [scope, category, queryQ, size, page, reloadKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: 同上，reloadKey 是刷新触发器
  React.useEffect(() => {
    let alive = true;
    api
      .knowledgeStats()
      .then((s) => alive && setStats(s))
      .catch(() => alive && setStats(null));
    return () => {
      alive = false;
    };
  }, [reloadKey]);

  const maxPage = Math.max(0, Math.ceil(total / size) - 1);
  const reload = () => setReloadKey((k) => k + 1);

  async function openDoc(row: KnowledgeDocRow) {
    setSelected(row);
    setSelectedContent("");
    setContentLoading(true);
    try {
      const r = await api.knowledgeDoc(row.id);
      setSelectedContent(r.content);
    } catch {
      setSelectedContent("（正文读取失败，可能已被删除）");
    } finally {
      setContentLoading(false);
    }
  }

  async function runSearch() {
    const q = searchQ.trim();
    if (!q) {
      setSearchRes(null);
      return;
    }
    setSearching(true);
    try {
      const r = await api.searchKnowledge(q, 0, 10);
      setSearchRes(r);
      if (r.hits.length === 0) toast.info("没有命中——换更具体的词，或先确认库里有没有相关资料");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "检索失败");
    } finally {
      setSearching(false);
    }
  }

  async function confirmDelete() {
    const row = pendingDelete;
    if (!row) return;
    setPendingDelete(null);
    try {
      await api.deleteKnowledgeDoc(row.id);
      toast.success(`已删除《${row.title}》`);
      setSelected((cur) => (cur && cur.id === row.id ? null : cur));
      reload();
    } catch {
      toast.error("删除失败——文档可能已被移除");
      reload();
    }
  }

  // 检索结果里的命中只有 doc_id，查看正文要先补一次列表查询拿元信息。
  async function openDocById(hit: KnowledgeHit) {
    try {
      const r = await api.knowledgeDoc(hit.doc_id);
      setSelected(r.doc);
      setSelectedContent(r.content);
    } catch {
      toast.error("读取文档失败——可能已被删除");
    }
  }

  // Radix Select 不接受空字符串 value：未分类的文档不进筛选项（表格里仍显示"未分类"）。
  const categories = (stats?.categories ?? []).filter((c) => c.category.trim() !== "");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <BookOpenIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">知识库</h1>
          <Badge variant="secondary">{total}</Badge>
          {stats && stats.embedded_chunks > 0 ? (
            <Badge variant="outline" className="gap-1 text-[11px]">
              <SparklesIcon className="size-3" />
              语义已启用
            </Badge>
          ) : (
            <Badge variant="outline" className="text-[11px]">
              纯关键词
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setConfigOpen(true)}>
            <Settings2Icon className="size-4" />
            向量设置
          </Button>
          <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            刷新
          </Button>
          <Button size="sm" onClick={() => setImportOpen(true)}>
            <PlusIcon className="size-4" />
            导入资料
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile
          label="文档"
          value={stats?.docs ?? 0}
          hint={`全局 ${stats?.global_docs ?? 0} / 任务 ${stats?.task_docs ?? 0}`}
        />
        <StatTile label="分块" value={stats?.chunks ?? 0} hint="agent 实际检索的粒度" />
        <StatTile
          label="已向量化"
          value={stats?.embedded_chunks ?? 0}
          hint={
            stats && stats.chunks > 0
              ? `覆盖率 ${Math.round((stats.embedded_chunks / stats.chunks) * 100)}%`
              : "未配置向量模型时按关键词检索"
          }
        />
        <StatTile label="总字数" value={stats?.chars ?? 0} hint="原文整篇入库，不做摘要" />
      </div>

      {/* Search */}
      <Card className="gap-3 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative max-w-xl flex-1">
            <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="试一句：内网横向该先做什么 / 客户给的账号体系 / SSRF 打元数据"
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void runSearch();
              }}
              className="h-9 pl-8"
            />
          </div>
          <Button size="sm" onClick={() => void runSearch()} disabled={searching}>
            {searching ? <Loader2Icon className="size-4 animate-spin" /> : <SearchIcon className="size-4" />}
            检索
          </Button>
          {searchRes ? (
            <Button variant="ghost" size="sm" onClick={() => setSearchRes(null)}>
              清除结果
            </Button>
          ) : null}
        </div>
        {searchRes ? (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2 text-muted-foreground text-xs">
              <Badge variant={searchRes.mode === "hybrid" ? "default" : "secondary"} className="text-[11px]">
                {searchRes.mode === "hybrid" ? "关键词 + 向量" : "纯关键词"}
              </Badge>
              <span>
                命中 {searchRes.hits.length} 条（候选 {searchRes.candidates}）
              </span>
              {searchRes.warning ? (
                <span className="text-amber-600 dark:text-amber-400">{searchRes.warning}</span>
              ) : null}
            </div>
            {searchRes.hits.map((h) => (
              <SearchHitCard key={h.chunk_id} hit={h} onOpen={() => void openDocById(h)} />
            ))}
          </div>
        ) : null}
      </Card>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="按标题 / 来源 / 正文过滤文档..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 pl-8"
          />
        </div>
        <Select
          value={scope}
          onValueChange={(v) => {
            setScope(v);
            setPage(0);
          }}
        >
          <SelectTrigger size="sm" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SCOPES.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={category}
          onValueChange={(v) => {
            setCategory(v);
            setPage(0);
          }}
        >
          <SelectTrigger size="sm" className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部分类</SelectItem>
            {categories.map((c) => (
              <SelectItem key={c.category || "(未分类)"} value={c.category}>
                {c.category || "(未分类)"} · {c.docs}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={String(size)}
          onValueChange={(v) => {
            setSize(Number(v));
            setPage(0);
          }}
        >
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
                <TableHead className="min-w-64">标题</TableHead>
                <TableHead className="w-32">分类</TableHead>
                <TableHead className="w-28">范围</TableHead>
                <TableHead className="min-w-48">来源</TableHead>
                <TableHead className="w-20 text-right">分块</TableHead>
                <TableHead className="w-24 text-right">字数</TableHead>
                <TableHead className="w-24">更新</TableHead>
                <TableHead className="w-20 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {docs.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center text-muted-foreground text-sm">
                    还没有资料。点右上角「导入资料」粘贴甲方文档/历史报告，或让 agent 在现场用 knowledge_add 入库。
                  </TableCell>
                </TableRow>
              )}
              {docs.map((d) => (
                <TableRow
                  key={d.id}
                  className="cursor-pointer"
                  onClick={() => void openDoc(d)}
                  data-state={selected?.id === d.id ? "selected" : undefined}
                >
                  <TableCell>
                    <div className="flex max-w-[420px] flex-col">
                      <span className="truncate font-medium">{d.title}</span>
                      <span className="truncate text-muted-foreground text-xs">{d.preview}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[11px]">
                      {d.category || "未分类"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={cn("text-xs", d.task_id === 0 ? "text-muted-foreground" : "")}>
                      {scopeLabel(d.task_id)}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-[280px] truncate font-mono text-xs">{d.source_ref || d.source}</TableCell>
                  <TableCell className="text-right tabular-nums">{d.chunk_count}</TableCell>
                  <TableCell className="text-right tabular-nums">{d.char_count}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">{fmtTime(d.updated_at)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      {d.embed_model ? (
                        <SparklesIcon className="size-3.5 text-emerald-600" aria-label="已向量化" />
                      ) : null}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        onClick={(e) => {
                          e.stopPropagation();
                          setPendingDelete(d);
                        }}
                        aria-label="删除文档"
                      >
                        <Trash2Icon className="size-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <div className="flex items-center justify-between border-t px-3 py-2">
          <div className="text-muted-foreground text-xs">
            共 {total} 篇 · 第 {page + 1} / {maxPage + 1} 页
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="icon"
              className="size-7"
              disabled={page <= 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              <ChevronLeftIcon className="size-4" />
            </Button>
            <Button
              variant="outline"
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
        <SheetContent className="w-full sm:max-w-2xl">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="text-base">{selected.title}</SheetTitle>
                <SheetDescription>
                  #{selected.id} · {scopeLabel(selected.task_id)} · {selected.category || "未分类"} ·{" "}
                  {selected.chunk_count} 块 / {selected.char_count} 字
                </SheetDescription>
              </SheetHeader>
              <div className="flex min-h-0 flex-col gap-3 px-4 pb-6">
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="outline">来源：{selected.source}</Badge>
                  {selected.source_ref ? (
                    <Badge variant="outline" className="max-w-full truncate font-mono">
                      {selected.source_ref}
                    </Badge>
                  ) : null}
                  <Badge variant={selected.embed_model ? "default" : "secondary"}>
                    {selected.embed_model ? `向量：${selected.embed_model}` : "未向量化"}
                  </Badge>
                  <Badge variant="outline">更新 {fmtTime(selected.updated_at)}</Badge>
                </div>
                <div className="min-h-0 flex-1 overflow-auto rounded-md border bg-muted/30 p-3">
                  {contentLoading ? (
                    <div className="flex items-center gap-2 text-muted-foreground text-sm">
                      <Loader2Icon className="size-4 animate-spin" />
                      读取正文...
                    </div>
                  ) : (
                    <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed">
                      {selectedContent}
                    </pre>
                  )}
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      <ImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onDone={(msg) => {
          toast.success(msg);
          reload();
        }}
      />
      <ConfigDialog
        open={configOpen}
        onOpenChange={setConfigOpen}
        onDone={() => {
          toast.success("向量配置已保存，对后续入库与检索立即生效");
          reload();
        }}
      />

      <AlertDialog open={!!pendingDelete} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除这篇资料？</AlertDialogTitle>
            <AlertDialogDescription>
              《{pendingDelete?.title ?? ""}》及其 {pendingDelete?.chunk_count ?? 0} 个分块会被一并删除， 之后 agent
              检索不到。删除不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={() => void confirmDelete()}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SearchHitCard({ hit, onOpen }: { hit: KnowledgeHit; onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-full flex-col gap-1 rounded-md border p-2.5 text-left transition-colors hover:bg-muted/50"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-sm">{hit.title}</span>
        <Badge variant="outline" className="text-[11px]">
          {hit.category || "未分类"}
        </Badge>
        {hit.task_id === 0 ? (
          <Badge variant="secondary" className="text-[11px]">
            全局
          </Badge>
        ) : null}
        <span className="text-muted-foreground text-xs">score {fmtScore(hit.score)}</span>
        <span className="text-muted-foreground text-xs">
          关键词 {fmtScore(hit.keyword)} · 向量 {fmtScore(hit.vector)}
        </span>
        {hit.source_ref ? (
          <span className="max-w-[240px] truncate font-mono text-muted-foreground text-xs">{hit.source_ref}</span>
        ) : null}
      </div>
      <div className="text-sm leading-relaxed">{hit.snippet}</div>
    </button>
  );
}

function ImportDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: (msg: string) => void;
}) {
  const [title, setTitle] = React.useState("");
  const [category, setCategory] = React.useState("");
  const [sourceRef, setSourceRef] = React.useState("");
  const [content, setContent] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [scope, setScope] = React.useState<"global" | "task">("global");
  const [taskId, setTaskId] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function submit() {
    if (!content.trim() && !url.trim()) {
      toast.error("正文与 URL 至少要给一个");
      return;
    }
    if (scope === "task") {
      const id = Number(taskId);
      if (!Number.isFinite(id) || id <= 0) {
        toast.error("写任务库必须填任务 ID");
        return;
      }
    }
    setBusy(true);
    try {
      const r = await api.createKnowledgeDoc({
        title: title.trim(),
        category: category.trim(),
        source_ref: sourceRef.trim(),
        content: content.trim() || undefined,
        url: url.trim() || undefined,
        scope,
        task_id: scope === "task" ? Number(taskId) : 0,
      });
      onDone(
        `已入库：${r.chunks} 个分块${r.embedded_chunks > 0 ? `，${r.embedded_chunks} 个已向量化` : ""}${
          r.warning ? `（${r.warning}）` : ""
        }`,
      );
      setTitle("");
      setCategory("");
      setSourceRef("");
      setContent("");
      setUrl("");
      onOpenChange(false);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "入库失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>导入资料</DialogTitle>
          <DialogDescription>
            原文整篇入库，分块与索引由服务端做。不要先总结：IP、路径、报错码这些检索关键信息会在摘要里丢掉。
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="kd-title">标题</Label>
              <Input
                id="kd-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="留空取正文首行"
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="kd-cat">分类</Label>
              <Input
                id="kd-cat"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                placeholder="客户资料 / 历史报告 / 内部规范 / payload"
              />
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kd-src">来源标注</Label>
            <Input
              id="kd-src"
              value={sourceRef}
              onChange={(e) => setSourceRef(e.target.value)}
              placeholder="文件名或网页地址，报告引用时靠它追溯出处"
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="kd-scope">作用域</Label>
              <Select value={scope} onValueChange={(v) => setScope(v as "global" | "task")}>
                <SelectTrigger id="kd-scope">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="global">全局库（跨任务）</SelectItem>
                  <SelectItem value="task">任务库（仅本任务）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="col-span-2 flex flex-col gap-1">
              <Label htmlFor="kd-task">任务 ID</Label>
              <Input
                id="kd-task"
                value={taskId}
                onChange={(e) => setTaskId(e.target.value)}
                disabled={scope !== "task"}
                placeholder={scope === "task" ? "必填，如 42" : "全局库不需要"}
                inputMode="numeric"
              />
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kd-content">正文</Label>
            <Textarea
              id="kd-content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="粘贴文档正文。留空则使用下面的 URL 抓取。"
              className="min-h-40"
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kd-url">或抓取网页</Label>
            <Input
              id="kd-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://...（只支持 http/https，正文非空时忽略此项）"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={() => void submit()} disabled={busy}>
            {busy ? <Loader2Icon className="size-4 animate-spin" /> : <DatabaseIcon className="size-4" />}
            入库
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ConfigDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: () => void;
}) {
  const [cfg, setCfg] = React.useState<KnowledgeConfig | null>(null);
  const [enabled, setEnabled] = React.useState(false);
  const [baseUrl, setBaseUrl] = React.useState("");
  const [model, setModel] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [dim, setDim] = React.useState("0");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    let alive = true;
    api
      .knowledgeConfig()
      .then((c) => {
        if (!alive) return;
        setCfg(c);
        setEnabled(c.enabled);
        setBaseUrl(c.base_url);
        setModel(c.model);
        setDim(String(c.dim));
        setApiKey("");
      })
      .catch(() => alive && setCfg(null));
    return () => {
      alive = false;
    };
  }, [open]);

  async function save() {
    setBusy(true);
    try {
      await api.saveKnowledgeConfig({
        enabled,
        base_url: baseUrl.trim(),
        model: model.trim(),
        api_key: apiKey.trim(),
        dim: Number(dim) || 0,
      });
      onDone();
      onOpenChange(false);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>向量模型（可选）</DialogTitle>
          <DialogDescription>
            填 OpenAI 兼容的 embeddings 接口即可开启语义召回；不填也能用——检索会退化为纯关键词，中文按二元组匹配。
            已入库但未向量化的分块不会自动补算（重新导入即可）。
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between rounded-md border p-2.5">
            <div className="flex flex-col">
              <span className="text-sm">启用向量检索</span>
              <span className="text-muted-foreground text-xs">关闭时所有入库与检索都只走关键词</span>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="启用向量检索" />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kc-base">Base URL</Label>
            <Input
              id="kc-base"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.openai.com/v1"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="kc-model">模型</Label>
              <Input
                id="kc-model"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="text-embedding-3-small"
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="kc-dim">维度（0=服务端决定）</Label>
              <Input id="kc-dim" value={dim} onChange={(e) => setDim(e.target.value)} inputMode="numeric" />
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kc-key">API Key</Label>
            <Input
              id="kc-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={cfg?.has_key ? `已配置 ${cfg.key_hint ?? ""}，留空保持不变` : "未配置"}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={() => void save()} disabled={busy}>
            {busy ? <Loader2Icon className="size-4 animate-spin" /> : null}
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function StatTile({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <Card className="gap-1 p-3">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className="font-semibold text-2xl tabular-nums">{value.toLocaleString("zh-CN")}</div>
      {hint ? <div className="text-muted-foreground text-xs">{hint}</div> : null}
    </Card>
  );
}
