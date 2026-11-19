"use client";

import * as React from "react";

import {
  ActivityIcon,
  BugIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  TerminalIcon,
  Trash2Icon,
  UploadIcon,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { WebShellExecResult, WebShellPayload, WebShellProbeResult, WebShellSession } from "@/lib/types";
import { copyText as writeClipboard, safeUUID } from "@/lib/utils";

// WebShell 通道管理页。
//
// 这一页对应的是「平台 → 目标上的马」：马已经落地（或由 agent 落地），平台把它
// 登记下来，之后可以持续执行命令、传文件、查活、最后清干净。
//
// 三层信息刻意分开显示，因为处置含义完全不同：
//   会话状态 —— 能不能连（unreachable / not_mine / ok）
//   出口     —— 请求从哪出去（直连是需要在页面上被看见的事实）
//   落地物   —— 马在哪、上传过什么（清痕迹的依据）
//
// 刻意不做的事：
//   - 不回显参数名。它等价于马的钥匙，服务端投影里就没有它；编辑时留空=保持原样。
//   - 不默认清远端。删会话默认只摘登记，要删文件必须显式勾选并二次确认。
//   - 不在页面上做「自动重连/自动保活」。维持是人的决策，不是界面的默认行为。

const TYPES = [
  { value: "php", label: "PHP（eval 型，自动识别载荷）" },
  { value: "php_raw", label: "PHP（只吃 PHP 代码）" },
  { value: "jsp", label: "JSP（命令型）" },
  { value: "aspx", label: "ASPX（命令型）" },
];

/** 执行面板的一条历史。id 用随机值：命令文本可能重复，下标会在清空/重排时串。 */
type HistItem = {
  id: string;
  cmd: string;
  res?: WebShellExecResult;
  err?: string;
};

type Draft = {
  name: string;
  url: string;
  type: string;
  param: string;
  method: string;
  remotePath: string;
  note: string;
  proxy: string;
  overwrite: boolean;
};

function emptyDraft(): Draft {
  return {
    name: "",
    url: "",
    type: "php",
    param: "",
    method: "POST",
    remotePath: "",
    note: "",
    proxy: "",
    overwrite: false,
  };
}

function fmtTime(s?: string) {
  if (!s) return "—";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

/** 状态色：ok 绿 / 未探测灰 / 失败红。 */
function stateBadge(p?: WebShellProbeResult) {
  if (!p) return <Badge variant="secondary">未探测</Badge>;
  if (p.alive) {
    return (
      <Badge className="bg-emerald-600/15 text-emerald-700 dark:text-emerald-400" variant="secondary">
        在线 · {p.latency_ms}ms
      </Badge>
    );
  }
  if (p.state === "not_mine") {
    return (
      <Badge className="bg-amber-600/15 text-amber-700 dark:text-amber-400" variant="secondary">
        不是我的马
      </Badge>
    );
  }
  return (
    <Badge className="bg-red-600/15 text-red-700 dark:text-red-400" variant="secondary">
      连不上
    </Badge>
  );
}

export default function WebShellPage() {
  const [items, setItems] = React.useState<WebShellSession[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState<string>("");
  const [probes, setProbes] = React.useState<Record<string, WebShellProbeResult>>({});
  const [payloads, setPayloads] = React.useState<WebShellPayload[]>([]);
  const [payloadDir, setPayloadDir] = React.useState("");
  const [showPayloads, setShowPayloads] = React.useState(false);

  // 新建
  const [addOpen, setAddOpen] = React.useState(false);
  const [draft, setDraft] = React.useState<Draft>(emptyDraft());

  // 执行面板
  const [active, setActive] = React.useState<WebShellSession | null>(null);
  const [cmd, setCmd] = React.useState("");
  const [history, setHistory] = React.useState<HistItem[]>([]);

  // 上传 / 下载
  const [uploadOpen, setUploadOpen] = React.useState(false);
  const [uploadPath, setUploadPath] = React.useState("");
  const [uploadData, setUploadData] = React.useState("");
  const [downloadOpen, setDownloadOpen] = React.useState(false);
  const [downloadPath, setDownloadPath] = React.useState("");
  const [downloadOut, setDownloadOut] = React.useState("");

  // 清理
  const [purgeTarget, setPurgeTarget] = React.useState<WebShellSession | null>(null);
  const [purgeRemote, setPurgeRemote] = React.useState(false);
  const [purgeForce, setPurgeForce] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.webshells();
      setItems(r.items);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载会话失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const loadPayloads = React.useCallback(async () => {
    try {
      const r = await api.webshellPayloads();
      setPayloads(r.items);
      setPayloadDir(r.payload_dir);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载载荷失败");
    }
  }, []);

  React.useEffect(() => {
    if (showPayloads && payloads.length === 0) void loadPayloads();
  }, [showPayloads, payloads.length, loadPayloads]);

  async function save() {
    if (!draft.url.trim()) {
      toast.error("URL 不能为空");
      return;
    }
    setBusy("add");
    try {
      await api.addWebshell({
        name: draft.name.trim() || undefined,
        url: draft.url.trim(),
        type: draft.type,
        param: draft.param.trim() || undefined,
        method: draft.method,
        remote_path: draft.remotePath.trim() || undefined,
        note: draft.note.trim() || undefined,
        proxy: draft.proxy.trim() || undefined,
        overwrite: draft.overwrite,
      });
      toast.success("会话已登记");
      setAddOpen(false);
      setDraft(emptyDraft());
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "登记失败");
    } finally {
      setBusy("");
    }
  }

  async function probeOne(name: string) {
    setBusy(`probe:${name}`);
    try {
      const r = await api.probeWebshell({ name, deep: true });
      if (r.item) {
        setProbes((p) => ({ ...p, [name]: r.item as WebShellProbeResult }));
        if (r.item.alive) {
          toast.success(`${name}: 在线${r.item.identity ? `（${r.item.identity.split("\n")[0]}）` : ""}`);
        } else {
          toast.warning(`${name}: ${r.item.detail ?? r.item.state}`);
        }
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "巡检失败");
    } finally {
      setBusy("");
    }
  }

  async function probeAll() {
    if (items.length === 0) return;
    setBusy("probe:all");
    try {
      const r = await api.probeWebshell({ deep: false });
      const next: Record<string, WebShellProbeResult> = {};
      for (const it of r.items ?? []) next[it.name] = it;
      setProbes(next);
      toast.success(`巡检完成：${r.alive ?? 0} 在线 / ${r.failed ?? 0} 异常`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "巡检失败");
    } finally {
      setBusy("");
    }
  }

  async function runCmd() {
    if (!active || !cmd.trim()) return;
    const name = active.name;
    const line = cmd.trim();
    setCmd("");
    setHistory((h) => [...h, { id: safeUUID(), cmd: line }]);
    setBusy(`exec:${name}`);
    try {
      const r = await api.execWebshell(name, line);
      setHistory((h) => {
        const next = [...h];
        const last = next[next.length - 1];
        next[next.length - 1] = { ...last, res: r };
        return next;
      });
      setProbes((p) => ({
        ...p,
        [name]: { ...(p[name] ?? { name, alive: true, state: "ok", latency_ms: 0 }), alive: true, state: "ok" },
      }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "执行失败";
      setHistory((h) => {
        const next = [...h];
        const last = next[next.length - 1];
        next[next.length - 1] = { ...last, err: msg };
        return next;
      });
    } finally {
      setBusy("");
    }
  }

  async function doUpload() {
    if (!active || !uploadPath.trim() || !uploadData.trim()) {
      toast.error("路径与内容都要填");
      return;
    }
    setBusy("upload");
    try {
      const r = await api.uploadWebshell(active.name, {
        remote_path: uploadPath.trim(),
        content_b64: uploadData.trim(),
      });
      toast.success(`已写入 ${r.result.bytes} 字节（${r.result.chunks} 块）`);
      setUploadOpen(false);
      setUploadPath("");
      setUploadData("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "上传失败");
    } finally {
      setBusy("");
    }
  }

  async function doDownload() {
    if (!active || !downloadPath.trim()) return;
    setBusy("download");
    setDownloadOut("读取中…");
    try {
      const r = await api.downloadWebshell(active.name, downloadPath.trim());
      const head = `// ${r.remote_path} · ${r.bytes}/${r.remote_size} 字节${r.truncated ? "（已截断）" : ""} · 出口 ${r.egress}\n`;
      setDownloadOut(head + (r.text ? (r.content ?? "") : `base64:\n${r.content_b64 ?? ""}`));
    } catch (e) {
      setDownloadOut(`读取失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy("");
    }
  }

  async function doPurge() {
    if (!purgeTarget) return;
    setBusy("purge");
    try {
      const r = await api.deleteWebshell(purgeTarget.name, {
        remove_remote: purgeRemote,
        force: purgeForce,
      });
      const res = r.result;
      if (res.local_removed) {
        toast.success(
          res.remote_touched
            ? `已清理并摘登记（远端复查：${res.verified ? "通过" : "未通过"}）`
            : "已摘登记（远端未动）",
        );
      } else {
        toast.warning(res.detail || "远端未清干净，登记已保留");
      }
      setPurgeTarget(null);
      setPurgeRemote(false);
      setPurgeForce(false);
      if (active?.name === purgeTarget.name) setActive(null);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "清理失败");
    } finally {
      setBusy("");
    }
  }

  async function copyPayload(name: string) {
    try {
      const r = await api.webshellPayload(name, "pass");
      if (await writeClipboard(r.content)) {
        toast.success("载荷已复制（参数名 pass，登记时要用同一个）");
      } else {
        toast.error("复制失败——浏览器拒绝访问剪贴板");
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "取载荷失败");
    }
  }

  const online = Object.values(probes).filter((p) => p.alive).length;
  const direct = items.filter((i) => i.egress === "直连").length;

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl">
            <BugIcon className="size-5" />
            WebShell 通道
          </h1>
          <p className="mt-1 max-w-3xl text-muted-foreground text-sm">
            把已落地的马登记成可复用入口：执行命令、传文件、查活、受管清理。会话按任务隔离，
            参数名与请求头值永不出现在本页。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            刷新
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void probeAll()}
            disabled={busy !== "" || items.length === 0}
          >
            <ActivityIcon className="size-4" />
            全部巡检
          </Button>
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <PlusIcon className="size-4" />
            登记会话
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">会话数</div>
          <div className="mt-1 font-semibold text-2xl">{items.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">本轮在线</div>
          <div className="mt-1 font-semibold text-2xl">{online}</div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">直连出口</div>
          <div className="mt-1 font-semibold text-2xl">
            {direct}
            {direct > 0 && <span className="ml-2 font-normal text-amber-600 text-xs">目标可见平台 IP</span>}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-muted-foreground text-xs">载荷库</div>
          <div className="mt-1 truncate font-medium text-sm" title={payloadDir || "内置模板"}>
            {payloadDir || "内置模板"}
          </div>
        </Card>
      </div>

      {items.length === 0 ? (
        <Card className="flex flex-col items-center gap-3 p-10 text-center">
          <TerminalIcon className="size-8 text-muted-foreground" />
          <div className="font-medium">还没有登记任何会话</div>
          <p className="max-w-lg text-muted-foreground text-sm">
            马落地后在这里登记（或用 agent 的 webshell_add）。登记后平台才能复用这条入口、
            复查是否还活着，并在收尾时按落地路径清干净。
          </p>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => setAddOpen(true)}>
              登记会话
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowPayloads(true)}>
              看看有哪些载荷
            </Button>
          </div>
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {items.map((it) => {
            const p = probes[it.name];
            return (
              <Card key={it.name} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{it.name}</span>
                      <Badge variant="outline">{it.type}</Badge>
                      <Badge variant="secondary">{it.method}</Badge>
                      {stateBadge(p)}
                      {it.egress === "直连" ? (
                        <Badge className="bg-amber-600/15 text-amber-700 dark:text-amber-400" variant="secondary">
                          直连
                        </Badge>
                      ) : (
                        <Badge variant="secondary">出口 {it.egress}</Badge>
                      )}
                      {it.task_id ? <Badge variant="outline">任务 #{it.task_id}</Badge> : null}
                    </div>
                    <div className="mt-1 truncate font-mono text-muted-foreground text-xs" title={it.url}>
                      {it.url}
                    </div>
                    {p?.identity ? (
                      <div className="mt-1 truncate font-mono text-emerald-700 text-xs dark:text-emerald-400">
                        身份: {p.identity.split("\n")[0]}
                      </div>
                    ) : null}
                    {p && !p.alive && p.detail ? (
                      <div className="mt-1 text-red-600 text-xs dark:text-red-400">{p.detail}</div>
                    ) : null}
                    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground text-xs">
                      {it.remote_path ? <span>马: {it.remote_path}</span> : <span>马路径未登记</span>}
                      {it.artifacts?.length ? <span>上传物 {it.artifacts.length} 个</span> : null}
                      {it.note ? <span>{it.note}</span> : null}
                      <span>登记 {fmtTime(it.created_at)}</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setActive(it);
                        setHistory([]);
                        setDownloadOut("");
                      }}
                    >
                      <TerminalIcon className="size-4" />
                      执行
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void probeOne(it.name)}
                      disabled={busy === `probe:${it.name}`}
                    >
                      {busy === `probe:${it.name}` ? (
                        <Loader2Icon className="size-4 animate-spin" />
                      ) : (
                        <ActivityIcon className="size-4" />
                      )}
                      巡检
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setActive(it);
                        setUploadOpen(true);
                      }}
                    >
                      <UploadIcon className="size-4" />
                      上传
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setActive(it);
                        setDownloadOpen(true);
                      }}
                    >
                      <DownloadIcon className="size-4" />
                      下载
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setPurgeTarget(it)}>
                      <Trash2Icon className="size-4" />
                      清理
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      <Card className="p-4">
        <button
          type="button"
          className="flex w-full items-center gap-2 text-left"
          onClick={() => setShowPayloads((v) => !v)}
        >
          {showPayloads ? <ChevronDownIcon className="size-4" /> : <ChevronRightIcon className="size-4" />}
          <span className="font-medium text-sm">载荷模板</span>
          <span className="text-muted-foreground text-xs">
            {payloadDir ? `自备库 ${payloadDir}` : "内置最小可用模板（点击展开）"}
          </span>
        </button>
        {showPayloads && (
          <div className="mt-3 flex flex-col gap-2">
            {payloads.length === 0 ? (
              <div className="text-muted-foreground text-sm">没有可用载荷。</div>
            ) : (
              payloads.map((p) => (
                <div key={p.name} className="flex flex-wrap items-start justify-between gap-2 rounded-md border p-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{p.name}</span>
                      <Badge variant="outline">{p.type}</Badge>
                      {p.builtin ? <Badge variant="secondary">内置</Badge> : null}
                    </div>
                    {p.summary ? <div className="mt-1 text-muted-foreground text-xs">{p.summary}</div> : null}
                    <div className="mt-1 flex flex-wrap gap-x-4 text-muted-foreground text-xs">
                      {p.scene ? <span>适用: {p.scene}</span> : null}
                      {p.perm ? <span>权限: {p.perm}</span> : null}
                    </div>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => void copyPayload(p.name)}>
                    <CopyIcon className="size-4" />
                    复制
                  </Button>
                </div>
              ))
            )}
            <p className="text-muted-foreground text-xs">
              内置模板只用于验证链路。要过目标 WAF/EDR 请自备马，放到
              <code className="mx-1 rounded bg-muted px-1">POJUN_WEBSHELL_PAYLOAD_DIR</code>
              下的 php/jsp/aspx 子目录。
            </p>
          </div>
        )}
      </Card>

      {/* 登记会话 */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>登记 WebShell 会话</DialogTitle>
            <DialogDescription>
              只登记已经能访问到的马。参数名要与载荷里的一致（默认 pass）；马的绝对路径用于清痕迹，填错会删不掉。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <div className="mb-1 text-xs">URL</div>
              <Input
                placeholder="http://10.0.0.5/upload/x.php"
                value={draft.url}
                onChange={(e) => setDraft({ ...draft, url: e.target.value })}
              />
            </div>
            <div>
              <div className="mb-1 text-xs">类型</div>
              <Select value={draft.type} onValueChange={(v) => setDraft({ ...draft, type: v })}>
                <SelectTrigger>
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
            </div>
            <div>
              <div className="mb-1 text-xs">请求方法</div>
              <Select value={draft.method} onValueChange={(v) => setDraft({ ...draft, method: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="GET">GET</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <div className="mb-1 text-xs">名称（留空自动生成）</div>
              <Input
                placeholder="web-01"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </div>
            <div>
              <div className="mb-1 text-xs">参数名（默认 pass）</div>
              <Input
                placeholder="pass"
                value={draft.param}
                onChange={(e) => setDraft({ ...draft, param: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <div className="mb-1 text-xs">马的绝对路径（清痕迹用）</div>
              <Input
                placeholder="/var/www/html/x.php"
                value={draft.remotePath}
                onChange={(e) => setDraft({ ...draft, remotePath: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <div className="mb-1 text-xs">出口代理（可选，避免目标日志里出现平台 IP）</div>
              <Input
                placeholder="socks5h://user:pass@127.0.0.1:1080"
                value={draft.proxy}
                onChange={(e) => setDraft({ ...draft, proxy: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <div className="mb-1 text-xs">备注</div>
              <Input
                placeholder="边界 Web-01 / 从上传漏洞落地"
                value={draft.note}
                onChange={(e) => setDraft({ ...draft, note: e.target.value })}
              />
            </div>
            <div className="flex items-center gap-2 sm:col-span-2">
              <Checkbox
                id="ws-overwrite"
                checked={draft.overwrite}
                onCheckedChange={(v) => setDraft({ ...draft, overwrite: v === true })}
              />
              <label htmlFor="ws-overwrite" className="text-sm">
                同名会话覆盖已有的
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void save()} disabled={busy === "add"}>
              {busy === "add" ? <Loader2Icon className="size-4 animate-spin" /> : null}
              登记
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 执行面板 */}
      <Dialog
        open={active !== null && !uploadOpen && !downloadOpen}
        onOpenChange={(v) => {
          if (!v) {
            setActive(null);
            setHistory([]);
          }
        }}
      >
        <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <TerminalIcon className="size-4" />
              {active?.name}
            </DialogTitle>
            <DialogDescription>
              {active ? `${active.type} · ${active.url} · 出口 ${active.egress ?? "直连"}` : ""}
            </DialogDescription>
          </DialogHeader>

          <div className="flex h-72 flex-col gap-2 overflow-y-auto rounded-md border bg-muted/30 p-3 font-mono text-xs">
            {history.length === 0 ? (
              <div className="text-muted-foreground">输入命令开始。PHP 会话会自动识别 eval / base64 两种载荷。</div>
            ) : (
              history.map((h) => (
                <div key={h.id} className="flex flex-col gap-1">
                  <div className="text-emerald-700 dark:text-emerald-400">$ {h.cmd}</div>
                  {h.err ? (
                    <div className="whitespace-pre-wrap text-red-600 dark:text-red-400">{h.err}</div>
                  ) : (
                    <div className="whitespace-pre-wrap">{h.res?.output || "(无输出)"}</div>
                  )}
                  {h.res ? (
                    <div className="text-muted-foreground">
                      [{h.res.mode} · {h.res.egress}
                      {h.res.truncated ? " · 已截断" : ""}]
                    </div>
                  ) : null}
                </div>
              ))
            )}
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="id; uname -a"
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void runCmd();
                }
              }}
            />
            <Button onClick={() => void runCmd()} disabled={busy.startsWith("exec:") || !cmd.trim()}>
              {busy.startsWith("exec:") ? <Loader2Icon className="size-4 animate-spin" /> : "执行"}
            </Button>
          </div>
          <p className="text-muted-foreground text-xs">
            每次执行都会在目标访问日志里留下一次请求。命令可带引号与管道——平台会 base64 包装。
          </p>
        </DialogContent>
      </Dialog>

      {/* 上传 */}
      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>上传文件到 {active?.name}</DialogTitle>
            <DialogDescription>
              内容用 base64（避免二进制/换行损坏）。PHP 会话按块写入，每块有独立回执；写过的路径会记进 artifacts，
              清理时一并处理。
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div>
              <div className="mb-1 text-xs">目标绝对路径</div>
              <Input
                placeholder="/tmp/tools/fscan"
                value={uploadPath}
                onChange={(e) => setUploadPath(e.target.value)}
              />
            </div>
            <div>
              <div className="mb-1 text-xs">内容（base64）</div>
              <Textarea
                className="min-h-32 font-mono text-xs"
                placeholder="把 base64 粘贴到这里"
                value={uploadData}
                onChange={(e) => setUploadData(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void doUpload()} disabled={busy === "upload"}>
              {busy === "upload" ? <Loader2Icon className="size-4 animate-spin" /> : "写入"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 下载 */}
      <Dialog open={downloadOpen} onOpenChange={setDownloadOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>读取 {active?.name} 上的文件</DialogTitle>
            <DialogDescription>文本直接显示；二进制以 base64 返回。默认 2MB 上限。</DialogDescription>
          </DialogHeader>
          <div className="flex gap-2">
            <Input
              placeholder="/etc/passwd"
              value={downloadPath}
              onChange={(e) => setDownloadPath(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void doDownload();
              }}
            />
            <Button onClick={() => void doDownload()} disabled={busy === "download"}>
              {busy === "download" ? <Loader2Icon className="size-4 animate-spin" /> : "读取"}
            </Button>
          </div>
          {downloadOut ? (
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md border bg-muted/30 p-3 font-mono text-xs">
              {downloadOut}
            </pre>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* 清理 */}
      <AlertDialog open={purgeTarget !== null} onOpenChange={(v) => !v && setPurgeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldAlertIcon className="size-4" />
              清理会话 {purgeTarget?.name}
            </AlertDialogTitle>
            <AlertDialogDescription>
              默认只摘登记，不动远端——马留不留由人决定。勾选「同时清远端」会删除马本体与经本平台上传的文件，
              并在删除后再请求一次确认打不通。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-2 text-sm">
            <div className="flex items-center gap-2">
              <Checkbox
                id="ws-purge-remote"
                checked={purgeRemote}
                onCheckedChange={(v) => setPurgeRemote(v === true)}
              />
              <label htmlFor="ws-purge-remote">同时清远端（删除马 + artifacts，不可逆）</label>
            </div>
            {purgeRemote && (
              <div className="flex items-center gap-2">
                <Checkbox id="ws-purge-force" checked={purgeForce} onCheckedChange={(v) => setPurgeForce(v === true)} />
                <label htmlFor="ws-purge-force">复查未通过也摘登记（远端可能仍有残留）</label>
              </div>
            )}
            {purgeTarget?.remote_path ? (
              <div className="font-mono text-muted-foreground text-xs">马: {purgeTarget.remote_path}</div>
            ) : (
              <div className="text-amber-600 text-xs">未登记马路径：命令型马将无法自删，PHP 马会尝试自报路径。</div>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void doPurge();
              }}
              disabled={busy === "purge"}
            >
              {busy === "purge" ? <Loader2Icon className="size-4 animate-spin" /> : "执行清理"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
