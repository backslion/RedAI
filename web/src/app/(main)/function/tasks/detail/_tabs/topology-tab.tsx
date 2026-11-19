"use client";

// 内网拓扑页签。
//
// 呈现分两层，刻意不合并：
//   - 网段/主机来自资产入库（「我知道它存在」）；
//   - 实测可达来自隧道连接日志（「我确实拨通过」）。
// 混成一个「边」，复盘时就分不清哪条是猜的、哪条是打出来的。
//
// 「实测」只在当前进程生命周期内有效：隧道是内存状态，服务重启即失。
// 所以这里不把它写成资产属性，只作为本轮会话的观测结果展示。

import * as React from "react";
import { CircleDotIcon, NetworkIcon, RefreshCwIcon, ServerIcon, ShieldCheckIcon, WaypointsIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { TaskTopology, TopologySegment } from "@/lib/types";
import { cn } from "@/lib/utils";

// 单个网段默认展示的主机数；超出折叠，避免大网段把页面拉成几屏。
const HOST_FOLD = 12;

export function TopologyTab({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<TaskTopology | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({});

  const load = React.useCallback(async () => {
    try {
      const next = await api.taskTopology(taskId);
      setData(next);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    setLoading(true);
    void load();
    // 隧道是运行时状态，定期刷新才能看到新拨通的边。20s 足够，且这个接口只读。
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load]);

  const stats = React.useMemo(() => {
    const segs = data?.segments ?? [];
    let hosts = 0;
    let authorizedSegs = 0;
    let verifiedHosts = 0;
    for (const s of segs) {
      hosts += s.host_count;
      if (s.authorized) authorizedSegs++;
      verifiedHosts += s.verified;
    }
    return { segs: segs.length, hosts, authorizedSegs, verifiedHosts };
  }, [data]);

  if (loading && !data) {
    return (
      <div className="flex h-40 items-center justify-center text-muted-foreground text-sm">
        <Spinner className="mr-2 size-4" />
        正在汇总网段…
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="flex h-40 flex-col items-center justify-center gap-3 text-muted-foreground text-sm">
        <p>加载失败：{error}</p>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          <RefreshCwIcon className="mr-1.5 size-4" />
          重试
        </Button>
      </div>
    );
  }

  const segments = data?.segments ?? [];
  const landings = data?.landings ?? [];

  return (
    <div className="space-y-4">
      {/* 汇总条 */}
      <div className="flex flex-wrap items-center gap-2">
        <StatChip icon={NetworkIcon} label="网段" value={stats.segs} />
        <StatChip icon={ShieldCheckIcon} label="已授权网段" value={stats.authorizedSegs} />
        <StatChip icon={ServerIcon} label="主机" value={stats.hosts} />
        <StatChip
          icon={CircleDotIcon}
          label="实测可达"
          value={stats.verifiedHosts}
          hint="经隧道真实拨通过的主机数；只在本次服务运行期间累计"
        />
        <div className="ml-auto flex items-center gap-2">
          <span className="text-muted-foreground text-xs">
            {data?.generated_at ? `快照 ${new Date(data.generated_at).toLocaleTimeString()}` : ""}
          </span>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            <RefreshCwIcon className="mr-1.5 size-4" />
            刷新
          </Button>
        </div>
      </div>

      {/* 立足点 */}
      {landings.length > 0 && (
        <Card>
          <CardContent className="space-y-2 p-4">
            <p className="flex items-center gap-1.5 font-medium text-sm">
              <WaypointsIcon className="size-4" />
              立足点（{landings.length}）
            </p>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {landings.map((l) => (
                <div key={`${l.kind}:${l.id}`} className="rounded-md border p-2.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={cn("size-2 rounded-full", l.alive ? "bg-emerald-500" : "bg-muted-foreground/40")}
                    />
                    <span className="truncate font-medium text-xs">{l.label || l.id}</span>
                    <Badge variant="outline" className="ml-auto shrink-0 text-[10px]">
                      {l.kind === "webshell" ? "WebShell" : "SSH"}
                    </Badge>
                  </div>
                  {l.hops && l.hops.length > 0 && (
                    <p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{l.hops.join(" → ")}</p>
                  )}
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {l.targets && l.targets.length > 0 ? `拨通过 ${l.targets.length} 个目标` : "尚未拨通任何目标"}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 网段 */}
      {segments.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-muted-foreground text-sm">
            <NetworkIcon className="mx-auto mb-2 size-8 opacity-40" />
            <p>任务范围内还没有带 IP 的资产。</p>
            <p className="mt-1 text-xs">
              网段来自资产入库（insert_assets），不是手工填的；先让 agent 收一批资产，这里才会有内容。
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {segments.map((seg) => (
            <SegmentCard
              key={seg.cidr}
              seg={seg}
              expanded={!!expanded[seg.cidr]}
              onToggle={() => setExpanded((prev) => ({ ...prev, [seg.cidr]: !prev[seg.cidr] }))}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function StatChip({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  hint?: string;
}) {
  return (
    <div className="flex items-center gap-2 rounded-md border px-2.5 py-1.5" title={hint}>
      <Icon className="size-3.5 text-muted-foreground" />
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="font-semibold text-sm tabular-nums">{value}</span>
    </div>
  );
}

function SegmentCard({
  seg,
  expanded,
  onToggle,
}: {
  seg: TopologySegment;
  expanded: boolean;
  onToggle: () => void;
}) {
  const hosts = expanded ? seg.hosts : seg.hosts.slice(0, HOST_FOLD);
  const hidden = seg.hosts.length - hosts.length;
  return (
    <Card className={cn(!seg.authorized && "border-dashed")}>
      <CardContent className="space-y-2 p-4">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono font-semibold text-sm">{seg.cidr}</span>
          {seg.authorized ? (
            <Badge className="bg-emerald-600/10 text-[10px] text-emerald-700 dark:text-emerald-400" variant="outline">
              已授权
            </Badge>
          ) : (
            <Badge className="text-[10px]" variant="outline">
              未授权
            </Badge>
          )}
          <span className="ml-auto flex items-center gap-2 text-muted-foreground text-xs">
            <span>{seg.host_count} 主机</span>
            <span>已测 {seg.tested}</span>
            {seg.verified > 0 && (
              <span className="text-emerald-600 dark:text-emerald-400">实测 {seg.verified}</span>
            )}
          </span>
        </div>
        <div className="space-y-1">
          {hosts.map((h) => (
            <div key={h.ip} className="flex flex-wrap items-center gap-1.5 rounded px-1 py-0.5 hover:bg-muted/50">
              <span
                className={cn(
                  "size-1.5 shrink-0 rounded-full",
                  h.tested ? "bg-emerald-500" : "bg-muted-foreground/30",
                )}
                title={h.tested ? "已测" : "未测"}
              />
              <span className="font-mono text-xs">{h.ip}</span>
              {(h.ports ?? []).slice(0, 8).map((p) => (
                <Badge key={p} variant="secondary" className="px-1 py-0 font-mono text-[10px]">
                  {p}
                </Badge>
              ))}
              {(h.ports ?? []).length > 8 && (
                <span className="text-muted-foreground text-[10px]">+{(h.ports ?? []).length - 8}</span>
              )}
              {(h.urls ?? []).length > 0 && (
                <span className="truncate text-muted-foreground text-[10px]">{h.urls?.[0]}</span>
              )}
            </div>
          ))}
        </div>
        {hidden > 0 && (
          <Button size="sm" variant="ghost" className="h-6 px-1 text-xs" onClick={onToggle}>
            再展开 {Math.min(hidden, HOST_FOLD)} 个（共 {seg.hosts.length}）
          </Button>
        )}
        {expanded && seg.hosts.length > HOST_FOLD && (
          <Button size="sm" variant="ghost" className="h-6 px-1 text-xs" onClick={onToggle}>
            收起
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
