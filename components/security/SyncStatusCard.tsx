import { CheckCircle2, Clock, Database, PlugZap, TriangleAlert, Wifi } from "lucide-react";
import type { SyncStatus } from "@/lib/security-data";

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function SyncStatusCard({ sync }: { sync: SyncStatus }) {
  const isHealthy = sync.status === "success" || sync.status === "sample";

  return (
    <aside className="overflow-hidden rounded-lg border border-[#182522] bg-[#07100e] text-stone-100">
      <div className="flex items-start justify-between gap-4 border-b border-emerald-400/15 px-4 py-3">
        <div>
          <p className="text-xs font-extrabold text-emerald-300">同步状态</p>
          <h2 className="mt-1 text-lg font-extrabold text-white">数据可信度</h2>
        </div>
        <div className={`rounded-md border p-2 ${isHealthy ? "border-emerald-400/35 bg-emerald-400/10 text-emerald-200" : "border-amber-400/35 bg-amber-400/10 text-amber-200"}`}>
          {isHealthy ? <CheckCircle2 size={20} /> : <TriangleAlert size={20} />}
        </div>
      </div>

      <div className="space-y-2 p-3">
        <StatusRow icon={<Clock size={16} />} label="最近同步" value={formatTime(sync.lastSyncAt)} />
        <StatusRow icon={<Wifi size={16} />} label="刷新周期" value={`${sync.refreshIntervalHours} 小时`} />
        <StatusRow icon={<Database size={16} />} label="本地事件" value={`${sync.localEventCount.toLocaleString("zh-CN")} 条`} />
        <StatusRow icon={<PlugZap size={16} />} label="聚合统计" value={`${sync.aggregateCount.toLocaleString("zh-CN")} 组`} />
      </div>

      {sync.apiError && (
        <div className="mx-3 rounded-md border border-amber-400/35 bg-amber-300/10 p-3 text-sm font-semibold leading-6 text-amber-100">
          {sync.apiError}
        </div>
      )}

      <div className="space-y-2 p-3">
        {sync.permissions.map((item) => (
          <div key={item.name} className="flex items-start gap-2 rounded-md border border-emerald-400/10 bg-black/20 px-3 py-2 text-xs font-semibold text-stone-400">
            <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-sm ${item.ok ? "bg-emerald-300" : "bg-stone-600"}`} />
            <span className="min-w-0">
              <span className="font-extrabold text-stone-100">{item.name}</span>
              <span className="mx-1 text-stone-600">/</span>
              {item.detail}
            </span>
          </div>
        ))}
      </div>
    </aside>
  );
}

function StatusRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex min-h-11 items-center justify-between gap-4 rounded-md border border-emerald-400/10 bg-black/25 px-3 py-2.5">
      <div className="flex items-center gap-2 text-sm font-semibold text-stone-400">
        {icon}
        {label}
      </div>
      <div className="security-num whitespace-nowrap text-sm font-black text-white">{value}</div>
    </div>
  );
}
