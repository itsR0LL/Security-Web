"use client";

import { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Code2,
  Filter,
  Globe2,
  ListFilter,
  MapPin,
  RadioTower,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  X,
} from "lucide-react";
import type { RiskLevel, SecurityEvent } from "@/lib/security-data";
import { getRiskRank, riskLabels, riskOrder } from "@/lib/security-data";
import { RiskBadge } from "./RiskBadge";

export type EventInitialFilters = {
  risk?: string;
  eventType?: string;
  ip?: string;
  country?: string;
  path?: string;
  action?: string;
  statusCode?: string;
  timeRange?: string;
  event?: string;
};

type FilterState = {
  risk: "all" | RiskLevel;
  eventType: string;
  source: string;
  country: string;
  path: string;
  action: string;
  statusCode: string;
  timeRange: "6h" | "24h" | "7d" | "all";
};

const timeRangeHours: Record<FilterState["timeRange"], number | null> = {
  "6h": 6,
  "24h": 24,
  "7d": 24 * 7,
  all: null,
};

const actionOptions = ["all", "allow", "block", "challenge", "managed_challenge", "log"];

const emptyFilters: FilterState = {
  risk: "all",
  eventType: "all",
  source: "",
  country: "",
  path: "",
  action: "all",
  statusCode: "",
  timeRange: "24h",
};

const filterPresets: Array<{
  id: string;
  label: string;
  description: string;
  filters: Partial<FilterState>;
}> = [
  {
    id: "hot",
    label: "高危阻断",
    description: "最近 24 小时 high 以上，聚焦 block / challenge",
    filters: { risk: "high", action: "block", timeRange: "24h" },
  },
  {
    id: "scan",
    label: "扫描探测",
    description: "敏感路径、后台入口、自动化 UA",
    filters: { risk: "medium", path: "admin", timeRange: "24h" },
  },
  {
    id: "origin",
    label: "来源定位",
    description: "按 IP、城市、国家快速收敛事件来源",
    filters: { source: "", country: "", timeRange: "7d" },
  },
];

const locationPrecisionLabels: Record<SecurityEvent["locationPrecision"], string> = {
  city: "城市级",
  region: "区域级",
  country: "国家级",
  estimated: "估算",
};

function normalizeRisk(value?: string): FilterState["risk"] {
  if (value && riskOrder.includes(value as RiskLevel)) return value as RiskLevel;
  return "all";
}

function normalizeTimeRange(value?: string): FilterState["timeRange"] {
  if (value === "6h" || value === "24h" || value === "7d" || value === "all") return value;
  return "24h";
}

function buildInitialFilters(initialFilters: EventInitialFilters): FilterState {
  return {
    risk: normalizeRisk(initialFilters.risk),
    eventType: initialFilters.eventType || "all",
    source: initialFilters.ip || "",
    country: initialFilters.country || "",
    path: initialFilters.path || "",
    action: initialFilters.action || "all",
    statusCode: initialFilters.statusCode || "",
    timeRange: normalizeTimeRange(initialFilters.timeRange),
  };
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function eventMatchesRisk(event: SecurityEvent, risk: FilterState["risk"]) {
  if (risk === "all") return true;
  if (risk === "high") return event.riskLevel === "high" || event.riskLevel === "critical";
  return event.riskLevel === risk;
}

function displayValue(value: unknown, fallback = "Cloudflare 未返回") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string" && value.trim().length === 0) return fallback;
  return String(value);
}

function sourceLabel(source: SecurityEvent["source"]) {
  if (source === "cloudflare") return "Cloudflare";
  if (source === "origin") return "Origin";
  return "Sample";
}

export function EventExplorer({
  events,
  initialFilters,
}: {
  events: SecurityEvent[];
  initialFilters: EventInitialFilters;
}) {
  const eventTypes = useMemo(() => Array.from(new Set(events.map((event) => event.eventType))).sort(), [events]);
  const [filters, setFilters] = useState<FilterState>(() => buildInitialFilters(initialFilters));
  const [selectedId, setSelectedId] = useState(initialFilters.event || events[0]?.id || "");
  const referenceTime = useMemo(
    () => (events.length > 0 ? Math.max(...events.map((event) => Date.parse(event.timestamp))) : 0),
    [events],
  );

  const filteredEvents = useMemo(() => {
    const hours = timeRangeHours[filters.timeRange];

    return events
      .filter((event) => {
        if (hours !== null) {
          const ageHours = (referenceTime - Date.parse(event.timestamp)) / (60 * 60 * 1000);
          if (ageHours > hours) return false;
        }
        if (!eventMatchesRisk(event, filters.risk)) return false;
        if (filters.eventType !== "all" && event.eventType !== filters.eventType) return false;
        if (filters.source) {
          const sourceText = `${event.clientIp} ${event.city} ${event.region} ${event.country}`.toLowerCase();
          if (!sourceText.includes(filters.source.toLowerCase())) return false;
        }
        if (filters.country && !`${event.country} ${event.region} ${event.city}`.toLowerCase().includes(filters.country.toLowerCase())) {
          return false;
        }
        if (filters.path) {
          const pathText = `${event.method} ${event.path} ${event.query || ""} ${event.userAgent}`.toLowerCase();
          if (!pathText.includes(filters.path.toLowerCase())) return false;
        }
        if (filters.action !== "all" && event.action !== filters.action) return false;
        if (filters.statusCode && String(event.statusCode) !== filters.statusCode.trim()) return false;
        return true;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [events, filters, referenceTime]);

  const selectedEvent = useMemo(
    () => filteredEvents.find((event) => event.id === selectedId) || filteredEvents[0] || null,
    [filteredEvents, selectedId],
  );

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters(emptyFilters);
  };

  const applyPreset = (presetFilters: Partial<FilterState>) => {
    setFilters({ ...emptyFilters, ...presetFilters });
  };

  const highCount = filteredEvents.filter((event) => getRiskRank(event.riskLevel) >= getRiskRank("high")).length;
  const criticalCount = filteredEvents.filter((event) => event.riskLevel === "critical").length;
  const blockedCount = filteredEvents.filter((event) => event.action === "block" || event.action === "managed_challenge").length;
  const topCountries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of filteredEvents) {
      counts.set(event.country, (counts.get(event.country) || 0) + 1);
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [filteredEvents]);
  const activeFilterCount = [
    filters.risk !== "all",
    filters.eventType !== "all",
    filters.source,
    filters.country,
    filters.path,
    filters.action !== "all",
    filters.statusCode,
    filters.timeRange !== "24h",
  ].filter(Boolean).length;

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[260px_minmax(0,1fr)_340px]">
      <aside className="space-y-4">
        <OrbitalSourceFrame
          total={filteredEvents.length}
          highCount={highCount}
          criticalCount={criticalCount}
          blockedCount={blockedCount}
          topCountries={topCountries}
        />
      </aside>

      <section className="min-w-0 space-y-4">
        <div className="relative overflow-hidden border border-[#1d2a25] bg-[#0b1412] text-white">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(20,255,211,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(20,255,211,0.05)_1px,transparent_1px)] bg-[size:22px_22px] opacity-50" />
          <div className="relative border-b border-emerald-300/15 p-4">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <p className="security-kicker flex items-center gap-2 text-emerald-300">
                  <ListFilter size={15} />
                  筛选方案
                </p>
                <h2 className="mt-1 text-xl font-extrabold text-white">安全事件检索面板</h2>
                <p className="mt-2 text-sm font-medium leading-6 text-emerald-50/70">
                  当前命中 {filteredEvents.length} 条，高风险 {highCount} 条，已处置或挑战 {blockedCount} 条。默认按时间倒序展示。
                </p>
              </div>
              <button
                type="button"
                onClick={clearFilters}
                className="security-button inline-flex items-center justify-center gap-2 border border-emerald-300/25 bg-emerald-300/10 px-4 text-sm font-bold text-emerald-50 hover:bg-emerald-300/18 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
              >
                <X size={16} />
                清空筛选
              </button>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-px overflow-hidden border border-emerald-300/18 bg-emerald-300/18 md:grid-cols-3">
              {filterPresets.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => applyPreset(preset.filters)}
                  className="min-h-20 bg-[#111f1c] p-3 text-left transition hover:bg-[#132722] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
                >
                  <span className="flex items-center gap-2 text-sm font-extrabold text-white">
                    <SlidersHorizontal size={15} />
                    {preset.label}
                  </span>
                  <span className="mt-1 block text-xs font-medium leading-5 text-emerald-50/62">{preset.description}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="relative grid grid-cols-1 gap-px border-emerald-300/18 bg-emerald-300/18 p-px md:grid-cols-2 xl:grid-cols-4">
            <LabelledSelect
              label="时间范围"
              helper="Cloudflare Free 数据窗口可能较短"
              icon={<CalendarDays size={15} />}
              value={filters.timeRange}
              onChange={(value) => updateFilter("timeRange", value as FilterState["timeRange"])}
              options={[
                ["6h", "最近 6 小时"],
                ["24h", "最近 24 小时"],
                ["7d", "最近 7 天"],
                ["all", "全部本地记录"],
              ]}
            />
            <LabelledSelect
              label="风险等级"
              helper="选择高风险会包含严重事件"
              icon={<ShieldCheck size={15} />}
              value={filters.risk}
              onChange={(value) => updateFilter("risk", value as FilterState["risk"])}
              options={[["all", "全部风险"], ...riskOrder.map((level) => [level, riskLabels[level]] as const)]}
            />
            <LabelledSelect
              label="事件类型"
              helper="按规则归类或样例类型过滤"
              icon={<Filter size={15} />}
              value={filters.eventType}
              onChange={(value) => updateFilter("eventType", value)}
              options={[["all", "全部类型"], ...eventTypes.map((type) => [type, type] as const)]}
            />
            <LabelledSelect
              label="Cloudflare Action"
              helper="allow / block / challenge"
              icon={<Code2 size={15} />}
              value={filters.action}
              onChange={(value) => updateFilter("action", value)}
              options={actionOptions.map((action) => [action, action === "all" ? "全部动作" : action] as const)}
            />
            <LabelledInput
              label="来源 IP / 城市"
              helper="支持 IP 片段、城市或区域"
              icon={<Globe2 size={15} />}
              value={filters.source}
              placeholder="例如 185.220 或 Frankfurt"
              onChange={(value) => updateFilter("source", value)}
            />
            <LabelledInput
              label="国家 / 地区"
              helper="用于归并地理来源"
              icon={<MapPin size={15} />}
              value={filters.country}
              placeholder="例如 德国"
              onChange={(value) => updateFilter("country", value)}
            />
            <LabelledInput
              label="路径 / UA 关键词"
              helper="查找 .env、wp-login、curl 等"
              icon={<Search size={15} />}
              value={filters.path}
              placeholder="例如 .env"
              onChange={(value) => updateFilter("path", value)}
            />
            <LabelledInput
              label="状态码"
              helper="只输入三位数字"
              icon={<Code2 size={15} />}
              value={filters.statusCode}
              placeholder="例如 403"
              onChange={(value) => updateFilter("statusCode", value.replace(/\D/g, "").slice(0, 3))}
            />
          </div>
        </div>

        <div className="border border-amber-300 bg-[#fff7dd] p-3 text-sm font-medium leading-6 text-amber-950">
          Cloudflare Free 可能存在采样、字段缺省或时间窗口限制。这里会优先展示本地已同步记录；缺少 Ray ID、规则名或地理精度时，明细区会标为“未返回”，避免误判为零风险。
        </div>

        <div className="overflow-hidden border border-[var(--security-line)] bg-white">
          <div className="flex flex-col gap-2 border-b border-[var(--security-line)] bg-[var(--security-surface-subtle)] p-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="security-kicker flex items-center gap-2">
                <Activity size={15} />
                SOC Event Stream
              </p>
              <p className="mt-1 text-sm font-bold text-[var(--security-ink)]">
                {activeFilterCount > 0 ? `已启用 ${activeFilterCount} 个筛选条件` : "未启用额外筛选条件"}
              </p>
            </div>
            <p className="security-num text-xs font-bold text-[var(--security-muted)]">排序：timestamp desc</p>
          </div>

          <div className="hidden overflow-x-auto lg:block">
            <table className="w-full min-w-[860px] border-collapse text-left">
              <thead className="bg-[#111816] text-xs font-bold text-emerald-50">
                <tr>
                  <th className="px-4 py-3">时间</th>
                  <th className="px-4 py-3">来源</th>
                  <th className="px-4 py-3">请求</th>
                  <th className="px-4 py-3">类型</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">风险</th>
                  <th className="px-4 py-3">定位</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--security-line)]">
                {filteredEvents.map((event) => {
                  const isSelected = selectedEvent?.id === event.id;
                  return (
                    <tr
                      key={event.id}
                      tabIndex={0}
                      role="button"
                      aria-pressed={isSelected}
                      onClick={() => setSelectedId(event.id)}
                      onKeyDown={(keyboardEvent) => {
                        if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
                          keyboardEvent.preventDefault();
                          setSelectedId(event.id);
                        }
                      }}
                      className={`cursor-pointer bg-white text-sm transition hover:bg-[var(--security-surface-subtle)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-[var(--security-accent)] ${
                        isSelected ? "bg-[var(--security-accent-soft)] shadow-[inset_4px_0_0_var(--security-accent)]" : ""
                      }`}
                    >
                      <td className="security-num whitespace-nowrap px-4 py-3 font-semibold text-[var(--security-muted)]">{formatTime(event.timestamp)}</td>
                      <td className="px-4 py-3">
                        <p className="security-num font-extrabold text-[var(--security-ink)]">{displayValue(event.clientIp)}</p>
                        <p className="text-xs font-medium text-[var(--security-soft)]">{displayValue(event.country)} {displayValue(event.city, "城市未返回")}</p>
                      </td>
                      <td className="max-w-[300px] px-4 py-3">
                        <p className="truncate font-extrabold text-[var(--security-ink)]">{event.method} {displayValue(event.path, "路径未返回")}</p>
                        <p className="truncate text-xs font-medium text-[var(--security-soft)]">{displayValue(event.userAgent, "User-Agent 未返回")}</p>
                      </td>
                      <td className="px-4 py-3 font-semibold text-[var(--security-muted)]">{displayValue(event.eventType)}</td>
                      <td className="px-4 py-3 font-mono text-xs font-bold text-[var(--security-muted)]">{displayValue(event.action)}</td>
                      <td className="px-4 py-3"><RiskBadge level={event.riskLevel} compact /></td>
                      <td className="px-4 py-3 text-xs font-medium text-[var(--security-soft)]">{locationPrecisionLabels[event.locationPrecision]}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="divide-y divide-[var(--security-line)] lg:hidden">
            {filteredEvents.map((event) => {
              const isSelected = selectedEvent?.id === event.id;
              return (
                <button
                  key={event.id}
                  type="button"
                  onClick={() => setSelectedId(event.id)}
                  className={`block min-h-24 w-full bg-white p-4 text-left transition hover:bg-[var(--security-surface-subtle)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-[var(--security-accent)] ${
                    isSelected ? "bg-[var(--security-accent-soft)]" : ""
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="break-words text-sm font-extrabold text-[var(--security-ink)]">{event.method} {displayValue(event.path, "路径未返回")}</p>
                      <p className="security-num mt-1 text-xs font-medium text-[var(--security-soft)]">{formatTime(event.timestamp)} / {displayValue(event.clientIp)}</p>
                    </div>
                    <ChevronRight size={18} className="mt-1 shrink-0 text-[var(--security-soft)]" />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <RiskBadge level={event.riskLevel} compact />
                    <span className="rounded-md border border-[var(--security-line)] bg-[var(--security-surface-subtle)] px-2 py-1 text-xs font-bold text-[var(--security-muted)]">{displayValue(event.eventType)}</span>
                    <span className="rounded-md border border-[var(--security-line)] bg-[var(--security-surface-subtle)] px-2 py-1 text-xs font-bold text-[var(--security-muted)]">{displayValue(event.action)}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {filteredEvents.length === 0 && (
            <div className="p-10 text-center">
              <p className="text-lg font-extrabold text-[var(--security-ink)]">没有匹配事件</p>
              <p className="mt-2 text-sm font-medium text-[var(--security-muted)]">调整风险等级、来源、路径或时间范围后再查看。</p>
            </div>
          )}
        </div>
      </section>

      <EventDetailPanel event={selectedEvent} />
    </div>
  );
}

function OrbitalSourceFrame({
  total,
  highCount,
  criticalCount,
  blockedCount,
  topCountries,
}: {
  total: number;
  highCount: number;
  criticalCount: number;
  blockedCount: number;
  topCountries: Array<[string, number]>;
}) {
  const maxCountry = Math.max(...topCountries.map(([, count]) => count), 1);

  return (
    <div className="relative overflow-hidden border border-[#1d2a25] bg-[#07100e] p-4 text-white 2xl:sticky 2xl:top-28">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(20,255,211,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(20,255,211,0.05)_1px,transparent_1px)] bg-[size:18px_18px] opacity-45" />
      <div className="relative">
        <p className="security-kicker flex items-center gap-2 text-emerald-300">
          <RadioTower size={15} />
          Orbital Source Frame
        </p>
        <div className="relative mx-auto mt-5 aspect-square max-w-60">
          <div className="absolute inset-3 rounded-full border border-emerald-300/25" />
          <div className="absolute inset-10 rounded-full border border-emerald-300/18" />
          <div className="absolute inset-16 rounded-full border border-emerald-300/30 bg-[radial-gradient(circle_at_40%_35%,rgba(20,255,211,0.36),rgba(15,118,110,0.16)_42%,rgba(7,16,14,0)_68%)]" />
          <div className="absolute left-1/2 top-0 h-full w-px -translate-x-1/2 bg-emerald-300/18" />
          <div className="absolute left-0 top-1/2 h-px w-full -translate-y-1/2 bg-emerald-300/18" />
          <div className="absolute left-[17%] top-[25%] h-2.5 w-2.5 rounded-full bg-rose-400 shadow-[0_0_18px_rgba(251,113,133,0.8)]" />
          <div className="absolute right-[21%] top-[38%] h-2 w-2 rounded-full bg-amber-300 shadow-[0_0_18px_rgba(252,211,77,0.75)]" />
          <div className="absolute bottom-[24%] left-[34%] h-2 w-2 rounded-full bg-emerald-300 shadow-[0_0_18px_rgba(110,231,183,0.75)]" />
          <div className="absolute inset-x-8 top-1/2 h-px -translate-y-1/2 rotate-[-24deg] bg-gradient-to-r from-transparent via-rose-300/70 to-transparent" />
          <div className="absolute inset-x-7 top-1/2 h-px -translate-y-1/2 rotate-[31deg] bg-gradient-to-r from-transparent via-emerald-300/70 to-transparent" />
          <div className="absolute inset-0 rounded-full border border-emerald-200/10 shadow-[inset_0_0_42px_rgba(20,255,211,0.16),0_0_40px_rgba(20,255,211,0.08)]" />
        </div>

        <div className="mt-4 grid grid-cols-3 gap-px border border-emerald-300/18 bg-emerald-300/18">
          <HudMetric label="EVENTS" value={String(total)} />
          <HudMetric label="HIGH+" value={String(highCount)} />
          <HudMetric label="CRIT" value={String(criticalCount)} />
        </div>

        <div className="mt-4 border border-emerald-300/18">
          <div className="flex items-center justify-between border-b border-emerald-300/18 px-3 py-2">
            <span className="text-xs font-extrabold text-emerald-50/82">TOP REGIONS</span>
            <span className="security-num text-xs font-bold text-emerald-300">{blockedCount} contained</span>
          </div>
          <div className="space-y-2 p-3">
            {topCountries.length > 0 ? topCountries.map(([country, count]) => (
              <div key={country}>
                <div className="flex items-center justify-between gap-2 text-xs font-bold text-emerald-50/72">
                  <span className="truncate">{country}</span>
                  <span className="security-num">{count}</span>
                </div>
                <div className="mt-1 h-1 bg-emerald-300/10">
                  <div className="h-full bg-emerald-300" style={{ width: `${Math.max(10, (count / maxCountry) * 100)}%` }} />
                </div>
              </div>
            )) : (
              <p className="text-xs font-medium leading-5 text-emerald-50/62">当前筛选没有来源区域。</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function HudMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#0b1412] p-3">
      <p className="text-[10px] font-extrabold text-emerald-50/52">{label}</p>
      <p className="security-num mt-1 text-lg font-extrabold text-white">{value}</p>
    </div>
  );
}

function LabelledInput({
  label,
  helper,
  icon,
  value,
  placeholder,
  onChange,
}: {
  label: string;
  helper: string;
  icon: React.ReactNode;
  value: string;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block bg-[#0b1412] p-3">
      <span className="mb-1.5 flex items-center gap-1.5 text-xs font-bold text-emerald-50/88">{icon}{label}</span>
      <input
        className="security-input border-emerald-300/30 bg-[#07100e] text-sm font-semibold text-white placeholder:text-emerald-50/35 focus:border-emerald-300 focus:shadow-[0_0_0_3px_rgba(20,255,211,0.16)]"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      <span className="mt-1.5 block text-xs font-medium leading-5 text-emerald-50/55">{helper}</span>
    </label>
  );
}

function LabelledSelect({
  label,
  helper,
  icon,
  value,
  options,
  onChange,
}: {
  label: string;
  helper: string;
  icon: React.ReactNode;
  value: string;
  options: readonly (readonly [string, string])[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="block bg-[#0b1412] p-3">
      <span className="mb-1.5 flex items-center gap-1.5 text-xs font-bold text-emerald-50/88">{icon}{label}</span>
      <select
        className="security-input border-emerald-300/30 bg-[#07100e] text-sm font-semibold text-white focus:border-emerald-300 focus:shadow-[0_0_0_3px_rgba(20,255,211,0.16)]"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map(([optionValue, labelText]) => (
          <option key={optionValue} value={optionValue}>{labelText}</option>
        ))}
      </select>
      <span className="mt-1.5 block text-xs font-medium leading-5 text-emerald-50/55">{helper}</span>
    </label>
  );
}

function EventDetailPanel({ event }: { event: SecurityEvent | null }) {
  if (!event) {
    return (
      <aside className="security-panel p-4">
        <p className="text-lg font-extrabold text-[var(--security-ink)]">选择一条事件查看详情</p>
        <p className="mt-2 text-sm font-medium text-[var(--security-muted)]">如果当前筛选为空，可以放宽时间或风险条件。</p>
      </aside>
    );
  }

  const fullPath = `${displayValue(event.path, "路径未返回")}${event.query ? `?${event.query}` : ""}`;
  const hasRaw = event.raw && Object.keys(event.raw).length > 0;

  return (
    <aside className="security-panel sticky top-28 h-fit overflow-hidden">
      <div className="border-b border-emerald-300/15 bg-[#0b1412] p-4 text-white">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="security-kicker text-emerald-300">取证明细</p>
            <h2 className="mt-1 break-words text-lg font-extrabold text-white">{displayValue(event.eventType)}</h2>
            <p className="security-num mt-1 text-xs font-semibold text-emerald-50/62">ID {event.id}</p>
          </div>
          <RiskBadge level={event.riskLevel} />
        </div>
      </div>

      <div className="p-4">
        <p className="rounded-md border border-[var(--security-line)] bg-[var(--security-surface-subtle)] p-3 text-sm font-medium leading-6 text-[var(--security-muted)]">
          {displayValue(event.summary, "该事件没有同步到摘要。可结合原始 JSON、Ray ID 和规则命中继续判断。")}
        </p>

        <div className="mt-4 grid grid-cols-2 gap-3">
          <DetailItem label="来源 IP" value={displayValue(event.clientIp)} />
          <DetailItem label="地理位置" value={`${displayValue(event.country)} / ${displayValue(event.city, "城市未返回")}`} />
          <DetailItem label="来源通道" value={sourceLabel(event.source)} />
          <DetailItem label="定位精度" value={locationPrecisionLabels[event.locationPrecision]} />
          <DetailItem label="请求方法" value={displayValue(event.method)} />
          <DetailItem label="状态码" value={String(event.statusCode)} />
          <DetailItem label="Action" value={displayValue(event.action)} />
          <DetailItem label="置信度" value={`${Math.round(event.confidence * 100)}%`} />
          <DetailItem label="Ray ID" value={displayValue(event.rayId, "Free 采样未返回")} />
          <DetailItem label="ASN" value={displayValue(event.asn, "ASN 未返回")} />
        </div>

        <div className="mt-4">
          <p className="mb-2 text-xs font-bold text-[var(--security-muted)]">请求路径</p>
          <code className="block max-w-full break-all rounded-md bg-[#111816] p-3 text-xs font-semibold leading-5 text-stone-100">
            {fullPath}
          </code>
        </div>

        <div className="mt-4">
          <p className="mb-2 flex items-center gap-2 text-xs font-bold text-[var(--security-muted)]">
            <Terminal size={14} />
            User-Agent
          </p>
          <p className="break-all rounded-md border border-[var(--security-line)] bg-[var(--security-surface-subtle)] p-3 text-xs font-semibold leading-5 text-[var(--security-muted)]">
            {displayValue(event.userAgent, "User-Agent 未返回")}
          </p>
        </div>

        <div className="mt-4">
          <p className="mb-2 flex items-center gap-2 text-xs font-bold text-[var(--security-muted)]">
            <CheckCircle2 size={14} />
            命中规则
          </p>
          <div className="space-y-2">
            {event.ruleMatches.length > 0 ? (
              event.ruleMatches.map((rule) => (
                <div key={rule} className="security-row px-3 py-2 text-xs font-semibold text-[var(--security-muted)]">{rule}</div>
              ))
            ) : (
              <div className="security-row px-3 py-2 text-xs font-semibold text-[var(--security-muted)]">规则命中未随当前事件返回。</div>
            )}
          </div>
        </div>

        <div className="mt-4 rounded-md border border-sky-200 bg-sky-50 p-4">
          <p className="flex items-center gap-2 text-sm font-extrabold text-sky-900">
            <AlertTriangle size={16} />
            数据窗口说明
          </p>
          <p className="mt-2 text-xs font-medium leading-5 text-sky-950/75">
            Free 计划下安全事件和分析接口可能存在延迟、采样或字段缺省。这里展示的是当前可用证据，不代表 Cloudflare 边缘侧没有更多历史命中。
          </p>
        </div>

        <div className="mt-4">
          <p className="mb-2 text-xs font-bold text-[var(--security-muted)]">原始事件 JSON</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-[#111816] p-3 text-xs leading-5 text-stone-100">
            {hasRaw ? JSON.stringify(event.raw, null, 2) : "当前同步记录没有原始 JSON。"}
          </pre>
        </div>
      </div>
    </aside>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="security-row min-w-0 p-3">
      <p className="text-[11px] font-bold text-[var(--security-soft)]">{label}</p>
      <p className="security-num mt-1 break-words text-sm font-extrabold text-[var(--security-ink)]">{value}</p>
    </div>
  );
}
