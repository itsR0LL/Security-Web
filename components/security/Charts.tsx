import Link from "next/link";
import { ArrowUpRight, BarChart3, ListTree, Signal } from "lucide-react";
import type { DistributionPoint, RankedItem, RiskLevel, TrendPoint } from "@/lib/security-data";
import { RiskBadge, riskTextClass } from "./RiskBadge";

type Tone = "sky" | "emerald" | "amber" | "rose" | "slate";

function normalize(values: number[]) {
  const safeValues = values.length ? values : [0];
  const min = Math.min(...safeValues);
  const max = Math.max(...safeValues);
  const range = Math.max(1, max - min);

  return safeValues.map((value, index) => {
    const x = safeValues.length === 1 ? 50 : (index / (safeValues.length - 1)) * 100;
    const y = 88 - ((value - min) / range) * 68;
    return { x, y };
  });
}

function linePath(points: ReturnType<typeof normalize>) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x},${point.y}`).join(" ");
}

const toneStroke: Record<Tone, string> = {
  sky: "stroke-sky-300",
  emerald: "stroke-emerald-300",
  amber: "stroke-amber-300",
  rose: "stroke-rose-300",
  slate: "stroke-stone-300",
};

const toneFill: Record<Tone, string> = {
  sky: "fill-sky-300/10",
  emerald: "fill-emerald-300/10",
  amber: "fill-amber-300/10",
  rose: "fill-rose-300/10",
  slate: "fill-stone-300/10",
};

const riskBarClass: Record<RiskLevel | "default", string> = {
  info: "bg-sky-300",
  low: "bg-emerald-300",
  medium: "bg-amber-300",
  high: "bg-rose-300",
  critical: "bg-red-400",
  default: "bg-emerald-300",
};

export function Sparkline({
  values,
  tone = "sky",
  height = 112,
}: {
  values: number[];
  tone?: Tone;
  height?: number;
}) {
  const points = normalize(values);
  const area = `${linePath(points)} L100,94 L0,94 Z`;

  return (
    <svg viewBox="0 0 100 100" height={height} className="w-full overflow-visible" role="img" aria-label="趋势折线图" preserveAspectRatio="none">
      <path d="M0 90H100" className="stroke-white/10" strokeWidth="1" />
      <path d="M0 56H100" className="stroke-white/10" strokeWidth="1" />
      <path d="M0 22H100" className="stroke-white/10" strokeWidth="1" />
      <path d={area} className={toneFill[tone]} />
      <path
        d={linePath(points)}
        className={`${toneStroke[tone]} fill-none`}
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function TrendPanel({ trend }: { trend: TrendPoint[] }) {
  const latest = trend.at(-1);
  const previous = trend.at(-2);
  const requestDelta = latest && previous ? latest.requests - previous.requests : 0;
  const threatTotal = latest ? latest.threats + latest.blocked : 0;

  return (
    <section className="overflow-hidden rounded-lg border border-[#182522] bg-[#07100e] text-stone-100">
      <div className="flex flex-col gap-3 border-b border-emerald-400/15 px-4 py-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="flex items-center gap-2 text-xs font-extrabold text-emerald-300">
            <Signal size={15} />
            流量分析
          </p>
          <h2 className="mt-1 text-lg font-extrabold text-white">请求、攻击与边缘带宽</h2>
        </div>
        <div className="rounded-md border border-emerald-400/20 bg-black/25 px-3 py-2 text-left sm:text-right">
          <p className="text-[11px] font-bold text-stone-400">当前窗口变化</p>
          <p className="security-num text-sm font-extrabold text-emerald-100">
            {requestDelta >= 0 ? "+" : ""}
            {requestDelta} 请求 / {threatTotal} 威胁
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 p-3 lg:grid-cols-3">
        <SignalCard label="请求趋势" value={latest?.requests ?? 0} unit="req" tone="sky" values={trend.map((point) => point.requests)} />
        <SignalCard label="攻击与拦截" value={threatTotal} unit="hit" tone="rose" values={trend.map((point) => point.threats + point.blocked)} />
        <SignalCard label="边缘带宽" value={latest?.bandwidthMb ?? 0} unit="MB" tone="emerald" values={trend.map((point) => point.bandwidthMb)} />
      </div>

      <div className="grid grid-cols-2 gap-px border-t border-emerald-400/15 bg-emerald-400/10 md:grid-cols-4">
        <MiniStat label="缓存命中" value={`${latest?.cachedPercent ?? 0}%`} />
        <MiniStat label="源站流量" value={`${latest?.originMb ?? 0} MB`} />
        <MiniStat label="拦截请求" value={`${latest?.blocked ?? 0}`} />
        <MiniStat label="边缘请求" value={`${latest?.requests ?? 0}`} />
      </div>
    </section>
  );
}

function SignalCard({
  label,
  value,
  unit,
  tone,
  values,
}: {
  label: string;
  value: number;
  unit: string;
  tone: Tone;
  values: number[];
}) {
  return (
    <div className="rounded-md border border-emerald-400/15 bg-black/25 p-3">
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-extrabold text-stone-400">{label}</p>
        <p className="security-num whitespace-nowrap text-sm font-black text-white">
          {value.toLocaleString("zh-CN")}
          <span className="ml-1 text-[11px] font-bold text-stone-500">{unit}</span>
        </p>
      </div>
      <Sparkline values={values} tone={tone} height={118} />
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-h-20 bg-[#07100e] p-3">
      <p className="text-xs font-bold text-stone-500">{label}</p>
      <p className="security-num mt-1 text-lg font-black text-white">{value}</p>
    </div>
  );
}

export function DistributionBars({ title, items }: { title: string; items: DistributionPoint[] }) {
  const max = Math.max(...items.map((item) => item.value), 1);

  return (
    <div className="security-panel p-4">
      <div className="mb-4 flex items-center gap-2">
        <BarChart3 size={18} className="text-[var(--security-accent)]" />
        <h2 className="text-base font-extrabold text-[var(--security-ink)]">{title}</h2>
      </div>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item.label}>
            <div className="mb-1.5 flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2">
                {item.riskLevel && <RiskBadge level={item.riskLevel} compact />}
                <span className="truncate text-sm font-bold text-[var(--security-muted)]">{item.label}</span>
              </div>
              <span className={`security-num shrink-0 text-sm font-black ${riskTextClass(item.riskLevel)}`}>{item.value.toLocaleString("zh-CN")}</span>
            </div>
            <div className="h-2.5 overflow-hidden rounded-sm bg-[#e1e6df]">
              <div
                className={`h-full rounded-sm ${riskBarClass[item.riskLevel ?? "default"]}`}
                style={{ width: `${Math.max(4, (item.value / max) * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RankedList({
  title,
  items,
  href,
}: {
  title: string;
  items: RankedItem[];
  href?: string;
}) {
  return (
    <div className="security-panel p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-base font-extrabold text-[var(--security-ink)]">
          <ListTree size={17} className="text-[var(--security-accent)]" />
          {title}
        </h2>
        {href && (
          <Link
            href={href}
            className="inline-flex min-h-11 shrink-0 items-center gap-1 rounded-md px-2 text-xs font-extrabold text-[var(--security-accent)] outline-none hover:bg-[var(--security-accent-soft)] hover:text-[var(--security-ink)] focus-visible:ring-2 focus-visible:ring-[var(--security-accent)]"
          >
            查看
            <ArrowUpRight size={14} />
          </Link>
        )}
      </div>
      <div className="space-y-2">
        {items.map((item, index) => (
          <div key={item.label} className="security-row flex min-h-16 items-center gap-3 p-3">
            <div className="security-num flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-[#1d2a25] bg-[#111816] text-xs font-black text-emerald-100">
              {String(index + 1).padStart(2, "0")}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-extrabold text-[var(--security-ink)]">{item.label}</p>
              <p className="truncate text-xs font-semibold text-[var(--security-soft)]">{item.detail}</p>
            </div>
            <div className="shrink-0 text-right">
              <p className="security-num text-sm font-black text-[var(--security-ink)]">{item.value.toLocaleString("zh-CN")}</p>
              {item.riskLevel && <RiskBadge level={item.riskLevel} compact />}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
