import Link from "next/link";
import { Activity, Ban, Cloud, DatabaseZap, ShieldAlert, UsersRound } from "lucide-react";
import type { KpiMetric } from "@/lib/security-data";

const iconMap = {
  "requests-6h": Activity,
  "requests-24h": Cloud,
  "requests-7d": DatabaseZap,
  abnormal: Ban,
  "high-risk": ShieldAlert,
  "cf-events": UsersRound,
} as const;

const toneStyles: Record<KpiMetric["tone"], string> = {
  sky: "border-sky-400/35 bg-sky-400/10 text-sky-200",
  emerald: "border-emerald-400/35 bg-emerald-400/10 text-emerald-200",
  amber: "border-amber-400/35 bg-amber-400/10 text-amber-200",
  rose: "border-rose-400/35 bg-rose-400/10 text-rose-200",
  slate: "border-stone-400/25 bg-stone-300/10 text-stone-200",
};

const meterStyles: Record<KpiMetric["tone"], string> = {
  sky: "bg-sky-300",
  emerald: "bg-emerald-300",
  amber: "bg-amber-300",
  rose: "bg-rose-300",
  slate: "bg-stone-300",
};

const meterWidth: Record<string, string> = {
  "requests-6h": "72%",
  "requests-24h": "78%",
  "requests-7d": "64%",
  abnormal: "58%",
  "high-risk": "42%",
  "cf-events": "67%",
};

export function KpiGrid({ kpis }: { kpis: KpiMetric[] }) {
  return (
    <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6" aria-label="关键安全指标">
      {kpis.map((kpi) => {
        const Icon = iconMap[kpi.id as keyof typeof iconMap] ?? Activity;
        const content = (
          <div className="group h-full overflow-hidden rounded-lg border border-[#182522] bg-[#07100e] p-3.5 text-stone-100 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] transition-colors hover:border-emerald-400/35">
            <div className="flex items-start justify-between gap-3">
              <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-md border ${toneStyles[kpi.tone]}`}>
                <Icon size={19} strokeWidth={2.5} />
              </div>
              <span className="security-num rounded-md border border-emerald-400/15 bg-black/25 px-2 py-1 text-xs font-extrabold text-emerald-100">{kpi.trend}</span>
            </div>
            <p className="mt-3 min-h-8 text-xs font-extrabold leading-4 text-stone-400">{kpi.label}</p>
            <p className="security-num mt-1 text-2xl font-black text-white">{kpi.value}</p>
            <div className="mt-3 h-1.5 overflow-hidden rounded-sm bg-white/10">
              <div
                className={`h-full rounded-sm ${meterStyles[kpi.tone]}`}
                style={{ width: meterWidth[kpi.id] ?? "54%" }}
              />
            </div>
            <p className="mt-2 min-h-9 text-xs font-semibold leading-relaxed text-stone-400">{kpi.detail}</p>
          </div>
        );

        return kpi.href ? (
          <Link
            key={kpi.id}
            href={kpi.href}
            className="block rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--security-bg)]"
            aria-label={`${kpi.label}，${kpi.value}，查看相关事件`}
          >
            {content}
          </Link>
        ) : (
          <div key={kpi.id}>{content}</div>
        );
      })}
    </section>
  );
}
