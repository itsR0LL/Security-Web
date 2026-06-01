import Link from "next/link";
import { ArrowUpRight, Clock, ExternalLink, TerminalSquare } from "lucide-react";
import type { SecurityEvent } from "@/lib/security-data";
import { RiskBadge } from "./RiskBadge";

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function RecentEvents({ events }: { events: SecurityEvent[] }) {
  return (
    <section className="overflow-hidden rounded-lg border border-[#182522] bg-[#07100e] text-stone-100">
      <div className="flex items-center justify-between gap-3 border-b border-emerald-400/15 px-4 py-3">
        <div>
          <p className="flex items-center gap-2 text-xs font-extrabold text-emerald-300">
            <TerminalSquare size={15} />
            最近事件
          </p>
          <h2 className="mt-1 text-lg font-extrabold text-white">告警日志流</h2>
        </div>
        <Link
          href="/security/events?risk=high"
          className="security-button inline-flex shrink-0 items-center gap-1 border border-emerald-400/25 bg-black/20 px-3 text-xs font-extrabold text-emerald-100 outline-none hover:bg-emerald-300 hover:text-[#07100e] focus-visible:ring-2 focus-visible:ring-emerald-300 focus-visible:ring-offset-2 focus-visible:ring-offset-[#07100e]"
        >
          全部事件
          <ArrowUpRight size={14} />
        </Link>
      </div>

      <div className="divide-y divide-emerald-400/10">
        {events.map((event) => (
          <Link
            key={event.id}
            href={`/security/events?event=${event.id}`}
            className="block min-h-24 px-4 py-3 outline-none transition hover:bg-emerald-300/5 focus-visible:bg-emerald-300/10 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-emerald-300"
          >
            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-start">
              <div className="min-w-0">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <RiskBadge level={event.riskLevel} />
                  <span className="rounded-md border border-emerald-400/15 bg-black/25 px-2 py-1 text-xs font-extrabold text-stone-300">{event.eventType}</span>
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-stone-500">
                    <Clock size={13} />
                    {formatTime(event.timestamp)}
                  </span>
                </div>
                <p className="line-clamp-2 text-sm font-extrabold leading-5 text-white">{event.summary}</p>
                <p className="mt-1 truncate text-xs font-semibold text-stone-500">
                  {event.clientIp} / {event.country} {event.city}
                </p>
              </div>
              <div className="min-w-0 md:w-64 md:text-right">
                <p className="security-num truncate text-xs font-extrabold text-emerald-100">
                  {event.method} {event.statusCode} / {event.action}
                </p>
                <p className="mt-1 truncate font-mono text-xs font-semibold text-stone-500">{event.path}</p>
                <p className="mt-2 inline-flex items-center gap-1 text-xs font-extrabold text-stone-400">
                  inspect
                  <ExternalLink size={13} />
                </p>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
