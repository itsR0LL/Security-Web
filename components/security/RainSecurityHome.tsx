"use client";

import Link from "next/link";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { SecurityEvent, SecurityOverview, SyncStatusValue } from "@/lib/security-data";

type RainSecurityHomeProps = {
  overview: SecurityOverview;
  source: "api" | "sample";
  error?: string;
};

const syncStatusLabel: Record<SyncStatusValue, string> = {
  success: "LIVE",
  failed: "DEGRADED",
  partial: "PARTIAL",
  sample: "SAMPLE",
};

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "PENDING";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function HomeEventLine({ event }: { event: SecurityEvent }) {
  return (
    <Link href={`/security/events/${encodeURIComponent(event.id)}`} className="rain-home-event-line" data-risk={event.riskLevel}>
      <span>{formatTime(event.timestamp)}</span>
      <strong>{event.city || event.country || event.clientIp}</strong>
      <em>{event.riskLevel.toUpperCase()}</em>
      <small>
        {event.method} {event.path}
      </small>
    </Link>
  );
}

export function RainSecurityHome({ overview, source, error }: RainSecurityHomeProps) {
  const { cursorRef } = useRainCursor();
  const latestTraffic = overview.trafficTrend.at(-1);
  const highEvents = overview.recentEvents.filter((event) => event.riskLevel === "high" || event.riskLevel === "critical");
  const primaryEvents = highEvents.length > 0 ? highEvents.slice(0, 3) : overview.recentEvents.slice(0, 3);

  return (
    <main className="rain-home rain-home-clean">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-left-dot" aria-hidden="true" />
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <SecurityGlobalNav active="home" />

      <div className="rain-home-corner rain-home-corner-left">
        <span>SECURITY STUDIO</span>
        <strong>{overview.monitoredHost}</strong>
      </div>
      <div className="rain-home-corner rain-home-corner-right">
        <span>UPDATED {formatTime(overview.generatedAt)}</span>
        <strong>{syncStatusLabel[overview.sync.status]}</strong>
      </div>

      <section className="rain-left-panel rain-sim-panel" aria-label="安全态势主视觉">
        <div className="rain-home-frame" aria-hidden="true">
          <div className="rain-home-frame-top">
            <span>CHENGDU TARGET</span>
            <span>{overview.globePoints.length} SOURCES</span>
          </div>
        </div>

        <div className="rain-globe-reserve">
          <ParticleGlobe points={overview.globePoints} />
        </div>
      </section>

      <section className="rain-home-status-strip" aria-label="数据状态">
        <div data-status={overview.sync.status}>
          <span>DATA MODE</span>
          <strong>{source === "api" ? syncStatusLabel[overview.sync.status] : "SAMPLE"}</strong>
        </div>
        <div>
          <span>REQUESTS</span>
          <strong>{latestTraffic?.requests.toLocaleString("zh-CN") ?? "0"}</strong>
        </div>
        <div>
          <span>CACHE HIT</span>
          <strong>{latestTraffic?.cachedPercent ?? 0}%</strong>
        </div>
        <div data-status={error ? "failed" : overview.sync.status}>
          <span>SYNC</span>
          <strong>{error ? "LOCAL FALLBACK" : `${overview.sync.refreshIntervalHours}H`}</strong>
        </div>
      </section>

      <section className="rain-home-mvp-dock" aria-label="安全平台入口">
        <div className="rain-home-kpi-cluster">
          {overview.kpis.slice(0, 4).map((metric) => (
            <Link key={metric.id} href={metric.href ?? "/security/events"} className="rain-home-kpi" data-tone={metric.tone}>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
              <em>{metric.trend}</em>
            </Link>
          ))}
        </div>

        <div className="rain-home-analysis-card">
          <p>TRAFFIC</p>
          <strong>{latestTraffic?.bandwidthMb ?? 0}MB</strong>
          <span>Origin {latestTraffic?.originMb ?? 0}MB</span>
          <Link href="/security/events?timeRange=24h" className="rain-home-card-link">
            OPEN EVENTS
          </Link>
        </div>

        <div className="rain-home-events-card">
          <div className="rain-home-card-heading">
            <p>RECENT RISK</p>
            <Link href="/security/events?risk=high">VIEW ALL</Link>
          </div>
          <div className="rain-home-mini-events">
            {primaryEvents.map((event) => (
              <HomeEventLine key={event.id} event={event} />
            ))}
          </div>
        </div>

        <div className="rain-home-sync-card" data-status={overview.sync.status}>
          <p>SYNC STATUS</p>
          <strong>{syncStatusLabel[overview.sync.status]}</strong>
          <span>{overview.sync.localEventCount.toLocaleString("zh-CN")} events</span>
          <small>{overview.sync.usedStaleData ? "STALE DATA" : "FRESH WINDOW"}</small>
          <Link href="/security/settings" className="rain-home-card-link">
            CONFIG
          </Link>
        </div>
      </section>

      <div className="rain-mobile-title">
        <p>SECURITY SITUATION</p>
        <h1>R0L1DEHOME</h1>
      </div>
    </main>
  );
}
