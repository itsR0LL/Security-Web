"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { RouteHoverPopover } from "@/components/security/RouteHoverPopover";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { SecurityOverview, SyncStatusValue } from "@/lib/security-data";

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
  degraded: "DEGRADED",
  stale: "STALE",
};

const railNavItems = [
  {
    href: "/security/situation",
    label: "VISUAL",
    cn: "态势",
    effect: "trace",
    code: "TRACE-021",
    desc: "3D / 2D security situation",
    meta: "globe attack flow",
    hud: ["GLOBE READY", "ATTACK FLOW", "SOURCE POINT", "TARGET CHENGDU", "2D MAP", "OPEN VISUAL"],
  },
  {
    href: "/security/events",
    label: "EVENTS",
    cn: "事件",
    effect: "scan",
    code: "EVENT-064",
    desc: "filter, inspect and copy alert text",
    meta: "latest event stream",
    hud: ["FILTER READY", "TIME RANGE", "RISK LEVEL", "EVENT DETAIL", "RAW JSON", "ALERT TEXT"],
  },
  {
    href: "/security/map",
    label: "MAP",
    cn: "地图",
    effect: "radar",
    code: "GEO-031",
    desc: "request distribution by region",
    meta: "source position layer",
    hud: ["COUNTRY", "REGION", "CITY FALLBACK", "REQUEST FLOW", "DISTRIBUTION", "OPEN MAP"],
  },
  {
    href: "/security/settings",
    label: "CONFIG",
    cn: "设置",
    effect: "tower",
    code: "ZONE-018",
    desc: "Cloudflare token and sync policy",
    meta: "local security config",
    hud: ["ZONE ID", "TOKEN CHECK", "SYNC CYCLE", "RISK LEVEL", "RETENTION", "SAVE CONFIG"],
  },
  {
    href: "/security/events?risk=high",
    label: "ALERT",
    cn: "告警",
    effect: "ecg",
    code: "RISK-009",
    desc: "high risk events ready to notify",
    meta: "manual message draft",
    hud: ["HIGH", "CRITICAL", "ACTION", "SOURCE IP", "MESSAGE", "COPY TEXT"],
  },
  {
    href: "/security",
    label: "STATUS",
    cn: "状态",
    effect: "focus",
    code: "SYNC-006",
    desc: "data source, freshness and fallback",
    meta: "overview status",
    hud: ["LIVE/SAMPLE", "UPDATED", "FALLBACK", "HOST", "REQUESTS", "OVERVIEW"],
  },
];

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

export function RainSecurityHome({ overview, source, error }: RainSecurityHomeProps) {
  const { cursorRef } = useRainCursor();
  const [routeHover, setRouteHover] = useState<GlobeRouteHover | null>(null);
  const latestTraffic = overview.trafficTrend.at(-1);
  const highEvents = overview.recentEvents.filter((event) => event.riskLevel === "high" || event.riskLevel === "critical");
  const modeLabel = error ? "FALLBACK" : source === "api" ? syncStatusLabel[overview.sync.status] : "SAMPLE";
  const totalBandwidth = useMemo(
    () => overview.trafficTrend.reduce((total, point) => total + point.bandwidthMb, 0),
    [overview.trafficTrend],
  );
  const blockedOrChallenged = overview.recentEvents.filter((event) =>
    ["block", "challenge", "managed_challenge"].includes(event.action),
  ).length;
  const sourceLocations = useMemo(
    () => new Set(overview.globePoints.map((point) => `${point.country}:${point.city || point.clientIp}`)).size,
    [overview.globePoints],
  );

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

      <div className="rain-home-corner rain-home-corner-left">
        <span>SECURITY STUDIO</span>
        <strong>{overview.monitoredHost}</strong>
      </div>
      <div className="rain-home-corner rain-home-corner-right">
        <span>UPDATED {formatTime(overview.generatedAt)}</span>
        <strong>{modeLabel}</strong>
      </div>

      <nav className="rain-right-panel rain-home-rail-nav" aria-label="安全平台首页导航">
        {railNavItems.map((item, index) => (
          <Link
            key={item.href}
            href={item.href}
            className={`rain-column rain-column-${index}`}
            data-effect={item.effect}
            aria-label={`${item.cn}: ${item.desc}`}
          >
            <span className="rain-vertical-word" aria-hidden="true">
              {item.label.split("").map((letter, letterIndex) => (
                <span
                  key={`${letter}-${letterIndex}`}
                  data-letter={letter}
                  style={{ "--char-delay": `${letterIndex * 46}ms` } as CSSProperties}
                >
                  {letter}
                </span>
              ))}
            </span>
            <span className="rain-column-hud" aria-hidden="true">
              <span className="rain-column-corner rain-column-corner-tl" />
              <span className="rain-column-corner rain-column-corner-br" />
              <span className="rain-column-label">
                <i />
                {item.cn}
              </span>
              <span className="rain-column-scan" />
              <span className="rain-ecg-line" />
              <span className="rain-ripple rain-ripple-1" />
              <span className="rain-ripple rain-ripple-2" />
              <span className="rain-ripple rain-ripple-3" />
              <span className="rain-data-hud">
                <i />
                {item.code}
              </span>
              <span className="rain-task-container">
                {item.hud.map((line, lineIndex) => (
                  <span
                    key={line}
                    className="rain-task-item"
                    style={{ "--task-delay": `${lineIndex * 160}ms` } as CSSProperties}
                  >
                    <i />
                    <span>{line}</span>
                  </span>
                ))}
              </span>
            </span>
          </Link>
        ))}
      </nav>

      <section className="rain-left-panel rain-sim-panel" aria-label="安全态势主视觉">
        <div className="rain-home-frame" aria-hidden="true">
          <div className="rain-home-frame-top">
            <span>CHENGDU TARGET</span>
            <span>{overview.globePoints.length} SOURCES</span>
          </div>
          <div className="rain-home-frame-left">
            <p>MODE</p>
            <strong>{modeLabel}</strong>
            <span>{overview.monitoredHost}</span>
            <p>ACTIVE FILTER</p>
            <strong>ALL</strong>
            <span>VISIT / ATTACK / ANOMALY</span>
            <p>TIME RANGE</p>
            <strong>24H</strong>
            <span>{formatTime(overview.sync.lastSyncAt)} LAST SYNC</span>
          </div>
          <div className="rain-home-frame-right">
            <p>REQUESTS</p>
            <strong>{latestTraffic?.requests.toLocaleString("zh-CN") ?? "0"}</strong>
            <span>{latestTraffic?.cachedPercent ?? 0}% CACHE HIT</span>
            <p>THROUGHPUT</p>
            <strong>{latestTraffic?.bandwidthMb ?? 0}MB</strong>
            <span>{totalBandwidth.toLocaleString("zh-CN")}MB WINDOW</span>
            <p>BLOCKED / SOURCES</p>
            <strong>{blockedOrChallenged}/{sourceLocations}</strong>
            <span>{highEvents.length} HIGH RISK</span>
          </div>
          <div className="rain-home-flow-strip">
            <span>FLOW THROUGHPUT</span>
            <strong>{latestTraffic?.bandwidthMb ?? 0}MB</strong>
            <span>ORIGIN {latestTraffic?.originMb ?? 0}MB</span>
          </div>
          <div className="rain-home-frame-bottom">
            <div className="rain-home-env">
              <span>DATA MODE / {modeLabel}</span>
              <span>SYNC / {formatTime(overview.sync.lastSyncAt)} / REFRESH {overview.sync.refreshIntervalHours}H</span>
            </div>
          </div>
        </div>

        <div className="rain-globe-reserve">
          <ParticleGlobe points={overview.globePoints} onRouteHover={setRouteHover} />
        </div>
        <RouteHoverPopover hover={routeHover} layout="home" />
      </section>

      <div className="rain-mobile-title">
        <p>SECURITY SITUATION</p>
        <h1>R0L1DEHOME</h1>
      </div>
    </main>
  );
}
