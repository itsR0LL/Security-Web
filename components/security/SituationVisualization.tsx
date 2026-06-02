"use client";

import { useState } from "react";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { RouteHoverPopover } from "@/components/security/RouteHoverPopover";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { AnalysisSummary } from "@/lib/security-api";
import type { RiskLevel, SecurityDataMode, SecurityOverview } from "@/lib/security-data";

type ViewMode = "3d" | "2d";

type SituationVisualizationProps = {
  overview: SecurityOverview;
  analysisSummary?: AnalysisSummary | null;
  source: "api" | "sample";
  error?: string;
  initialView?: ViewMode;
};

function formatCompact(value: number) {
  return Intl.NumberFormat("zh-CN", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

const riskText: Record<RiskLevel, string> = {
  info: "INFO",
  low: "LOW",
  medium: "WATCH",
  high: "HIGH",
  critical: "CRITICAL",
};

function formatEventTime(timestamp: string) {
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function resolveSituationMode(source: "api" | "sample", error: string | undefined, overview: SecurityOverview): SecurityDataMode {
  if (overview.sync.mode && !(error && source === "api" && overview.sync.mode === "sample")) return overview.sync.mode;
  if (overview.sync.usedStaleData) return "stale";
  if (overview.sync.status === "failed") return "degraded";
  if (source === "api" && !error) return "live";
  return "sample";
}

function situationModeText(mode: SecurityDataMode, overview: SecurityOverview) {
  if (mode === "live") return "Cloudflare live data";
  if (mode === "stale") return "Showing retained stale data";
  if (mode === "degraded") return overview.sync.apiError || "Cloudflare sync degraded";
  if (mode === "mock" || mode === "mock-cloudflare") return "Local token check with mock sync data";
  return "Sample data mode";
}

export function SituationVisualization({
  overview,
  analysisSummary,
  source,
  error,
  initialView = "3d",
}: SituationVisualizationProps) {
  const [view, setView] = useState<ViewMode>(initialView);
  const [routeHover, setRouteHover] = useState<GlobeRouteHover | null>(null);
  const { cursorRef } = useRainCursor();
  const mode = resolveSituationMode(source, error, overview);
  const status = mode.toUpperCase();
  const analysisText = analysisSummary?.summary || analysisSummary?.message;

  return (
    <main className="rain-situation-page">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <div className="rain-left-dot" aria-hidden="true" />
      <SecurityGlobalNav active="situation" />

      <header className="situation-header">
        <div>
          <p>SECURITY SITUATION</p>
          <h1>Threat Visual</h1>
        </div>
      </header>

      <div className="situation-mode" role="group" aria-label="态势视图切换">
        <button type="button" aria-pressed={view === "3d"} onClick={() => setView("3d")}>
          3D 仿真
        </button>
        <button type="button" aria-pressed={view === "2d"} onClick={() => setView("2d")}>
          2D 分布
        </button>
      </div>

      <section className="situation-stage" data-view={view} aria-label={view === "3d" ? "3D 攻击态势" : "2D 请求分布"}>
        <div className="situation-globe-stage">
          <ParticleGlobe
            points={overview.globePoints}
            projection={view === "2d" ? "map" : "globe"}
            controls
            onRouteHover={setRouteHover}
          />
        </div>
      </section>
      <RouteHoverPopover hover={routeHover} layout="situation" />

      <aside className="situation-region-panel" aria-label="安全态势信息">
        <div className="situation-panel-section">
          <p>TOP REGIONS</p>
          {overview.countries.slice(0, 4).map((country, index) => (
            <div key={`${country.label}-${index}`} className="situation-region" data-risk={country.riskLevel ?? "info"}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{country.label}</strong>
              <em>{formatCompact(country.value)}</em>
            </div>
          ))}
        </div>

        <div className="situation-panel-section">
          <p>ATTACK MIX</p>
          {overview.eventTypes
            .filter((item) => item.riskLevel !== "info")
            .slice(0, 4)
            .map((item) => (
              <div key={item.label} className="situation-threat" data-risk={item.riskLevel ?? "info"}>
                <span>{riskText[item.riskLevel ?? "info"]}</span>
                <strong>{item.label}</strong>
                <em>{formatCompact(item.value)}</em>
              </div>
            ))}
        </div>

        <div className="situation-panel-section situation-stream-section">
          <p>LIVE STREAM</p>
          {overview.recentEvents.slice(0, 4).map((event) => (
            <div key={event.id} className="situation-event" data-risk={event.riskLevel}>
              <span>{formatEventTime(event.timestamp)}</span>
              <strong>{event.city || event.country}</strong>
              <em>{riskText[event.riskLevel]}</em>
              <small>{event.path}</small>
            </div>
          ))}
        </div>

        <div className="situation-panel-section situation-data-section">
          <p>DATA STATE</p>
          <div className="situation-data-row">
            <span>MODE</span>
            <strong>{status}</strong>
          </div>
          <div className="situation-data-row">
            <span>EVENTS</span>
            <strong>{formatCompact(overview.sync.localEventCount)}</strong>
          </div>
          <div className="situation-data-row">
            <span>AGG</span>
            <strong>{formatCompact(overview.sync.aggregateCount)}</strong>
          </div>
          <small>{situationModeText(mode, overview)}</small>
          {analysisText && <small>{analysisText}</small>}
        </div>

        <div className="situation-sync-line" data-status={overview.sync.status}>
          <span>{overview.sync.status.toUpperCase()}</span>
          <strong>{overview.sync.refreshIntervalHours}H REFRESH</strong>
          <em>{overview.sync.usedStaleData ? "STALE" : "FRESH"}</em>
        </div>
      </aside>

      <aside className="situation-status" aria-label="数据状态">
        <span>{status}</span>
        <span>{overview.globePoints.length} SOURCES</span>
        <span>CHENGDU TARGET</span>
      </aside>
    </main>
  );
}
