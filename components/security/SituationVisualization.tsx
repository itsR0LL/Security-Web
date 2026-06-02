"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { RouteHoverPopover } from "@/components/security/RouteHoverPopover";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { AnalysisSummary } from "@/lib/security-api";
import { resolveTrafficKind } from "@/lib/security-data";
import type { DistributionPoint, GlobePoint, RiskLevel, SecurityDataMode, SecurityEvent, SecurityOverview } from "@/lib/security-data";

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

function riskRank(riskLevel: RiskLevel) {
  if (riskLevel === "critical") return 4;
  if (riskLevel === "high") return 3;
  if (riskLevel === "medium") return 2;
  if (riskLevel === "low") return 1;
  return 0;
}

function maxRiskLevel(events: SecurityEvent[]) {
  return events.reduce<RiskLevel>((current, event) => (riskRank(event.riskLevel) > riskRank(current) ? event.riskLevel : current), "info");
}

function isAttackMixItem(item: DistributionPoint) {
  return item.riskLevel ? riskRank(item.riskLevel) >= 2 : false;
}

function pointWithTrafficKind(point: GlobePoint): GlobePoint {
  return {
    ...point,
    trafficKind: point.trafficKind ?? resolveTrafficKind(point),
  };
}

function eventTrafficKind(event: SecurityEvent) {
  return resolveTrafficKind(event);
}

function analysisEventsHref(attackCategory: string, ruleId: string, extra?: Record<string, string>) {
  const params = new URLSearchParams();
  if (attackCategory) params.set("attackCategory", attackCategory);
  if (ruleId) params.set("ruleId", ruleId);
  Object.entries(extra ?? {}).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  const query = params.toString();
  return query ? `/security/events?${query}` : "/security/events";
}

function normalizedRuleHits(event: SecurityEvent) {
  if (event.ruleHits?.length) return event.ruleHits;
  if (!event.ruleId && !event.ruleName) return [];
  return [
    {
      id: event.ruleId,
      name: event.ruleName || event.ruleId,
      mode: "observe",
      severity: event.riskLevel,
      classification: event.attackCategory || event.eventType,
      evidence: event.ruleMatches,
      confidence: event.confidence,
      matched: true,
    },
  ];
}

function mostUsed(values: string[], fallback = "N/A") {
  const counts = new Map<string, number>();
  values.filter(Boolean).forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? fallback;
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
  const visualPoints = useMemo(() => overview.globePoints.map(pointWithTrafficKind), [overview.globePoints]);
  const attackMix = useMemo(() => overview.eventTypes.filter(isAttackMixItem).slice(0, 4), [overview.eventTypes]);
  const analysisItems = useMemo(() => analysisSummary?.items ?? [], [analysisSummary]);
  const ruleTrend = useMemo(() => {
    const rules = new Map<
      string,
      { id: string; name: string; hits: number; severity: RiskLevel | string; mode: string; attackCategory: string; href: string }
    >();
    overview.recentEvents.forEach((event) => {
      normalizedRuleHits(event).forEach((rule) => {
        const attackCategory = event.attackCategory || event.eventType;
        const current = rules.get(rule.id);
        if (current) {
          current.hits += 1;
          if (riskRank(rule.severity as RiskLevel) > riskRank(current.severity as RiskLevel)) current.severity = rule.severity;
        } else {
          rules.set(rule.id, {
            id: rule.id,
            name: rule.name,
            hits: 1,
            severity: rule.severity,
            mode: rule.mode,
            attackCategory,
            href: analysisEventsHref(attackCategory, rule.id),
          });
        }
      });
    });
    return Array.from(rules.values()).sort((a, b) => b.hits - a.hits).slice(0, 4);
  }, [overview.recentEvents]);
  const sourceHabits = useMemo(() => {
    const groups = new Map<string, SecurityEvent[]>();
    overview.recentEvents
      .filter((event) => eventTrafficKind(event) === "attack")
      .forEach((event) => {
        const key = event.country || event.clientIp || event.id;
        groups.set(key, [...(groups.get(key) ?? []), event]);
      });
    return Array.from(groups.entries())
      .map(([label, events]) => {
        const category = mostUsed(events.map((event) => event.attackCategory || event.eventType));
        const ruleId = mostUsed(events.flatMap((event) => normalizedRuleHits(event).map((rule) => rule.id)), "");
        return {
          label,
          region: mostUsed(events.map((event) => event.city || event.region)),
          count: events.length,
          riskLevel: maxRiskLevel(events),
          category,
          ruleId,
          href: analysisEventsHref(category, ruleId, { country: label }),
        };
      })
      .sort((a, b) => riskRank(b.riskLevel) - riskRank(a.riskLevel) || b.count - a.count)
      .slice(0, 4);
  }, [overview.recentEvents]);
  const dataTrust = useMemo(() => {
    const cityPrecision = overview.globePoints.filter((point) => point.locationPrecision === "city").length;
    const covered = overview.recentEvents.filter((event) => normalizedRuleHits(event).length > 0).length;
    const coverage = overview.recentEvents.length ? Math.round((covered / overview.recentEvents.length) * 100) : 0;
    const readyPermissions = overview.sync.permissions.filter((permission) => permission.ok).length;
    return {
      cityPrecision,
      coverage,
      readyPermissions,
      totalPermissions: overview.sync.permissions.length,
    };
  }, [overview.globePoints, overview.recentEvents, overview.sync.permissions]);

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

      <section className="situation-stage" data-view={view} aria-label={view === "3d" ? "3D 访问与攻击态势" : "2D 请求分布"}>
        <div className="situation-globe-stage">
          <ParticleGlobe
            points={visualPoints}
            projection={view === "2d" ? "map" : "globe"}
            controls
            onRouteHover={setRouteHover}
          />
        </div>
      </section>
      <RouteHoverPopover hover={routeHover} layout="situation" />

      <aside className="situation-region-panel" aria-label="安全态势信息">
        <div className="situation-panel-section situation-analysis-section">
          <p>ANALYSIS SUMMARY</p>
          {analysisText && <small>{analysisText}</small>}
          {analysisItems.slice(0, 3).map((item) => (
            <div key={item.label} className="situation-data-row">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
          {attackMix.map((item) => (
            <Link
              key={item.label}
              href={analysisEventsHref(item.label, "")}
              className="situation-threat"
              data-risk={item.riskLevel ?? "info"}
            >
              <span>{riskText[item.riskLevel ?? "info"]}</span>
              <strong>{item.label}</strong>
              <em>{formatCompact(item.value)}</em>
            </Link>
          ))}
          {attackMix.length === 0 && (
            <div className="situation-threat situation-threat-note" data-risk="info">
              <span>STATE</span>
              <strong>NO ATTACK TYPE</strong>
              <em>0</em>
            </div>
          )}
        </div>

        <div className="situation-panel-section">
          <p>RULE TREND</p>
          {ruleTrend.map((rule) => (
            <Link key={rule.id} href={rule.href} className="situation-threat situation-rule-link" data-risk={rule.severity}>
              <span>{rule.mode.toUpperCase()}</span>
              <strong>{rule.id}</strong>
              <em>{rule.hits}</em>
              <small>{rule.attackCategory} / {rule.name}</small>
            </Link>
          ))}
          {ruleTrend.length === 0 && <small>NO RULE HIT</small>}
        </div>

        <div className="situation-panel-section">
          <p>SOURCE HABITS</p>
          {sourceHabits.map((habit) => (
            <Link key={habit.label} href={habit.href} className="situation-region" data-risk={habit.riskLevel}>
              <span>{formatCompact(habit.count)}</span>
              <strong>{habit.label}</strong>
              <em>{habit.ruleId || "NO_RULE"}</em>
              <small>{habit.region} / {habit.category}</small>
            </Link>
          ))}
          {sourceHabits.length === 0 && <small>NO ATTACK SOURCE</small>}
        </div>

        <div className="situation-panel-section situation-data-section">
          <p>DATA TRUST</p>
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
          <div className="situation-data-row">
            <span>RULE</span>
            <strong>{dataTrust.coverage}%</strong>
          </div>
          <div className="situation-data-row">
            <span>PERM</span>
            <strong>{dataTrust.readyPermissions}/{dataTrust.totalPermissions}</strong>
          </div>
          <div className="situation-data-row">
            <span>GEO</span>
            <strong>{dataTrust.cityPrecision} CITY</strong>
          </div>
          <small>{situationModeText(mode, overview)}</small>
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
