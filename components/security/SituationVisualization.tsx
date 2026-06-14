"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { RouteHoverPopover } from "@/components/security/RouteHoverPopover";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { AnalysisSummary, SecuritySituationQuery } from "@/lib/security-api";
import { resolveTrafficKind } from "@/lib/security-data";
import { formatCountryDisplayName } from "@/lib/security-locale";
import type { DistributionPoint, GlobePoint, RiskLevel, SecurityDataMode, SecurityEvent, SecurityOverview } from "@/lib/security-data";

type ViewMode = "3d" | "2d";

const PANEL_LAYERS = ["01", "02", "03", "04"] as const;

type SituationVisualizationProps = {
  overview: SecurityOverview;
  analysisSummary?: AnalysisSummary | null;
  source: "api" | "sample";
  error?: string;
  initialView?: ViewMode;
  filters: SecuritySituationQuery;
};

function formatCompact(value: number) {
  return Intl.NumberFormat("zh-CN", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

const riskText: Record<RiskLevel, string> = {
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高风险",
  critical: "严重",
};

const timeRangeOptions = [
  { value: "6h", label: "06H", title: "近 6 小时" },
  { value: "24h", label: "24H", title: "近 24 小时" },
  { value: "7d", label: "07D", title: "近 7 天" },
  { value: "all", label: "ALL", title: "全部数据" },
];

const riskFilterOptions = [
  { value: "all", label: "ALL", title: "全部风险" },
  { value: "medium", label: "MED", title: "关注" },
  { value: "high+", label: "HIGH+", title: "高及以上" },
  { value: "critical", label: "CRIT", title: "严重" },
];

const timeRangeText: Record<string, string> = {
  "6h": "近 6 小时",
  "24h": "近 24 小时",
  "7d": "近 7 天",
  all: "全部数据",
};

const riskFilterText: Record<string, string> = {
  all: "全部风险",
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高及以上",
  "high+": "高及以上",
  critical: "严重",
};

const summaryLabelText: Record<string, string> = {
  attackEvents: "攻击事件",
  behaviorGroups: "行为分组",
  affectedSources: "影响来源",
  totalRequests: "总请求",
};

const analysisMessageText: Record<string, string> = {
  "Analysis is generated from local aggregation. No large model was called.": "分析结果来自本地聚合，未调用大模型。",
  "No attack behavior groups were detected for the selected filters.": "当前筛选条件下未检测到攻击行为分组。",
};

const ruleModeText: Record<string, string> = {
  active: "启用",
  enforce: "执行",
  observe: "观察",
  shadow: "影子",
};

const dataModeText: Record<SecurityDataMode, string> = {
  live: "实时数据",
  degraded: "降级",
  stale: "旧数据",
  mock: "模拟",
  "mock-cloudflare": "模拟 Cloudflare",
  sample: "样例数据",
};

const syncStatusText: Record<string, string> = {
  sample: "样例",
  mock: "模拟",
  success: "成功",
  failed: "失败",
  partial: "部分成功",
  stale: "旧数据",
  degraded: "降级",
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

function pointWithTrafficKind(point: GlobePoint): GlobePoint {
  return {
    ...point,
    trafficKind: point.trafficKind ?? resolveTrafficKind(point),
  };
}

function eventTrafficKind(event: SecurityEvent) {
  return resolveTrafficKind(event);
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

function localizedCountryName(value?: string) {
  return formatCountryDisplayName(value) || "N/A";
}

function summaryLabel(label: string) {
  return summaryLabelText[label] ?? label;
}

function analysisMessage(message?: string) {
  if (!message) return "聚合摘要尚未返回。";
  return analysisMessageText[message] ?? message;
}

function ruleModeLabel(mode: string) {
  return ruleModeText[mode] ?? mode.toUpperCase();
}

function modeLabel(mode: SecurityDataMode) {
  return dataModeText[mode] ?? mode.toUpperCase();
}

function syncLabel(status: string) {
  return syncStatusText[status] ?? status.toUpperCase();
}

function summaryItemValue(summary: AnalysisSummary | null | undefined, label: string) {
  const value = summary?.items?.find((item) => item.label === label)?.value;
  if (typeof value === "number") return formatCompact(value);
  if (typeof value === "string") return value;
  return "";
}

function situationAnalysisCopy(summary: AnalysisSummary | null | undefined, attackMix: DistributionPoint[]) {
  const attackEvents = summaryItemValue(summary, "attackEvents");
  const behaviorGroups = summaryItemValue(summary, "behaviorGroups");
  if (attackEvents && behaviorGroups) return `当前聚合 ${attackEvents} 条攻击事件，归并为 ${behaviorGroups} 个行为组。`;
  if (attackMix.length > 0) {
    const total = attackMix.reduce((sum, item) => sum + item.value, 0);
    return `当前视图展示 ${formatCompact(total)} 条攻击相关记录，优先关注 ${attackMix[0].label}。`;
  }
  return analysisMessage(summary?.summary || summary?.message);
}

function resolveSituationMode(source: "api" | "sample", error: string | undefined, overview: SecurityOverview): SecurityDataMode {
  if (overview.sync.mode && !(error && source === "api" && overview.sync.mode === "sample")) return overview.sync.mode;
  if (overview.sync.usedStaleData) return "stale";
  if (overview.sync.status === "failed") return "degraded";
  if (source === "api" && !error) return "live";
  return "sample";
}

function situationModeText(mode: SecurityDataMode, overview: SecurityOverview) {
  if (mode === "live") return "Cloudflare 实时数据可用。";
  if (mode === "stale") return "正在展示上次保留的旧数据。";
  if (mode === "degraded") return overview.sync.apiError || "Cloudflare 同步降级。";
  if (mode === "mock" || mode === "mock-cloudflare") return "Token 校验通过，当前展示模拟同步数据。";
  return "当前为样例数据模式。";
}

function riskLockText(riskLevel: RiskLevel) {
  if (riskLevel === "critical") return "CRITICAL / 严重";
  if (riskLevel === "high") return "HIGH / 高风险";
  if (riskLevel === "medium") return "MEDIUM / 关注";
  if (riskLevel === "low") return "LOW / 低风险";
  return "INFO / 信息";
}

function sourceLabel(source: "api" | "sample") {
  return source === "api" ? "API / 接口" : "SAMPLE / 样例";
}

function timeRangeFilterLabel(value?: string) {
  if (!value) return "后端默认";
  return timeRangeText[value] ?? value;
}

function riskFilterLabel(value?: string) {
  if (!value) return riskFilterText.all;
  return riskFilterText[value] ?? value;
}

function filterDisplayValue(value?: string, fallback = "全部") {
  if (!value || value === "all") return fallback;
  return value;
}

function activeFilterSummary(filters: SecuritySituationQuery) {
  const parts = [
    filters.timeRange ? timeRangeFilterLabel(filters.timeRange) : "",
    filters.risk && filters.risk !== "all" ? riskFilterLabel(filters.risk) : "",
    filters.country && filters.country !== "all" ? localizedCountryName(filters.country) : "",
    filters.attackCategory && filters.attackCategory !== "all" ? filters.attackCategory : "",
    filters.ruleId && filters.ruleId !== "all" ? filters.ruleId : "",
  ].filter(Boolean);
  return parts.length ? `展示口径：${parts.join(" / ")}` : "展示口径跟随后端默认态势聚合。";
}

function isRiskOptionActive(current: string | undefined, value: string) {
  const active = current || "all";
  if (value === "high") return active === "high" || active === "high+";
  return active === value;
}

export function SituationVisualization({
  overview,
  analysisSummary,
  source,
  error,
  initialView = "3d",
  filters,
}: SituationVisualizationProps) {
  const [view, setView] = useState<ViewMode>(initialView);
  const [routeHover, setRouteHover] = useState<GlobeRouteHover | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const currentSearchParams = useSearchParams();
  const { cursorRef } = useRainCursor();
  const mode = resolveSituationMode(source, error, overview);
  const status = modeLabel(mode);
  const filterSummary = useMemo(() => activeFilterSummary(filters), [filters]);
  const situationHref = (updates: Partial<SecuritySituationQuery>) => {
    const params = new URLSearchParams(currentSearchParams.toString());
    Object.entries(updates).forEach(([key, value]) => {
      if (value === undefined || value === null || value === "" || (key !== "timeRange" && value === "all")) {
        params.delete(key);
      } else {
        params.set(key, String(value));
      }
    });
    params.set("view", view);
    const query = params.toString();
    return query ? `${pathname}?${query}` : pathname;
  };
  const clearFiltersHref = () => {
    const params = new URLSearchParams(currentSearchParams.toString());
    ["timeRange", "risk", "country", "attackCategory", "ruleId"].forEach((key) => params.delete(key));
    params.set("view", view);
    const query = params.toString();
    return query ? `${pathname}?${query}` : pathname;
  };
  const handleViewChange = (nextView: ViewMode) => {
    setView(nextView);
    const params = new URLSearchParams(currentSearchParams.toString());
    params.set("view", nextView);
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };
  const visualPoints = useMemo(() => overview.globePoints.map(pointWithTrafficKind), [overview.globePoints]);
  const attackMix = useMemo(() => {
    const groups = new Map<string, { value: number; riskLevel: RiskLevel }>();
    overview.recentEvents
      .filter((event) => eventTrafficKind(event) === "attack")
      .forEach((event) => {
        const label = event.attackCategory || event.eventType;
        const current = groups.get(label);
        if (current) {
          current.value += 1;
          if (riskRank(event.riskLevel) > riskRank(current.riskLevel)) current.riskLevel = event.riskLevel;
        } else {
          groups.set(label, { value: 1, riskLevel: event.riskLevel });
        }
      });
    return Array.from(groups.entries())
      .map(([label, item]) => ({ label, value: item.value, riskLevel: item.riskLevel }))
      .sort((a, b) => riskRank(b.riskLevel) - riskRank(a.riskLevel) || b.value - a.value)
      .slice(0, 4);
  }, [overview.recentEvents]);
  const analysisItems = useMemo(() => analysisSummary?.items ?? [], [analysisSummary]);
  const analysisText = useMemo(() => situationAnalysisCopy(analysisSummary, attackMix), [analysisSummary, attackMix]);
  const ruleTrend = useMemo(() => {
    const rules = new Map<
      string,
      { id: string; name: string; hits: number; severity: RiskLevel | string; mode: string; attackCategory: string }
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
        const category = mostUsed(events.map((event) => event.attackCategory || event.eventType), "");
        const ruleId = mostUsed(events.flatMap((event) => normalizedRuleHits(event).map((rule) => rule.id)), "");
        return {
          label,
          region: mostUsed(events.map((event) => event.city || event.region), "无位置"),
          count: events.length,
          riskLevel: maxRiskLevel(events),
          category,
          ruleId,
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
  const globalRiskLevel = useMemo(() => maxRiskLevel(overview.recentEvents), [overview.recentEvents]);
  const lockedPoint = routeHover?.point ?? null;
  const activeRiskLevel = lockedPoint?.riskLevel ?? globalRiskLevel;

  return (
    <main className="rain-situation-page" data-lock={lockedPoint ? "on" : "idle"} data-risk={activeRiskLevel}>
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
          <p>GLOBAL THREAT LOCK / 全局威胁锁定舱</p>
          <h1>Threat Lock Bay</h1>
        </div>
      </header>

      <div className="situation-mode" role="group" aria-label="态势视图切换">
        <span className="situation-mode-rail" aria-hidden="true">
          <i data-view={view} />
        </span>
        <button type="button" aria-pressed={view === "3d"} onClick={() => handleViewChange("3d")}>
          <span>MODE A</span>
          <strong>3D / 立体追踪</strong>
        </button>
        <button type="button" aria-pressed={view === "2d"} onClick={() => handleViewChange("2d")}>
          <span>MODE B</span>
          <strong>2D / 平面投影</strong>
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

      <aside className="situation-edge-controls" aria-label="态势状态控件">
        <div className="situation-edge-control">
          <span>DATA SOURCE</span>
          <strong>{sourceLabel(source)}</strong>
          <em>{modeLabel(mode)}</em>
        </div>
        <div className="situation-edge-control">
          <span>SYNC STATE</span>
          <strong>{syncLabel(overview.sync.status)}</strong>
          <em>{overview.sync.usedStaleData ? "旧数据回读" : "最新回读"}</em>
        </div>
        <div className="situation-edge-control" data-risk={activeRiskLevel}>
          <span>RISK LOCK</span>
          <strong>{riskLockText(activeRiskLevel)}</strong>
          <em>{lockedPoint ? "目标已锁定" : "等待锁定"}</em>
        </div>
        <div className="situation-edge-control">
          <span>VIEW MODE</span>
          <strong>{view === "3d" ? "3D GLOBE" : "2D MAP"}</strong>
          <em>{view === "3d" ? "立体舱" : "平面投影"}</em>
        </div>
      </aside>

      <aside className="situation-region-panel" aria-label="安全态势信息">
        <div className="situation-panel-section situation-data-section" data-layer="00">
          <p><span>FILTER SCOPE</span><strong>态势筛选</strong></p>
          <small>{filterSummary}</small>
          <div className="situation-data-row">
            <span>时间</span>
            <strong>{timeRangeFilterLabel(filters.timeRange)}</strong>
          </div>
          <div className="situation-data-row">
            <span>风险</span>
            <strong>{riskFilterLabel(filters.risk)}</strong>
          </div>
          <div className="situation-data-row">
            <span>国家/地区</span>
            <strong>{filters.country && filters.country !== "all" ? localizedCountryName(filters.country) : "全部来源"}</strong>
          </div>
          <div className="situation-data-row">
            <span>攻击类型</span>
            <strong>{filterDisplayValue(filters.attackCategory, "全部类型")}</strong>
          </div>
          <div className="situation-data-row">
            <span>规则</span>
            <strong>{filterDisplayValue(filters.ruleId, "全部规则")}</strong>
          </div>
          {timeRangeOptions.map((option) => (
            <Link
              key={`${option.value}:time-filter`}
              href={situationHref({ timeRange: option.value })}
              className="situation-threat situation-threat-note"
              data-risk="info"
              data-active={(filters.timeRange || "") === option.value}
            >
              <span>{option.label}</span>
              <strong>{option.title}</strong>
              <em>{(filters.timeRange || "") === option.value ? "ON" : "SET"}</em>
            </Link>
          ))}
          {riskFilterOptions.map((option) => (
            <Link
              key={`${option.value}:risk-filter`}
              href={situationHref({ risk: option.value })}
              className="situation-threat"
              data-risk={option.value === "all" ? "info" : option.value}
              data-active={isRiskOptionActive(filters.risk, option.value)}
            >
              <span>{option.label}</span>
              <strong>{option.title}</strong>
              <em>{isRiskOptionActive(filters.risk, option.value) ? "ON" : "SET"}</em>
            </Link>
          ))}
          <Link href={clearFiltersHref()} className="situation-threat situation-threat-note" data-risk="info">
            <span>RESET</span>
            <strong>清除态势筛选</strong>
            <em>{view.toUpperCase()}</em>
          </Link>
        </div>

        <div className="situation-panel-section situation-analysis-section" data-layer={PANEL_LAYERS[0]}>
          <p><span>SUMMARY READBACK</span><strong>分析摘要</strong></p>
          {analysisText && <small>{analysisText}</small>}
          {analysisItems.slice(0, 3).map((item, index) => (
            <div key={`${item.label}:analysis:${index}`} className="situation-data-row">
              <span>{summaryLabel(item.label)}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
          {attackMix.map((item, index) => (
            <Link
              key={`${item.label}:attack:${index}`}
              href={situationHref({ attackCategory: item.label })}
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
              <span>状态</span>
              <strong>暂无攻击类型</strong>
              <em>0</em>
            </div>
          )}
        </div>

        <div className="situation-panel-section" data-layer={PANEL_LAYERS[1]}>
          <p><span>THREAT SOURCE</span><strong>威胁来源</strong></p>
          {sourceHabits.map((habit, index) => (
            <Link key={`${habit.label}:source:${index}`} href={situationHref({ country: habit.label })} className="situation-region" data-risk={habit.riskLevel}>
              <span>{formatCompact(habit.count)}</span>
              <strong>{localizedCountryName(habit.label)}</strong>
              <em>{habit.ruleId || "无规则"}</em>
              <small>{habit.region} / {habit.category || "无攻击类型"}</small>
            </Link>
          ))}
          {sourceHabits.length === 0 && <small>暂无攻击来源</small>}
        </div>

        <div className="situation-panel-section" data-layer={PANEL_LAYERS[2]}>
          <p><span>RULE TREND</span><strong>规则趋势</strong></p>
          {ruleTrend.map((rule, index) => (
            <Link
              key={`${rule.id}:rule:${index}`}
              href={situationHref({ attackCategory: rule.attackCategory, ruleId: rule.id })}
              className="situation-threat situation-rule-link"
              data-risk={rule.severity}
            >
              <span>{ruleModeLabel(rule.mode)}</span>
              <strong>{rule.id}</strong>
              <em>{rule.hits}</em>
              <small>{rule.attackCategory} / {rule.name}</small>
            </Link>
          ))}
          {ruleTrend.length === 0 && <small>暂无规则命中</small>}
        </div>

        <div className="situation-panel-section situation-data-section" data-layer={PANEL_LAYERS[3]}>
          <p><span>DATA TRUST</span><strong>数据可信度</strong></p>
          <div className="situation-data-row">
            <span>模式</span>
            <strong>{status}</strong>
          </div>
          <div className="situation-data-row">
            <span>事件数</span>
            <strong>{formatCompact(overview.sync.localEventCount)}</strong>
          </div>
          <div className="situation-data-row">
            <span>聚合数</span>
            <strong>{formatCompact(overview.sync.aggregateCount)}</strong>
          </div>
          <div className="situation-data-row">
            <span>规则</span>
            <strong>{dataTrust.coverage}%</strong>
          </div>
          <div className="situation-data-row">
            <span>权限</span>
            <strong>{dataTrust.readyPermissions}/{dataTrust.totalPermissions}</strong>
          </div>
          <div className="situation-data-row">
            <span>地理</span>
            <strong>{dataTrust.cityPrecision} 个市级定位</strong>
          </div>
          <small>{situationModeText(mode, overview)}</small>
        </div>

        <div className="situation-sync-line" data-status={overview.sync.status}>
          <span>{syncLabel(overview.sync.status)}</span>
          <strong>每 {overview.sync.refreshIntervalHours} 小时刷新</strong>
          <em>{overview.sync.usedStaleData ? "旧数据" : "最新"}</em>
        </div>
      </aside>

      <aside className="situation-status" aria-label="数据状态">
        <span>{status}</span>
        <span>{overview.globePoints.length} 个来源</span>
        <span>成都目标</span>
      </aside>
    </main>
  );
}
