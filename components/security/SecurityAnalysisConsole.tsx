"use client";

import Link from "next/link";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { AnalysisSummary } from "@/lib/security-api";
import type { AnalysisAdvice, AnalysisAdviceResult, AnalysisCluster, AnalysisClustersResult, AnalysisRule, AnalysisRulesResult, AnalysisSources, RiskLevel } from "@/lib/security-data";

type SecurityAnalysisConsoleProps = {
  summary: AnalysisSummary | null;
  clusters: AnalysisClustersResult;
  rules: AnalysisRulesResult;
  sources: AnalysisSources;
  advice: AnalysisAdviceResult;
  source: "api" | "sample";
  error?: string;
};

const riskText: Record<RiskLevel, string> = {
  info: "INFO",
  low: "LOW",
  medium: "WATCH",
  high: "HIGH",
  critical: "CRITICAL",
};

function riskLabel(riskLevel: RiskLevel | string) {
  return riskLevel in riskText ? riskText[riskLevel as RiskLevel] : riskLevel.toUpperCase();
}

function percent(value: number) {
  return `${Math.round(value * 100)}%`;
}

function compact(value: number) {
  return Intl.NumberFormat("zh-CN", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function timeRangeLabel(timeRange: { firstSeen: string; lastSeen: string }) {
  const format = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return `${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
  };
  return `${format(timeRange.firstSeen)} / ${format(timeRange.lastSeen)}`;
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

function clusterEventsHref(cluster: AnalysisCluster) {
  return analysisEventsHref(cluster.attackCategory, cluster.ruleId);
}

function ruleEventsHref(rule: AnalysisRule) {
  return analysisEventsHref(rule.attackCategory, rule.ruleId);
}

function sourceEventsHref(item: AnalysisSources["items"][number]) {
  return analysisEventsHref(item.topAttackCategory, item.topRuleId, { country: item.country });
}

function adviceEventsHref(item: AnalysisAdvice) {
  return analysisEventsHref(item.ruleDraft.classification.attackCategory, "");
}

function dataModeText(source: "api" | "sample", error?: string) {
  if (error && source === "api") return "DEGRADED";
  if (source === "api") return "API";
  return "SAMPLE";
}

export function SecurityAnalysisConsole({ summary, clusters, rules, sources, advice, source, error }: SecurityAnalysisConsoleProps) {
  const { cursorRef } = useRainCursor();
  const clusterItems = clusters.items;
  const ruleItems = rules.items;
  const adviceItems = advice.items;
  const dominantCluster = clusterItems[0] ?? null;
  const summaryItems = summary?.items ?? [];
  const totalClusterEvents = clusterItems.reduce((sum, cluster) => sum + cluster.eventCount, 0);
  const activeRules = ruleItems.filter((rule) => rule.mode === "active").length;
  const ruleCoverage = sources.totalAttackEvents
    ? Math.round((ruleItems.reduce((sum, rule) => sum + rule.eventCount, 0) / sources.totalAttackEvents) * 100)
    : 0;

  return (
    <main className="rain-analysis-page">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <div className="rain-left-dot" aria-hidden="true" />
      <SecurityGlobalNav active="analysis" />

      <header className="analysis-hero">
        <div>
          <p>SECURITY / ANALYSIS</p>
          <h1>Attack Analysis</h1>
          <span>攻击类型、规则命中、来源习惯与规则建议草案集中在这里。</span>
        </div>
        <Link href="/security/events">OPEN EVENTS</Link>
      </header>

      <section className="analysis-status-rail" aria-label="分析状态">
        <div>
          <span>MODE</span>
          <strong>{dataModeText(source, error)}</strong>
        </div>
        <div>
          <span>CLUSTERS</span>
          <strong>{clusters.totalClusters}</strong>
        </div>
        <div>
          <span>EVENTS</span>
          <strong>{compact(totalClusterEvents)}</strong>
        </div>
        <div>
          <span>RULES</span>
          <strong>{activeRules}/{rules.totalRules}</strong>
        </div>
      </section>

      <section className="analysis-workspace" aria-label="攻击行为分析">
        <div className="analysis-cluster-lane">
          <div className="analysis-section-title">
            <span>01</span>
            <p>ATTACK BEHAVIOR GROUPS</p>
          </div>

          {clusterItems.map((cluster, index) => (
            <Link
              key={cluster.clusterId}
              href={clusterEventsHref(cluster)}
              className="analysis-cluster-row"
              data-risk={cluster.riskLevel}
              style={
                {
                  "--cluster-strength": `${Math.min(100, Math.max(16, cluster.eventCount * 22))}%`,
                  "--row-delay": `${index * 46}ms`,
                } as React.CSSProperties
              }
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{cluster.attackCategory}</strong>
              <em>{riskLabel(cluster.riskLevel)}</em>
              <small>{cluster.attackSubtype}</small>
              <i>{timeRangeLabel(cluster.timeRange)}</i>
              <b>{cluster.ruleId || "NO_RULE"}</b>
            </Link>
          ))}

          {clusterItems.length === 0 && <div className="analysis-empty-line">NO ATTACK GROUP</div>}
        </div>

        <div className="analysis-core-panel">
          <div className="analysis-matrix-head">
            <div>
              <p>TYPE MATRIX</p>
              <strong>{dominantCluster?.attackCategory ?? "NO SIGNAL"}</strong>
              <span>{dominantCluster ? `${dominantCluster.eventCount} events / ${percent(dominantCluster.confidence)}` : "等待攻击聚合数据"}</span>
            </div>
            <Link href={dominantCluster ? clusterEventsHref(dominantCluster) : "/security/events"}>TRACE</Link>
          </div>

          <div className="analysis-matrix-lines" aria-hidden="true">
            {clusterItems.slice(0, 7).map((cluster, index) => (
              <span
                key={cluster.clusterId}
                data-risk={cluster.riskLevel}
                style={
                  {
                    "--line-width": `${Math.min(96, Math.max(14, cluster.eventCount * 18))}%`,
                    "--line-offset": `${index * 13}%`,
                  } as React.CSSProperties
                }
              />
            ))}
          </div>

          <div className="analysis-evidence-strip">
            {(dominantCluster?.evidence ?? []).map((item) => (
              <small key={item.id}>{item.summary || `${item.method} ${item.path}`}</small>
            ))}
            {!dominantCluster && <small>规则分析等待后端聚合结果。</small>}
          </div>

          <div className="analysis-rule-trend">
            <div className="analysis-section-title">
              <span>02</span>
              <p>RULE HIT TREND</p>
            </div>
            {ruleItems.slice(0, 6).map((rule) => (
              <Link key={rule.ruleId} href={ruleEventsHref(rule)} className="analysis-rule-row" data-risk={rule.severity}>
                <span>{rule.mode.toUpperCase()}</span>
                <strong>{rule.ruleId}</strong>
                <em>{riskLabel(rule.severity)}</em>
                <small>{rule.attackCategory} / {rule.attackSubtype}</small>
                <i style={{ "--rule-hit": `${Math.max(8, sources.totalAttackEvents ? Math.round((rule.eventCount / sources.totalAttackEvents) * 100) : 0)}%` } as React.CSSProperties} />
              </Link>
            ))}
          </div>
        </div>

        <aside className="analysis-side-rail" aria-label="来源习惯、数据可信度与建议">
          <div className="analysis-side-section">
            <p>ANALYSIS SUMMARY</p>
            {summaryItems.slice(0, 4).map((item) => (
              <div key={item.label} className="analysis-summary-row">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
                {item.detail && <small>{item.detail}</small>}
              </div>
            ))}
            {summaryItems.length === 0 && <small>{summary?.message ?? "AI analysis is reserved."}</small>}
          </div>

          <div className="analysis-side-section">
            <p>SOURCE HABITS</p>
            {sources.items.slice(0, 4).map((item) => (
              <Link key={item.clientIp} href={sourceEventsHref(item)} className="analysis-source-row" data-risk={item.riskLevel}>
                <span>{item.clientIp}</span>
                <strong>{item.topAttackCategory || "NO_ATTACK"}</strong>
                <em>{item.topRuleId || "NO_RULE"}</em>
                <small>{item.country} / {item.city || item.region || "N/A"} / {item.topPath || "NO_PATH"}</small>
              </Link>
            ))}
            {sources.items.length === 0 && <small>暂无攻击来源习惯聚合。</small>}
          </div>

          <div className="analysis-side-section">
            <p>DATA TRUST</p>
            <div className="analysis-trust-grid">
              <span>MODE</span>
              <strong>{dataModeText(source, error)}</strong>
              <span>RULE COVER</span>
              <strong>{ruleCoverage}%</strong>
              <span>REQUESTS</span>
              <strong>{compact(sources.totalRequests)}</strong>
              <span>ATTACK</span>
              <strong>{Math.round(sources.attackShare * 100)}%</strong>
              <span>SOURCES</span>
              <strong>{sources.affectedSources}</strong>
              <span>COUNTRIES</span>
              <strong>{sources.affectedCountries}</strong>
            </div>
            <small>{source === "sample" ? "样例模式只用于前端验证，不代表真实站点风险。" : "当前分析来自后端聚合接口。"}</small>
            {error && <small>{error}</small>}
          </div>

          <div className="analysis-side-section">
            <p>RULE ADVICE DRAFT</p>
            {adviceItems.slice(0, 3).map((item) => (
              <Link key={item.id} href={adviceEventsHref(item)} className="analysis-advice-row" data-risk={item.riskLevel}>
                <span>{item.status.toUpperCase()}</span>
                <strong>{item.title}</strong>
                <small>{item.manualReviewQuestions[0] ?? item.rationale}</small>
              </Link>
            ))}
          </div>
        </aside>
      </section>

      <div className="analysis-mobile-title">
        <p>ANALYSIS</p>
        <h1>ATTACKS</h1>
      </div>
    </main>
  );
}
