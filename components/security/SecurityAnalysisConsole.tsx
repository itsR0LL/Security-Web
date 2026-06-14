"use client";

import type { CSSProperties } from "react";
import Link from "next/link";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { AnalysisSummary } from "@/lib/security-api";
import { formatCountryDisplayName } from "@/lib/security-locale";
import type {
  AnalysisAdvice,
  AnalysisAdviceResult,
  AnalysisCluster,
  AnalysisClustersResult,
  AnalysisEventEvidence,
  AnalysisRule,
  AnalysisRulesResult,
  AnalysisSources,
  RiskLevel,
} from "@/lib/security-data";

type SecurityAnalysisConsoleProps = {
  summary: AnalysisSummary | null;
  clusters: AnalysisClustersResult;
  rules: AnalysisRulesResult;
  sources: AnalysisSources;
  advice: AnalysisAdviceResult;
  source: "api" | "sample";
  error?: string;
  timeRange: AnalysisTimeRange;
};

type AnalysisTimeRange = "6h" | "24h" | "7d" | "all";

const timeRangeOptions: Array<{ value: AnalysisTimeRange; label: string; title: string }> = [
  { value: "6h", label: "06H", title: "近 6 小时" },
  { value: "24h", label: "24H", title: "近 24 小时" },
  { value: "7d", label: "07D", title: "近 7 天" },
  { value: "all", label: "ALL", title: "全部数据" },
];

const timeRangeText: Record<AnalysisTimeRange, string> = {
  "6h": "近 6 小时",
  "24h": "近 24 小时",
  "7d": "近 7 天",
  all: "全部数据",
};

const riskText: Record<RiskLevel, string> = {
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高风险",
  critical: "严重",
};

const summaryLabelText: Record<string, string> = {
  attackEvents: "攻击事件",
  behaviorGroups: "行为分组",
  affectedSources: "影响来源",
  totalRequests: "总请求",
};

const summaryDetailText: Record<string, string> = {
  "raw_events rows included in attack aggregation": "纳入攻击聚合的 raw_events 记录",
  "Attack behavior groups after normal visits were excluded": "排除正常访问后的攻击行为分组",
  "Source IPs associated with attack events": "与攻击事件关联的来源 IP",
  "Normal and attack request comparison baseline": "正常请求与攻击请求的对比基线",
};

const analysisMessageText: Record<string, string> = {
  "Analysis is generated from local aggregation. No large model was called.": "分析结果来自本地聚合，未调用大模型。",
  "No attack behavior groups were detected for the selected filters.": "当前筛选条件下未检测到攻击行为分组。",
  "Rule advice is generated from aggregate data only. No large model was called.": "规则建议仅由聚合数据生成，未调用大模型。",
};

const ruleModeText: Record<string, string> = {
  active: "启用",
  enforce: "执行",
  observe: "观察",
  shadow: "影子",
};

const adviceStatusText: Record<string, string> = {
  draft: "待审核",
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

function localizedCountryName(value?: string) {
  return formatCountryDisplayName(value) || "N/A";
}

function summaryLabel(label: string) {
  return summaryLabelText[label] ?? label;
}

function summaryDetail(detail: string) {
  return summaryDetailText[detail] ?? detail;
}

function analysisMessage(message?: string) {
  if (!message) return "聚合摘要尚未返回。";
  return analysisMessageText[message] ?? message;
}

function ruleModeLabel(mode: string) {
  return ruleModeText[mode] ?? mode.toUpperCase();
}

function adviceStatusLabel(status: string) {
  return adviceStatusText[status] ?? status.toUpperCase();
}

function formatDate(value?: string) {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

function timeRangeLabel(timeRange: { firstSeen: string; lastSeen: string }) {
  return `${formatDate(timeRange.firstSeen)} / ${formatDate(timeRange.lastSeen)}`;
}

function analysisSummaryCopy(
  summary: AnalysisSummary | null,
  clusters: AnalysisClustersResult,
  sources: AnalysisSources,
  dominantCluster: AnalysisCluster | null,
) {
  if (sources.totalAttackEvents > 0 || clusters.totalClusters > 0) {
    const leading = dominantCluster
      ? `锁定主行为组：${dominantCluster.attackCategory || "未分类"}，${dominantCluster.eventCount} 条事件进入复核。`
      : "";
    return `聚合 ${compact(sources.totalAttackEvents)} 条攻击事件，归并为 ${clusters.totalClusters} 个行为组。${leading}`;
  }
  return analysisMessage(summary?.summary || summary?.message);
}

function clusterPathLabel(cluster: AnalysisCluster) {
  if (!cluster.primaryPath) return "路径信号未返回";
  return `${cluster.primaryPath.method} ${cluster.primaryPath.path} / ${cluster.primaryPath.statusCode}`;
}

function clusterSourceLabel(cluster: AnalysisCluster) {
  if (!cluster.primarySource) return "来源信号未返回";
  const location = [localizedCountryName(cluster.primarySource.country), cluster.primarySource.city || cluster.primarySource.region]
    .filter(Boolean)
    .join(" / ");
  return `${cluster.primarySource.clientIp} / ${location || "N/A"}`;
}

function evidenceRouteLabel(item: AnalysisEventEvidence) {
  return `${item.method} ${item.path}`;
}

function adviceTitle(item: AnalysisAdvice) {
  const category = item.ruleDraft.classification.attackCategory;
  return category ? `复核 ${category} 规则` : item.title;
}

function adviceDetail(item: AnalysisAdvice) {
  return `影响 ${item.impact.eventCount} 条事件 / ${item.impact.sourceCount} 个来源 / ${item.impact.pathCount} 条路径`;
}

function ruleDraftCondition(item: AnalysisAdvice) {
  const text = JSON.stringify(item.ruleDraft.condition);
  return text || "{}";
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
  if (error && source === "api") return "接口降级";
  if (source === "api") return "实时接口";
  return "样例数据";
}

export function SecurityAnalysisConsole({
  summary,
  clusters,
  rules,
  sources,
  advice,
  source,
  error,
  timeRange,
}: SecurityAnalysisConsoleProps) {
  const { cursorRef } = useRainCursor();
  const clusterItems = clusters.items;
  const ruleItems = rules.items;
  const adviceItems = advice.items;
  const dominantCluster = clusterItems[0] ?? null;
  const summaryItems = summary?.items ?? [];
  const totalClusterEvents = clusterItems.reduce((sum, cluster) => sum + cluster.eventCount, 0);
  const evidenceCount = clusterItems.reduce((sum, cluster) => sum + cluster.evidence.length, 0);
  const activeRules = ruleItems.filter((rule) => rule.mode === "active").length;
  const ruleCoverage = sources.totalAttackEvents
    ? Math.min(100, Math.round((ruleItems.reduce((sum, rule) => sum + rule.eventCount, 0) / sources.totalAttackEvents) * 100))
    : 0;
  const summaryCopy = analysisSummaryCopy(summary, clusters, sources, dominantCluster);
  const matrixEvidence = dominantCluster?.evidence ?? [];
  const statusMode = error ? "DEGRADED" : source === "api" ? "LIVE" : "SAMPLE";

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
        <div className="analysis-hero-copy">
          <p>SECURITY / ANALYSIS CONTROL</p>
          <h1>分析任务控制舱</h1>
          <span>模型聚合、证据锁定、规则覆盖与待审核指令在同一终端层级内回读。</span>
        </div>
        <div className="analysis-hero-actions">
          <div className="analysis-time-switch" role="group" aria-label="分析时间范围">
            {timeRangeOptions.map((option) => (
              <Link
                key={option.value}
                href={`/security/analysis?timeRange=${option.value}`}
                title={option.title}
                data-active={timeRange === option.value}
              >
                <span>{option.label}</span>
              </Link>
            ))}
          </div>
          <Link href="/security/events" className="analysis-command-link">
            EVENT JUMP
          </Link>
        </div>
      </header>

      <section className="analysis-status-rail" aria-label="任务状态">
        <div data-mode={statusMode.toLowerCase()}>
          <span>TASK STATE</span>
          <strong>{statusMode}</strong>
          <small>{dataModeText(source, error)}</small>
        </div>
        <div>
          <span>SCAN WINDOW</span>
          <strong>{timeRangeText[timeRange]}</strong>
          <small>时间范围切换</small>
        </div>
        <div>
          <span>BEHAVIOR LOCK</span>
          <strong>{clusters.totalClusters}</strong>
          <small>行为组</small>
        </div>
        <div>
          <span>EVIDENCE READ</span>
          <strong>{evidenceCount}</strong>
          <small>{compact(totalClusterEvents)} 条事件</small>
        </div>
        <div>
          <span>RULE COVER</span>
          <strong>{ruleCoverage}%</strong>
          <small>{activeRules}/{rules.totalRules} 启用</small>
        </div>
        <div>
          <span>DRAFT QUEUE</span>
          <strong>{advice.totalDrafts}</strong>
          <small>{adviceStatusLabel(advice.status)}</small>
        </div>
      </section>

      <section className="analysis-workspace" aria-label="智能分析任务控制舱">
        <aside className="analysis-cluster-lane analysis-frame" aria-label="攻击行为分组扫描结果">
          <div className="analysis-section-title">
            <span>01</span>
            <p>扫描结果列表 / 行为分组</p>
          </div>

          <div className="analysis-cluster-list">
            {clusterItems.map((cluster, index) => (
              <Link
                key={`${cluster.clusterId}:${index}`}
                href={clusterEventsHref(cluster)}
                className="analysis-cluster-row"
                data-risk={cluster.riskLevel}
                data-locked={index === 0}
                style={
                  {
                    "--cluster-strength": `${Math.min(100, Math.max(12, cluster.eventCount * 18))}%`,
                    "--row-delay": `${index * 58}ms`,
                  } as CSSProperties
                }
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{cluster.attackCategory || "未分类行为"}</strong>
                <em>{riskLabel(cluster.riskLevel)}</em>
                <small>{cluster.attackSubtype || cluster.behaviorFingerprint || "子类型未返回"}</small>
                <i>{clusterSourceLabel(cluster)}</i>
                <b>{cluster.ruleId || "无规则"}</b>
                <u>{timeRangeLabel(cluster.timeRange)}</u>
              </Link>
            ))}
          </div>

          {clusterItems.length === 0 && <div className="analysis-empty-line">暂无攻击行为分组</div>}
        </aside>

        <div className="analysis-core-panel analysis-frame" aria-label="结论、证据与规则覆盖率">
          <div className="analysis-conclusion-panel">
            <div className="analysis-matrix-head">
              <div>
                <p>02 / MODEL CONCLUSION</p>
                <strong>{dominantCluster?.attackCategory ?? "暂无攻击信号"}</strong>
                <span>{summaryCopy}</span>
              </div>
              <Link href={dominantCluster ? clusterEventsHref(dominantCluster) : "/security/events"} className="analysis-command-link">
                LOCK EVENT
              </Link>
            </div>

            <div className="analysis-conclusion-grid">
              <div>
                <span>CONFIDENCE</span>
                <strong>{dominantCluster ? percent(dominantCluster.confidence) : "0%"}</strong>
                <small>{dominantCluster ? timeRangeLabel(dominantCluster.timeRange) : "等待聚合窗口"}</small>
              </div>
              <div>
                <span>PRIMARY PATH</span>
                <strong>{dominantCluster ? clusterPathLabel(dominantCluster) : "N/A"}</strong>
                <small>证据入口</small>
              </div>
              <div>
                <span>PRIMARY SOURCE</span>
                <strong>{dominantCluster ? clusterSourceLabel(dominantCluster) : "N/A"}</strong>
                <small>来源回读</small>
              </div>
              <div>
                <span>RULE COVERAGE</span>
                <strong>{ruleCoverage}%</strong>
                <small>{rules.totalRules} 条规则命中记录</small>
              </div>
            </div>
          </div>

          <div className="analysis-evidence-matrix" aria-label="证据矩阵">
            <div className="analysis-section-title">
              <span>03</span>
              <p>证据矩阵 / 回读通道</p>
            </div>

            <div className="analysis-evidence-grid">
              {matrixEvidence.map((item, index) => (
                <Link
                  key={`${item.id}:evidence:${index}`}
                  href={analysisEventsHref("", item.ruleId)}
                  className="analysis-evidence-cell"
                  data-risk={item.riskLevel}
                  style={{ "--row-delay": `${index * 62}ms` } as CSSProperties}
                >
                  <span>{formatDate(item.timestamp)}</span>
                  <strong>{evidenceRouteLabel(item)}</strong>
                  <em>{item.statusCode} / {item.action}</em>
                  <small>{item.clientIp} / {localizedCountryName(item.country)} / {item.ruleId || item.ruleName}</small>
                </Link>
              ))}
              {!dominantCluster && <div className="analysis-empty-line">规则分析等待后端聚合结果。</div>}
            </div>
          </div>

          <div className="analysis-rule-trend" aria-label="规则趋势">
            <div className="analysis-section-title">
              <span>04</span>
              <p>规则趋势 / 覆盖扫描</p>
            </div>

            {ruleItems.slice(0, 7).map((rule, index) => (
              <Link
                key={`${rule.ruleId}:rule:${index}`}
                href={ruleEventsHref(rule)}
                className="analysis-rule-row"
                data-risk={rule.severity}
                style={
                  {
                    "--rule-hit": `${Math.max(8, sources.totalAttackEvents ? Math.round((rule.eventCount / sources.totalAttackEvents) * 100) : 0)}%`,
                    "--row-delay": `${index * 48}ms`,
                  } as CSSProperties
                }
              >
                <span>{ruleModeLabel(rule.mode)}</span>
                <strong>{rule.ruleId}</strong>
                <em>{riskLabel(rule.severity)}</em>
                <small>{rule.attackCategory} / {rule.attackSubtype} / {rule.sourceCount} 来源 / {rule.pathCount} 路径</small>
                <b>{rule.eventCount}</b>
                <i />
              </Link>
            ))}
          </div>
        </div>

        <aside className="analysis-side-rail analysis-frame" aria-label="任务状态、来源画像与规则建议草案">
          <div className="analysis-side-section">
            <p>任务状态 / 终端回显</p>
            <small>{summaryCopy}</small>
            {summaryItems.slice(0, 4).map((item, index) => (
              <div key={`${item.label}:summary:${index}`} className="analysis-summary-row">
                <span>{summaryLabel(item.label)}</span>
                <strong>{item.value}</strong>
                {item.detail && <small>{summaryDetail(item.detail)}</small>}
              </div>
            ))}
          </div>

          <div className="analysis-side-section">
            <p>来源画像 / 证据侧线</p>
            {sources.items.slice(0, 4).map((item, index) => (
              <Link
                key={`${item.clientIp}:source:${index}`}
                href={sourceEventsHref(item)}
                className="analysis-source-row"
                data-risk={item.riskLevel}
                style={{ "--row-delay": `${index * 54}ms` } as CSSProperties}
              >
                <span>{item.clientIp}</span>
                <strong>{item.topAttackCategory || "无攻击类型"}</strong>
                <em>{item.topRuleId || "无规则"}</em>
                <small>{localizedCountryName(item.country)} / {item.city || item.region || "无位置"} / {item.topPath || "无路径"}</small>
              </Link>
            ))}
            {sources.items.length === 0 && <small>暂无攻击来源习惯聚合。</small>}
          </div>

          <div className="analysis-side-section">
            <p>数据可信度 / 覆盖校验</p>
            <div className="analysis-trust-grid">
              <span>模式</span>
              <strong>{dataModeText(source, error)}</strong>
              <span>规则覆盖</span>
              <strong>{ruleCoverage}%</strong>
              <span>请求数</span>
              <strong>{compact(sources.totalRequests)}</strong>
              <span>攻击占比</span>
              <strong>{Math.round(sources.attackShare * 100)}%</strong>
              <span>来源</span>
              <strong>{sources.affectedSources}</strong>
              <span>国家/地区</span>
              <strong>{sources.affectedCountries}</strong>
            </div>
            <small>{source === "sample" ? "样例数据仅用于前端验证，不代表真实站点风险。" : "当前分析来自后端聚合接口。"}</small>
            {error && <small>{error}</small>}
          </div>

          <div className="analysis-side-section analysis-advice-section">
            <p>建议草案 / 待审核指令</p>
            {adviceItems.slice(0, 4).map((item, index) => (
              <Link
                key={`${item.id}:advice:${index}`}
                href={adviceEventsHref(item)}
                className="analysis-advice-row"
                data-risk={item.riskLevel}
                style={{ "--row-delay": `${index * 72}ms` } as CSSProperties}
              >
                <span>{adviceStatusLabel(item.status)}</span>
                <strong>{adviceTitle(item)}</strong>
                <em>{riskLabel(item.riskLevel)} / {percent(item.confidence)}</em>
                <small>{adviceDetail(item)}</small>
                <code>{item.ruleDraft.ruleType} {ruleDraftCondition(item)}</code>
              </Link>
            ))}
            {adviceItems.length === 0 && <small>暂无规则建议草案。</small>}
          </div>
        </aside>
      </section>

      <div className="analysis-mobile-title">
        <p>ANALYSIS</p>
        <h1>CTRL</h1>
      </div>
    </main>
  );
}
