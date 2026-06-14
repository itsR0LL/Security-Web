"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import {
  checkCloudflareToken,
  runSecuritySync,
  runWorkerLogSync,
  saveCloudflareSettings,
  updateRiskThreshold,
  type TokenCheckApiResult,
} from "@/lib/security-api";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import { resolveTrafficKind } from "@/lib/security-data";
import { formatCountryDisplayName } from "@/lib/security-locale";
import type { PermissionCheck, RiskLevel, SecurityDataMode, SecurityEvent, SecurityRuleHit, SecuritySettings, SyncStatus } from "@/lib/security-data";

export type EventInitialFilters = {
  risk?: string;
  eventType?: string;
  ip?: string;
  country?: string;
  path?: string;
  action?: string;
  statusCode?: string;
  method?: string;
  userAgent?: string;
  attackCategory?: string;
  ruleId?: string;
  timeRange?: string;
  event?: string;
};

type RainSecuritySubPageProps =
  | {
      page: "events";
      events: SecurityEvent[];
      syncStatus: SyncStatus;
      initialFilters?: EventInitialFilters;
      source: "api" | "sample";
      error?: string;
    }
  | {
      page: "settings";
      settings: SecuritySettings;
      syncStatus: SyncStatus;
      source: "api" | "sample";
      error?: string;
    };

type FilterState = {
  risk: "all" | RiskLevel;
  eventType: string;
  ip: string;
  country: string;
  path: string;
  userAgent: string;
  method: string;
  statusCode: string;
  action: string;
  attackCategory: string;
  ruleId: string;
  timeRange: "6h" | "24h" | "7d" | "all";
};

const riskRank: Record<RiskLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const riskText: Record<RiskLevel, string> = {
  info: "信息",
  low: "低",
  medium: "关注",
  high: "高",
  critical: "严重",
};

const riskOptionText: Record<"all" | RiskLevel, string> = {
  all: "全部",
  info: "信息 (info)",
  low: "低 (low)",
  medium: "关注 (medium)",
  high: "高 (high)",
  critical: "严重 (critical)",
};

const riskOptions: Array<"all" | RiskLevel> = ["all", "info", "low", "medium", "high", "critical"];
const actionOptions = ["all", "allow", "block", "blocked", "challenge", "managed_challenge", "js_challenge", "log", "simulate"];
const methodOptions = ["all", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const pageCopy = {
  events: {
    eyebrow: "SECURITY / EVENT STREAM",
    title: "Security Events",
    subtitle: "按时间倒序查看请求、扫描、挑战与拦截记录，并生成高风险待发送文本。",
    active: "events" as const,
    index: "02",
  },
  settings: {
    eyebrow: "SECURITY / CONTROL ROOM",
    title: "Security Config",
    subtitle: "配置 Cloudflare 只读接入、同步周期、提醒阈值与本地数据保留策略。",
    index: "03",
  },
};

function normalizeRisk(value?: string): FilterState["risk"] {
  if (value === "info" || value === "low" || value === "medium" || value === "high" || value === "critical") return value;
  return "all";
}

function normalizeTimeRange(value?: string): FilterState["timeRange"] {
  if (value === "6h" || value === "24h" || value === "7d" || value === "all") return value;
  return "24h";
}

function buildFilters(initialFilters: EventInitialFilters = {}): FilterState {
  return {
    risk: normalizeRisk(initialFilters.risk),
    eventType: initialFilters.eventType || "all",
    ip: initialFilters.ip || "",
    country: initialFilters.country || "",
    path: initialFilters.path || "",
    userAgent: initialFilters.userAgent || "",
    method: initialFilters.method || "all",
    statusCode: initialFilters.statusCode || "",
    action: initialFilters.action || "all",
    attackCategory: initialFilters.attackCategory || "",
    ruleId: initialFilters.ruleId || "",
    timeRange: normalizeTimeRange(initialFilters.timeRange),
  };
}

function formatTime(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function localizedCountryName(value?: string) {
  return formatCountryDisplayName(value) || "N/A";
}

function localizedPlaceName(country?: string, locality?: string) {
  const displayLocality = locality?.trim();
  if (!country?.trim()) return displayLocality || "N/A";
  const displayCountry = localizedCountryName(country);
  if (!displayLocality) return displayCountry;
  return `${displayCountry} / ${displayLocality}`;
}

function eventMatchesRisk(event: SecurityEvent, risk: FilterState["risk"]) {
  if (risk === "all") return true;
  return event.riskLevel === risk;
}

function eventRuleIds(event: SecurityEvent) {
  return Array.from(new Set([event.ruleId, ...eventRuleHits(event).map((rule) => rule.id)].filter(Boolean)));
}

function eventMatchesFilters(event: SecurityEvent, filters: FilterState) {
  if (!eventMatchesRisk(event, filters.risk)) return false;
  if (filters.eventType !== "all" && event.eventType !== filters.eventType) return false;
  if (filters.action !== "all" && event.action !== filters.action) return false;
  if (filters.method !== "all" && event.method !== filters.method) return false;
  if (filters.statusCode && String(event.statusCode) !== filters.statusCode) return false;
  if (filters.attackCategory && event.attackCategory !== filters.attackCategory) return false;
  if (filters.ruleId && !eventRuleIds(event).includes(filters.ruleId)) return false;
  if (filters.ip && !event.clientIp.toLowerCase().includes(filters.ip.toLowerCase())) return false;
  if (filters.country && !`${event.country} ${event.region} ${event.city}`.toLowerCase().includes(filters.country.toLowerCase())) return false;
  if (filters.path && !`${event.path} ${event.query ?? ""}`.toLowerCase().includes(filters.path.toLowerCase())) return false;
  if (filters.userAgent && !event.userAgent.toLowerCase().includes(filters.userAgent.toLowerCase())) return false;
  return true;
}

function buildEventQuery(filters: FilterState) {
  const params = new URLSearchParams();
  if (filters.risk !== "all") params.set("risk", filters.risk);
  if (filters.eventType !== "all") params.set("eventType", filters.eventType);
  if (filters.ip) params.set("ip", filters.ip);
  if (filters.country) params.set("country", filters.country);
  if (filters.path) params.set("path", filters.path);
  if (filters.userAgent) params.set("userAgent", filters.userAgent);
  if (filters.method !== "all") params.set("method", filters.method);
  if (filters.statusCode) params.set("statusCode", filters.statusCode);
  if (filters.action !== "all") params.set("action", filters.action);
  if (filters.attackCategory) params.set("attackCategory", filters.attackCategory);
  if (filters.ruleId) params.set("ruleId", filters.ruleId);
  if (filters.timeRange !== "24h") params.set("timeRange", filters.timeRange);
  return params.toString();
}

type ModeCopy = {
  label: string;
  detail: string;
  tone: "live" | "degraded" | "stale" | "mock" | "sample";
};

function resolveDataMode(source: "api" | "sample", error?: string, syncStatus?: SyncStatus): SecurityDataMode {
  if (syncStatus?.mode && !(error && source === "api" && syncStatus.mode === "sample")) return syncStatus.mode;
  if (syncStatus?.usedStaleData) return "stale";
  if (syncStatus?.status === "failed") return "degraded";
  if (error && source === "api") return "degraded";
  if (source === "api") return "live";
  return "sample";
}

function modeCopy(mode: SecurityDataMode | "worker_log", syncStatus?: Pick<SyncStatus, "apiError">): ModeCopy {
  if (mode === "worker_log") {
    return {
      label: "Worker/D1",
      detail: syncStatus?.apiError || "Worker/D1 access log sync is available.",
      tone: "live",
    };
  }
  if (mode === "live") {
    return {
      label: "实时",
      detail: "Cloudflare 实时同步可用，当前数据来自后端实时模式。",
      tone: "live",
    };
  }
  if (mode === "stale") {
    return {
      label: "旧数据",
      detail: "同步失败，当前展示上次成功保留的旧数据。",
      tone: "stale",
    };
  }
  if (mode === "degraded") {
    return {
      label: "降级",
      detail: syncStatus?.apiError || "Cloudflare 校验或同步失败，页面保留可读数据。",
      tone: "degraded",
    };
  }
  if (mode === "mock" || mode === "mock-cloudflare") {
    return {
      label: mode === "mock-cloudflare" ? "本地模拟 Cloudflare" : "本地模拟",
      detail: "Token 格式通过，本阶段未调用 Cloudflare，展示结构等价同步数据。",
      tone: "mock",
    };
  }
  return {
    label: "样例",
    detail: "未接入后端或未配置 Token，当前展示样例数据。",
    tone: "sample",
  };
}

function tokenCheckStatusText(status: TokenCheckApiResult["tokenCheck"]["status"]) {
  if (status === "success") return "通过";
  if (status === "failed") return "失败";
  if (status === "partial") return "部分通过";
  if (status === "degraded") return "降级";
  return status;
}

function HudMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rain-console-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="rain-console-field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function EventAlertText({ event }: { event: SecurityEvent | null }) {
  const [copied, setCopied] = useState(false);
  const text = event
    ? `[Security Studio] ${event.riskLevel.toUpperCase()} / ${event.eventType}
LOCK: ${event.id}
SOURCE: ${event.clientIp} / ${localizedPlaceName(event.country, event.city || event.region)}
REQUEST: ${event.method} ${event.path}
ACTION: ${event.action}
RULE: ${ruleHitSummary(event)}
RAY: ${event.rayId || "N/A"}
LINK: /security/events/${event.id}`
    : "请选择事件";

  const copyText = async () => {
    await navigator.clipboard?.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="rain-template-block rain-alert-command">
      <span>COMMAND / ALERT BUFFER</span>
      <pre className="rain-raw-json">{text}</pre>
      <button type="button" onClick={copyText}>
        {copied ? "BUFFER COPIED" : "复制告警文本"}
      </button>
    </div>
  );
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value : "";
}

function stringArray(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function normalizeRuleHit(hit: SecurityRuleHit | Record<string, unknown>, event: SecurityEvent, fallbackEvidence: string[]): SecurityRuleHit {
  const raw = hit as Record<string, unknown>;
  const mode = stringValue(raw.mode) || "observe";
  const matchedField = stringValue(raw.matchedField);
  const matchedValue = stringValue(raw.matchedValue);
  const evidence = stringArray(raw.evidence);
  const generatedEvidence = matchedField || matchedValue ? [`${matchedField || "字段"}=${matchedValue || "命中"}`] : fallbackEvidence;
  const classification =
    stringValue(raw.classification) ||
    [stringValue(raw.attackCategory), stringValue(raw.attackSubtype)].filter(Boolean).join(" / ") ||
    event.eventType;

  return {
    id: stringValue(raw.id) || stringValue(raw.ruleId) || event.ruleId || "unmapped-rule",
    name: stringValue(raw.name) || stringValue(raw.ruleName) || event.ruleName || "未映射规则",
    mode,
    severity: stringValue(raw.severity) || event.riskLevel,
    classification,
    evidence: evidence.length ? evidence : generatedEvidence,
    confidence: typeof raw.confidence === "number" ? raw.confidence : event.confidence,
    matched: typeof raw.matched === "boolean" ? raw.matched : mode !== "shadow",
  };
}

function eventRuleHits(event: SecurityEvent): SecurityRuleHit[] {
  const ruleMatches = Array.isArray(event.ruleMatches) ? event.ruleMatches : [];
  if (event.ruleHits?.length) return event.ruleHits.map((hit) => normalizeRuleHit(hit, event, ruleMatches));
  if (ruleMatches.length === 0 && !event.ruleId && !event.ruleName) return [];
  return [
    {
      id: event.ruleId || "unmapped-rule",
      name: event.ruleName || "未映射规则",
      mode: "observe",
      severity: event.riskLevel,
      classification: event.eventType,
      evidence: ruleMatches,
      confidence: event.confidence,
      matched: true,
    },
  ];
}

function primaryRuleHit(event: SecurityEvent) {
  const hits = eventRuleHits(event);
  return hits.find((hit) => hit.matched) ?? hits[0] ?? null;
}

function ruleHitSummary(event: SecurityEvent) {
  const hits = eventRuleHits(event);
  const primary = hits.find((hit) => hit.matched) ?? hits[0];
  if (!primary) return "无规则";
  return hits.length > 1 ? `${hits.length} 条规则 / ${primary.name}` : primary.name;
}

function toolSummary(event: SecurityEvent) {
  return event.toolSignature || event.userAgent || event.action;
}

function eventTrafficKind(event: SecurityEvent) {
  return resolveTrafficKind(event);
}

function eventKindText(event: SecurityEvent) {
  return eventTrafficKind(event) === "visit" ? "访问" : "攻击";
}

function eventDisplayCategory(event: SecurityEvent) {
  return event.attackCategory || event.eventType;
}

function compactEventLine(event: SecurityEvent) {
  return `${event.method} ${event.path} / 流量类型: ${eventKindText(event)} / ${eventDisplayCategory(event)} / ${ruleHitSummary(event)}`;
}

function eventEvidenceItems(event: SecurityEvent) {
  return [
    `request=${event.method} ${event.path}${event.query ? `?${event.query}` : ""}`,
    `status=${event.statusCode}`,
    `action=${event.action}`,
    `source=${event.clientIp}`,
    `ray=${event.rayId || "N/A"}`,
  ];
}

function RainEventConsole({
  events,
  initialFilters,
  syncStatus,
  source,
  error,
}: {
  events: SecurityEvent[];
  initialFilters: EventInitialFilters;
  syncStatus: SyncStatus;
  source: "api" | "sample";
  error?: string;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();
  const mergedInitialFilters = useMemo<EventInitialFilters>(
    () => ({
      ...initialFilters,
      risk: searchParams.get("risk") ?? initialFilters.risk,
      eventType: searchParams.get("eventType") ?? initialFilters.eventType,
      ip: searchParams.get("ip") ?? searchParams.get("source") ?? initialFilters.ip,
      country: searchParams.get("country") ?? initialFilters.country,
      path: searchParams.get("path") ?? initialFilters.path,
      action: searchParams.get("action") ?? initialFilters.action,
      statusCode: searchParams.get("statusCode") ?? initialFilters.statusCode,
      method: searchParams.get("method") ?? initialFilters.method,
      userAgent: searchParams.get("userAgent") ?? initialFilters.userAgent,
      attackCategory: searchParams.get("attackCategory") ?? initialFilters.attackCategory,
      ruleId: searchParams.get("ruleId") ?? initialFilters.ruleId,
      timeRange: searchParams.get("timeRange") ?? initialFilters.timeRange,
      event: searchParams.get("event") ?? initialFilters.event,
    }),
    [initialFilters, searchParams],
  );
  const [filters, setFilters] = useState<FilterState>(() => buildFilters(mergedInitialFilters));
  const [selectedId, setSelectedId] = useState(mergedInitialFilters.event ?? events[0]?.id ?? "");
  const eventTypes = useMemo(() => Array.from(new Set(events.map((event) => event.eventType))).filter(Boolean), [events]);
  const attackCategories = useMemo(
    () => Array.from(new Set(events.map((event) => event.attackCategory || event.eventType))).filter(Boolean),
    [events],
  );

  const visibleEvents = useMemo(
    () => events.filter((event) => eventMatchesFilters(event, filters)).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)),
    [events, filters],
  );
  const highMetricEvents = useMemo(() => {
    const filtersWithoutRisk: FilterState = { ...filters, risk: "all" };
    return events.filter((event) => eventMatchesFilters(event, filtersWithoutRisk));
  }, [events, filters]);
  const selectedEvent = visibleEvents.find((event) => event.id === selectedId) ?? visibleEvents[0] ?? null;
  const selectedRuleHits = selectedEvent ? eventRuleHits(selectedEvent) : [];
  const selectedPrimaryRule = selectedEvent ? primaryRuleHit(selectedEvent) : null;
  const highCount = highMetricEvents.filter((event) => riskRank[event.riskLevel] >= riskRank.high).length;
  const blockedCount = visibleEvents.filter((event) => event.action === "block" || event.action === "managed_challenge").length;
  const dataMode = resolveDataMode(source, error, syncStatus);
  const dataModeInfo = modeCopy(dataMode, syncStatus);

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const applyFilters = () => {
    const query = buildEventQuery(filters);
    startTransition(() => {
      router.push(query ? `/security/events?${query}` : "/security/events");
    });
  };

  const clearFilters = () => {
    const next = buildFilters({});
    setFilters(next);
    startTransition(() => router.push("/security/events"));
  };

  return (
    <div className="rain-console-grid rain-event-console">
      <aside className="rain-console-spine rain-filter-panel" aria-label="事件筛选">
        <div className="rain-filter-head">
          <span>FILTER CONTROL</span>
          <strong>SCAN LOCK</strong>
        </div>
        <div className="rain-filter-metrics">
          <HudMetric label="匹配事件" value={String(visibleEvents.length)} />
          <HudMetric label="高危锁定" value={String(highCount)} />
          <HudMetric label="已处置" value={String(blockedCount)} />
          <HudMetric label="数据链路" value={dataModeInfo.label} />
        </div>
        <div className="rain-mode-note" data-mode={dataModeInfo.tone}>
          <strong>{dataModeInfo.label}</strong>
          <span>{dataModeInfo.detail}</span>
        </div>

        <div className="rain-filter-section">
          <span>01 / TIME + RISK</span>
          <FieldLabel label="时间范围">
            <select value={filters.timeRange} onChange={(event) => updateFilter("timeRange", event.target.value as FilterState["timeRange"])}>
              <option value="6h">近 6 小时</option>
              <option value="24h">近 24 小时</option>
              <option value="7d">近 7 天</option>
              <option value="all">全部本地</option>
            </select>
          </FieldLabel>

          <FieldLabel label="风险等级">
            <select value={filters.risk} onChange={(event) => updateFilter("risk", event.target.value as FilterState["risk"])}>
              {riskOptions.map((risk) => (
                <option key={risk} value={risk}>
                  {riskOptionText[risk]}
                </option>
              ))}
            </select>
          </FieldLabel>
        </div>

        <div className="rain-filter-section">
          <span>02 / RULE TRACE</span>
          <FieldLabel label="事件类型">
            <select value={filters.eventType} onChange={(event) => updateFilter("eventType", event.target.value)}>
              <option value="all">全部类型</option>
              {eventTypes.map((eventType, index) => (
                <option key={`${eventType}:eventType:${index}`} value={eventType}>
                  {eventType}
                </option>
              ))}
            </select>
          </FieldLabel>

          <FieldLabel label="攻击分类">
            <select value={filters.attackCategory} onChange={(event) => updateFilter("attackCategory", event.target.value)}>
              <option value="">全部分类</option>
              {attackCategories.map((attackCategory, index) => (
                <option key={`${attackCategory}:attackCategory:${index}`} value={attackCategory}>
                  {attackCategory}
                </option>
              ))}
            </select>
          </FieldLabel>

          <FieldLabel label="规则 ID">
            <input value={filters.ruleId} placeholder="builtin-sensitive-path" onChange={(event) => updateFilter("ruleId", event.target.value)} />
          </FieldLabel>
        </div>

        <div className="rain-filter-section">
          <span>03 / SOURCE READBACK</span>
          <FieldLabel label="源 IP">
            <input value={filters.ip} placeholder="185.220" onChange={(event) => updateFilter("ip", event.target.value)} />
          </FieldLabel>
          <FieldLabel label="国家 / 地区">
            <input value={filters.country} placeholder="JP / 日本 / Tokyo" onChange={(event) => updateFilter("country", event.target.value)} />
          </FieldLabel>
          <FieldLabel label="path / query">
            <input value={filters.path} placeholder=".env / admin" onChange={(event) => updateFilter("path", event.target.value)} />
          </FieldLabel>
          <FieldLabel label="User-Agent">
            <input value={filters.userAgent} placeholder="curl / scanner" onChange={(event) => updateFilter("userAgent", event.target.value)} />
          </FieldLabel>
        </div>

        <div className="rain-filter-section">
          <span>04 / EDGE ACTION</span>
          <div className="rain-console-row-controls">
            <label>
              <span>HTTP 方法</span>
              <select value={filters.method} onChange={(event) => updateFilter("method", event.target.value)}>
                {methodOptions.map((method) => (
                  <option key={method} value={method}>
                    {method === "all" ? "全部" : method}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>状态码</span>
              <input value={filters.statusCode} placeholder="403" onChange={(event) => updateFilter("statusCode", event.target.value.replace(/\D/g, "").slice(0, 3))} />
            </label>
          </div>

          <FieldLabel label="Cloudflare action">
            <select value={filters.action} onChange={(event) => updateFilter("action", event.target.value)}>
              {actionOptions.map((action) => (
                <option key={action} value={action}>
                  {action === "all" ? "全部" : action}
                </option>
              ))}
            </select>
          </FieldLabel>
        </div>

        <div className="rain-console-pills">
          <button type="button" onClick={applyFilters} data-active={isPending}>
            {isPending ? "扫描中" : "执行扫描"}
          </button>
          <button type="button" onClick={clearFilters}>
            清除锁定
          </button>
        </div>
      </aside>

      <section className="rain-console-main rain-event-queue" aria-label="事件列表">
        <div className="rain-console-topline">
          <span>EVENT QUEUE / TIME DESC</span>
          <strong>{visibleEvents.length} ITEMS / {highCount} HIGH+</strong>
          <Link href="/security/situation">打开态势图</Link>
        </div>
        <div className="rain-event-stream">
          {visibleEvents.map((event, index) => (
            <button
              key={`${event.id}:event:${index}`}
              type="button"
              className="rain-event-row"
              data-risk={event.riskLevel}
              data-kind={eventTrafficKind(event)}
              data-active={selectedEvent?.id === event.id}
              style={{ "--row-delay": `${index * 28}ms` } as React.CSSProperties}
              onClick={() => setSelectedId(event.id)}
            >
              <span className="rain-event-time">
                {formatTime(event.timestamp)}
                <b>{event.source}</b>
              </span>
              <em className="rain-event-risk">{riskText[event.riskLevel]}</em>
              <strong className="rain-event-source">{event.clientIp}</strong>
              <small className="rain-event-action" title={`${event.action} / ${event.method} / ${event.statusCode}`}>
                <span>{event.action}</span>
                <b>
                  {event.method} / {event.statusCode}
                </b>
              </small>
              <span className="rain-event-rule" title={ruleHitSummary(event)}>
                {ruleHitSummary(event)}
              </span>
              <i title={`${compactEventLine(event)} / ${toolSummary(event)}`}>{toolSummary(event)}</i>
            </button>
          ))}
          {visibleEvents.length === 0 && <div className="rain-console-empty">没有匹配事件</div>}
        </div>
      </section>

      <aside className="rain-console-detail rain-evidence-lock" data-risk={selectedEvent?.riskLevel ?? "info"} aria-label="事件详情">
        {selectedEvent ? (
          <div key={selectedEvent.id} className="rain-evidence-window">
            <div className="rain-detail-lockbar">
              <span>LOCKED EVENT</span>
              <strong>{selectedEvent.id}</strong>
            </div>
            <div className="rain-detail-heading rain-detail-phase-title">
              <span>FORENSIC WINDOW</span>
              <strong>{eventKindText(selectedEvent)} / {eventDisplayCategory(selectedEvent)}</strong>
              <div className="rain-detail-actions">
                <Link href={`/security/events/${encodeURIComponent(selectedEvent.id)}`}>查看固定链接</Link>
                <Link href="/security/situation">打开态势图</Link>
              </div>
            </div>
            <div className="rain-detail-summary rain-detail-phase-summary">{selectedEvent.summary}</div>
            <div className="rain-detail-grid">
              <HudMetric label="源 IP" value={selectedEvent.clientIp} />
              <HudMetric label="区域" value={localizedPlaceName(selectedEvent.country, selectedEvent.city || selectedEvent.region)} />
              <HudMetric label="流量类型" value={eventKindText(selectedEvent)} />
              <HudMetric label="事件类型" value={eventDisplayCategory(selectedEvent)} />
              <HudMetric label="子类型" value={selectedEvent.attackSubtype || selectedEvent.eventType} />
              <HudMetric label="HTTP 方法" value={selectedEvent.method} />
              <HudMetric label="状态码" value={String(selectedEvent.statusCode)} />
              <HudMetric label="Cloudflare action" value={selectedEvent.action} />
              <HudMetric label="风险" value={riskText[selectedEvent.riskLevel]} />
              <HudMetric label="ray id" value={selectedEvent.rayId || "N/A"} />
              <HudMetric label="置信度" value={`${Math.round(selectedEvent.confidence * 100)}%`} />
              <HudMetric label="规则数" value={String(selectedRuleHits.length)} />
              <HudMetric label="版本" value={selectedEvent.ruleVersion || "N/A"} />
            </div>
            <div className="rain-template-block rain-evidence-section">
              <span>EVIDENCE / REQUEST TRACE</span>
              {eventEvidenceItems(selectedEvent).map((item, index) => (
                <p key={`${selectedEvent.id}:evidence:${index}`}>{item}</p>
              ))}
              <p>tool={selectedEvent.toolSignature || selectedEvent.userAgent || "N/A"}</p>
              <p>fingerprint={selectedEvent.behaviorFingerprint || "当前事件 payload 未提供 behaviorFingerprint。"}</p>
              <p>campaignId={selectedEvent.campaignId || "N/A"}</p>
            </div>
            <div className="rain-rule-list">
              <span>RULE HIT / READBACK</span>
              {selectedRuleHits.map((rule, index) => (
                <small key={`${rule.id}:${rule.mode}:${rule.classification}:${index}`} data-risk={rule.severity}>
                  <b>{rule.matched ? "MATCH" : "SHADOW"}</b> / {rule.id} / {rule.name}
                  <br />
                  {rule.mode} / {rule.severity} / {rule.classification} / {Math.round(rule.confidence * 100)}%
                  {Array.isArray(rule.evidence) && rule.evidence.length > 0 ? ` / evidence: ${rule.evidence.join(" | ")}` : ""}
                </small>
              ))}
              {selectedRuleHits.length === 0 && <small>Cloudflare 未返回命中规则详情。</small>}
              {selectedPrimaryRule && <small>PRIMARY / {selectedPrimaryRule.id} / {selectedPrimaryRule.name}</small>}
            </div>
            <EventAlertText event={selectedEvent} />
            <div className="rain-template-block rain-raw-json-block">
              <span>RAW JSON / EVENT PAYLOAD</span>
              <pre className="rain-raw-json">{JSON.stringify(selectedEvent.raw, null, 2)}</pre>
            </div>
          </div>
        ) : (
          <div className="rain-console-empty">请选择事件</div>
        )}
      </aside>
    </div>
  );
}

function permissionStatus(permissions: PermissionCheck[]) {
  if (permissions.length === 0) return "待校验";
  if (permissions.every((permission) => permission.ok)) return "就绪";
  if (permissions.some((permission) => permission.ok)) return "部分就绪";
  return "失败";
}

function tokenFormatStatus(zoneId: string, token: string, hasToken: boolean) {
  const zoneOk = /^[A-Za-z0-9_-]{8,}$/.test(zoneId || "");
  const tokenOk = Boolean(token && token.length >= 10 && !/\s/.test(token));
  if (!token && hasToken) return zoneOk ? "已保存" : "待填写 Zone ID";
  if (zoneOk && tokenOk) return "本地格式通过";
  if (!zoneId && !token && !hasToken) return "未填写";
  return "本地格式异常";
}

function realCheckStatus(mode: SecurityDataMode, cloudflareLive?: boolean) {
  if (cloudflareLive || mode === "live") return "Cloudflare 已连通";
  if (mode === "stale") return "使用旧数据";
  if (mode === "degraded") return "降级";
  if (mode === "mock" || mode === "mock-cloudflare") return "仅本地校验";
  return "样例";
}

function syncStatusText(status?: string) {
  if (!status) return "未同步";
  if (status === "success") return "成功";
  if (status === "failed") return "失败";
  if (status === "partial") return "部分完成";
  if (status === "stale") return "旧数据";
  if (status === "degraded") return "降级";
  if (status === "sample") return "样例";
  if (status === "mock") return "模拟";
  return status;
}

function RainSettingsConsole({
  settings,
  syncStatus,
  source,
  error,
}: {
  settings: SecuritySettings;
  syncStatus: SyncStatus;
  source: "api" | "sample";
  error?: string;
}) {
  const [zoneId, setZoneId] = useState(settings.zoneId);
  const [token, setToken] = useState("");
  const [monitoredHost, setMonitoredHost] = useState(settings.monitoredHost);
  const [refreshHours, setRefreshHours] = useState(settings.refreshIntervalHours);
  const [threshold, setThreshold] = useState<RiskLevel>(settings.highRiskThreshold);
  const [retentionDays, setRetentionDays] = useState(settings.rawRetentionDays);
  const [permissions, setPermissions] = useState(settings.permissions);
  const [hasToken, setHasToken] = useState(settings.hasCloudflareToken);
  const [message, setMessage] = useState(settings.lastTokenCheckAt ? `上次校验 ${settings.lastTokenCheckAt}` : "等待 Token");
  const [busy, setBusy] = useState<"save" | "check" | "sync" | "workerSync" | null>(null);

  const sampleMode = !hasToken && !token;
  const readiness = permissionStatus(permissions);
  const cloudflareSyncStatus: SyncStatus = { ...syncStatus, ...(syncStatus.cloudflare ?? {}) };
  const workerLogSync = syncStatus.workerLog;
  const dataMode = resolveDataMode(source, error, cloudflareSyncStatus);
  const dataModeInfo = modeCopy(dataMode, cloudflareSyncStatus);
  const workerModeInfo = workerLogSync
    ? modeCopy(workerLogSync.mode ?? (workerLogSync.usedStaleData ? "stale" : workerLogSync.status === "failed" ? "degraded" : "live"), workerLogSync)
    : {
        label: "未同步",
        detail: "尚未执行 Worker/D1 访问日志同步。本地运行测试时可从 D1 拉取最新访问记录。",
        tone: "degraded" as const,
      };
  const formatStatus = tokenFormatStatus(zoneId, token, hasToken);
  const cloudflareStatus = realCheckStatus(dataMode, cloudflareSyncStatus.cloudflareLive);

  const saveSettings = async () => {
    setBusy("save");
    const result = await saveCloudflareSettings({
      monitoredHost,
      zoneId,
      apiToken: token || undefined,
      refreshIntervalHours: refreshHours,
    });
    setBusy(null);
    const savedSettings = result.data.settings;
    if (savedSettings) {
      setHasToken(savedSettings.hasCloudflareToken);
      setPermissions(savedSettings.permissions ?? permissions);
    }
    setMessage(result.error ?? `${modeCopy(result.data.mode).label} / ${result.data.message || "配置已保存"}`);
  };

  const checkToken = async () => {
    setBusy("check");
    const result = await checkCloudflareToken({ zoneId, apiToken: token || undefined, monitoredHost, refreshIntervalHours: refreshHours });
    setBusy(null);
    const check = (result.data as TokenCheckApiResult).tokenCheck;
    if (check.permissions) setPermissions(check.permissions);
    setMessage(result.error ?? result.data.message ?? check.errorMessage ?? `Token 校验${tokenCheckStatusText(check.status)}`);
  };

  const syncNow = async () => {
    setBusy("sync");
    const result = await runSecuritySync();
    setBusy(null);
    const mode = result.data.mode === "worker_log" ? "live" : result.data.mode;
    setMessage(result.error ?? `${modeCopy(mode).label} / ${result.data.message}`);
  };

  const syncWorkerLogs = async () => {
    setBusy("workerSync");
    const result = await runWorkerLogSync();
    setBusy(null);
    setMessage(result.error ?? `${syncStatusText(result.data.status)} / ${result.data.message}`);
  };

  const saveThreshold = async (level: RiskLevel) => {
    setThreshold(level);
    const result = await updateRiskThreshold(level);
    setMessage(result.error ?? `风险阈值已更新为 ${riskText[result.data.highRiskThreshold]}`);
  };

  return (
    <div className="rain-console-grid rain-settings-console">
      <aside className="rain-console-spine" aria-label="配置状态">
        <p>控制状态</p>
        <HudMetric label="监控 Host" value={monitoredHost} />
        <HudMetric label="Cloudflare" value={sampleMode ? "样例" : dataModeInfo.label} />
        <HudMetric label="Worker/D1" value={workerModeInfo.label} />
        <HudMetric label="Token 格式" value={formatStatus} />
        <HudMetric label="校验" value={cloudflareStatus} />
        <HudMetric label="Token" value={hasToken ? "已配置" : "未填写"} />
        <HudMetric label="权限" value={readiness} />
        <HudMetric label="官方同步" value={`${refreshHours} 小时`} />
        <HudMetric label="原始保留" value={`${retentionDays} 天`} />
        <div className="rain-mode-note" data-mode={dataModeInfo.tone}>
          <strong>{dataModeInfo.label}</strong>
          <span>{dataModeInfo.detail}</span>
        </div>
        <div className="rain-mode-note" data-mode={workerModeInfo.tone}>
          <strong>{workerModeInfo.label}</strong>
          <span>{workerModeInfo.detail}</span>
        </div>
      </aside>

      <section className="rain-console-main rain-settings-main" aria-label="安全设置分区">
        <div className="rain-console-topline">
          <span>CONFIG / OFFICIAL + D1 CHANNELS</span>
          <strong>{sampleMode ? "样例模式" : `${readiness} / ${cloudflareStatus}`}</strong>
        </div>

        <div className="rain-settings-section-grid">
          <section className="rain-settings-section" aria-label="Cloudflare 官方 API">
            <div className="rain-settings-section-head">
              <span>01 / CLOUDFLARE API</span>
              <h2>Cloudflare 官方 API</h2>
              <p>配置只读接入信息，并通过 Token 校验确认权限状态。</p>
            </div>

            <div className="rain-settings-fields">
              <FieldLabel label="监控 Host">
                <input value={monitoredHost} onChange={(event) => setMonitoredHost(event.target.value)} />
              </FieldLabel>
              <FieldLabel label="Cloudflare Zone ID">
                <input value={zoneId} placeholder="Zone ID" onChange={(event) => setZoneId(event.target.value)} />
              </FieldLabel>
              <FieldLabel label="API Token">
                <input
                  value={token}
                  type="password"
                  placeholder={hasToken ? "Token 已配置，输入新 Token 后替换。" : "Token 未填写，当前使用样例数据。"}
                  onChange={(event) => setToken(event.target.value)}
                />
              </FieldLabel>
              <div className="rain-console-field">
                <span>Token 就绪状态</span>
                <strong>{sampleMode ? "样例模式" : `${readiness} / ${cloudflareStatus}`}</strong>
              </div>
              <div className="rain-console-field rain-console-field-wide">
                <span>Token 存储说明</span>
                <strong>{hasToken ? "已保存的 Token 不会回显；只在输入新 Token 后替换。" : "保存 Token 后页面只显示已配置状态。"}</strong>
              </div>
            </div>

            <div className="rain-console-pills">
              <button type="button" onClick={saveSettings} disabled={busy !== null}>
                {busy === "save" ? "保存中" : "保存配置"}
              </button>
              <button type="button" onClick={checkToken} disabled={busy !== null}>
                {busy === "check" ? "校验中" : "校验 Token"}
              </button>
            </div>
          </section>

          <section className="rain-settings-section" aria-label="Worker/D1 日志链路">
            <div className="rain-settings-section-head">
              <span>02 / WORKER D1 LOGS</span>
              <h2>Worker/D1 日志链路</h2>
              <p>从 Worker 采集服务导出 D1 访问日志，并写入本地 SQLite；这不使用 Cloudflare 官方 API Token。</p>
            </div>

            <div className="rain-detail-grid">
              <HudMetric label="本地事件" value={String(syncStatus.localEventCount)} />
              <HudMetric label="聚合统计" value={String(syncStatus.aggregateCount)} />
              <HudMetric label="日志状态" value={syncStatusText(workerLogSync?.status)} />
              <HudMetric label="最近成功" value={workerLogSync?.lastSuccessAt || "未同步"} />
            </div>

            <div className="rain-console-pills rain-console-pills-single">
              <button type="button" onClick={syncWorkerLogs} disabled={busy !== null}>
                {busy === "workerSync" ? "拉取中" : "同步访问日志"}
              </button>
            </div>

            <div className="rain-mode-note" data-mode={workerModeInfo.tone}>
              <strong>{workerModeInfo.label}</strong>
              <span>{workerModeInfo.detail}</span>
            </div>

            <div className="rain-rule-list">
              <span>Cloudflare 官方权限项</span>
              {permissions.map((permission, index) => (
                <small key={`${permission.name}:permission:${index}`} data-ok={permission.ok}>
                  {permission.name} / {permission.ok ? "通过" : "待处理"} / {permission.detail}
                </small>
              ))}
            </div>
          </section>

          <section className="rain-settings-section" aria-label="同步状态">
            <div className="rain-settings-section-head">
              <span>03 / SYNC STATE</span>
              <h2>Cloudflare 官方同步</h2>
              <p>控制 Cloudflare GraphQL 同步间隔，并查看官方统计与安全事件的最近同步状态。</p>
            </div>

            <div className="rain-settings-fields rain-settings-fields-compact">
              <FieldLabel label="同步间隔（小时）">
                <input min={1} max={24} type="number" value={refreshHours} onChange={(event) => setRefreshHours(Number(event.target.value))} />
              </FieldLabel>
              <div className="rain-console-field">
                <span>当前状态</span>
                <strong>{syncStatusText(cloudflareSyncStatus.status)}</strong>
              </div>
              <div className="rain-console-field">
                <span>最近同步</span>
                <strong>{cloudflareSyncStatus.lastSyncAt || "N/A"}</strong>
              </div>
              <div className="rain-console-field">
                <span>最近成功</span>
                <strong>{cloudflareSyncStatus.lastSuccessAt || "N/A"}</strong>
              </div>
            </div>

            <div className="rain-console-pills rain-console-pills-single">
              <button type="button" onClick={syncNow} disabled={busy !== null}>
                {busy === "sync" ? "同步中" : "同步 Cloudflare"}
              </button>
            </div>

            <div className="rain-mode-note" data-mode={dataModeInfo.tone}>
              <strong>{dataModeInfo.label}</strong>
              <span>{dataModeInfo.detail}</span>
            </div>
          </section>

          <section className="rain-settings-section" aria-label="数据保留">
            <div className="rain-settings-section-head">
              <span>04 / RETENTION</span>
              <h2>数据保留</h2>
              <p>管理原始事件保留天数、聚合保留策略和提醒阈值。</p>
            </div>

            <div className="rain-settings-fields">
              <FieldLabel label="原始事件保留（天）">
                <input min={7} max={365} type="number" value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))} />
              </FieldLabel>
              <FieldLabel label="提醒阈值">
                <select value={threshold} onChange={(event) => saveThreshold(event.target.value as RiskLevel)}>
                  {(["info", "low", "medium", "high", "critical"] as RiskLevel[]).map((level) => (
                    <option key={level} value={level}>
                      {riskText[level]}
                    </option>
                  ))}
                </select>
              </FieldLabel>
              <div className="rain-console-field">
                <span>聚合保留</span>
                <strong>{settings.aggregateRetention}</strong>
              </div>
              <div className="rain-console-field">
                <span>旧数据</span>
                <strong>{cloudflareSyncStatus.usedStaleData || workerLogSync?.usedStaleData ? "使用中" : "未使用"}</strong>
              </div>
            </div>

            <div className="rain-template-block">
              <span>边界</span>
              <p>Cloudflare 官方 API 与 Worker/D1 访问日志是两条独立链路；访问日志同步失败不会清空已保存的 Zone ID 或 API Token。</p>
              <p>原始事件默认保留 {retentionDays} 天；聚合统计长期保留。</p>
            </div>
          </section>
        </div>

        <div className="rain-template-block rain-settings-result" aria-live="polite">
          <span>操作结果</span>
          <p>{message}</p>
          <p>Cloudflare API: {formatStatus} / {cloudflareStatus}；Worker/D1: {syncStatusText(workerLogSync?.status)}</p>
        </div>
      </section>
    </div>
  );
}

export function RainSecuritySubPage(props: RainSecuritySubPageProps) {
  const router = useRouter();
  const { cursorRef } = useRainCursor();
  const isEvents = props.page === "events";
  const isSettings = props.page === "settings";
  const pageMeta = isEvents ? pageCopy.events : pageCopy.settings;
  const dataMode = resolveDataMode(props.source, props.error, props.syncStatus);
  const dataModeInfo = modeCopy(dataMode, props.syncStatus);
  const rootClassName = isEvents ? "rain-home rain-subpage rain-subpage-plain rain-events-page" : "rain-home rain-subpage rain-subpage-plain";
  const layerClassName = isEvents
    ? "rain-content-layer rain-content-layer-mvp rain-content-layer-rain rain-events-layer"
    : "rain-content-layer rain-content-layer-mvp rain-content-layer-rain rain-settings-layer";
  const workspaceClassName = isEvents ? "rain-mvp-workspace rain-mvp-workspace-rain rain-event-workspace" : "rain-mvp-workspace rain-mvp-workspace-rain rain-settings-workspace";

  const stats: Array<[string, string]> = isEvents
    ? [
        ["事件", props.events.length.toString()],
        ["高危+", props.events.filter((event) => riskRank[event.riskLevel] >= riskRank.high).length.toString()],
        ["区域", new Set(props.events.map((event) => event.country).filter(Boolean)).size.toString()],
        ["模式", dataModeInfo.label],
      ]
    : [
        ["Zone ID", props.settings.zoneId ? "就绪" : "待填写"],
        ["Token", props.settings.hasCloudflareToken ? "就绪" : "未填写"],
        ["同步", props.settings.sampleMode ? "样例" : dataModeInfo.label],
        ["风险", riskText[props.settings.highRiskThreshold]],
      ];

  const returnToPreviousPage = () => {
    if (window.history.length > 1) {
      router.back();
      return;
    }

    router.push("/security");
  };

  return (
    <main className={rootClassName}>
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-left-dot" aria-hidden="true" />
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      {isEvents ? <SecurityGlobalNav active="events" /> : null}
      {isSettings ? (
        <button type="button" className="security-settings-back" onClick={returnToPreviousPage}>
          <span>BACK</span>
          <strong>返回上一页</strong>
        </button>
      ) : null}

      <section className={layerClassName} aria-label={pageMeta.title}>
        <div className="rain-content-index" aria-hidden="true">
          {pageMeta.index}
        </div>
        <div className="rain-content-header">
          <p>{pageMeta.eyebrow}</p>
          <h1>{pageMeta.title}</h1>
          <span>{pageMeta.subtitle}</span>
        </div>

        <div className="rain-content-metrics">
          {stats.map(([label, value], index) => (
            <div key={`${label}:stat:${index}`}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <div className={workspaceClassName}>
          {isEvents ? (
            <RainEventConsole
              key={JSON.stringify(props.initialFilters ?? {})}
              events={props.events}
              initialFilters={props.initialFilters ?? {}}
              syncStatus={props.syncStatus}
              source={props.source}
              error={props.error}
            />
          ) : (
            <RainSettingsConsole settings={props.settings} syncStatus={props.syncStatus} source={props.source} error={props.error} />
          )}
        </div>
      </section>

      <div className="rain-mobile-title">
        <p>{isEvents ? "事件流" : "控制室"}</p>
        <h1>{isEvents ? "事件" : "配置"}</h1>
      </div>
    </main>
  );
}
