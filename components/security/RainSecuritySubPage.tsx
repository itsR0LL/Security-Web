"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import {
  checkCloudflareToken,
  runSecuritySync,
  saveCloudflareSettings,
  updateRiskThreshold,
  type TokenCheckApiResult,
} from "@/lib/security-api";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import { resolveTrafficKind } from "@/lib/security-data";
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
  info: "INFO",
  low: "LOW",
  medium: "WATCH",
  high: "HIGH",
  critical: "CRIT",
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
    active: "settings" as const,
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

function eventMatchesRisk(event: SecurityEvent, risk: FilterState["risk"]) {
  if (risk === "all") return true;
  if (risk === "high") return event.riskLevel === "high" || event.riskLevel === "critical";
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

function modeCopy(mode: SecurityDataMode, syncStatus?: SyncStatus): ModeCopy {
  if (mode === "live") {
    return {
      label: "LIVE",
      detail: "Cloudflare 实时同步可用，当前数据来自后端 live 模式。",
      tone: "live",
    };
  }
  if (mode === "stale") {
    return {
      label: "STALE",
      detail: "同步失败，当前展示上次成功保留的旧数据。",
      tone: "stale",
    };
  }
  if (mode === "degraded") {
    return {
      label: "DEGRADED",
      detail: syncStatus?.apiError || "Cloudflare 校验或同步失败，页面保留可读数据。",
      tone: "degraded",
    };
  }
  if (mode === "mock" || mode === "mock-cloudflare") {
    return {
      label: mode === "mock-cloudflare" ? "MOCK-CF" : "MOCK",
      detail: "Token 格式通过，本阶段未调用 Cloudflare，展示结构等价同步数据。",
      tone: "mock",
    };
  }
  return {
    label: "SAMPLE",
    detail: "未接入后端或未配置 Token，当前展示样例数据。",
    tone: "sample",
  };
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
    ? `[Security Studio] ${event.riskLevel.toUpperCase()} ${event.eventType}
Source: ${event.clientIp} / ${event.country} ${event.city}
Request: ${event.method} ${event.path}
Action: ${event.action}
Ray: ${event.rayId || "N/A"}
Open: /security/events/${event.id}`
    : "SELECT EVENT";

  const copyText = async () => {
    await navigator.clipboard?.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="rain-template-block">
      <span>ALERT TEXT / PENDING CHANNEL</span>
      <pre className="rain-raw-json">{text}</pre>
      <button type="button" onClick={copyText}>
        {copied ? "COPIED" : "COPY TEXT"}
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
  const generatedEvidence = matchedField || matchedValue ? [`${matchedField || "field"}=${matchedValue || "matched"}`] : fallbackEvidence;
  const classification =
    stringValue(raw.classification) ||
    [stringValue(raw.attackCategory), stringValue(raw.attackSubtype)].filter(Boolean).join(" / ") ||
    event.eventType;

  return {
    id: stringValue(raw.id) || stringValue(raw.ruleId) || event.ruleId || "unmapped-rule",
    name: stringValue(raw.name) || stringValue(raw.ruleName) || event.ruleName || "Unmapped rule",
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
      name: event.ruleName || "Unmapped rule",
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
  if (!primary) return "NO RULE";
  return hits.length > 1 ? `${hits.length} RULES / ${primary.name}` : primary.name;
}

function toolSummary(event: SecurityEvent) {
  return event.toolSignature || event.userAgent || event.action;
}

function eventTrafficKind(event: SecurityEvent) {
  return resolveTrafficKind(event);
}

function eventKindText(event: SecurityEvent) {
  return eventTrafficKind(event) === "visit" ? "VISIT" : "ATTACK";
}

function eventDisplayCategory(event: SecurityEvent) {
  return event.attackCategory || event.eventType;
}

function compactEventLine(event: SecurityEvent) {
  return `${event.method} ${event.path} / ${eventKindText(event)}: ${eventDisplayCategory(event)} / ${ruleHitSummary(event)}`;
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
  const selectedEvent = visibleEvents.find((event) => event.id === selectedId) ?? visibleEvents[0] ?? null;
  const selectedRuleHits = selectedEvent ? eventRuleHits(selectedEvent) : [];
  const selectedPrimaryRule = selectedEvent ? primaryRuleHit(selectedEvent) : null;
  const highCount = visibleEvents.filter((event) => riskRank[event.riskLevel] >= riskRank.high).length;
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
      <aside className="rain-console-spine" aria-label="事件筛选">
        <p>FILTER SYSTEM</p>
        <HudMetric label="MATCHED" value={String(visibleEvents.length)} />
        <HudMetric label="HIGH+" value={String(highCount)} />
        <HudMetric label="CONTAINED" value={String(blockedCount)} />
        <HudMetric label="MODE" value={dataModeInfo.label} />
        <div className="rain-mode-note" data-mode={dataModeInfo.tone}>
          <strong>{dataModeInfo.label}</strong>
          <span>{dataModeInfo.detail}</span>
        </div>

        <FieldLabel label="TIME WINDOW">
          <select value={filters.timeRange} onChange={(event) => updateFilter("timeRange", event.target.value as FilterState["timeRange"])}>
            <option value="6h">6H</option>
            <option value="24h">24H</option>
            <option value="7d">7D</option>
            <option value="all">ALL LOCAL</option>
          </select>
        </FieldLabel>

        <FieldLabel label="RISK LEVEL">
          <select value={filters.risk} onChange={(event) => updateFilter("risk", event.target.value as FilterState["risk"])}>
            {riskOptions.map((risk) => (
              <option key={risk} value={risk}>
                {risk.toUpperCase()}
              </option>
            ))}
          </select>
        </FieldLabel>

        <FieldLabel label="EVENT TYPE">
          <select value={filters.eventType} onChange={(event) => updateFilter("eventType", event.target.value)}>
            <option value="all">ALL TYPES</option>
            {eventTypes.map((eventType) => (
              <option key={eventType} value={eventType}>
                {eventType}
              </option>
            ))}
          </select>
        </FieldLabel>

        <FieldLabel label="ATTACK CATEGORY">
          <select value={filters.attackCategory} onChange={(event) => updateFilter("attackCategory", event.target.value)}>
            <option value="">ALL CATEGORIES</option>
            {attackCategories.map((attackCategory) => (
              <option key={attackCategory} value={attackCategory}>
                {attackCategory}
              </option>
            ))}
          </select>
        </FieldLabel>

        <FieldLabel label="RULE ID">
          <input value={filters.ruleId} placeholder="builtin-sensitive-path" onChange={(event) => updateFilter("ruleId", event.target.value)} />
        </FieldLabel>

        <FieldLabel label="SOURCE IP">
          <input value={filters.ip} placeholder="185.220" onChange={(event) => updateFilter("ip", event.target.value)} />
        </FieldLabel>
        <FieldLabel label="COUNTRY / REGION">
          <input value={filters.country} placeholder="Frankfurt / Germany" onChange={(event) => updateFilter("country", event.target.value)} />
        </FieldLabel>
        <FieldLabel label="PATH / QUERY">
          <input value={filters.path} placeholder=".env / admin" onChange={(event) => updateFilter("path", event.target.value)} />
        </FieldLabel>
        <FieldLabel label="USER AGENT">
          <input value={filters.userAgent} placeholder="curl / scanner" onChange={(event) => updateFilter("userAgent", event.target.value)} />
        </FieldLabel>

        <div className="rain-console-row-controls">
          <label>
            <span>METHOD</span>
            <select value={filters.method} onChange={(event) => updateFilter("method", event.target.value)}>
              {methodOptions.map((method) => (
                <option key={method} value={method}>
                  {method}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>STATUS</span>
            <input value={filters.statusCode} placeholder="403" onChange={(event) => updateFilter("statusCode", event.target.value.replace(/\D/g, "").slice(0, 3))} />
          </label>
        </div>

        <FieldLabel label="CLOUDFLARE ACTION">
          <select value={filters.action} onChange={(event) => updateFilter("action", event.target.value)}>
            {actionOptions.map((action) => (
              <option key={action} value={action}>
                {action.toUpperCase()}
              </option>
            ))}
          </select>
        </FieldLabel>

        <div className="rain-console-pills">
          <button type="button" onClick={applyFilters} data-active={isPending}>
            {isPending ? "APPLYING" : "APPLY"}
          </button>
          <button type="button" onClick={clearFilters}>
            RESET
          </button>
        </div>
      </aside>

      <section className="rain-console-main" aria-label="事件列表">
        <div className="rain-console-topline">
          <span>STREAM / TIMESTAMP DESC</span>
          <Link href="/security/situation">OPEN VISUAL</Link>
        </div>
        <div className="rain-event-stream">
          {visibleEvents.map((event, index) => (
            <button
              key={event.id}
              type="button"
              className="rain-event-row"
              data-risk={event.riskLevel}
              data-kind={eventTrafficKind(event)}
              data-active={selectedEvent?.id === event.id}
              style={{ "--row-delay": `${index * 28}ms` } as React.CSSProperties}
              onClick={() => setSelectedId(event.id)}
            >
              <span>{formatTime(event.timestamp)}</span>
              <em>{eventKindText(event)}</em>
              <strong>{event.clientIp}</strong>
              <small title={compactEventLine(event)}>{compactEventLine(event)}</small>
              <i title={`${event.action} / ${toolSummary(event)}`}>{toolSummary(event)}</i>
            </button>
          ))}
          {visibleEvents.length === 0 && <div className="rain-console-empty">NO MATCHED EVENT</div>}
        </div>
      </section>

      <aside className="rain-console-detail" aria-label="事件详情">
        {selectedEvent ? (
          <>
            <div className="rain-detail-heading">
              <span>FORENSIC DETAIL</span>
              <strong>{eventKindText(selectedEvent)} / {eventDisplayCategory(selectedEvent)}</strong>
              <Link href={`/security/events/${encodeURIComponent(selectedEvent.id)}`}>PERMALINK</Link>
            </div>
            <div className="rain-detail-summary">{selectedEvent.summary}</div>
            <div className="rain-detail-grid">
              <HudMetric label="SOURCE" value={selectedEvent.clientIp} />
              <HudMetric label="AREA" value={`${selectedEvent.country} / ${selectedEvent.city || selectedEvent.region || "N/A"}`} />
              <HudMetric label={eventTrafficKind(selectedEvent) === "visit" ? "VISIT" : "ATTACK"} value={eventDisplayCategory(selectedEvent)} />
              <HudMetric label="SUBTYPE" value={selectedEvent.attackSubtype || selectedEvent.eventType} />
              <HudMetric label="METHOD" value={selectedEvent.method} />
              <HudMetric label="STATUS" value={String(selectedEvent.statusCode)} />
              <HudMetric label="ACTION" value={selectedEvent.action} />
              <HudMetric label="RISK" value={riskText[selectedEvent.riskLevel]} />
              <HudMetric label="RAY" value={selectedEvent.rayId || "N/A"} />
              <HudMetric label="CONF" value={`${Math.round(selectedEvent.confidence * 100)}%`} />
              <HudMetric label="RULES" value={String(selectedRuleHits.length)} />
              <HudMetric label="VERSION" value={selectedEvent.ruleVersion || "N/A"} />
            </div>
            <div className="rain-template-block">
              <span>TOOL SIGNATURE</span>
              <p>{selectedEvent.toolSignature || selectedEvent.userAgent || "N/A"}</p>
              <p>{selectedEvent.behaviorFingerprint || "No behavior fingerprint in current event payload."}</p>
              <p>Campaign: {selectedEvent.campaignId || "N/A"}</p>
            </div>
            <div className="rain-rule-list">
              <span>RULE HITS</span>
              {selectedRuleHits.map((rule) => (
                <small key={`${rule.id}:${rule.mode}:${rule.classification}`}>
                  {rule.matched ? "MATCHED" : "SHADOW"} / {rule.id} / {rule.name} / {rule.mode} / {rule.severity} / {rule.classification} /{" "}
                  {Math.round(rule.confidence * 100)}%
                  {Array.isArray(rule.evidence) && rule.evidence.length > 0 ? ` / evidence: ${rule.evidence.join(" | ")}` : ""}
                </small>
              ))}
              {selectedRuleHits.length === 0 && <small>Cloudflare did not return matched rule details.</small>}
              {selectedPrimaryRule && <small>PRIMARY / {selectedPrimaryRule.id} / {selectedPrimaryRule.name}</small>}
            </div>
            <div className="rain-template-block">
              <span>AI ANALYSIS / RESERVED</span>
              <p>大模型分析暂缓接入；当前只展示规则分析、Cloudflare action 和原始证据。</p>
            </div>
            <EventAlertText event={selectedEvent} />
            <pre className="rain-raw-json">{JSON.stringify(selectedEvent.raw, null, 2)}</pre>
          </>
        ) : (
          <div className="rain-console-empty">SELECT EVENT</div>
        )}
      </aside>
    </div>
  );
}

function permissionStatus(permissions: PermissionCheck[]) {
  if (permissions.length === 0) return "WAIT";
  if (permissions.every((permission) => permission.ok)) return "READY";
  if (permissions.some((permission) => permission.ok)) return "PARTIAL";
  return "FAILED";
}

function tokenFormatStatus(zoneId: string, token: string, hasToken: boolean) {
  const zoneOk = /^[A-Za-z0-9_-]{8,}$/.test(zoneId || "");
  const tokenOk = Boolean(token && token.length >= 10 && !/\s/.test(token));
  if (!token && hasToken) return zoneOk ? "STORED" : "ZONE PENDING";
  if (zoneOk && tokenOk) return "LOCAL OK";
  if (!zoneId && !token && !hasToken) return "EMPTY";
  return "LOCAL FAIL";
}

function realCheckStatus(mode: SecurityDataMode, cloudflareLive?: boolean) {
  if (cloudflareLive || mode === "live") return "CLOUDFLARE LIVE";
  if (mode === "stale") return "STALE DATA";
  if (mode === "degraded") return "DEGRADED";
  if (mode === "mock" || mode === "mock-cloudflare") return "LOCAL ONLY";
  return "SAMPLE";
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
  const [message, setMessage] = useState(settings.lastTokenCheckAt ? `LAST CHECK ${settings.lastTokenCheckAt}` : "WAITING_FOR_TOKEN");
  const [busy, setBusy] = useState<"save" | "check" | "sync" | null>(null);

  const sampleMode = !hasToken && !token;
  const readiness = permissionStatus(permissions);
  const dataMode = resolveDataMode(source, error, syncStatus);
  const dataModeInfo = modeCopy(dataMode, syncStatus);
  const formatStatus = tokenFormatStatus(zoneId, token, hasToken);
  const cloudflareStatus = realCheckStatus(dataMode, syncStatus.cloudflareLive);

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
    setMessage(result.error ?? `${result.data.mode.toUpperCase()} / ${result.data.message || "CONFIG SAVED"}`);
  };

  const checkToken = async () => {
    setBusy("check");
    const result = await checkCloudflareToken({ zoneId, apiToken: token || undefined, monitoredHost, refreshIntervalHours: refreshHours });
    setBusy(null);
    const check = (result.data as TokenCheckApiResult).tokenCheck;
    if (check.permissions) setPermissions(check.permissions);
    setMessage(result.error ?? result.data.message ?? check.errorMessage ?? `TOKEN CHECK ${check.status.toUpperCase()}`);
  };

  const syncNow = async () => {
    setBusy("sync");
    const result = await runSecuritySync();
    setBusy(null);
    setMessage(result.error ?? `${result.data.mode.toUpperCase()} / ${result.data.message}`);
  };

  const saveThreshold = async (level: RiskLevel) => {
    setThreshold(level);
    const result = await updateRiskThreshold(level);
    setMessage(result.error ?? `RISK THRESHOLD ${result.data.highRiskThreshold.toUpperCase()}`);
  };

  return (
    <div className="rain-console-grid rain-settings-console">
      <aside className="rain-console-spine" aria-label="配置状态">
        <p>CONTROL SPINE</p>
        <HudMetric label="HOST" value={monitoredHost} />
        <HudMetric label="MODE" value={sampleMode ? "SAMPLE" : dataModeInfo.label} />
        <HudMetric label="FORMAT" value={formatStatus} />
        <HudMetric label="CHECK" value={cloudflareStatus} />
        <HudMetric label="TOKEN" value={hasToken ? "CONFIGURED" : "EMPTY"} />
        <HudMetric label="PERMISSION" value={readiness} />
        <HudMetric label="SYNC" value={`${refreshHours}H`} />
        <HudMetric label="RAW" value={`${retentionDays}D`} />
        <div className="rain-mode-note" data-mode={dataModeInfo.tone}>
          <strong>{dataModeInfo.label}</strong>
          <span>{dataModeInfo.detail}</span>
        </div>
      </aside>

      <section className="rain-console-main" aria-label="Cloudflare 配置">
        <div className="rain-console-topline">
          <span>CLOUDFLARE / READ ONLY</span>
          <button type="button" onClick={syncNow} disabled={busy !== null}>
            {busy === "sync" ? "SYNCING" : "SYNC NOW"}
          </button>
        </div>

        <div className="rain-settings-fields">
          <FieldLabel label="MONITORED HOST">
            <input value={monitoredHost} onChange={(event) => setMonitoredHost(event.target.value)} />
          </FieldLabel>
          <FieldLabel label="CLOUDFLARE ZONE ID">
            <input value={zoneId} placeholder="Zone ID" onChange={(event) => setZoneId(event.target.value)} />
          </FieldLabel>
          <FieldLabel label="API TOKEN">
            <input
              value={token}
              type="password"
              placeholder={hasToken ? "Token configured. Enter a new token to replace." : "Token is empty. Sample data is active."}
              onChange={(event) => setToken(event.target.value)}
            />
          </FieldLabel>
          <FieldLabel label="REFRESH WINDOW">
            <input min={1} max={24} type="number" value={refreshHours} onChange={(event) => setRefreshHours(Number(event.target.value))} />
          </FieldLabel>
          <FieldLabel label="ALERT THRESHOLD">
            <select value={threshold} onChange={(event) => saveThreshold(event.target.value as RiskLevel)}>
              {(["info", "low", "medium", "high", "critical"] as RiskLevel[]).map((level) => (
                <option key={level} value={level}>
                  {riskText[level]}
                </option>
              ))}
            </select>
          </FieldLabel>
          <FieldLabel label="RAW RETENTION">
            <input min={7} max={365} type="number" value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))} />
          </FieldLabel>
          <div className="rain-console-field">
            <span>AGGREGATE</span>
            <strong>{settings.aggregateRetention}</strong>
          </div>
        </div>

        <div className="rain-console-pills">
          <button type="button" onClick={saveSettings} disabled={busy !== null}>
            {busy === "save" ? "SAVING" : "SAVE CONFIG"}
          </button>
          <button type="button" onClick={checkToken} disabled={busy !== null}>
            {busy === "check" ? "CHECKING" : "CHECK TOKEN"}
          </button>
        </div>

        <div className="rain-template-block" aria-live="polite">
          <span>OPERATION RESULT</span>
          <p>{message}</p>
          <p>Token 格式: {formatStatus} / 真实校验: {cloudflareStatus}</p>
        </div>
      </section>

      <aside className="rain-console-detail" aria-label="权限与边界">
        <div className="rain-detail-heading">
          <span>TOKEN READINESS</span>
          <strong>{sampleMode ? "SAMPLE MODE" : `${readiness} / ${cloudflareStatus}`}</strong>
        </div>
        <div className="rain-detail-summary">
          {sampleMode
            ? "未配置 Cloudflare Token 时自动启用样例数据。Token 无效、权限不足或同步失败时，页面会展示 degraded 或 stale 状态。"
            : "Token 已配置；页面只显示配置状态，不回显 Token 明文。真实 Cloudflare 状态以 CHECK 和 MODE 为准。"}
        </div>
        <div className="rain-rule-list">
          <span>PERMISSIONS</span>
          {permissions.map((permission) => (
            <small key={permission.name} data-ok={permission.ok}>
              {permission.name} / {permission.ok ? "OK" : "WAIT"} / {permission.detail}
            </small>
          ))}
        </div>
        <div className="rain-template-block">
          <span>BOUNDARY</span>
          <p>一期只读取 Cloudflare 数据，不主动修改 WAF、防火墙或访问规则。</p>
          <p>原始事件默认保留 {retentionDays} 天；聚合统计长期保留。</p>
        </div>
      </aside>
    </div>
  );
}

export function RainSecuritySubPage(props: RainSecuritySubPageProps) {
  const { cursorRef } = useRainCursor();
  const isEvents = props.page === "events";
  const pageMeta = isEvents ? pageCopy.events : pageCopy.settings;
  const dataMode = resolveDataMode(props.source, props.error, props.syncStatus);
  const dataModeInfo = modeCopy(dataMode, props.syncStatus);

  const stats: Array<[string, string]> = isEvents
    ? [
        ["EVENTS", props.events.length.toString()],
        ["HIGH+", props.events.filter((event) => riskRank[event.riskLevel] >= riskRank.high).length.toString()],
        ["AREAS", new Set(props.events.map((event) => event.country).filter(Boolean)).size.toString()],
        ["MODE", dataModeInfo.label],
      ]
    : [
        ["ZONE", props.settings.zoneId ? "READY" : "PENDING"],
        ["TOKEN", props.settings.hasCloudflareToken ? "READY" : "EMPTY"],
        ["SYNC", props.settings.sampleMode ? "SAMPLE" : dataModeInfo.label],
        ["RISK", riskText[props.settings.highRiskThreshold]],
      ];

  return (
    <main className="rain-home rain-subpage rain-subpage-plain">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-left-dot" aria-hidden="true" />
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <SecurityGlobalNav active={pageMeta.active} />

      <section className="rain-content-layer rain-content-layer-mvp rain-content-layer-rain" aria-label={pageMeta.title}>
        <div className="rain-content-index" aria-hidden="true">
          {pageMeta.index}
        </div>
        <div className="rain-content-header">
          <p>{pageMeta.eyebrow}</p>
          <h1>{pageMeta.title}</h1>
          <span>{pageMeta.subtitle}</span>
        </div>

        <div className="rain-content-metrics">
          {stats.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <div className="rain-mvp-workspace rain-mvp-workspace-rain">
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
        <p>{isEvents ? "EVENT STREAM" : "CONTROL ROOM"}</p>
        <h1>{isEvents ? "EVENTS" : "CONFIG"}</h1>
      </div>
    </main>
  );
}
