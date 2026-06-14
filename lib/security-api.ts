import {
  createAnalysisAdvice,
  createAnalysisClusters,
  createAnalysisRules,
  createAnalysisSources,
  createSampleSecurityData,
  type AnalysisAdviceResult,
  type AnalysisClustersResult,
  type AnalysisRulesResult,
  type AnalysisSources,
  type SecurityEvent,
  type SecurityDataMode,
  type SecurityOverview,
  type SecurityRuleHit,
  type SecuritySettings,
  type SyncStatus,
  type RiskLevel,
  type DistributionPoint,
  type RankedItem,
  riskOrder,
} from "./security-data";

export type SecurityApiResult<T> = {
  data: T;
  source: "api" | "sample";
  error?: string;
};

const requestTimeoutMs = 1200;

export type SecurityEventQuery = {
  risk?: string;
  riskLevel?: string;
  eventType?: string;
  ip?: string;
  country?: string;
  region?: string;
  path?: string;
  userAgent?: string;
  method?: string;
  action?: string;
  statusCode?: string;
  attackCategory?: string;
  ruleId?: string;
  timeRange?: string;
  limit?: number;
  offset?: number;
};

export type SecurityAnalysisQuery = {
  timeRange?: string;
  risk?: string;
  country?: string;
  attackCategory?: string;
  ruleId?: string;
  limit?: number;
};

export type SecuritySituationQuery = Omit<SecurityAnalysisQuery, "limit"> & {
  view?: string;
};

export type CloudflareSettingsPayload = {
  monitoredHost: string;
  zoneId: string;
  apiToken?: string;
  refreshIntervalHours: number;
};

export type TokenCheckResult = {
  checkedAt: string;
  status: "success" | "failed" | "partial" | "degraded";
  zoneRead: boolean;
  analyticsRead: boolean;
  securityEventsRead: boolean;
  errorMessage: string | null;
  details?: Record<string, unknown>;
  permissions?: SecuritySettings["permissions"];
};

export type TokenCheckApiResult = {
  mode: SecurityDataMode;
  status: "sample" | "mock" | "degraded" | "live" | "stale" | "success" | "failed" | "partial" | string;
  cloudflareLive: boolean;
  message: string;
  tokenCheck: TokenCheckResult;
  settings?: SecuritySettings;
  usedStaleData?: boolean;
};

export type SyncRunResult = {
  mode: SecurityDataMode | "worker_log";
  status?: "sample" | "mock" | "success" | "failed" | "partial" | "stale" | "degraded" | string;
  cloudflareLive?: boolean;
  usedStaleData?: boolean;
  message: string;
  events?: number;
  accessLogs?: number;
  aggregates?: number;
  cursor?: number;
  nextCursor?: number;
  hasMore?: boolean;
  tokenCheck?: TokenCheckResult;
};

export type AnalysisSummary = {
  status?: string;
  message?: string;
  summary?: string;
  generatedAt?: string;
  items?: Array<{
    label: string;
    value: string | number;
    detail?: string;
  }>;
  [key: string]: unknown;
};

function getApiBaseUrl() {
  return process.env.SECURITY_API_BASE_URL || process.env.NEXT_PUBLIC_SECURITY_API_BASE_URL || "";
}

function joinUrl(baseUrl: string, path: string) {
  return `${baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

function appendQuery(path: string, query: Record<string, string | number | undefined | null>) {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    params.set(key, String(value));
  });
  const queryString = params.toString();
  return queryString ? `${path}?${queryString}` : path;
}

async function fetchWithFallback<T>(path: string, fallback: T): Promise<SecurityApiResult<T>> {
  const baseUrl = getApiBaseUrl();

  if (!baseUrl) {
    return {
      data: fallback,
      source: "sample",
      error: "未配置 SECURITY_API_BASE_URL，使用样例数据。",
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

  try {
    const response = await fetch(joinUrl(baseUrl, path), {
      cache: "no-store",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`后端返回 ${response.status}`);
    }

    const payload = await response.json();
    if (payload && payload.success === false) {
      throw new Error(payload.message || "后端返回失败");
    }

    return {
      data: (payload?.data ?? payload) as T,
      source: "api",
    };
  } catch (error) {
    return {
      data: fallback,
      source: "sample",
      error: error instanceof Error ? error.message : "读取后端数据失败，使用样例数据。",
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function postWithFallback<T>(path: string, payload: unknown, fallback: T): Promise<SecurityApiResult<T>> {
  const baseUrl = getApiBaseUrl();

  if (!baseUrl) {
    return {
      data: fallback,
      source: "sample",
      error: "未配置 SECURITY_API_BASE_URL，当前仅完成前端本地预览。",
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

  try {
    const response = await fetch(joinUrl(baseUrl, path), {
      method: "POST",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload ?? {}),
    });

    if (!response.ok) {
      throw new Error(`后端返回 ${response.status}`);
    }

    const body = await response.json();
    if (body && body.success === false) {
      throw new Error(body.message || "后端返回失败");
    }

    return {
      data: (body?.data ?? body) as T,
      source: "api",
    };
  } catch (error) {
    return {
      data: fallback,
      source: "sample",
      error: error instanceof Error ? error.message : "写入后端失败，已保留页面本地状态。",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function queryToParams(query: SecurityEventQuery = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "" || value === "all") continue;
    params.set(key, String(value));
  }
  return params.toString();
}

function sampleMatchesQuery(event: SecurityEvent, query: SecurityEventQuery) {
  if (query.timeRange && query.timeRange !== "all") {
    const hours = query.timeRange === "6h" ? 6 : query.timeRange === "24h" ? 24 : query.timeRange === "7d" ? 24 * 7 : null;
    const newest = Date.now();
    if (hours !== null && (newest - Date.parse(event.timestamp)) / 36e5 > hours) return false;
  }
  const risk = query.risk ?? query.riskLevel;
  if (risk && risk !== "all") {
    if (event.riskLevel !== risk) return false;
  }
  if (query.eventType && event.eventType !== query.eventType) return false;
  if (query.action && event.action !== query.action) return false;
  if (query.method && event.method !== query.method) return false;
  if (query.statusCode && String(event.statusCode) !== String(query.statusCode)) return false;
  if (query.attackCategory && event.attackCategory !== query.attackCategory) return false;
  if (query.ruleId && event.ruleId !== query.ruleId && !event.ruleHits?.some((rule) => rule.id === query.ruleId)) return false;
  if (query.ip && !event.clientIp.toLowerCase().includes(query.ip.toLowerCase())) return false;
  if (query.country && !`${event.country} ${event.region} ${event.city}`.toLowerCase().includes(query.country.toLowerCase())) return false;
  if (query.region && !`${event.region} ${event.city}`.toLowerCase().includes(query.region.toLowerCase())) return false;
  if (query.path && !`${event.path} ${event.query ?? ""} ${event.userAgent}`.toLowerCase().includes(query.path.toLowerCase())) return false;
  if (query.userAgent && !event.userAgent.toLowerCase().includes(query.userAgent.toLowerCase())) return false;
  return true;
}

function filterSampleEvents(query: SecurityEventQuery = {}) {
  const limit = Math.max(1, Math.min(query.limit ?? 100, 500));
  const offset = Math.max(0, query.offset ?? 0);
  return createSampleSecurityData()
    .events.filter((event) => sampleMatchesQuery(event, query))
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(offset, offset + limit);
}

function riskRankValue(riskLevel: RiskLevel | string) {
  const index = riskOrder.indexOf(riskLevel as RiskLevel);
  return index >= 0 ? index : 0;
}

function sampleMatchesSituationQuery(event: SecurityEvent, query: SecuritySituationQuery) {
  if (query.timeRange && query.timeRange !== "all") {
    const hours = query.timeRange === "6h" ? 6 : query.timeRange === "24h" ? 24 : query.timeRange === "7d" ? 24 * 7 : null;
    const newest = Date.now();
    if (hours !== null && (newest - Date.parse(event.timestamp)) / 36e5 > hours) return false;
  }
  if (query.risk && query.risk !== "all") {
    if (query.risk === "high" || query.risk === "high+") {
      if (riskRankValue(event.riskLevel) < riskRankValue("high")) return false;
    } else if (event.riskLevel !== query.risk) {
      return false;
    }
  }
  if (query.country && query.country !== "all" && event.country !== query.country) return false;
  if (query.attackCategory && query.attackCategory !== "all" && event.attackCategory !== query.attackCategory) return false;
  if (query.ruleId && query.ruleId !== "all" && event.ruleId !== query.ruleId && !event.ruleHits?.some((rule) => rule.id === query.ruleId)) {
    return false;
  }
  return true;
}

function hasSituationFilter(query: SecuritySituationQuery = {}) {
  return ["timeRange", "risk", "country", "attackCategory", "ruleId"].some((key) => {
    const value = query[key as keyof SecuritySituationQuery];
    if (key === "timeRange") return value !== undefined && value !== null && value !== "";
    return value !== undefined && value !== null && value !== "" && value !== "all";
  });
}

function timeRangeLabel(value?: string) {
  if (value === "6h") return "最近 6 小时";
  if (value === "24h") return "最近 24 小时";
  if (value === "7d") return "最近 7 天";
  if (value === "all") return "全部数据";
  return "后端默认窗口";
}

function distributionFromEvents(events: SecurityEvent[], valueForEvent: (event: SecurityEvent) => string): DistributionPoint[] {
  const groups = new Map<string, { value: number; riskLevel: RiskLevel }>();
  events.forEach((event) => {
    const label = valueForEvent(event).trim();
    if (!label) return;
    const current = groups.get(label);
    if (current) {
      current.value += 1;
      if (riskRankValue(event.riskLevel) > riskRankValue(current.riskLevel)) current.riskLevel = event.riskLevel;
    } else {
      groups.set(label, { value: 1, riskLevel: event.riskLevel });
    }
  });
  return Array.from(groups.entries())
    .map(([label, item]) => ({ label, value: item.value, riskLevel: item.riskLevel }))
    .sort((a, b) => riskRankValue(b.riskLevel ?? "info") - riskRankValue(a.riskLevel ?? "info") || b.value - a.value);
}

function rankedItemsFromEvents(events: SecurityEvent[], valueForEvent: (event: SecurityEvent) => string, detailForEvent: (event: SecurityEvent) => string): RankedItem[] {
  const groups = new Map<string, { value: number; detail: string; riskLevel: RiskLevel }>();
  events.forEach((event) => {
    const label = valueForEvent(event).trim();
    if (!label) return;
    const current = groups.get(label);
    if (current) {
      current.value += 1;
      if (riskRankValue(event.riskLevel) > riskRankValue(current.riskLevel)) current.riskLevel = event.riskLevel;
    } else {
      groups.set(label, { value: 1, detail: detailForEvent(event), riskLevel: event.riskLevel });
    }
  });
  return Array.from(groups.entries())
    .map(([label, item]) => ({ label, value: item.value, detail: item.detail, riskLevel: item.riskLevel }))
    .sort((a, b) => riskRankValue(b.riskLevel ?? "info") - riskRankValue(a.riskLevel ?? "info") || b.value - a.value);
}

function createSampleSituationOverview(query: SecuritySituationQuery = {}): SecurityOverview {
  const sample = createSampleSecurityData();
  if (!hasSituationFilter(query)) return sample.overview;

  const events = sample.events
    .filter((event) => sampleMatchesSituationQuery(event, query))
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .map(normalizeSecurityEvent);
  const eventIds = new Set(events.map((event) => event.id));

  return {
    ...sample.overview,
    timeRangeLabel: timeRangeLabel(query.timeRange),
    statusCodes: distributionFromEvents(events, (event) => String(event.statusCode)),
    riskDistribution: distributionFromEvents(events, (event) => event.riskLevel),
    eventTypes: distributionFromEvents(events, (event) => event.attackCategory || event.eventType),
    topIps: rankedItemsFromEvents(events, (event) => event.clientIp, (event) => [event.country, event.city].filter(Boolean).join(" ")),
    topPaths: rankedItemsFromEvents(events, (event) => event.path, (event) => event.eventType),
    topAgents: rankedItemsFromEvents(events, (event) => event.userAgent, (event) => event.eventType),
    countries: rankedItemsFromEvents(events, (event) => event.country, (event) => event.attackCategory || event.eventType),
    globePoints: sample.overview.globePoints.filter((point) => eventIds.has(point.id)),
    recentEvents: events.slice(0, 6),
    sync: {
      ...sample.overview.sync,
      localEventCount: events.length,
      aggregateCount: events.length,
    },
  };
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

function normalizeRuleHits(event: SecurityEvent): SecurityRuleHit[] {
  const ruleMatches = Array.isArray(event.ruleMatches) ? event.ruleMatches : [];
  if (event.ruleHits?.length) return event.ruleHits.map((hit) => normalizeRuleHit(hit, event, ruleMatches));
  if (!event.ruleId && !event.ruleName && ruleMatches.length === 0) return [];
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

function normalizeSecurityEvent(event: SecurityEvent): SecurityEvent {
  return {
    ...event,
    attackCategory: event.attackCategory || event.eventType,
    attackSubtype: event.attackSubtype || event.eventType,
    toolSignature: event.toolSignature || event.userAgent,
    behaviorFingerprint: event.behaviorFingerprint || event.summary,
    ruleVersion: event.ruleVersion || "unversioned",
    ruleHits: normalizeRuleHits(event),
  };
}

function createLocalTokenCheckApiResult(zoneId: string, apiToken?: string): TokenCheckApiResult {
  const tokenCheck = createLocalTokenCheck(zoneId, apiToken);
  const mode: SecurityDataMode = tokenCheck.status === "success" ? "mock" : "sample";
  return {
    mode,
    status: mode,
    cloudflareLive: false,
    message:
      tokenCheck.status === "success"
        ? "Token 仅通过本地格式校验，尚未完成 Cloudflare 实时校验。"
        : "当前只完成本地格式校验，等待真实 Cloudflare 校验。",
    tokenCheck,
  };
}

export async function getSecurityOverview(): Promise<SecurityApiResult<SecurityOverview>> {
  return fetchWithFallback("/api/overview", createSampleSecurityData().overview);
}

export async function getSecurityHomeSimulationOverview(): Promise<SecurityApiResult<SecurityOverview>> {
  return fetchWithFallback("/api/security/home", createSampleSecurityData().overview);
}

export async function getSecuritySituationOverview(query: SecuritySituationQuery = {}): Promise<SecurityApiResult<SecurityOverview>> {
  return fetchWithFallback(appendQuery("/api/security/situation", query), createSampleSituationOverview(query));
}

export async function getSecurityEvents(query: SecurityEventQuery = {}): Promise<SecurityApiResult<SecurityEvent[]>> {
  const search = queryToParams(query);
  const path = search ? `/api/events?${search}` : "/api/events";
  const result = await fetchWithFallback(path, filterSampleEvents(query));
  return {
    ...result,
    data: result.data.map(normalizeSecurityEvent),
  };
}

export async function getSecurityEvent(id: string): Promise<SecurityApiResult<SecurityEvent | null>> {
  const fallback = createSampleSecurityData().events.find((event) => event.id === id) ?? null;
  const result = await fetchWithFallback(`/api/events/${encodeURIComponent(id)}`, fallback);
  return {
    ...result,
    data: result.data ? normalizeSecurityEvent(result.data) : null,
  };
}

export async function getSecuritySettings(): Promise<SecurityApiResult<SecuritySettings>> {
  return fetchWithFallback("/api/settings", createSampleSecurityData().settings);
}

export async function getSecuritySyncStatus(): Promise<SecurityApiResult<SyncStatus>> {
  const fallback = createSampleSecurityData().overview.sync;
  return fetchWithFallback("/api/sync/status", {
    ...fallback,
    mode: "sample",
    cloudflareLive: false,
  });
}

export async function getAnalysisSummary(query: SecurityAnalysisQuery = {}): Promise<SecurityApiResult<AnalysisSummary | null>> {
  return fetchWithFallback<AnalysisSummary | null>(appendQuery("/api/analysis/summary", query), null);
}

export async function getAnalysisClusters(query: SecurityAnalysisQuery = {}): Promise<SecurityApiResult<AnalysisClustersResult>> {
  const sample = createSampleSecurityData();
  return fetchWithFallback(appendQuery("/api/analysis/clusters", query), createAnalysisClusters(sample.events));
}

export async function getAnalysisRules(query: SecurityAnalysisQuery = {}): Promise<SecurityApiResult<AnalysisRulesResult>> {
  const sample = createSampleSecurityData();
  return fetchWithFallback(appendQuery("/api/analysis/rules", query), createAnalysisRules(sample.events));
}

export async function getAnalysisSources(query: SecurityAnalysisQuery = {}): Promise<SecurityApiResult<AnalysisSources>> {
  const sample = createSampleSecurityData();
  return fetchWithFallback(appendQuery("/api/analysis/sources", query), createAnalysisSources(sample.overview));
}

export async function getAnalysisAdvice(query: SecurityAnalysisQuery = {}): Promise<SecurityApiResult<AnalysisAdviceResult>> {
  const sample = createSampleSecurityData();
  const clusters = createAnalysisClusters(sample.events);
  return fetchWithFallback(appendQuery("/api/analysis/advice", query), createAnalysisAdvice(clusters));
}

export async function saveCloudflareSettings(payload: CloudflareSettingsPayload): Promise<SecurityApiResult<TokenCheckApiResult>> {
  const sample = createSampleSecurityData().settings;
  const fallback = {
    ...createLocalTokenCheckApiResult(payload.zoneId, payload.apiToken),
    settings: {
      ...sample,
      monitoredHost: payload.monitoredHost || sample.monitoredHost,
      zoneId: payload.zoneId,
      refreshIntervalHours: payload.refreshIntervalHours,
      hasCloudflareToken: Boolean(payload.apiToken || sample.hasCloudflareToken),
      sampleMode: !payload.apiToken && !sample.hasCloudflareToken,
    },
  };
  return postWithFallback("/api/settings/cloudflare", payload, fallback);
}

export async function checkCloudflareToken(payload: Partial<CloudflareSettingsPayload>) {
  return postWithFallback<TokenCheckApiResult>(
    "/api/token/check",
    payload,
    createLocalTokenCheckApiResult(payload.zoneId ?? "", payload.apiToken),
  );
}

export async function runSecuritySync() {
  return postWithFallback<SyncRunResult>("/api/sync/run", {}, {
    mode: "sample",
    status: "sample",
    cloudflareLive: false,
    usedStaleData: false,
    message: "未连接后端，当前仅刷新前端样例状态。",
    events: createSampleSecurityData().events.length,
    aggregates: createSampleSecurityData().overview.trafficTrend.length,
  });
}

export async function runWorkerLogSync() {
  return postWithFallback<SyncRunResult>("/api/worker-logs/sync", {}, {
    mode: "degraded",
    status: "failed",
    cloudflareLive: false,
    usedStaleData: true,
    message: "未连接后端，无法从 Worker/D1 拉取访问日志。",
    accessLogs: 0,
    events: 0,
    aggregates: 0,
    hasMore: false,
  });
}

export async function updateRiskThreshold(riskLevel: RiskLevel) {
  const sample = createSampleSecurityData().settings;
  return postWithFallback<SecuritySettings>("/api/settings/risk-threshold", { riskLevel }, {
    ...sample,
    highRiskThreshold: riskLevel,
  });
}

function createLocalTokenCheck(zoneId: string, apiToken?: string): TokenCheckResult {
  const zoneRead = /^[A-Za-z0-9_-]{8,}$/.test(zoneId || "");
  const tokenOk = Boolean(apiToken && apiToken.length >= 10 && !/\s/.test(apiToken));
  return {
    checkedAt: new Date().toISOString(),
    status: zoneRead && tokenOk ? "success" : "failed",
    zoneRead,
    analyticsRead: zoneRead && tokenOk,
    securityEventsRead: zoneRead && tokenOk,
    errorMessage: zoneRead && tokenOk ? null : "当前只完成本地格式校验，真实 Cloudflare 权限检查需要连接后端。",
    details: {
      mode: "local-preview",
      networkRequest: false,
    },
    permissions: [
      { name: "Zone Read", ok: zoneRead, detail: zoneRead ? "Zone ID 格式可用" : "缺少或格式错误" },
      { name: "Analytics Read", ok: zoneRead && tokenOk, detail: tokenOk ? "Token 格式可用" : "缺少 Token 或格式错误" },
      { name: "Security Events Read", ok: zoneRead && tokenOk, detail: tokenOk ? "Token 格式可用" : "缺少 Token 或格式错误" },
    ],
  };
}
