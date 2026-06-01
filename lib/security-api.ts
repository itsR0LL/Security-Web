import {
  createSampleSecurityData,
  type SecurityEvent,
  type SecurityOverview,
  type SecuritySettings,
  type RiskLevel,
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
  timeRange?: string;
  limit?: number;
  offset?: number;
};

export type CloudflareSettingsPayload = {
  monitoredHost: string;
  zoneId: string;
  apiToken?: string;
  refreshIntervalHours: number;
};

export type TokenCheckResult = {
  checkedAt: string;
  status: "success" | "failed" | "partial";
  zoneRead: boolean;
  analyticsRead: boolean;
  securityEventsRead: boolean;
  errorMessage: string | null;
  details?: Record<string, unknown>;
  permissions?: SecuritySettings["permissions"];
};

export type SyncRunResult = {
  mode: "sample" | "mock" | "mock-cloudflare" | "live" | "degraded" | "stale";
  message: string;
  events?: number;
  aggregates?: number;
  tokenCheck?: TokenCheckResult;
};

function getApiBaseUrl() {
  return process.env.SECURITY_API_BASE_URL || process.env.NEXT_PUBLIC_SECURITY_API_BASE_URL || "";
}

function joinUrl(baseUrl: string, path: string) {
  return `${baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
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
    if (risk === "high") {
      if (event.riskLevel !== "high" && event.riskLevel !== "critical") return false;
    } else if (event.riskLevel !== risk) {
      return false;
    }
  }
  if (query.eventType && event.eventType !== query.eventType) return false;
  if (query.action && event.action !== query.action) return false;
  if (query.method && event.method !== query.method) return false;
  if (query.statusCode && String(event.statusCode) !== String(query.statusCode)) return false;
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

export async function getSecurityOverview(): Promise<SecurityApiResult<SecurityOverview>> {
  return fetchWithFallback("/api/overview", createSampleSecurityData().overview);
}

export async function getSecurityEvents(query: SecurityEventQuery = {}): Promise<SecurityApiResult<SecurityEvent[]>> {
  const search = queryToParams(query);
  const path = search ? `/api/events?${search}` : "/api/events";
  return fetchWithFallback(path, filterSampleEvents(query));
}

export async function getSecurityEvent(id: string): Promise<SecurityApiResult<SecurityEvent | null>> {
  const fallback = createSampleSecurityData().events.find((event) => event.id === id) ?? null;
  return fetchWithFallback(`/api/events/${encodeURIComponent(id)}`, fallback);
}

export async function getSecuritySettings(): Promise<SecurityApiResult<SecuritySettings>> {
  return fetchWithFallback("/api/settings", createSampleSecurityData().settings);
}

export async function saveCloudflareSettings(payload: CloudflareSettingsPayload) {
  const sample = createSampleSecurityData().settings;
  const fallback = {
    settings: {
      ...sample,
      monitoredHost: payload.monitoredHost || sample.monitoredHost,
      zoneId: payload.zoneId,
      refreshIntervalHours: payload.refreshIntervalHours,
      hasCloudflareToken: Boolean(payload.apiToken || sample.hasCloudflareToken),
      sampleMode: !payload.apiToken && !sample.hasCloudflareToken,
    },
    tokenCheck: createLocalTokenCheck(payload.zoneId, payload.apiToken),
  };
  return postWithFallback("/api/settings/cloudflare", payload, fallback);
}

export async function checkCloudflareToken(payload: Partial<CloudflareSettingsPayload>) {
  return postWithFallback<TokenCheckResult>(
    "/api/token/check",
    payload,
    createLocalTokenCheck(payload.zoneId ?? "", payload.apiToken),
  );
}

export async function runSecuritySync() {
  return postWithFallback<SyncRunResult>("/api/sync/run", {}, {
    mode: "sample",
    message: "未连接后端，当前仅刷新前端样例状态。",
    events: createSampleSecurityData().events.length,
    aggregates: createSampleSecurityData().overview.trafficTrend.length,
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
