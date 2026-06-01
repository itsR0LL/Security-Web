export type RiskLevel = "info" | "low" | "medium" | "high" | "critical";

export type SyncStatusValue = "success" | "failed" | "partial" | "sample";

export type LocationPrecision = "city" | "region" | "country" | "estimated";

export type SecurityEvent = {
  id: string;
  timestamp: string;
  source: "cloudflare" | "origin" | "sample";
  clientIp: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  locationPrecision: LocationPrecision;
  asn: string;
  host: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  path: string;
  query?: string;
  statusCode: number;
  userAgent: string;
  referer?: string;
  rayId: string;
  action: "allow" | "block" | "challenge" | "managed_challenge" | "log";
  ruleId: string;
  ruleName: string;
  eventType: string;
  riskLevel: RiskLevel;
  confidence: number;
  summary: string;
  ruleMatches: string[];
  raw: Record<string, unknown>;
};

export type KpiMetric = {
  id: string;
  label: string;
  value: string;
  detail: string;
  trend: string;
  tone: "sky" | "emerald" | "amber" | "rose" | "slate";
  href?: string;
};

export type TrendPoint = {
  label: string;
  requests: number;
  threats: number;
  blocked: number;
  bandwidthMb: number;
  cachedPercent: number;
  originMb: number;
};

export type DistributionPoint = {
  label: string;
  value: number;
  riskLevel?: RiskLevel;
};

export type RankedItem = {
  label: string;
  value: number;
  detail: string;
  riskLevel?: RiskLevel;
};

export type GlobePoint = {
  id: string;
  label: string;
  clientIp: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  count: number;
  riskLevel: RiskLevel;
  eventType: string;
  locationPrecision: LocationPrecision;
};

export type PermissionCheck = {
  name: string;
  ok: boolean;
  detail: string;
};

export type SyncStatus = {
  status: SyncStatusValue;
  lastSyncAt: string;
  lastSuccessAt: string;
  usedStaleData: boolean;
  apiError: string | null;
  localEventCount: number;
  aggregateCount: number;
  refreshIntervalHours: number;
  permissions: PermissionCheck[];
};

export type SecurityOverview = {
  monitoredHost: string;
  timeRangeLabel: string;
  sampleMode: boolean;
  generatedAt: string;
  kpis: KpiMetric[];
  trafficTrend: TrendPoint[];
  statusCodes: DistributionPoint[];
  riskDistribution: DistributionPoint[];
  eventTypes: DistributionPoint[];
  topIps: RankedItem[];
  topPaths: RankedItem[];
  topAgents: RankedItem[];
  countries: RankedItem[];
  globePoints: GlobePoint[];
  sync: SyncStatus;
  recentEvents: SecurityEvent[];
};

export type SecuritySettings = {
  monitoredHost: string;
  zoneId: string;
  hasCloudflareToken: boolean;
  sampleMode: boolean;
  refreshIntervalHours: number;
  highRiskThreshold: RiskLevel;
  rawRetentionDays: number;
  aggregateRetention: string;
  permissions: PermissionCheck[];
  lastTokenCheckAt: string | null;
};

export type SecuritySampleData = {
  overview: SecurityOverview;
  events: SecurityEvent[];
  settings: SecuritySettings;
};

export const riskLabels: Record<RiskLevel, string> = {
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高风险",
  critical: "严重",
};

export const riskOrder: RiskLevel[] = ["info", "low", "medium", "high", "critical"];

const destination = {
  city: "成都",
  latitude: 30.5728,
  longitude: 104.0668,
};

function isoHoursAgo(base: Date, hours: number) {
  return new Date(base.getTime() - hours * 60 * 60 * 1000).toISOString();
}

function shortBucket(base: Date, hoursAgo: number) {
  const date = new Date(base.getTime() - hoursAgo * 60 * 60 * 1000);
  return `${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:00`;
}

function createEvent(
  base: Date,
  event: Omit<SecurityEvent, "timestamp" | "source" | "host" | "raw"> & { hoursAgo: number },
): SecurityEvent {
  const { hoursAgo, ...rest } = event;
  return {
    ...rest,
    timestamp: isoHoursAgo(base, hoursAgo),
    source: "sample",
    host: "r0l1dehome.asia",
    raw: {
      source: "sample",
      destination,
      rayId: rest.rayId,
      matchedRules: rest.ruleMatches,
      cloudflareAction: rest.action,
    },
  };
}

export function createSampleSecurityData(now = new Date()): SecuritySampleData {
  const events: SecurityEvent[] = [
    createEvent(now, {
      id: "evt-1009",
      hoursAgo: 0.35,
      clientIp: "185.220.101.42",
      country: "德国",
      region: "Hesse",
      city: "Frankfurt",
      latitude: 50.1109,
      longitude: 8.6821,
      locationPrecision: "city",
      asn: "AS24940",
      method: "GET",
      path: "/.env",
      statusCode: 403,
      userAgent: "curl/8.2 security scanner",
      rayId: "8fc1a21d4e12c901",
      action: "block",
      ruleId: "builtin-sensitive-path",
      ruleName: "敏感路径探测",
      eventType: "敏感路径探测",
      riskLevel: "critical",
      confidence: 0.96,
      summary: "来源 IP 请求 .env 并被 Cloudflare 拦截。",
      ruleMatches: ["路径命中 .env", "Cloudflare block", "扫描器 User-Agent"],
    }),
    createEvent(now, {
      id: "evt-1008",
      hoursAgo: 0.9,
      clientIp: "45.61.139.18",
      country: "美国",
      region: "California",
      city: "San Jose",
      latitude: 37.3387,
      longitude: -121.8853,
      locationPrecision: "city",
      asn: "AS53667",
      method: "POST",
      path: "/api/search",
      query: "q=' OR 1=1--",
      statusCode: 403,
      userAgent: "Mozilla/5.0",
      rayId: "8fc1a1b25aa244db",
      action: "managed_challenge",
      ruleId: "builtin-sqli",
      ruleName: "疑似 SQL 注入",
      eventType: "疑似注入",
      riskLevel: "high",
      confidence: 0.88,
      summary: "查询参数包含典型 SQL 注入片段，已触发挑战。",
      ruleMatches: ["SQL 关键词", "POST 请求", "Cloudflare managed_challenge"],
    }),
    createEvent(now, {
      id: "evt-1007",
      hoursAgo: 1.6,
      clientIp: "103.253.144.19",
      country: "新加坡",
      region: "Central",
      city: "Singapore",
      latitude: 1.3521,
      longitude: 103.8198,
      locationPrecision: "city",
      asn: "AS45102",
      method: "GET",
      path: "/wp-login.php",
      statusCode: 404,
      userAgent: "Mozilla/5.0 zgrab/0.x",
      rayId: "8fc19f753e24a8ae",
      action: "challenge",
      ruleId: "builtin-wp-probe",
      ruleName: "WordPress 探测",
      eventType: "目录探测",
      riskLevel: "high",
      confidence: 0.91,
      summary: "非 WordPress 站点出现 wp-login.php 探测请求。",
      ruleMatches: ["敏感路径 wp-login.php", "可疑 User-Agent"],
    }),
    createEvent(now, {
      id: "evt-1006",
      hoursAgo: 2.25,
      clientIp: "91.219.237.21",
      country: "俄罗斯",
      region: "Moscow",
      city: "Moscow",
      latitude: 55.7558,
      longitude: 37.6173,
      locationPrecision: "region",
      asn: "AS197695",
      method: "GET",
      path: "/admin",
      statusCode: 403,
      userAgent: "python-requests/2.31",
      rayId: "8fc19d62d093ed27",
      action: "block",
      ruleId: "builtin-admin-probe",
      ruleName: "后台路径探测",
      eventType: "恶意扫描",
      riskLevel: "high",
      confidence: 0.84,
      summary: "后台路径被连续探测，Cloudflare 已执行 block。",
      ruleMatches: ["路径 /admin", "Cloudflare block"],
    }),
    createEvent(now, {
      id: "evt-1005",
      hoursAgo: 3.1,
      clientIp: "203.0.113.84",
      country: "日本",
      region: "Tokyo",
      city: "Tokyo",
      latitude: 35.6762,
      longitude: 139.6503,
      locationPrecision: "city",
      asn: "AS2516",
      method: "GET",
      path: "/posts/first",
      statusCode: 200,
      userAgent: "Mozilla/5.0 AppleWebKit/537.36",
      rayId: "8fc199b671da441a",
      action: "allow",
      ruleId: "traffic-normal",
      ruleName: "普通访问",
      eventType: "正常访问",
      riskLevel: "info",
      confidence: 0.64,
      summary: "公开文章访问，请求行为正常。",
      ruleMatches: ["缓存命中", "状态码 200"],
    }),
    createEvent(now, {
      id: "evt-1004",
      hoursAgo: 4.4,
      clientIp: "152.32.210.77",
      country: "中国香港",
      region: "Hong Kong",
      city: "Hong Kong",
      latitude: 22.3193,
      longitude: 114.1694,
      locationPrecision: "city",
      asn: "AS135377",
      method: "GET",
      path: "/phpmyadmin/index.php",
      statusCode: 404,
      userAgent: "Go-http-client/1.1",
      rayId: "8fc194d73b128eee",
      action: "challenge",
      ruleId: "builtin-sensitive-path",
      ruleName: "敏感路径探测",
      eventType: "敏感路径探测",
      riskLevel: "high",
      confidence: 0.9,
      summary: "phpMyAdmin 路径探测触发挑战。",
      ruleMatches: ["路径 phpmyadmin", "可疑 User-Agent"],
    }),
    createEvent(now, {
      id: "evt-1003",
      hoursAgo: 5.2,
      clientIp: "198.51.100.21",
      country: "荷兰",
      region: "North Holland",
      city: "Amsterdam",
      latitude: 52.3676,
      longitude: 4.9041,
      locationPrecision: "country",
      asn: "AS60781",
      method: "GET",
      path: "/api/comment",
      query: "content=<script>alert(1)</script>",
      statusCode: 403,
      userAgent: "Mozilla/5.0",
      rayId: "8fc1915c01924409",
      action: "managed_challenge",
      ruleId: "builtin-xss",
      ruleName: "疑似 XSS",
      eventType: "疑似 XSS",
      riskLevel: "medium",
      confidence: 0.79,
      summary: "评论接口参数包含 script 片段，已触发托管挑战。",
      ruleMatches: ["XSS 关键词", "Cloudflare managed_challenge"],
    }),
    createEvent(now, {
      id: "evt-1002",
      hoursAgo: 8.4,
      clientIp: "200.160.2.3",
      country: "巴西",
      region: "Sao Paulo",
      city: "Sao Paulo",
      latitude: -23.5505,
      longitude: -46.6333,
      locationPrecision: "estimated",
      asn: "AS22548",
      method: "GET",
      path: "/rss.xml",
      statusCode: 200,
      userAgent: "FeedFetcher-Google",
      rayId: "8fc17921704dcb3a",
      action: "allow",
      ruleId: "crawler-known",
      ruleName: "已知爬虫",
      eventType: "爬虫访问",
      riskLevel: "low",
      confidence: 0.58,
      summary: "订阅抓取行为，暂不构成威胁。",
      ruleMatches: ["已知爬虫 User-Agent"],
    }),
    createEvent(now, {
      id: "evt-1001",
      hoursAgo: 12.2,
      clientIp: "203.0.113.210",
      country: "韩国",
      region: "Seoul",
      city: "Seoul",
      latitude: 37.5665,
      longitude: 126.978,
      locationPrecision: "city",
      asn: "AS4766",
      method: "HEAD",
      path: "/",
      statusCode: 200,
      userAgent: "UptimeRobot/2.0",
      rayId: "8fc151b28076f1b7",
      action: "allow",
      ruleId: "monitor-normal",
      ruleName: "可用性检测",
      eventType: "正常访问",
      riskLevel: "info",
      confidence: 0.7,
      summary: "站点可用性探测，请求正常。",
      ruleMatches: ["HEAD 请求", "状态码 200"],
    }),
  ];

  const trafficTrend: TrendPoint[] = [
    { label: shortBucket(now, 21), requests: 760, threats: 18, blocked: 9, bandwidthMb: 86, cachedPercent: 84, originMb: 14 },
    { label: shortBucket(now, 18), requests: 690, threats: 15, blocked: 8, bandwidthMb: 72, cachedPercent: 81, originMb: 13 },
    { label: shortBucket(now, 15), requests: 820, threats: 24, blocked: 15, bandwidthMb: 94, cachedPercent: 83, originMb: 16 },
    { label: shortBucket(now, 12), requests: 930, threats: 31, blocked: 18, bandwidthMb: 111, cachedPercent: 79, originMb: 23 },
    { label: shortBucket(now, 9), requests: 880, threats: 27, blocked: 14, bandwidthMb: 104, cachedPercent: 82, originMb: 19 },
    { label: shortBucket(now, 6), requests: 1012, threats: 44, blocked: 24, bandwidthMb: 128, cachedPercent: 77, originMb: 30 },
    { label: shortBucket(now, 3), requests: 1160, threats: 57, blocked: 31, bandwidthMb: 143, cachedPercent: 74, originMb: 37 },
    { label: shortBucket(now, 0), requests: 1084, threats: 49, blocked: 29, bandwidthMb: 136, cachedPercent: 78, originMb: 30 },
  ];

  const topIps: RankedItem[] = [
    { label: "185.220.101.42", value: 68, detail: "德国 Frankfurt", riskLevel: "critical" },
    { label: "45.61.139.18", value: 43, detail: "美国 San Jose", riskLevel: "high" },
    { label: "103.253.144.19", value: 39, detail: "新加坡", riskLevel: "high" },
    { label: "91.219.237.21", value: 31, detail: "俄罗斯 Moscow", riskLevel: "high" },
    { label: "203.0.113.84", value: 24, detail: "日本 Tokyo", riskLevel: "info" },
  ];

  const overview: SecurityOverview = {
    monitoredHost: "r0l1dehome.asia",
    timeRangeLabel: "最近 24 小时",
    sampleMode: true,
    generatedAt: now.toISOString(),
    kpis: [
      { id: "requests-6h", label: "最近 6 小时访问", value: "3,256", detail: "边缘侧请求量", trend: "+8.4%", tone: "sky", href: "/security/events?timeRange=6h" },
      { id: "requests-24h", label: "最近 24 小时访问", value: "7,336", detail: "缓存命中率 78%", trend: "+4.1%", tone: "emerald", href: "/security/events?timeRange=24h" },
      { id: "requests-7d", label: "最近 7 天访问", value: "42,908", detail: "聚合统计长期保留", trend: "+11.7%", tone: "slate", href: "/security/events?timeRange=7d" },
      { id: "abnormal", label: "异常请求", value: "265", detail: "扫描、挑战与异常状态码", trend: "+18", tone: "amber", href: "/security/events?risk=medium" },
      { id: "high-risk", label: "高风险事件", value: "6", detail: "high 及以上", trend: "+3", tone: "rose", href: "/security/events?risk=high" },
      { id: "cf-events", label: "Cloudflare 安全事件", value: "113", detail: "block / challenge / log", trend: "+12", tone: "sky", href: "/security/events?action=block" },
    ],
    trafficTrend,
    statusCodes: [
      { label: "200", value: 6128 },
      { label: "301/302", value: 426 },
      { label: "403", value: 84, riskLevel: "high" },
      { label: "404", value: 291, riskLevel: "medium" },
      { label: "5xx", value: 12, riskLevel: "high" },
    ],
    riskDistribution: [
      { label: "信息", value: 5800, riskLevel: "info" },
      { label: "低风险", value: 812, riskLevel: "low" },
      { label: "关注", value: 201, riskLevel: "medium" },
      { label: "高风险", value: 53, riskLevel: "high" },
      { label: "严重", value: 6, riskLevel: "critical" },
    ],
    eventTypes: [
      { label: "正常访问", value: 5800, riskLevel: "info" },
      { label: "爬虫访问", value: 812, riskLevel: "low" },
      { label: "目录探测", value: 104, riskLevel: "high" },
      { label: "敏感路径探测", value: 61, riskLevel: "critical" },
      { label: "疑似注入", value: 18, riskLevel: "high" },
      { label: "疑似 XSS", value: 12, riskLevel: "medium" },
    ],
    topIps,
    topPaths: [
      { label: "/", value: 1832, detail: "首页", riskLevel: "info" },
      { label: "/posts/first", value: 1084, detail: "公开文章", riskLevel: "info" },
      { label: "/rss.xml", value: 516, detail: "订阅流", riskLevel: "low" },
      { label: "/wp-login.php", value: 73, detail: "不存在路径", riskLevel: "high" },
      { label: "/.env", value: 36, detail: "已拦截", riskLevel: "critical" },
    ],
    topAgents: [
      { label: "Mozilla/5.0", value: 4120, detail: "浏览器访问", riskLevel: "info" },
      { label: "FeedFetcher-Google", value: 298, detail: "RSS 抓取", riskLevel: "low" },
      { label: "python-requests/2.31", value: 79, detail: "扫描特征", riskLevel: "high" },
      { label: "Go-http-client/1.1", value: 54, detail: "自动化请求", riskLevel: "medium" },
      { label: "curl/8.2", value: 41, detail: "命令行探测", riskLevel: "critical" },
    ],
    countries: [
      { label: "中国大陆", value: 3190, detail: "正常访问为主", riskLevel: "info" },
      { label: "美国", value: 1042, detail: "注入与正常访问混合", riskLevel: "high" },
      { label: "日本", value: 860, detail: "文章访问", riskLevel: "info" },
      { label: "德国", value: 312, detail: "敏感路径探测", riskLevel: "critical" },
      { label: "新加坡", value: 286, detail: "目录探测", riskLevel: "high" },
    ],
    globePoints: events.map((event, index) => ({
      id: event.id,
      label: `${event.city} ${event.eventType}`,
      clientIp: event.clientIp,
      country: event.country,
      city: event.city,
      latitude: event.latitude,
      longitude: event.longitude,
      count: topIps[index]?.value ?? Math.max(8, 34 - index * 3),
      riskLevel: event.riskLevel,
      eventType: event.eventType,
      locationPrecision: event.locationPrecision,
    })),
    sync: {
      status: "sample",
      lastSyncAt: isoHoursAgo(now, 0.25),
      lastSuccessAt: isoHoursAgo(now, 6.1),
      usedStaleData: false,
      apiError: "未配置 Cloudflare Token，当前自动展示样例数据。",
      localEventCount: 42873,
      aggregateCount: 1880,
      refreshIntervalHours: 6,
      permissions: [
        { name: "Zone Read", ok: false, detail: "等待配置 Zone ID" },
        { name: "Analytics Read", ok: false, detail: "等待配置 Token" },
        { name: "Security Events Read", ok: false, detail: "等待配置 Token" },
      ],
    },
    recentEvents: events.slice(0, 6),
  };

  const settings: SecuritySettings = {
    monitoredHost: "r0l1dehome.asia",
    zoneId: "",
    hasCloudflareToken: false,
    sampleMode: true,
    refreshIntervalHours: 6,
    highRiskThreshold: "high",
    rawRetentionDays: 90,
    aggregateRetention: "长期保留",
    permissions: overview.sync.permissions,
    lastTokenCheckAt: null,
  };

  return { overview, events, settings };
}

export function getRiskRank(riskLevel: RiskLevel) {
  return riskOrder.indexOf(riskLevel);
}
