import { formatCountryDisplayName } from "./security-locale";

export type RiskLevel = "info" | "low" | "medium" | "high" | "critical";

export type SyncStatusValue = "success" | "failed" | "partial" | "sample" | "degraded" | "stale";

export type SecurityDataMode = "live" | "degraded" | "stale" | "mock" | "mock-cloudflare" | "sample";

export type LocationPrecision = "city" | "region" | "country" | "estimated";

export type TrafficKind = "visit" | "attack";

export type SecurityRuleHit = {
  id: string;
  name: string;
  ruleId?: string;
  ruleName?: string;
  ruleType?: string;
  version?: string;
  matchedField?: string;
  matchedValue?: string;
  attackCategory?: string;
  attackSubtype?: string;
  toolSignature?: string;
  behaviorFingerprint?: string;
  mode: string;
  severity: RiskLevel | string;
  classification: string;
  evidence: string[];
  confidence: number;
  matched: boolean;
};

export type SecurityEvent = {
  id: string;
  timestamp: string;
  source: "cloudflare" | "worker_log" | "origin" | "sample";
  clientIp: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  locationPrecision: LocationPrecision;
  asn: string;
  host: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
  path: string;
  query?: string;
  statusCode: number;
  userAgent: string;
  referer?: string;
  rayId: string;
  action: "allow" | "block" | "blocked" | "challenge" | "managed_challenge" | "js_challenge" | "log" | "simulate";
  ruleId: string;
  ruleName: string;
  eventType: string;
  riskLevel: RiskLevel;
  confidence: number;
  summary: string;
  ruleMatches: string[];
  attackCategory?: string;
  attackSubtype?: string;
  toolSignature?: string;
  behaviorFingerprint?: string;
  campaignId?: string;
  ruleHits?: SecurityRuleHit[];
  aiClusterId?: string;
  ruleVersion?: string;
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
  trafficKind?: TrafficKind;
  locationPrecision: LocationPrecision;
  source?: SecurityEvent["source"] | "cloudflare_aggregate" | "cloudflare_http_aggregate" | "worker_log_aggregate" | "raw_events";
  sourceType?: "normal_visit" | "security_event" | "raw_event";
  bandwidthBytes?: number;
  action?: SecurityEvent["action"];
  method?: SecurityEvent["method"];
  path?: string;
  statusCode?: number;
  rayId?: string;
  asn?: string;
  ruleName?: string;
  throughputMb?: number;
};

export type PermissionCheck = {
  name: string;
  ok: boolean;
  detail: string;
};

export type SyncRunSource = "cloudflare" | "worker_log";

export type SyncStatus = {
  status: SyncStatusValue;
  mode?: SecurityDataMode;
  cloudflareLive?: boolean;
  lastSyncAt: string;
  lastSuccessAt: string;
  usedStaleData: boolean;
  apiError: string | null;
  localEventCount: number;
  aggregateCount: number;
  refreshIntervalHours: number;
  permissions: PermissionCheck[];
  cloudflare?: SyncSourceStatus;
  workerLog?: SyncSourceStatus;
};

export type SyncSourceStatus = {
  syncType: SyncRunSource;
  source: SyncRunSource;
  status: SyncStatusValue;
  mode?: SecurityDataMode;
  cloudflareLive?: boolean;
  lastSyncAt: string;
  lastSuccessAt: string;
  usedStaleData: boolean;
  apiError: string | null;
  eventCount: number;
  aggregateCount: number;
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

export type AnalysisRuleDefinition = {
  id: string;
  version: string;
  mode: string;
  ruleType: string;
  condition: Record<string, unknown>;
  severity: RiskLevel | string;
  classification: {
    attackCategory: string;
    attackSubtype: string;
    toolSignature: string;
    behaviorFingerprint: string;
  };
};

export type AnalysisFiltersPayload = {
  timeRange: string;
  risk: string | null;
  country: string | null;
  attackCategory: string | null;
  ruleId: string | null;
};

export type AnalysisCountItem = {
  label: string;
  value: number;
  riskLevel?: RiskLevel | string;
  attackCategory?: string;
  ruleId?: string;
};

export type AnalysisEventEvidence = {
  id: string;
  timestamp: string;
  clientIp: string;
  country: string;
  method: SecurityEvent["method"];
  path: string;
  query?: string | null;
  statusCode: number;
  action: SecurityEvent["action"];
  riskLevel: RiskLevel;
  ruleId: string;
  ruleName: string;
  summary: string;
  ruleMatches: string[];
};

export type AnalysisRuleDraft = {
  id: string;
  version: string;
  name: string;
  enabled: boolean;
  mode: string;
  ruleType: string;
  condition: Record<string, unknown>;
  severity: RiskLevel | string;
  classification: {
    attackCategory: string;
    attackSubtype: string;
    toolSignature: string;
    behaviorFingerprint: string;
  };
  actions?: {
    alert: boolean;
    block: boolean;
  };
  lifecycle?: {
    createdBy: string;
    reviewStatus: string;
  };
};

export type AnalysisRule = {
  ruleId: string;
  ruleName: string;
  eventCount: number;
  riskLevel: RiskLevel | string;
  severity: RiskLevel | string;
  mode: string;
  version: string;
  attackCategory: string;
  attackSubtype: string;
  firstSeen: string;
  lastSeen: string;
  sourceCount: number;
  pathCount: number;
  matchedFields: AnalysisCountItem[];
  matchedValues: AnalysisCountItem[];
  definition?: AnalysisRuleDefinition;
  evidence: AnalysisEventEvidence[];
};

export type AnalysisRulesResult = {
  generatedAt: string;
  filters: AnalysisFiltersPayload;
  totalRules: number;
  items: AnalysisRule[];
};

export type AnalysisPrimarySource = {
  clientIp: string;
  country: string;
  region: string;
  city: string;
  asn: string;
  latitude: number;
  longitude: number;
  locationPrecision: LocationPrecision;
  count: number;
};

export type AnalysisPrimaryPath = {
  method: SecurityEvent["method"] | string;
  path: string;
  statusCode: number;
  count: number;
};

export type AnalysisPrimaryAction = {
  action: SecurityEvent["action"] | string;
  count: number;
};

export type AnalysisPrimaryUserAgent = {
  userAgent: string;
  count: number;
};

export type AnalysisCluster = {
  clusterId: string;
  attackCategory: string;
  attackSubtype: string;
  ruleId: string;
  ruleName: string;
  toolSignature: string;
  behaviorFingerprint: string;
  eventCount: number;
  riskLevel: RiskLevel | string;
  confidence: number;
  timeRange: {
    firstSeen: string;
    lastSeen: string;
  };
  primarySource: AnalysisPrimarySource | null;
  primaryPath: AnalysisPrimaryPath | null;
  primaryAction: AnalysisPrimaryAction | null;
  primaryUserAgent: AnalysisPrimaryUserAgent | null;
  countries: AnalysisCountItem[];
  paths: AnalysisCountItem[];
  methods: AnalysisCountItem[];
  statusCodes: AnalysisCountItem[];
  actions: AnalysisCountItem[];
  userAgents: AnalysisCountItem[];
  evidence: AnalysisEventEvidence[];
};

export type AnalysisClustersResult = {
  generatedAt: string;
  filters: AnalysisFiltersPayload;
  totalClusters: number;
  items: AnalysisCluster[];
};

export type AnalysisSourceItem = {
  clientIp: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  locationPrecision: LocationPrecision;
  requestCount: number;
  attackCount: number;
  normalCount: number;
  attackShare: number;
  riskLevel: RiskLevel | string;
  latestSeen?: string;
  topAttackCategory: string;
  topRuleId: string;
  topPath: string;
};

export type AnalysisSourceCountry = {
  country: string;
  requestCount: number;
  attackCount: number;
  normalCount: number;
  attackShare: number;
  riskLevel: RiskLevel | string;
};

export type AnalysisSources = {
  generatedAt: string;
  filters: AnalysisFiltersPayload;
  totalRequests: number;
  totalAttackEvents: number;
  normalRequests: number;
  attackShare: number;
  affectedSources: number;
  affectedCountries: number;
  items: AnalysisSourceItem[];
  countries: AnalysisSourceCountry[];
};

export type AnalysisAdvice = {
  id: string;
  status: string;
  sourceClusterId: string;
  title: string;
  riskLevel: RiskLevel | string;
  confidence: number;
  rationale: string;
  impact: {
    eventCount: number;
    sourceCount: number;
    pathCount: number;
    timeRange: {
      firstSeen: string;
      lastSeen: string;
    };
  };
  ruleDraft: AnalysisRuleDraft;
  evidence: AnalysisEventEvidence[];
  manualReviewQuestions: string[];
};

export type AnalysisAdviceResult = {
  status: string;
  message: string;
  generatedAt: string;
  filters: AnalysisFiltersPayload;
  totalDrafts: number;
  items: AnalysisAdvice[];
};

export const riskLabels: Record<RiskLevel, string> = {
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高风险",
  critical: "严重",
};

export const riskOrder: RiskLevel[] = ["info", "low", "medium", "high", "critical"];

export function resolveTrafficKind(input: { eventType?: string; riskLevel?: RiskLevel; action?: SecurityEvent["action"] }): TrafficKind {
  if (input.eventType === "normal_visit" || input.eventType === "正常访问") return "visit";
  if (input.action === "allow" && (input.riskLevel === "info" || input.riskLevel === "low")) return "visit";
  if (
    input.action === "block" ||
    input.action === "blocked" ||
    input.action === "challenge" ||
    input.action === "managed_challenge" ||
    input.action === "js_challenge" ||
    input.action === "log" ||
    input.action === "simulate"
  ) {
    return "attack";
  }
  if (input.riskLevel === "info" || input.riskLevel === "low") return "visit";
  return "attack";
}

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
      ruleHits: rest.ruleHits ?? [],
      ruleVersion: rest.ruleVersion,
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
      attackCategory: "敏感信息探测",
      attackSubtype: ".env 配置文件探测",
      toolSignature: "curl/8.2 / 命令行扫描器",
      behaviorFingerprint: "短时间直接访问敏感根路径，User-Agent 暴露自动化工具特征。",
      campaignId: "campaign-sensitive-path-001",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-sensitive-path",
      ruleHits: [
        {
          id: "builtin-sensitive-path",
          name: "敏感路径探测",
          mode: "enforce",
          severity: "critical",
          classification: "sensitive_path",
          evidence: ["path=/.env", "action=block", "userAgent=curl/8.2 security scanner"],
          confidence: 0.96,
          matched: true,
        },
        {
          id: "shadow-tool-curl",
          name: "命令行工具指纹",
          mode: "shadow",
          severity: "medium",
          classification: "tool_signature",
          evidence: ["userAgent contains curl"],
          confidence: 0.82,
          matched: false,
        },
      ],
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
      attackCategory: "注入攻击",
      attackSubtype: "SQL 布尔绕过探测",
      toolSignature: "Browser UA / 手工注入片段",
      behaviorFingerprint: "POST 查询接口携带 `' OR 1=1--` 注入语句并触发托管挑战。",
      campaignId: "campaign-injection-001",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-sqli",
      ruleHits: [
        {
          id: "builtin-sqli",
          name: "疑似 SQL 注入",
          mode: "enforce",
          severity: "high",
          classification: "sql_injection",
          evidence: ["query=q=' OR 1=1--", "method=POST", "action=managed_challenge"],
          confidence: 0.88,
          matched: true,
        },
      ],
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
      attackCategory: "目录探测",
      attackSubtype: "WordPress 登录入口探测",
      toolSignature: "zgrab/0.x / 互联网资产探测器",
      behaviorFingerprint: "访问不存在的 WordPress 登录路径，User-Agent 指向 zgrab 扫描器。",
      campaignId: "campaign-cms-probe-001",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-cms-probe",
      ruleHits: [
        {
          id: "builtin-wp-probe",
          name: "WordPress 探测",
          mode: "enforce",
          severity: "high",
          classification: "cms_probe",
          evidence: ["path=/wp-login.php", "statusCode=404", "userAgent contains zgrab"],
          confidence: 0.91,
          matched: true,
        },
      ],
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
      attackCategory: "后台探测",
      attackSubtype: "管理入口枚举",
      toolSignature: "python-requests/2.31 / 自动化请求库",
      behaviorFingerprint: "自动化请求库直接访问后台路径，并触发阻断动作。",
      campaignId: "campaign-admin-probe-001",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-admin-probe",
      ruleHits: [
        {
          id: "builtin-admin-probe",
          name: "后台路径探测",
          mode: "enforce",
          severity: "high",
          classification: "admin_probe",
          evidence: ["path=/admin", "action=block", "userAgent=python-requests/2.31"],
          confidence: 0.84,
          matched: true,
        },
      ],
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
      attackCategory: "正常访问",
      attackSubtype: "公开内容访问",
      toolSignature: "Browser UA / 常规浏览器",
      behaviorFingerprint: "浏览器访问公开文章，状态码与行为均在正常范围内。",
      campaignId: "campaign-benign-traffic",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-benign",
      ruleHits: [
        {
          id: "traffic-normal",
          name: "普通访问",
          mode: "observe",
          severity: "info",
          classification: "benign_traffic",
          evidence: ["path=/posts/first", "statusCode=200", "action=allow"],
          confidence: 0.64,
          matched: true,
        },
      ],
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
      attackCategory: "敏感信息探测",
      attackSubtype: "phpMyAdmin 入口探测",
      toolSignature: "Go-http-client/1.1 / 自动化 HTTP 客户端",
      behaviorFingerprint: "自动化客户端访问常见数据库管理入口，目标路径返回 404 后触发挑战。",
      campaignId: "campaign-sensitive-path-001",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-sensitive-path",
      ruleHits: [
        {
          id: "builtin-sensitive-path",
          name: "敏感路径探测",
          mode: "enforce",
          severity: "high",
          classification: "sensitive_path",
          evidence: ["path=/phpmyadmin/index.php", "statusCode=404", "userAgent=Go-http-client/1.1"],
          confidence: 0.9,
          matched: true,
        },
      ],
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
      attackCategory: "注入攻击",
      attackSubtype: "反射型 XSS 探测",
      toolSignature: "Browser UA / 参数注入片段",
      behaviorFingerprint: "评论接口参数包含 script 标签片段，并触发托管挑战。",
      campaignId: "campaign-injection-002",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-xss",
      ruleHits: [
        {
          id: "builtin-xss",
          name: "疑似 XSS",
          mode: "enforce",
          severity: "medium",
          classification: "xss",
          evidence: ["query contains <script>", "path=/api/comment", "action=managed_challenge"],
          confidence: 0.79,
          matched: true,
        },
      ],
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
      attackCategory: "爬虫访问",
      attackSubtype: "已知订阅抓取",
      toolSignature: "FeedFetcher-Google / 已知爬虫",
      behaviorFingerprint: "已知订阅抓取器访问 RSS 路径，允许通过。",
      campaignId: "campaign-known-crawler",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-crawler",
      ruleHits: [
        {
          id: "crawler-known",
          name: "已知爬虫",
          mode: "observe",
          severity: "low",
          classification: "known_crawler",
          evidence: ["userAgent=FeedFetcher-Google", "path=/rss.xml", "action=allow"],
          confidence: 0.58,
          matched: true,
        },
      ],
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
      attackCategory: "正常访问",
      attackSubtype: "可用性检测",
      toolSignature: "UptimeRobot/2.0 / 监控探针",
      behaviorFingerprint: "监控探针使用 HEAD 请求检查站点可用性。",
      campaignId: "campaign-availability-check",
      ruleVersion: "ruleset-2026.06.02",
      aiClusterId: "cluster-benign",
      ruleHits: [
        {
          id: "monitor-normal",
          name: "可用性检测",
          mode: "observe",
          severity: "info",
          classification: "availability_check",
          evidence: ["method=HEAD", "statusCode=200", "action=allow"],
          confidence: 0.7,
          matched: true,
        },
      ],
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
      label: [formatCountryDisplayName(event.country), event.city, event.eventType].filter(Boolean).join(" "),
      clientIp: event.clientIp,
      country: event.country,
      city: event.city,
      latitude: event.latitude,
      longitude: event.longitude,
      count: topIps[index]?.value ?? Math.max(8, 34 - index * 3),
      riskLevel: event.riskLevel,
      eventType: event.eventType,
      trafficKind: resolveTrafficKind(event),
      locationPrecision: event.locationPrecision,
      action: event.action,
      method: event.method,
      path: event.path,
      statusCode: event.statusCode,
      rayId: event.rayId,
      asn: event.asn,
      ruleName: event.ruleName,
      throughputMb: Number(
        (
          Math.max(6, (topIps[index]?.value ?? Math.max(8, 34 - index * 3)) * 0.46) +
          riskOrder.indexOf(event.riskLevel) * 1.8
        ).toFixed(1),
      ),
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

function riskRankValue(riskLevel: RiskLevel | string) {
  return riskOrder.includes(riskLevel as RiskLevel) ? riskOrder.indexOf(riskLevel as RiskLevel) : 0;
}

function mostUsed(values: Array<string | undefined>, fallback = "unknown") {
  const counts = new Map<string, number>();
  values.filter((value): value is string => Boolean(value)).forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  const ranked = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  return ranked[0]?.[0] ?? fallback;
}

function eventRuleHits(event: SecurityEvent): SecurityRuleHit[] {
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

function defaultAnalysisFilters(): AnalysisFiltersPayload {
  return {
    timeRange: "24h",
    risk: null,
    country: null,
    attackCategory: null,
    ruleId: null,
  };
}

function maxRiskLevel(events: SecurityEvent[]) {
  return events.reduce<RiskLevel>((current, event) => (riskRankValue(event.riskLevel) > riskRankValue(current) ? event.riskLevel : current), "info");
}

function countItems(values: Array<string | number | undefined | null>, limit = 8): AnalysisCountItem[] {
  const counts = new Map<string, number>();
  values.forEach((value) => {
    const label = String(value ?? "").trim();
    if (!label) return;
    counts.set(label, (counts.get(label) ?? 0) + 1);
  });
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

function displayCountryCountItems(values: Array<string | undefined | null>, limit = 8): AnalysisCountItem[] {
  return countItems(values, limit).map((item) => ({
    ...item,
    label: formatCountryDisplayName(item.label),
  }));
}

function eventEvidence(event: SecurityEvent): AnalysisEventEvidence {
  return {
    id: event.id,
    timestamp: event.timestamp,
    clientIp: event.clientIp,
    country: event.country,
    method: event.method,
    path: event.path,
    query: event.query ?? null,
    statusCode: event.statusCode,
    action: event.action,
    riskLevel: event.riskLevel,
    ruleId: event.ruleId,
    ruleName: event.ruleName,
    summary: event.summary,
    ruleMatches: event.ruleMatches,
  };
}

function ruleDefinitionFromBase(rule: {
  id: string;
  version: string;
  mode: string;
  ruleType: string;
  condition: Record<string, unknown>;
  severity: RiskLevel | string;
  attackCategory: string;
  attackSubtype: string;
  toolSignature: string;
  behaviorFingerprint: string;
}): AnalysisRuleDefinition {
  return {
    id: rule.id,
    version: rule.version,
    mode: rule.mode,
    ruleType: rule.ruleType,
    condition: rule.condition,
    severity: rule.severity,
    classification: {
      attackCategory: rule.attackCategory,
      attackSubtype: rule.attackSubtype,
      toolSignature: rule.toolSignature,
      behaviorFingerprint: rule.behaviorFingerprint,
    },
  };
}

function baseRuleDefinitions(): Record<string, AnalysisRuleDefinition & { name: string }> {
  const rules = [
    {
      id: "builtin-sensitive-path",
      name: "敏感路径探测",
      ruleType: "path_keyword",
      condition: {
        keywords: [
          ".env",
          ".env.local",
          ".env.bak",
          ".env.backup",
          "wp-login.php",
          "phpmyadmin",
          "/admin",
          "firebase-adminsdk.json",
          "firebase.json",
          "google-credentials.json",
          "credentials.json",
          "config.json",
          "key.json",
        ],
      },
      severity: "high",
      version: "2026.06.02",
      mode: "active",
      attackCategory: "reconnaissance",
      attackSubtype: "sensitive_path_probe",
      toolSignature: "scanner_path_probe",
      behaviorFingerprint: "http_path_keyword_probe",
    },
    {
      id: "builtin-sqli",
      name: "SQL 注入探测",
      ruleType: "query_keyword",
      condition: { keywords: [" OR 1=1", "UNION SELECT", "--"] },
      severity: "high",
      version: "2026.06.02",
      mode: "active",
      attackCategory: "injection",
      attackSubtype: "sql_injection_probe",
      toolSignature: "manual_or_scanner_sqli",
      behaviorFingerprint: "http_query_sqli_keyword",
    },
    {
      id: "builtin-xss",
      name: "XSS 探测",
      ruleType: "query_keyword",
      condition: { keywords: ["<script", "javascript:", "onerror="] },
      severity: "medium",
      version: "2026.06.02",
      mode: "active",
      attackCategory: "injection",
      attackSubtype: "xss_probe",
      toolSignature: "manual_or_scanner_xss",
      behaviorFingerprint: "http_query_xss_keyword",
    },
    {
      id: "builtin-scanner-ua",
      name: "扫描器 User-Agent",
      ruleType: "user_agent_keyword",
      condition: { keywords: ["curl", "zgrab", "python-requests", "Go-http-client"] },
      severity: "medium",
      version: "2026.06.02",
      mode: "active",
      attackCategory: "reconnaissance",
      attackSubtype: "scanner_user_agent",
      toolSignature: "scanner_user_agent",
      behaviorFingerprint: "http_user_agent_keyword",
    },
    {
      id: "builtin-cloudflare-action",
      name: "Cloudflare 安全处置",
      ruleType: "cloudflare_action",
      condition: { actions: ["block", "challenge", "managed_challenge"] },
      severity: "high",
      version: "2026.06.02",
      mode: "active",
      attackCategory: "edge_security",
      attackSubtype: "cloudflare_action",
      toolSignature: "cloudflare_firewall",
      behaviorFingerprint: "cloudflare_action_match",
    },
  ];

  return Object.fromEntries(rules.map((rule) => [rule.id, { ...ruleDefinitionFromBase(rule), name: rule.name }]));
}

export function createAnalysisClusters(events: SecurityEvent[] = createSampleSecurityData().events): AnalysisClustersResult {
  const attackEvents = events.filter((event) => resolveTrafficKind(event) === "attack" || riskRankValue(event.riskLevel) >= riskRankValue("medium"));
  const groups = new Map<string, SecurityEvent[]>();
  attackEvents.forEach((event) => {
    const key = [
      event.attackCategory || "unclassified",
      event.attackSubtype || "",
      event.toolSignature || "",
      event.behaviorFingerprint || "",
      event.ruleId || "",
      event.ruleName || "",
    ].join("|");
    groups.set(key, [...(groups.get(key) ?? []), event]);
  });

  const items = Array.from(groups.entries())
    .map(([key, group]) => {
      const ordered = [...group].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
      const newest = [...group].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
      const firstSeen = ordered[0]?.timestamp ?? "";
      const lastSeen = ordered[ordered.length - 1]?.timestamp ?? firstSeen;
      const attackCategory = mostUsed(group.map((event) => event.attackCategory || event.eventType), "unknown");
      const attackSubtype = mostUsed(group.map((event) => event.attackSubtype || event.eventType), attackCategory);
      const confidence = group.length ? group.reduce((sum, event) => sum + event.confidence, 0) / group.length : 0;
      const source = countItems(group.map((event) => event.clientIp), 1)[0]?.label;
      const sourceEvent = group.find((event) => event.clientIp === source) ?? group[0];
      const path = countItems(group.map((event) => `${event.method}|${event.path}|${event.statusCode}`), 1)[0];
      const [method = "", pathValue = "", statusValue = "0"] = (path?.label ?? "").split("|");
      const action = countItems(group.map((event) => event.action), 1)[0];
      const userAgent = countItems(group.map((event) => event.userAgent), 1)[0];
      const ruleId = mostUsed(group.map((event) => event.ruleId), "");

      return {
        clusterId: `cluster-${key.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-|-$/g, "").slice(0, 64) || newest[0]?.id || "unknown"}`,
        attackCategory,
        attackSubtype,
        ruleId,
        ruleName: mostUsed(group.map((event) => event.ruleName), ""),
        toolSignature: mostUsed(group.map((event) => event.toolSignature || event.userAgent), ""),
        behaviorFingerprint: mostUsed(group.map((event) => event.behaviorFingerprint), ""),
        eventCount: group.length,
        riskLevel: maxRiskLevel(group),
        confidence: Number(confidence.toFixed(3)),
        timeRange: {
          firstSeen,
          lastSeen,
        },
        primarySource: sourceEvent
          ? {
              clientIp: sourceEvent.clientIp,
              country: sourceEvent.country,
              region: sourceEvent.region,
              city: sourceEvent.city,
              asn: sourceEvent.asn,
              latitude: sourceEvent.latitude,
              longitude: sourceEvent.longitude,
              locationPrecision: sourceEvent.locationPrecision,
              count: countItems(group.map((event) => event.clientIp), 1)[0]?.value ?? 0,
            }
          : null,
        primaryPath: path
          ? {
              method,
              path: pathValue,
              statusCode: Number(statusValue),
              count: path.value,
            }
          : null,
        primaryAction: action ? { action: action.label, count: action.value } : null,
        primaryUserAgent: userAgent ? { userAgent: userAgent.label, count: userAgent.value } : null,
        countries: displayCountryCountItems(group.map((event) => event.country)),
        paths: countItems(group.map((event) => event.path)),
        methods: countItems(group.map((event) => event.method)),
        statusCodes: countItems(group.map((event) => event.statusCode)),
        actions: countItems(group.map((event) => event.action)),
        userAgents: countItems(group.map((event) => event.userAgent), 5),
        evidence: newest.slice(0, 5).map(eventEvidence),
      };
    })
    .sort((a, b) => riskRankValue(b.riskLevel) - riskRankValue(a.riskLevel) || b.eventCount - a.eventCount);

  return {
    generatedAt: new Date().toISOString(),
    filters: defaultAnalysisFilters(),
    totalClusters: items.length,
    items,
  };
}

export function createAnalysisRules(events: SecurityEvent[] = createSampleSecurityData().events): AnalysisRulesResult {
  const definitions = baseRuleDefinitions();
  const stats = new Map<string, AnalysisRule & { sourceSet: Set<string>; pathSet: Set<string> }>();
  events.forEach((event) => {
    eventRuleHits(event).forEach((hit) => {
      const definition = definitions[hit.id];
      const current = stats.get(hit.id);
      if (current) {
        current.eventCount += 1;
        current.riskLevel = riskRankValue(event.riskLevel) > riskRankValue(current.riskLevel) ? event.riskLevel : current.riskLevel;
        current.firstSeen = Date.parse(event.timestamp) < Date.parse(current.firstSeen) ? event.timestamp : current.firstSeen;
        current.lastSeen = Date.parse(event.timestamp) > Date.parse(current.lastSeen) ? event.timestamp : current.lastSeen;
        current.sourceSet.add(event.clientIp);
        current.pathSet.add(event.path);
        if (current.evidence.length < 5) current.evidence.push(eventEvidence(event));
      } else {
        stats.set(hit.id, {
          ruleId: hit.id,
          ruleName: hit.name || definition?.name || hit.id,
          eventCount: 1,
          riskLevel: event.riskLevel,
          severity: hit.severity || definition?.severity || event.riskLevel,
          mode: hit.mode || definition?.mode || "observe",
          version: event.ruleVersion || definition?.version || "",
          attackCategory: event.attackCategory || definition?.classification.attackCategory || "",
          attackSubtype: event.attackSubtype || definition?.classification.attackSubtype || "",
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
          sourceCount: 1,
          pathCount: 1,
          matchedFields: [],
          matchedValues: countItems(hit.evidence, 8),
          definition,
          evidence: [eventEvidence(event)],
          sourceSet: new Set([event.clientIp]),
          pathSet: new Set([event.path]),
        });
      }
    });
  });

  const items = Array.from(stats.values()).map(({ sourceSet, pathSet, ...item }) => ({
    ...item,
    sourceCount: sourceSet.size,
    pathCount: pathSet.size,
  }));
  items.sort((a, b) => riskRankValue(b.riskLevel) - riskRankValue(a.riskLevel) || b.eventCount - a.eventCount);

  return {
    generatedAt: new Date().toISOString(),
    filters: defaultAnalysisFilters(),
    totalRules: items.length,
    items,
  };
}

export function createAnalysisSources(overview: SecurityOverview = createSampleSecurityData().overview): AnalysisSources {
  const attackEvents = overview.recentEvents.filter((event) => resolveTrafficKind(event) === "attack" || riskRankValue(event.riskLevel) >= riskRankValue("medium"));
  const groups = new Map<string, { events: SecurityEvent[]; requestCount: number }>();
  overview.topIps.forEach((item) => groups.set(item.label, { events: [], requestCount: item.value }));
  attackEvents.forEach((event) => {
    const key = event.clientIp || event.id;
    const current = groups.get(key) ?? { events: [], requestCount: 0 };
    current.events.push(event);
    current.requestCount = Math.max(current.requestCount, current.events.length);
    groups.set(key, current);
  });
  const items = Array.from(groups.entries())
    .map(([clientIp, data]) => {
      const latest = [...data.events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
      const requestCount = Math.max(data.requestCount, data.events.length);
      const attackCount = data.events.length;
      return {
        clientIp,
        country: latest?.country ?? "",
        region: latest?.region ?? "",
        city: latest?.city ?? "",
        latitude: latest?.latitude ?? 0,
        longitude: latest?.longitude ?? 0,
        locationPrecision: latest?.locationPrecision ?? "estimated",
        requestCount,
        attackCount,
        normalCount: Math.max(0, requestCount - attackCount),
        attackShare: requestCount ? Number((attackCount / requestCount).toFixed(4)) : 0,
        riskLevel: data.events.length ? maxRiskLevel(data.events) : "info",
        latestSeen: latest?.timestamp,
        topAttackCategory: mostUsed(data.events.map((event) => event.attackCategory || event.eventType), ""),
        topRuleId: mostUsed(data.events.map((event) => event.ruleId), ""),
        topPath: mostUsed(data.events.map((event) => event.path), ""),
      };
    })
    .sort((a, b) => b.attackCount - a.attackCount || b.requestCount - a.requestCount);
  const countryRequests = new Map(overview.countries.map((item) => [item.label, item.value]));
  const countryAttacks = new Map<string, SecurityEvent[]>();
  attackEvents.forEach((event) => countryAttacks.set(event.country, [...(countryAttacks.get(event.country) ?? []), event]));
  const countries = Array.from(new Set([...countryRequests.keys(), ...countryAttacks.keys()]))
    .map((country) => {
      const eventsForCountry = countryAttacks.get(country) ?? [];
      const requestCount = Math.max(countryRequests.get(country) ?? 0, eventsForCountry.length);
      const attackCount = eventsForCountry.length;
      return {
        country,
        requestCount,
        attackCount,
        normalCount: Math.max(0, requestCount - attackCount),
        attackShare: requestCount ? Number((attackCount / requestCount).toFixed(4)) : 0,
        riskLevel: eventsForCountry.length ? maxRiskLevel(eventsForCountry) : "info",
      };
    })
    .sort((a, b) => b.attackCount - a.attackCount || b.requestCount - a.requestCount);
  const totalRequests = countries.reduce((sum, item) => sum + item.requestCount, 0);
  const totalAttackEvents = attackEvents.length;

  return {
    generatedAt: new Date().toISOString(),
    filters: defaultAnalysisFilters(),
    totalRequests,
    totalAttackEvents,
    normalRequests: Math.max(0, totalRequests - totalAttackEvents),
    attackShare: totalRequests ? Number((totalAttackEvents / totalRequests).toFixed(4)) : 0,
    affectedSources: new Set(attackEvents.map((event) => event.clientIp).filter(Boolean)).size,
    affectedCountries: new Set(attackEvents.map((event) => event.country).filter(Boolean)).size,
    items,
    countries,
  };
}

export function createAnalysisAdvice(clusters: AnalysisClustersResult = createAnalysisClusters()): AnalysisAdviceResult {
  const items = clusters.items.slice(0, 4).map((cluster) => {
    const ruleType = cluster.primaryPath?.path ? "path_keyword" : cluster.primaryUserAgent?.userAgent ? "user_agent_keyword" : "cloudflare_action";
    const condition =
      ruleType === "path_keyword"
        ? { keywords: cluster.primaryPath?.path ? [cluster.primaryPath.path] : [] }
        : ruleType === "user_agent_keyword"
          ? { keywords: cluster.primaryUserAgent?.userAgent ? [cluster.primaryUserAgent.userAgent] : [] }
          : { actions: cluster.primaryAction?.action ? [cluster.primaryAction.action] : [] };
    return {
      id: `draft-${cluster.clusterId}`,
      status: "draft",
      sourceClusterId: cluster.clusterId,
      title: `复核规则：${cluster.attackCategory}`,
      riskLevel: cluster.riskLevel,
      confidence: cluster.confidence,
      rationale: `${cluster.eventCount} 条事件共享相同规则、处置动作、来源、路径或工具证据。`,
      impact: {
        eventCount: cluster.eventCount,
        sourceCount: cluster.countries.length,
        pathCount: cluster.paths.length,
        timeRange: cluster.timeRange,
      },
      ruleDraft: {
        id: `draft-${cluster.clusterId}`,
        version: "draft",
        name: `Review ${cluster.attackCategory}`,
        enabled: false,
        mode: "shadow",
        ruleType,
        condition,
        severity: cluster.riskLevel,
        classification: {
          attackCategory: cluster.attackCategory,
          attackSubtype: cluster.attackSubtype,
          toolSignature: cluster.toolSignature,
          behaviorFingerprint: cluster.behaviorFingerprint,
        },
        actions: {
          alert: true,
          block: false,
        },
        lifecycle: {
          createdBy: "attack_aggregator",
          reviewStatus: "manual_review_required",
        },
      },
      evidence: cluster.evidence,
      manualReviewQuestions: [
        "确认主要路径是否属于预期的生产访问。",
        "确认来源国家和 User-Agent 是否匹配已知的合法客户端。",
        "在启用拦截前确认规则模式。",
      ],
    };
  });

  return {
    status: "draft",
    message: "规则建议仅由聚合数据生成，当前未调用大模型。",
    generatedAt: new Date().toISOString(),
    filters: defaultAnalysisFilters(),
    totalDrafts: items.length,
    items,
  };
}
