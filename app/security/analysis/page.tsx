import { SecurityAnalysisConsole } from "@/components/security/SecurityAnalysisConsole";
import {
  getAnalysisAdvice,
  getAnalysisClusters,
  getAnalysisRules,
  getAnalysisSources,
  getAnalysisSummary,
} from "@/lib/security-api";

type AnalysisTimeRange = "6h" | "24h" | "7d" | "all";

type SecurityAnalysisPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

const analysisTimeRanges = new Set<AnalysisTimeRange>(["6h", "24h", "7d", "all"]);

function firstParam(params: Record<string, string | string[] | undefined>, key: string) {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeTimeRange(value?: string): AnalysisTimeRange {
  return analysisTimeRanges.has(value as AnalysisTimeRange) ? (value as AnalysisTimeRange) : "7d";
}

function normalizeFilter(value?: string) {
  return value && value !== "all" ? value : undefined;
}

export default async function SecurityAnalysisPage({ searchParams }: SecurityAnalysisPageProps) {
  const params = await searchParams;
  const timeRange = normalizeTimeRange(firstParam(params, "timeRange"));
  const filters = {
    timeRange,
    risk: normalizeFilter(firstParam(params, "risk")),
    country: normalizeFilter(firstParam(params, "country")),
    attackCategory: normalizeFilter(firstParam(params, "attackCategory")),
    ruleId: normalizeFilter(firstParam(params, "ruleId")),
  };

  const [summary, clusters, rules, sources, advice] = await Promise.all([
    getAnalysisSummary(filters),
    getAnalysisClusters(filters),
    getAnalysisRules(filters),
    getAnalysisSources(filters),
    getAnalysisAdvice(filters),
  ]);
  const source = [summary, clusters, rules, sources, advice].some((result) => result.source === "api") ? "api" : "sample";
  const error = clusters.error ?? rules.error ?? sources.error ?? advice.error ?? summary.error;

  return (
    <SecurityAnalysisConsole
      summary={summary.data}
      clusters={clusters.data}
      rules={rules.data}
      sources={sources.data}
      advice={advice.data}
      source={source}
      error={error}
      timeRange={timeRange}
      filters={filters}
    />
  );
}
