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

export default async function SecurityAnalysisPage({ searchParams }: SecurityAnalysisPageProps) {
  const params = await searchParams;
  const timeRange = normalizeTimeRange(firstParam(params, "timeRange"));
  const query = { timeRange };

  const [summary, clusters, rules, sources, advice] = await Promise.all([
    getAnalysisSummary(query),
    getAnalysisClusters(query),
    getAnalysisRules(query),
    getAnalysisSources(query),
    getAnalysisAdvice(query),
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
    />
  );
}
