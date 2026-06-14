import { SituationVisualization } from "@/components/security/SituationVisualization";
import { getAnalysisSummary, getSecuritySituationOverview, type SecurityAnalysisQuery, type SecuritySituationQuery } from "@/lib/security-api";

type SecuritySituationPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

function firstParam(params: Record<string, string | string[] | undefined> | undefined, key: string) {
  const value = params?.[key];
  return Array.isArray(value) ? value[0] : value;
}

export default async function SecuritySituationPage({ searchParams }: SecuritySituationPageProps) {
  const params = searchParams ? await searchParams : undefined;
  const viewParam = firstParam(params, "view");
  const situationQuery: SecuritySituationQuery = {
    timeRange: firstParam(params, "timeRange"),
    risk: firstParam(params, "risk"),
    country: firstParam(params, "country"),
    attackCategory: firstParam(params, "attackCategory"),
    ruleId: firstParam(params, "ruleId"),
    view: viewParam,
  };
  const analysisQuery: SecurityAnalysisQuery = {
    timeRange: situationQuery.timeRange,
    risk: situationQuery.risk,
    country: situationQuery.country,
    attackCategory: situationQuery.attackCategory,
    ruleId: situationQuery.ruleId,
  };
  const [result, analysisSummary] = await Promise.all([
    getSecuritySituationOverview(situationQuery),
    getAnalysisSummary(analysisQuery),
  ]);
  const overview = result.data;

  return (
    <SituationVisualization
      overview={overview}
      analysisSummary={analysisSummary.data}
      source={result.source}
      error={result.error}
      initialView={viewParam === "2d" ? "2d" : "3d"}
      filters={situationQuery}
    />
  );
}
