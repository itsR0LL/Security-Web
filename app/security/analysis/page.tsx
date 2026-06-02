import { SecurityAnalysisConsole } from "@/components/security/SecurityAnalysisConsole";
import {
  getAnalysisAdvice,
  getAnalysisClusters,
  getAnalysisRules,
  getAnalysisSources,
  getAnalysisSummary,
} from "@/lib/security-api";

export default async function SecurityAnalysisPage() {
  const [summary, clusters, rules, sources, advice] = await Promise.all([
    getAnalysisSummary(),
    getAnalysisClusters(),
    getAnalysisRules(),
    getAnalysisSources(),
    getAnalysisAdvice(),
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
    />
  );
}
