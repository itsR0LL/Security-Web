import { SituationVisualization } from "@/components/security/SituationVisualization";
import { getSecurityOverview } from "@/lib/security-api";

type SecuritySituationPageProps = {
  searchParams?: Promise<{
    view?: string | string[];
  }>;
};

export default async function SecuritySituationPage({ searchParams }: SecuritySituationPageProps) {
  const params = searchParams ? await searchParams : undefined;
  const viewParam = Array.isArray(params?.view) ? params?.view[0] : params?.view;
  const result = await getSecurityOverview();
  const overview = result.data;

  return (
    <SituationVisualization
      overview={overview}
      source={result.source}
      error={result.error}
      initialView={viewParam === "2d" ? "2d" : "3d"}
    />
  );
}
