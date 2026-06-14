import { getSecurityHomeSimulationOverview } from "@/lib/security-api";
import { RainSecurityHome } from "@/components/security/RainSecurityHome";

export default async function SecurityOverviewPage() {
  const result = await getSecurityHomeSimulationOverview();
  const overview = result.data;

  return <RainSecurityHome overview={overview} source={result.source} error={result.error} />;
}
