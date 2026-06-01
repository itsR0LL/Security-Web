import { RainSecuritySubPage } from "@/components/security/RainSecuritySubPage";
import { getSecurityEvent } from "@/lib/security-api";

type SecurityEventDetailPageProps = {
  params: Promise<{ id: string }>;
};

export default async function SecurityEventDetailPage({ params }: SecurityEventDetailPageProps) {
  const { id } = await params;
  const result = await getSecurityEvent(id);

  return (
    <RainSecuritySubPage
      page="events"
      events={result.data ? [result.data] : []}
      initialFilters={{ event: id, timeRange: "all" }}
      source={result.source}
      error={result.error}
    />
  );
}
