import { RainSecuritySubPage } from "@/components/security/RainSecuritySubPage";
import { getSecurityEvent, getSecuritySyncStatus } from "@/lib/security-api";

type SecurityEventDetailPageProps = {
  params: Promise<{ id: string }>;
};

export default async function SecurityEventDetailPage({ params }: SecurityEventDetailPageProps) {
  const { id } = await params;
  const [result, syncStatus] = await Promise.all([getSecurityEvent(id), getSecuritySyncStatus()]);

  return (
    <RainSecuritySubPage
      page="events"
      events={result.data ? [result.data] : []}
      syncStatus={syncStatus.data}
      initialFilters={{ event: id, timeRange: "all" }}
      source={result.source}
      error={result.error ?? syncStatus.error}
    />
  );
}
