import { getSecurityEvents, getSecuritySyncStatus } from "@/lib/security-api";
import { RainSecuritySubPage, type EventInitialFilters } from "@/components/security/RainSecuritySubPage";

type SecurityEventsPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function firstParam(params: Record<string, string | string[] | undefined>, key: string) {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
}

export default async function SecurityEventsPage({ searchParams }: SecurityEventsPageProps) {
  const params = await searchParams;
  const initialFilters: EventInitialFilters = {
    risk: firstParam(params, "risk"),
    eventType: firstParam(params, "eventType"),
    ip: firstParam(params, "ip") ?? firstParam(params, "source"),
    country: firstParam(params, "country"),
    path: firstParam(params, "path"),
    action: firstParam(params, "action"),
    statusCode: firstParam(params, "statusCode"),
    method: firstParam(params, "method"),
    userAgent: firstParam(params, "userAgent"),
    attackCategory: firstParam(params, "attackCategory"),
    ruleId: firstParam(params, "ruleId"),
    timeRange: firstParam(params, "timeRange"),
    event: firstParam(params, "event"),
  };
  const [result, syncStatus] = await Promise.all([
    getSecurityEvents({
      risk: initialFilters.risk,
      eventType: initialFilters.eventType,
      ip: initialFilters.ip,
      country: initialFilters.country,
      path: initialFilters.path,
      action: initialFilters.action,
      statusCode: initialFilters.statusCode,
      method: initialFilters.method,
      userAgent: initialFilters.userAgent,
      attackCategory: initialFilters.attackCategory,
      ruleId: initialFilters.ruleId,
      timeRange: initialFilters.timeRange,
      limit: 100,
    }),
    getSecuritySyncStatus(),
  ]);

  return (
    <RainSecuritySubPage
      page="events"
      events={result.data}
      syncStatus={syncStatus.data}
      initialFilters={initialFilters}
      source={result.source}
      error={result.error ?? syncStatus.error}
    />
  );
}
