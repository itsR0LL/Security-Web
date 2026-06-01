import { getSecurityEvents } from "@/lib/security-api";
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
    timeRange: firstParam(params, "timeRange"),
    event: firstParam(params, "event"),
  };
  const result = await getSecurityEvents({
    risk: initialFilters.risk,
    eventType: initialFilters.eventType,
    ip: initialFilters.ip,
    country: initialFilters.country,
    path: initialFilters.path,
    action: initialFilters.action,
    statusCode: initialFilters.statusCode,
    timeRange: initialFilters.timeRange,
    limit: 100,
  });

  return (
    <RainSecuritySubPage
      page="events"
      events={result.data}
      initialFilters={initialFilters}
      source={result.source}
      error={result.error}
    />
  );
}
