import { getSecuritySettings, getSecuritySyncStatus } from "@/lib/security-api";
import { RainSecuritySubPage } from "@/components/security/RainSecuritySubPage";

export default async function SecuritySettingsPage() {
  const [result, syncStatus] = await Promise.all([getSecuritySettings(), getSecuritySyncStatus()]);

  return (
    <RainSecuritySubPage
      page="settings"
      settings={result.data}
      syncStatus={syncStatus.data}
      source={result.source}
      error={result.error ?? syncStatus.error}
    />
  );
}
