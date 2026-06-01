import { getSecuritySettings } from "@/lib/security-api";
import { RainSecuritySubPage } from "@/components/security/RainSecuritySubPage";

export default async function SecuritySettingsPage() {
  const result = await getSecuritySettings();

  return (
    <RainSecuritySubPage
      page="settings"
      settings={result.data}
      source={result.source}
      error={result.error}
    />
  );
}
