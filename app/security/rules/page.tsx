import { SecurityRulesConsole } from "@/components/security/SecurityRulesConsole";
import { getCloudflareDerivedRules, getRuleDrafts, getSecurityRules } from "@/lib/security-api";

type SecurityRulesPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function firstParam(params: Record<string, string | string[] | undefined>, key: string) {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
}

export default async function SecurityRulesPage({ searchParams }: SecurityRulesPageProps) {
  const params = await searchParams;
  const [rules, drafts, cloudflareRules] = await Promise.all([getSecurityRules(), getRuleDrafts(), getCloudflareDerivedRules()]);
  const source = [rules, drafts, cloudflareRules].some((result) => result.source === "api") ? "api" : "sample";
  const error = rules.error ?? drafts.error ?? cloudflareRules.error;

  return (
    <SecurityRulesConsole
      initialRules={rules.data}
      initialDrafts={drafts.data}
      initialCloudflareRules={cloudflareRules.data}
      source={source}
      error={error}
      initialFocus={{
        ruleId: firstParam(params, "ruleId"),
        draftId: firstParam(params, "draftId"),
        attackCategory: firstParam(params, "attackCategory"),
      }}
    />
  );
}
