"use client";

import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { SecurityGlobalNav } from "@/components/security/SecurityGlobalNav";
import { useRainCursor } from "@/components/security/useRainCursor";
import {
  createSecurityRule,
  deleteSecurityRule,
  getCloudflareDerivedRules,
  getRuleDrafts,
  getSecurityRules,
  patchSecurityRule,
  promoteRuleDraft,
  refreshRuleDrafts,
  updateRuleDraft,
} from "@/lib/security-api";
import type {
  CloudflareDerivedRule,
  ManagedSecurityRule,
  RiskLevel,
  RuleConditionField,
  RuleConditionOperator,
  SecurityRuleConditionClause,
  SecurityRuleConditionDocument,
  SecurityRuleDraft,
  SecurityRuleMode,
  SecurityRuleMutation,
} from "@/lib/security-data";
import { riskOrder } from "@/lib/security-data";

type SecurityRulesConsoleProps = {
  initialRules: ManagedSecurityRule[];
  initialDrafts: SecurityRuleDraft[];
  initialCloudflareRules: CloudflareDerivedRule[];
  source: "api" | "sample";
  error?: string;
  initialFocus?: {
    ruleId?: string;
    draftId?: string;
    attackCategory?: string;
  };
};

type BusyState = null | "refresh" | "save" | "delete" | `promote:${string}` | `ignore:${string}`;
type RuleFilter = "all" | "active" | "shadow" | "disabled";
type FieldKind = "text" | "identity" | "status";
type EditableRuleConditionClause = Omit<SecurityRuleConditionClause, "value"> & {
  value: string;
  valueTo?: string;
};

const conditionFields: Array<{ value: RuleConditionField; label: string; kind: FieldKind }> = [
  { value: "path", label: "path", kind: "text" },
  { value: "query", label: "query", kind: "text" },
  { value: "userAgent", label: "userAgent", kind: "text" },
  { value: "action", label: "action", kind: "identity" },
  { value: "method", label: "method", kind: "identity" },
  { value: "statusCode", label: "statusCode", kind: "status" },
  { value: "clientIp", label: "clientIp", kind: "identity" },
  { value: "country", label: "country", kind: "identity" },
  { value: "region", label: "region", kind: "identity" },
  { value: "city", label: "city", kind: "identity" },
  { value: "asn", label: "asn", kind: "identity" },
];

const textOperators: RuleConditionOperator[] = ["contains", "equals", "in"];
const identityOperators: RuleConditionOperator[] = ["equals", "in"];
const statusOperators: RuleConditionOperator[] = ["equals", "range"];
const modeOptions: SecurityRuleMode[] = ["active", "shadow"];
const defaultRuleTypes = ["field_conditions", "path_keyword", "query_keyword", "user_agent_keyword", "cloudflare_action"];

const riskText: Record<RiskLevel, string> = {
  info: "信息",
  low: "低风险",
  medium: "关注",
  high: "高风险",
  critical: "严重",
};

const modeText: Record<SecurityRuleMode, string> = {
  active: "ACTIVE / 生效",
  shadow: "SHADOW / 影子",
};

const filterText: Record<RuleFilter, string> = {
  all: "全部规则",
  active: "active / 生效",
  shadow: "shadow / 影子",
  disabled: "disabled / 停用",
};

const draftStatusText: Record<string, string> = {
  draft: "待复核",
  promoted: "已提升",
  ignored: "已忽略",
};

function fieldMeta(field: RuleConditionField) {
  return conditionFields.find((item) => item.value === field) ?? conditionFields[0];
}

function operatorsForField(field: RuleConditionField): RuleConditionOperator[] {
  const kind = fieldMeta(field).kind;
  if (kind === "status") return statusOperators;
  if (kind === "identity") return identityOperators;
  return textOperators;
}

function normalizeMode(value: string): SecurityRuleMode {
  return value === "active" ? "active" : "shadow";
}

function normalizeRisk(value: string): RiskLevel | string {
  return riskOrder.includes(value as RiskLevel) ? (value as RiskLevel) : value || "medium";
}

function riskLabel(value: RiskLevel | string) {
  return riskText[value as RiskLevel] ?? value.toUpperCase();
}

function draftStatusLabel(status: string) {
  return draftStatusText[status] ?? status.toUpperCase();
}

function formatDate(value?: string) {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

function stringArray(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function splitValues(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function defaultFieldForRuleType(ruleType: string): RuleConditionField {
  if (ruleType === "query_keyword") return "query";
  if (ruleType === "user_agent_keyword") return "userAgent";
  if (ruleType === "cloudflare_action") return "action";
  return "path";
}

function editableConditionValue(value: SecurityRuleConditionClause["value"]) {
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
  if (value && typeof value === "object") {
    return value.min === undefined || value.min === null ? "" : String(value.min);
  }
  return String(value ?? "");
}

function editableConditionValueTo(value: SecurityRuleConditionClause["value"]) {
  if (value && !Array.isArray(value) && typeof value === "object") {
    return value.max === undefined || value.max === null ? "" : String(value.max);
  }
  return undefined;
}

function normalizeClause(value: unknown): EditableRuleConditionClause | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  const field = conditionFields.some((item) => item.value === raw.field) ? (raw.field as RuleConditionField) : null;
  if (!field) return null;
  const allowedOperators = operatorsForField(field);
  const operator = allowedOperators.includes(raw.operator as RuleConditionOperator) ? (raw.operator as RuleConditionOperator) : allowedOperators[0];
  const rawValue = raw.value as SecurityRuleConditionClause["value"];
  return {
    field,
    operator,
    value: editableConditionValue(rawValue),
    valueTo: editableConditionValueTo(rawValue),
  };
}

function conditionClauses(condition: SecurityRuleConditionDocument | Record<string, unknown>, ruleType: string): EditableRuleConditionClause[] {
  const rawConditions = Array.isArray(condition.conditions) ? condition.conditions.map(normalizeClause).filter(Boolean) : [];
  if (rawConditions.length > 0) return rawConditions as EditableRuleConditionClause[];

  const keywords = stringArray(condition.keywords);
  if (keywords.length > 0) {
    return [
      {
        field: defaultFieldForRuleType(ruleType),
        operator: keywords.length > 1 ? "in" : "contains",
        value: keywords.join(", "),
      },
    ];
  }

  const actions = stringArray(condition.actions);
  if (actions.length > 0) {
    return [
      {
        field: "action",
        operator: actions.length > 1 ? "in" : "equals",
        value: actions.join(", "),
      },
    ];
  }

  return [{ field: defaultFieldForRuleType(ruleType), operator: "contains", value: "" }];
}

function legacyCondition(clause: EditableRuleConditionClause): Record<string, string[]> {
  if ((clause.field === "path" || clause.field === "query" || clause.field === "userAgent") && clause.operator !== "range") {
    return { keywords: clause.operator === "in" ? splitValues(clause.value) : [clause.value].filter(Boolean) };
  }
  if (clause.field === "action" && clause.operator !== "range") {
    return { actions: clause.operator === "in" ? splitValues(clause.value) : [clause.value].filter(Boolean) };
  }
  return {};
}

function conditionValueForPayload(clause: EditableRuleConditionClause): SecurityRuleConditionClause["value"] {
  if (clause.operator === "in") return splitValues(clause.value);
  if (clause.operator === "range") {
    return {
      ...(clause.value.trim() ? { min: clause.value.trim() } : {}),
      ...(clause.valueTo?.trim() ? { max: clause.valueTo.trim() } : {}),
    };
  }
  return clause.value.trim();
}

function conditionDocumentFromClauses(clauses: EditableRuleConditionClause[]): SecurityRuleConditionDocument {
  const cleaned = clauses
    .map((clause) => ({
      field: clause.field,
      operator: clause.operator,
      value: conditionValueForPayload(clause),
    }))
    .filter((clause) => {
      if (Array.isArray(clause.value)) return clause.value.length > 0;
      if (typeof clause.value === "object") return clause.value.min !== undefined || clause.value.max !== undefined;
      return Boolean(String(clause.value).trim());
    });
  return {
    conditions: cleaned,
    ...(clauses.length === 1 ? legacyCondition(clauses[0]) : {}),
  };
}

function conditionSummary(rule: ManagedSecurityRule) {
  const clauses = conditionClauses(rule.condition, rule.ruleType);
  if (clauses.length === 0) return "未配置条件";
  return clauses
    .map((clause) => `${clause.field} ${clause.operator} ${clause.value}${clause.valueTo ? `..${clause.valueTo}` : ""}`)
    .join(" / ");
}

function emptyRule(): ManagedSecurityRule {
  const now = Date.now().toString(36);
  return {
    id: `local-rule-${now}`,
    name: "本地复核规则",
    enabled: false,
    ruleType: "field_conditions",
    condition: { conditions: [{ field: "path", operator: "contains", value: "" }] },
    severity: "medium",
    version: "draft",
    mode: "shadow",
    attackCategory: "manual_review",
    attackSubtype: "field_conditions",
    toolSignature: "operator_defined",
    behaviorFingerprint: "manual_condition",
  };
}

function draftToRule(draft: SecurityRuleDraft): ManagedSecurityRule {
  return {
    id: draft.ruleDraft.id.replace(/^draft-/, "rule-"),
    name: draft.ruleDraft.name,
    enabled: draft.ruleDraft.enabled,
    mode: draft.ruleDraft.mode,
    ruleType: draft.ruleDraft.ruleType,
    condition: draft.ruleDraft.condition,
    severity: draft.ruleDraft.severity,
    version: draft.ruleDraft.version,
    attackCategory: draft.ruleDraft.classification.attackCategory,
    attackSubtype: draft.ruleDraft.classification.attackSubtype,
    toolSignature: draft.ruleDraft.classification.toolSignature,
    behaviorFingerprint: draft.ruleDraft.classification.behaviorFingerprint,
  };
}

function ruleMutation(rule: ManagedSecurityRule, clauses: EditableRuleConditionClause[]): SecurityRuleMutation {
  return {
    id: rule.id.trim(),
    name: rule.name.trim(),
    enabled: rule.enabled,
    ruleType: rule.ruleType.trim(),
    condition: conditionDocumentFromClauses(clauses),
    severity: normalizeRisk(String(rule.severity)),
    version: rule.version.trim() || "draft",
    mode: normalizeMode(String(rule.mode)),
    attackCategory: rule.attackCategory.trim(),
    attackSubtype: rule.attackSubtype.trim(),
    toolSignature: rule.toolSignature.trim(),
    behaviorFingerprint: rule.behaviorFingerprint.trim(),
  };
}

function dataModeText(source: "api" | "sample", error?: string) {
  if (error && source === "api") return "接口降级";
  if (source === "api") return "实时接口";
  return "样例预览";
}

function updateListItem<T extends { id: string }>(items: T[], next: T) {
  return items.some((item) => item.id === next.id) ? items.map((item) => (item.id === next.id ? next : item)) : [next, ...items];
}

export function SecurityRulesConsole({
  initialRules,
  initialDrafts,
  initialCloudflareRules,
  source,
  error,
  initialFocus,
}: SecurityRulesConsoleProps) {
  const { cursorRef } = useRainCursor();
  const [rules, setRules] = useState(initialRules);
  const [drafts, setDrafts] = useState(initialDrafts);
  const [cloudflareRules, setCloudflareRules] = useState(initialCloudflareRules);
  const focusedRule = initialFocus?.ruleId ? initialRules.find((rule) => rule.id === initialFocus.ruleId) : undefined;
  const focusedDraft = initialFocus?.draftId ? initialDrafts.find((draft) => draft.id === initialFocus.draftId) : undefined;
  const initialRule = focusedRule ?? (focusedDraft ? draftToRule(focusedDraft) : initialRules[0]) ?? emptyRule();
  const [selectedRuleId, setSelectedRuleId] = useState(initialRule.id);
  const [draftRule, setDraftRule] = useState<ManagedSecurityRule>(initialRule);
  const [clauses, setClauses] = useState<EditableRuleConditionClause[]>(() => conditionClauses(initialRule.condition, initialRule.ruleType));
  const [filter, setFilter] = useState<RuleFilter>("all");
  const [query, setQuery] = useState(initialFocus?.attackCategory ?? "");
  const [busy, setBusy] = useState<BusyState>(null);
  const [message, setMessage] = useState(error ?? "规则控制台就绪。");

  const ruleTypeOptions = useMemo(
    () => Array.from(new Set([...defaultRuleTypes, ...rules.map((rule) => rule.ruleType), draftRule.ruleType].filter(Boolean))),
    [draftRule.ruleType, rules],
  );

  const visibleRules = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (filter === "active" && !(rule.enabled && rule.mode === "active")) return false;
      if (filter === "shadow" && rule.mode !== "shadow") return false;
      if (filter === "disabled" && rule.enabled) return false;
      if (!needle) return true;
      return [rule.id, rule.name, rule.attackCategory, rule.attackSubtype, rule.toolSignature, conditionSummary(rule)]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [filter, query, rules]);

  const activeCount = rules.filter((rule) => rule.enabled && rule.mode === "active").length;
  const shadowCount = rules.filter((rule) => rule.mode === "shadow").length;
  const disabledCount = rules.filter((rule) => !rule.enabled).length;
  const isExistingRule = rules.some((rule) => rule.id === draftRule.id);
  const canSubmit = draftRule.id.trim() && draftRule.name.trim() && clauses.some((clause) => clause.value.trim() || clause.valueTo?.trim());

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setBusy("refresh");
      const refresh = await refreshRuleDrafts();
      const nextDrafts = await getRuleDrafts();
      if (cancelled) return;
      setDrafts(nextDrafts.data);
      setMessage(nextDrafts.error ?? refresh.error ?? "草稿队列已刷新。");
      setBusy(null);
    };
    run();
    return () => {
      cancelled = true;
    };
  }, []);

  const selectRule = (rule: ManagedSecurityRule) => {
    setSelectedRuleId(rule.id);
    setDraftRule(rule);
    setClauses(conditionClauses(rule.condition, rule.ruleType));
  };

  const updateDraftRule = <K extends keyof ManagedSecurityRule>(key: K, value: ManagedSecurityRule[K]) => {
    setDraftRule((current) => ({ ...current, [key]: value }));
  };

  const updateClause = (index: number, patch: Partial<EditableRuleConditionClause>) => {
    setClauses((current) =>
      current.map((clause, clauseIndex) => {
        if (clauseIndex !== index) return clause;
        const nextField = patch.field ?? clause.field;
        const allowed = operatorsForField(nextField);
        const nextOperator = patch.operator && allowed.includes(patch.operator) ? patch.operator : allowed.includes(clause.operator) ? clause.operator : allowed[0];
        return {
          ...clause,
          ...patch,
          field: nextField,
          operator: nextOperator,
          valueTo: nextOperator === "range" ? patch.valueTo ?? clause.valueTo ?? "" : undefined,
        };
      }),
    );
  };

  const addClause = () => {
    setClauses((current) => [...current, { field: "path", operator: "contains", value: "" }]);
  };

  const removeClause = (index: number) => {
    setClauses((current) => (current.length > 1 ? current.filter((_, clauseIndex) => clauseIndex !== index) : current));
  };

  const startNewRule = () => {
    const next = emptyRule();
    setSelectedRuleId(next.id);
    setDraftRule(next);
    setClauses(conditionClauses(next.condition, next.ruleType));
  };

  const reloadAll = async () => {
    setBusy("refresh");
    const [nextRules, refresh, nextDrafts, nextCloudflare] = await Promise.all([
      getSecurityRules(),
      refreshRuleDrafts(),
      getRuleDrafts(),
      getCloudflareDerivedRules(),
    ]);
    setRules(nextRules.data);
    setDrafts(nextDrafts.data);
    setCloudflareRules(nextCloudflare.data);
    setMessage(nextRules.error ?? nextDrafts.error ?? nextCloudflare.error ?? refresh.error ?? "规则控制台已刷新。");
    setBusy(null);
  };

  const saveRule = async () => {
    if (!canSubmit || busy) return;
    const payload = ruleMutation(draftRule, clauses);
    setBusy("save");
    const result = isExistingRule ? await patchSecurityRule(draftRule.id, payload) : await createSecurityRule(payload);
    const nextRule = result.data;
    setRules((current) => updateListItem(current, nextRule));
    setDraftRule(nextRule);
    setSelectedRuleId(nextRule.id);
    setClauses(conditionClauses(nextRule.condition, nextRule.ruleType));
    setMessage(result.error ?? `${nextRule.id} 已保存。`);
    setBusy(null);
  };

  const removeRule = async () => {
    if (!isExistingRule || busy) return;
    const confirmed = window.confirm(`确认删除规则 ${draftRule.id}？`);
    if (!confirmed) return;
    setBusy("delete");
    const result = await deleteSecurityRule(draftRule.id);
    setRules((current) => current.filter((rule) => rule.id !== draftRule.id));
    const next = rules.find((rule) => rule.id !== draftRule.id) ?? emptyRule();
    setDraftRule(next);
    setSelectedRuleId(next.id);
    setClauses(conditionClauses(next.condition, next.ruleType));
    setMessage(result.error ?? `${draftRule.id} 已删除。`);
    setBusy(null);
  };

  const ignoreDraft = async (draft: SecurityRuleDraft) => {
    setBusy(`ignore:${draft.id}`);
    const result = await updateRuleDraft(draft.id, { status: "ignored" });
    setDrafts((current) => current.map((item) => (item.id === draft.id ? result.data : item)));
    setMessage(result.error ?? `${draft.id} 已忽略。`);
    setBusy(null);
  };

  const promoteDraft = async (draft: SecurityRuleDraft) => {
    setBusy(`promote:${draft.id}`);
    const result = await promoteRuleDraft(draft.id);
    const nextRule = result.data;
    setRules((current) => updateListItem(current, nextRule));
    setDrafts((current) =>
      current.map((item) =>
        item.id === draft.id
          ? {
              ...item,
              status: "promoted",
              promotedRuleId: nextRule.id,
              updatedAt: new Date().toISOString(),
            }
          : item,
      ),
    );
    selectRule(nextRule);
    setMessage(result.error ?? `${draft.id} 已提升为 ${nextRule.id}。`);
    setBusy(null);
  };

  return (
    <main className="rain-home rain-subpage rain-subpage-plain rain-events-page rain-rules-page">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-left-dot" aria-hidden="true" />
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <SecurityGlobalNav active="rules" />

      <section className="rain-content-layer rain-content-layer-mvp rain-content-layer-rain rain-events-layer rain-rules-layer" aria-label="规则管理">
        <div className="rain-content-index" aria-hidden="true">
          04
        </div>
        <div className="rain-content-header">
          <p>SECURITY / RULE CONTROL</p>
          <h1>Rules Management</h1>
          <span>本地规则编辑、影子复核、智能草稿队列与 Cloudflare 派生只读信号集中回读。</span>
        </div>

        <div className="rain-content-metrics">
          <div>
            <span>LOCAL RULES</span>
            <strong>{rules.length}</strong>
          </div>
          <div>
            <span>ACTIVE</span>
            <strong>{activeCount}</strong>
          </div>
          <div>
            <span>SHADOW / OFF</span>
            <strong>{shadowCount}/{disabledCount}</strong>
          </div>
          <div>
            <span>DRAFT / CF</span>
            <strong>{drafts.length}/{cloudflareRules.length}</strong>
          </div>
        </div>

        <div className="rain-mvp-workspace rain-mvp-workspace-rain rain-event-workspace rain-rules-workspace">
          <div className="rain-system-message rules-system-message" aria-live="polite">
            <span>{dataModeText(source, error)}</span>
            <strong>{message}</strong>
          </div>

          <div className="rain-console-grid rain-rules-console">
            <aside className="rain-console-spine rules-panel rules-local-panel" aria-label="本地规则列表">
              <div className="rain-filter-head">
                <span>LOCAL RULES</span>
                <strong>{visibleRules.length}/{rules.length}</strong>
              </div>

              <div className="rules-list-tools">
                <label className="rain-console-field">
                  <span>筛选文本</span>
                  <input value={query} placeholder="规则 ID / 分类 / 条件" onChange={(event) => setQuery(event.target.value)} />
                </label>
                <label className="rain-console-field">
                  <span>模式范围</span>
                  <select value={filter} onChange={(event) => setFilter(event.target.value as RuleFilter)}>
                    <option value="all">{filterText.all}</option>
                    <option value="active">{filterText.active}</option>
                    <option value="shadow">{filterText.shadow}</option>
                    <option value="disabled">{filterText.disabled}</option>
                  </select>
                </label>
                <div className="rain-console-pills">
                  <button type="button" onClick={startNewRule} disabled={busy !== null}>
                    新建规则
                  </button>
                  <button type="button" onClick={reloadAll} disabled={busy !== null}>
                    {busy === "refresh" ? "刷新中" : "刷新"}
                  </button>
                </div>
              </div>

              <div className="rules-rule-list">
                {visibleRules.map((rule, index) => (
                  <button
                    key={rule.id}
                    type="button"
                    className="rules-rule-row"
                    data-active={selectedRuleId === rule.id}
                    data-risk={rule.severity}
                    onClick={() => selectRule(rule)}
                    style={{ "--row-delay": `${index * 36}ms` } as CSSProperties}
                  >
                    <span>{normalizeMode(String(rule.mode)).toUpperCase()}</span>
                    <strong>{rule.name}</strong>
                    <em>{rule.enabled ? "启用" : "停用"}</em>
                    <small>{rule.id}</small>
                    <i>{conditionSummary(rule)}</i>
                  </button>
                ))}
                {visibleRules.length === 0 && <div className="rules-empty-line">当前范围没有匹配的本地规则。</div>}
              </div>
            </aside>

            <section className="rain-console-main rules-panel rules-edit-panel" aria-label="规则编辑面板">
              <div className="rain-console-topline">
                <span>{isExistingRule ? "编辑本地规则" : "创建本地规则"}</span>
                <strong>{draftRule.id}</strong>
              </div>

              <div className="rules-editor-scroll">
                <div className="rules-form-grid">
                  <label className="rain-console-field">
                    <span>规则 ID</span>
                    <input value={draftRule.id} onChange={(event) => updateDraftRule("id", event.target.value)} disabled={isExistingRule} />
                  </label>
                  <label className="rain-console-field">
                    <span>规则名称</span>
                    <input value={draftRule.name} onChange={(event) => updateDraftRule("name", event.target.value)} />
                  </label>
                  <label className="rain-console-field">
                    <span>ruleType</span>
                    <select value={draftRule.ruleType} onChange={(event) => updateDraftRule("ruleType", event.target.value)}>
                      {ruleTypeOptions.map((ruleType) => (
                        <option key={ruleType} value={ruleType}>
                          {ruleType}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="rain-console-field">
                    <span>风险等级</span>
                    <select value={String(draftRule.severity)} onChange={(event) => updateDraftRule("severity", event.target.value)}>
                      {riskOrder.map((risk) => (
                        <option key={risk} value={risk}>
                          {risk}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="rain-console-field">
                    <span>attackCategory</span>
                    <input value={draftRule.attackCategory} onChange={(event) => updateDraftRule("attackCategory", event.target.value)} />
                  </label>
                  <label className="rain-console-field">
                    <span>attackSubtype</span>
                    <input value={draftRule.attackSubtype} onChange={(event) => updateDraftRule("attackSubtype", event.target.value)} />
                  </label>
                  <label className="rain-console-field">
                    <span>toolSignature</span>
                    <input value={draftRule.toolSignature} onChange={(event) => updateDraftRule("toolSignature", event.target.value)} />
                  </label>
                  <label className="rain-console-field">
                    <span>behaviorFingerprint</span>
                    <input value={draftRule.behaviorFingerprint} onChange={(event) => updateDraftRule("behaviorFingerprint", event.target.value)} />
                  </label>
                </div>

                <div className="rules-state-line">
                  <label className="rules-switch">
                    <input type="checkbox" checked={draftRule.enabled} onChange={(event) => updateDraftRule("enabled", event.target.checked)} />
                    <span aria-hidden="true" />
                    <strong>enabled 开关</strong>
                  </label>
                  <label className="rain-console-field">
                    <span>mode 模式</span>
                    <select value={normalizeMode(String(draftRule.mode))} onChange={(event) => updateDraftRule("mode", event.target.value)}>
                      {modeOptions.map((mode) => (
                        <option key={mode} value={mode}>
                          {mode}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="rules-mode-note">
                    <span>{modeText[normalizeMode(String(draftRule.mode))]}</span>
                    <strong>{draftRule.enabled ? "enabled=true" : "enabled=false"}</strong>
                  </div>
                </div>

                <div className="rules-condition-editor">
                  <div className="analysis-section-title">
                    <span>COND</span>
                    <p>固定字段条件编辑器</p>
                  </div>
                  {clauses.map((clause, index) => (
                    <div className="rules-condition-row" key={`${clause.field}:${index}`}>
                      <label className="rain-console-field">
                        <span>字段</span>
                        <select value={clause.field} onChange={(event) => updateClause(index, { field: event.target.value as RuleConditionField })}>
                          {conditionFields.map((field) => (
                            <option key={field.value} value={field.value}>
                              {field.label}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="rain-console-field">
                        <span>操作符</span>
                        <select value={clause.operator} onChange={(event) => updateClause(index, { operator: event.target.value as RuleConditionOperator })}>
                          {operatorsForField(clause.field).map((operator) => (
                            <option key={operator} value={operator}>
                              {operator}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="rain-console-field">
                        <span>{clause.operator === "range" ? "起始值" : "取值"}</span>
                        <input value={clause.value} onChange={(event) => updateClause(index, { value: event.target.value })} />
                      </label>
                      {clause.operator === "range" ? (
                        <label className="rain-console-field">
                          <span>结束值</span>
                          <input value={clause.valueTo ?? ""} onChange={(event) => updateClause(index, { valueTo: event.target.value })} />
                        </label>
                      ) : (
                        <button type="button" className="rules-line-button" onClick={() => removeClause(index)} disabled={clauses.length === 1}>
                          移除
                        </button>
                      )}
                      {clause.operator === "range" && (
                        <button type="button" className="rules-line-button" onClick={() => removeClause(index)} disabled={clauses.length === 1}>
                          移除
                        </button>
                      )}
                    </div>
                  ))}
                  <button type="button" className="rules-add-condition" onClick={addClause}>
                    添加条件
                  </button>
                </div>

                <div className="rules-editor-actions">
                  <button type="button" onClick={saveRule} disabled={!canSubmit || busy !== null}>
                    {busy === "save" ? "保存中" : "保存规则"}
                  </button>
                  <button type="button" onClick={removeRule} disabled={!isExistingRule || busy !== null}>
                    {busy === "delete" ? "删除中" : "删除"}
                  </button>
                </div>
              </div>
            </section>

            <aside className="rain-console-detail rules-panel rules-draft-panel" aria-label="智能建议队列">
              <div className="rain-filter-head">
                <span>DRAFT QUEUE</span>
                <strong>{drafts.length}</strong>
              </div>
              <div className="rules-draft-list">
                {drafts.map((draft, index) => (
                  <div
                    className="rules-draft-row"
                    data-risk={draft.riskLevel}
                    data-status={draft.status}
                    key={draft.id}
                    style={{ "--row-delay": `${index * 48}ms` } as CSSProperties}
                  >
                    <span>{draftStatusLabel(draft.status)}</span>
                    <strong>{draft.title}</strong>
                    <em>{riskLabel(draft.riskLevel)} / {Math.round(draft.confidence * 100)}%</em>
                    <small>
                      默认：enabled=false / mode=shadow / {draft.impact.eventCount} 条事件 / {draft.impact.sourceCount} 个来源
                    </small>
                    <code>{draft.ruleDraft.ruleType} {JSON.stringify(draft.ruleDraft.condition)}</code>
                    <div className="rules-draft-actions">
                      <button type="button" onClick={() => promoteDraft(draft)} disabled={busy !== null || draft.status === "promoted"}>
                        {busy === `promote:${draft.id}` ? "提升中" : "提升为规则"}
                      </button>
                      <button type="button" onClick={() => ignoreDraft(draft)} disabled={busy !== null || draft.status === "ignored"}>
                        {busy === `ignore:${draft.id}` ? "忽略中" : "忽略"}
                      </button>
                    </div>
                  </div>
                ))}
                {drafts.length === 0 && <div className="rules-empty-line">暂无智能规则建议。</div>}
              </div>
            </aside>

            <aside className="rain-console-detail rules-panel rules-cloudflare-panel" aria-label="Cloudflare 派生只读层">
              <div className="rain-filter-head">
                <span>CLOUDFLARE LAYER</span>
                <strong>READ ONLY</strong>
              </div>
              <div className="rules-cloudflare-list">
                {cloudflareRules.map((rule, index) => (
                  <div className="rules-cloudflare-row" data-risk={rule.severity} key={rule.id} style={{ "--row-delay": `${index * 42}ms` } as CSSProperties}>
                    <span>{rule.mode.toUpperCase()}</span>
                    <strong>{rule.name}</strong>
                    <em>{rule.eventCount ?? 0} 次命中</em>
                    <small>{rule.description || conditionSummary(rule)}</small>
                    <code>{rule.id} / 最近 {formatDate(rule.lastSeen)}</code>
                  </div>
                ))}
                {cloudflareRules.length === 0 && <div className="rules-empty-line">Cloudflare 派生只读层暂无规则。</div>}
              </div>
            </aside>
          </div>
        </div>
      </section>

      <div className="rain-mobile-title">
        <p>RULES</p>
        <h1>CTRL</h1>
      </div>
    </main>
  );
}
