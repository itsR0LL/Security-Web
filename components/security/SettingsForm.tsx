"use client";

import { useMemo, useState } from "react";
import {
  CheckCircle2,
  Clock,
  Database,
  Gauge,
  KeyRound,
  Loader2,
  Save,
  ServerCog,
  ShieldCheck,
  SlidersHorizontal,
  TestTube2,
  TriangleAlert,
} from "lucide-react";
import type { RiskLevel, SecuritySettings } from "@/lib/security-data";
import { riskLabels, riskOrder } from "@/lib/security-data";

export function SettingsForm({ settings }: { settings: SecuritySettings }) {
  const [zoneId, setZoneId] = useState(settings.zoneId);
  const [token, setToken] = useState("");
  const [refreshHours, setRefreshHours] = useState(settings.refreshIntervalHours);
  const [threshold, setThreshold] = useState<RiskLevel>(settings.highRiskThreshold);
  const [retentionDays, setRetentionDays] = useState(settings.rawRetentionDays);
  const [checking, setChecking] = useState(false);
  const [lastCheckMessage, setLastCheckMessage] = useState<string | null>(settings.lastTokenCheckAt);

  const sampleMode = useMemo(() => !settings.hasCloudflareToken && !token, [settings.hasCloudflareToken, token]);

  const runPermissionCheck = () => {
    setChecking(true);
    window.setTimeout(() => {
      setChecking(false);
      if (!zoneId || !token) {
        setLastCheckMessage("Zone ID 或 Token 为空，当前保持样例数据模式。配置完成后再执行权限检测。");
        return;
      }
      setLastCheckMessage("已记录一次前端检测动作；真实权限检测仍由后端 /api/token/check 或等价服务完成。");
    }, 650);
  };

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[240px_minmax(0,1fr)_330px]">
      <ControlSpine
        sampleMode={sampleMode}
        refreshHours={refreshHours}
        threshold={threshold}
        retentionDays={retentionDays}
        monitoredHost={settings.monitoredHost}
      />

      <section className="min-w-0 space-y-4">
        <ConsoleSection
          icon={<KeyRound size={16} />}
          kicker="Cloudflare 接入"
          title="只读 Token 与 Zone 绑定"
          description="用于同步安全事件和分析数据。Token 不写入前端源码，页面只保留输入状态和后端保存入口。"
          status={
            <span className={`inline-flex min-h-11 items-center rounded-md border px-3 text-xs font-bold ${sampleMode ? "border-amber-300 bg-amber-50 text-amber-900" : "border-emerald-300 bg-emerald-50 text-emerald-900"}`}>
              {sampleMode ? "样例数据模式" : "已配置 Token"}
            </span>
          }
        >
          <div className="grid grid-cols-1 gap-px border border-[var(--security-line)] bg-[var(--security-line)] md:grid-cols-2">
            <TextField
              label="监控域名"
              helper="当前后台监控的公开站点。"
              value={settings.monitoredHost}
              readOnly
            />
            <TextField
              label="Cloudflare Zone ID"
              helper="从 Cloudflare 域名概览页复制。"
              value={zoneId}
              placeholder="填写 Zone ID"
              onChange={setZoneId}
            />
            <TextField
              className="md:col-span-2"
              label="Cloudflare API Token"
              helper="建议只授予 Zone Read、Analytics Read、Security Events Read 等最小只读权限。"
              value={token}
              placeholder={settings.hasCloudflareToken ? "已配置，重新输入可替换" : "未配置时自动启用样例数据"}
              type="password"
              onChange={setToken}
              monospace
            />
          </div>

          <div className="mt-5 flex flex-col gap-3 sm:flex-row">
            <button
              type="button"
              onClick={runPermissionCheck}
              disabled={checking}
              className="security-button inline-flex items-center justify-center gap-2 bg-[#111816] px-4 text-sm font-bold text-white transition hover:bg-[#1d2a25] disabled:opacity-60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--security-accent)]"
            >
              {checking ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
              检测权限
            </button>
            <button
              type="button"
              className="security-button inline-flex items-center justify-center gap-2 border border-[var(--security-line)] bg-white px-4 text-sm font-bold text-[var(--security-muted)] transition hover:bg-[var(--security-surface-subtle)] hover:text-[var(--security-ink)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--security-accent)]"
            >
              <Save size={16} />
              保存配置占位
            </button>
          </div>

          {lastCheckMessage && (
            <div className="mt-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-semibold leading-6 text-amber-950" aria-live="polite">
              {lastCheckMessage}
            </div>
          )}
        </ConsoleSection>

        <ConsoleSection
          icon={<Clock size={16} />}
          kicker="同步与风险策略"
          title="采集窗口和本地保留"
          description="这些参数影响后台同步频率、本地原始事件保留和告警阈值，不改变 Cloudflare 侧规则。"
        >
          <div className="grid grid-cols-1 gap-px border border-[var(--security-line)] bg-[var(--security-line)] md:grid-cols-3">
            <TextField
              label="刷新周期（小时）"
              helper="Free 计划建议避免过高频率轮询。"
              value={String(refreshHours)}
              type="number"
              min={1}
              max={24}
              onChange={(value) => setRefreshHours(Number(value))}
            />
            <SelectField
              label="高风险提醒阈值"
              helper="达到该等级及以上时进入告警文本。"
              value={threshold}
              options={riskOrder.map((level) => [level, riskLabels[level]] as const)}
              onChange={(value) => setThreshold(value as RiskLevel)}
            />
            <TextField
              label="原始事件保留（天）"
              helper="本地 SQLite 原始记录保留周期。"
              value={String(retentionDays)}
              type="number"
              min={7}
              max={365}
              onChange={(value) => setRetentionDays(Number(value))}
            />
          </div>

          <div className="mt-5 grid grid-cols-1 gap-px border border-[var(--security-line)] bg-[var(--security-line)] md:grid-cols-3">
            <StatusTile icon={<Gauge size={16} />} label="同步周期" value={`${refreshHours} 小时`} detail="后端任务读取该设置" />
            <StatusTile icon={<Database size={16} />} label="原始保留" value={`${retentionDays} 天`} detail={`聚合统计${settings.aggregateRetention}`} />
            <StatusTile icon={<TriangleAlert size={16} />} label="告警阈值" value={riskLabels[threshold]} detail="含更高等级事件" />
          </div>

          <div className="mt-5 border border-sky-200 bg-sky-50 p-4 text-sm font-medium leading-6 text-sky-950">
            Cloudflare Free 的分析和安全事件接口可能存在采样、延迟或较短查询窗口。系统会保留本地已同步数据；当新窗口拿不到完整字段时，应展示“字段未返回”，而不是当作没有风险。
          </div>
        </ConsoleSection>

        <ConsoleSection
          icon={<TriangleAlert size={16} />}
          kicker="告警模板"
          title="高风险待发送文本"
          description="保留现有占位功能，便于后续接入通知渠道。"
        >
          <pre className="max-w-full whitespace-pre-wrap break-words border border-[#263b35] bg-[#111816] p-4 text-sm font-semibold leading-6 text-stone-100">
{`【Security Studio】检测到 ${riskLabels[threshold]} 及以上事件
站点：${settings.monitoredHost}
阈值：${threshold}
处理：请进入 /security/events 查看来源 IP、路径、Cloudflare action 和规则命中。`}
          </pre>
        </ConsoleSection>
      </section>

      <aside className="space-y-4">
        <ConsoleSection
          icon={<ShieldCheck size={16} />}
          kicker="权限检测结果"
          title="Token Readiness"
          description="按最小权限原则检查只读同步需要的能力。"
        >
          <div className="space-y-2">
            {settings.permissions.map((permission) => (
              <div key={permission.name} className="security-row p-3">
                <div className="flex items-center gap-2">
                  {permission.ok ? <CheckCircle2 size={16} className="text-emerald-700" /> : <TriangleAlert size={16} className="text-amber-700" />}
                  <p className="text-sm font-extrabold text-[var(--security-ink)]">{permission.name}</p>
                </div>
                <p className="mt-1 text-xs font-medium leading-5 text-[var(--security-muted)]">{permission.detail}</p>
              </div>
            ))}
          </div>
        </ConsoleSection>

        <ConsoleSection
          icon={<ServerCog size={16} />}
          kicker="运行边界"
          title="一期只读控制台"
          description="明确哪些行为不会被这个页面触发。"
        >
          <div className="space-y-3 text-sm font-medium leading-6 text-[var(--security-muted)]">
            <p>不主动修改 Cloudflare WAF、防火墙或访问规则。</p>
            <p>无 Token 时展示样例数据；Token 无效或权限不足时展示配置错误，不伪装成样例数据。</p>
            <p>同步失败时保留上一次成功数据，并提示数据可能过期。</p>
          </div>
        </ConsoleSection>

        <ConsoleSection
          icon={<TestTube2 size={16} />}
          kicker="样例数据"
          title={sampleMode ? "当前启用" : "可作为降级模式"}
          description="样例数据用于本地演示和前端开发，真实运行时以 Cloudflare 同步结果为准。"
        >
          <div className="rounded-md border border-[var(--security-line)] bg-[var(--security-surface-subtle)] p-3 text-sm font-semibold leading-6 text-[var(--security-muted)]">
            目标域名：{settings.monitoredHost}
            <br />
            当前模式：{sampleMode ? "样例数据" : "真实 Token 已配置"}
          </div>
        </ConsoleSection>
      </aside>
    </div>
  );
}

function ControlSpine({
  sampleMode,
  refreshHours,
  threshold,
  retentionDays,
  monitoredHost,
}: {
  sampleMode: boolean;
  refreshHours: number;
  threshold: RiskLevel;
  retentionDays: number;
  monitoredHost: string;
}) {
  return (
    <aside className="relative overflow-hidden border border-[#1d2a25] bg-[#07100e] p-4 text-white 2xl:sticky 2xl:top-28 2xl:h-fit">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(20,255,211,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(20,255,211,0.05)_1px,transparent_1px)] bg-[size:18px_18px] opacity-45" />
      <div className="relative">
        <p className="security-kicker flex items-center gap-2 text-emerald-300">
          <SlidersHorizontal size={15} />
          Control Spine
        </p>
        <h2 className="mt-1 text-lg font-extrabold text-white">运维参数骨架</h2>
        <p className="mt-2 text-xs font-medium leading-5 text-emerald-50/62">
          用线框表达控制域，表单仍保持可读和可操作。
        </p>

        <div className="relative mt-5 pl-5">
          <div className="absolute bottom-3 left-1.5 top-3 w-px bg-emerald-300/30" />
          <SpineNode label="HOST" value={monitoredHost} />
          <SpineNode label="MODE" value={sampleMode ? "sample" : "token"} />
          <SpineNode label="SYNC" value={`${refreshHours}h`} />
          <SpineNode label="RISK" value={riskLabels[threshold]} />
          <SpineNode label="RAW" value={`${retentionDays}d`} />
        </div>

        <div className="mt-5 border border-emerald-300/18 p-3">
          <p className="text-xs font-extrabold text-emerald-50/82">WINDOW POLICY</p>
          <p className="mt-2 text-xs font-medium leading-5 text-emerald-50/62">
            Free 计划可能返回采样窗口。这里保留提示，不把缺失字段解释成安全。
          </p>
        </div>
      </div>
    </aside>
  );
}

function SpineNode({ label, value }: { label: string; value: string }) {
  return (
    <div className="relative border-b border-emerald-300/15 py-3">
      <span className="absolute -left-[1.18rem] top-4 h-2.5 w-2.5 rounded-full border border-emerald-300 bg-[#07100e] shadow-[0_0_14px_rgba(20,255,211,0.55)]" />
      <p className="text-[10px] font-extrabold text-emerald-50/45">{label}</p>
      <p className="security-num mt-1 break-words text-sm font-extrabold text-white">{value}</p>
    </div>
  );
}

function ConsoleSection({
  icon,
  kicker,
  title,
  description,
  status,
  children,
}: {
  icon: React.ReactNode;
  kicker: string;
  title: string;
  description: string;
  status?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="overflow-hidden border border-[var(--security-line)] bg-white">
      <div className="border-b border-[var(--security-line)] bg-[var(--security-surface-subtle)] p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <p className="security-kicker flex items-center gap-2">
              {icon}
              {kicker}
            </p>
            <h2 className="mt-1 text-lg font-extrabold text-[var(--security-ink)]">{title}</h2>
            <p className="mt-2 text-sm font-medium leading-6 text-[var(--security-muted)]">{description}</p>
          </div>
          {status}
        </div>
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function TextField({
  label,
  helper,
  value,
  placeholder,
  type = "text",
  min,
  max,
  readOnly = false,
  monospace = false,
  className = "",
  onChange,
}: {
  label: string;
  helper: string;
  value: string;
  placeholder?: string;
  type?: "text" | "password" | "number";
  min?: number;
  max?: number;
  readOnly?: boolean;
  monospace?: boolean;
  className?: string;
  onChange?: (value: string) => void;
}) {
  return (
    <label className={`block bg-white p-3 ${className}`}>
      <span className="mb-1.5 block text-xs font-bold text-[var(--security-muted)]">{label}</span>
      <input
        className={`security-input text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--security-accent)] ${monospace ? "font-mono" : ""} ${readOnly ? "bg-[var(--security-surface-subtle)] text-[var(--security-muted)]" : ""}`}
        value={value}
        placeholder={placeholder}
        type={type}
        min={min}
        max={max}
        readOnly={readOnly}
        onChange={(event) => onChange?.(event.target.value)}
      />
      <span className="mt-1.5 block text-xs font-medium leading-5 text-[var(--security-soft)]">{helper}</span>
    </label>
  );
}

function SelectField({
  label,
  helper,
  value,
  options,
  onChange,
}: {
  label: string;
  helper: string;
  value: string;
  options: readonly (readonly [string, string])[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="block bg-white p-3">
      <span className="mb-1.5 block text-xs font-bold text-[var(--security-muted)]">{label}</span>
      <select
        className="security-input text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--security-accent)]"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map(([optionValue, labelText]) => (
          <option key={optionValue} value={optionValue}>{labelText}</option>
        ))}
      </select>
      <span className="mt-1.5 block text-xs font-medium leading-5 text-[var(--security-soft)]">{helper}</span>
    </label>
  );
}

function StatusTile({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="bg-white p-3">
      <p className="flex items-center gap-2 text-xs font-bold text-[var(--security-soft)]">
        {icon}
        {label}
      </p>
      <p className="security-num mt-1 break-words text-lg font-extrabold text-[var(--security-ink)]">{value}</p>
      <p className="mt-1 text-xs font-medium leading-5 text-[var(--security-muted)]">{detail}</p>
    </div>
  );
}
