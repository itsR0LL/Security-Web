import { AlertTriangle, CircleAlert, Info, Shield, ShieldAlert } from "lucide-react";
import { riskLabels, type RiskLevel } from "@/lib/security-data";

const badgeStyles: Record<RiskLevel, string> = {
  info: "border-sky-300 bg-sky-50 text-sky-800",
  low: "border-emerald-300 bg-emerald-50 text-emerald-800",
  medium: "border-amber-300 bg-amber-50 text-amber-900",
  high: "border-rose-300 bg-rose-50 text-rose-800",
  critical: "border-red-400 bg-red-50 text-red-800",
};

const iconMap = {
  info: Info,
  low: Shield,
  medium: CircleAlert,
  high: ShieldAlert,
  critical: AlertTriangle,
} satisfies Record<RiskLevel, typeof Info>;

export function RiskBadge({ level, compact = false }: { level: RiskLevel; compact?: boolean }) {
  const Icon = iconMap[level];

  return (
    <span
      className={`inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-1 text-xs font-extrabold shadow-[inset_0_1px_0_rgba(255,255,255,0.5)] ${badgeStyles[level]}`}
    >
      <Icon size={compact ? 12 : 14} strokeWidth={2.5} />
      {compact ? riskLabels[level].replace("风险", "") : riskLabels[level]}
    </span>
  );
}

export function riskTextClass(level?: RiskLevel) {
  if (level === "critical") return "text-red-600";
  if (level === "high") return "text-rose-600";
  if (level === "medium") return "text-amber-600";
  if (level === "low") return "text-emerald-600";
  return "text-blue-700";
}
