"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";

export function RefreshButton() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const label = isPending ? "正在刷新" : "手动刷新";

  return (
    <button
      type="button"
      onClick={() => startTransition(() => router.refresh())}
      className="security-button inline-flex min-h-11 w-full min-w-[8.75rem] items-center justify-center gap-2 border border-[rgba(57,217,138,0.62)] bg-[rgba(57,217,138,0.12)] px-4 text-sm font-extrabold text-[var(--security-ink)] shadow-[inset_0_0_0_1px_rgba(57,217,138,0.08),0_0_24px_rgba(57,217,138,0.08)] hover:bg-[rgba(57,217,138,0.18)] disabled:opacity-65 md:w-auto"
      disabled={isPending}
      aria-label={isPending ? "安全态势数据正在刷新" : "手动刷新安全态势数据"}
      aria-busy={isPending}
    >
      <RefreshCw size={16} strokeWidth={2.6} className={isPending ? "animate-spin" : ""} aria-hidden="true" />
      <span aria-live="polite">{label}</span>
    </button>
  );
}
