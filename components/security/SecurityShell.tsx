import Link from "next/link";
import { Activity, ListFilter, RefreshCw, Settings, Shield, TriangleAlert } from "lucide-react";
import { RefreshButton } from "./RefreshButton";

type SecurityShellProps = {
  active: "overview" | "events" | "settings";
  source: "api" | "sample";
  error?: string;
  children: React.ReactNode;
};

const navItems = [
  {
    id: "overview",
    label: "态势总览",
    shortLabel: "态势",
    href: "/security",
    icon: Activity,
    desc: "视觉入口与实时态势",
    rail: "SIGNAL",
  },
  {
    id: "events",
    label: "事件研判",
    shortLabel: "事件",
    href: "/security/events",
    icon: ListFilter,
    desc: "筛选、定位与溯源",
    rail: "EVENTS",
  },
  {
    id: "settings",
    label: "接入设置",
    shortLabel: "设置",
    href: "/security/settings",
    icon: Settings,
    desc: "只读凭据与阈值",
    rail: "CONFIG",
  },
] as const;

export function SecurityShell({ active, source, error, children }: SecurityShellProps) {
  const sourceLabel = source === "api" ? "实时 API" : "样例数据";

  if (active === "overview") {
    return (
      <div className="security-shell security-stage min-h-screen text-[var(--security-ink)]">
        <header className="security-stage-header">
          <Link href="/security" className="group flex min-w-0 items-center gap-3 outline-none" aria-label="Security Studio 首页">
            <div className="relative flex h-11 w-11 shrink-0 items-center justify-center border border-[rgba(178,242,187,0.46)] bg-black/20 text-[var(--security-accent)]">
              <span className="security-status-light absolute -right-1 -top-1" aria-hidden="true" />
              <Shield size={21} strokeWidth={2.2} aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="security-kicker">Security Studio / r0l1dehome.asia</p>
              <h1 className="truncate text-lg font-extrabold text-white md:text-xl">个人安全态势观测</h1>
            </div>
          </Link>

          <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
            <nav className="hidden min-h-11 items-center border border-[rgba(178,242,187,0.18)] bg-black/12 px-1 md:flex" aria-label="安全态势入口导航">
              {navItems.slice(1).map((item) => (
                <Link
                  key={item.id}
                  href={item.href}
                  className="inline-flex min-h-9 items-center px-3 font-mono text-[11px] font-black text-white/46 outline-none transition hover:text-[#b2f2bb] focus-visible:ring-2 focus-visible:ring-[#b2f2bb]"
                >
                  {item.label}
                </Link>
              ))}
            </nav>
            <div className="hidden min-h-11 items-center justify-between gap-3 border border-[rgba(178,242,187,0.18)] bg-black/12 px-3 text-xs font-bold text-[var(--security-muted)] sm:flex sm:justify-start">
              <span className="inline-flex items-center gap-2 whitespace-nowrap">
                <span className="security-status-light" aria-hidden="true" />
                数据源
              </span>
              <span className="security-num text-white">{sourceLabel}</span>
            </div>
            <Link
              href="/security"
              className="inline-flex min-h-11 items-center justify-center gap-2 border border-[rgba(178,242,187,0.18)] bg-black/12 px-3 font-mono text-[11px] font-black text-white/58 outline-none transition hover:text-[#b2f2bb] focus-visible:ring-2 focus-visible:ring-[#b2f2bb]"
            >
              <RefreshCw size={14} />
              REFRESH
            </Link>
          </div>
        </header>

        <div className="security-stage-rail hidden lg:flex" aria-hidden="true">
          {navItems.map((item) => {
            const isActive = active === item.id;
            return (
              <Link
                key={item.id}
                href={item.href}
                tabIndex={-1}
                data-active={isActive ? "true" : "false"}
                aria-current={isActive ? "page" : undefined}
                className="security-rail-link"
              >
                <span>{item.rail}</span>
              </Link>
            );
          })}
        </div>

        <nav className="security-stage-mobile-nav mx-auto grid w-[calc(100%-1rem)] grid-cols-3 gap-1 border border-[rgba(178,242,187,0.2)] bg-black/20 p-1 lg:hidden" aria-label="安全态势移动导航">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = active === item.id;
            return (
              <Link
                key={item.id}
                href={item.href}
                data-active={isActive ? "true" : "false"}
                className="security-nav-link inline-flex items-center justify-center gap-1.5 px-2 text-sm font-bold"
                aria-current={isActive ? "page" : undefined}
              >
                <Icon size={16} strokeWidth={2.4} aria-hidden="true" />
                <span>{item.shortLabel}</span>
              </Link>
            );
          })}
        </nav>

        <div className="security-stage-note" aria-live="polite">
          <span>{source === "api" ? "LIVE_API" : "SAMPLE_SIGNAL"}</span>
          <span>{source === "api" ? "CLOUDFLARE_SYNCED" : "TOKEN_NOT_ATTACHED"}</span>
        </div>

        <div className="security-stage-content security-enter">{children}</div>
      </div>
    );
  }

  return (
    <div className="security-shell min-h-screen pb-10 text-[var(--security-ink)]">
      <header className="security-topbar sticky top-0 z-30">
        <div className="mx-auto flex w-[94%] max-w-7xl flex-col gap-3 py-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <div className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-[var(--security-line-strong)] bg-[var(--security-bg-elevated)] text-[var(--security-accent)] shadow-[inset_0_0_0_1px_rgba(57,217,138,0.08)]">
              <span className="security-status-light absolute -right-1 -top-1" aria-hidden="true" />
              <Shield size={21} strokeWidth={2.4} aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="security-kicker">Security Studio / r0l1dehome.asia</p>
              <h1 className="truncate text-lg font-extrabold text-[var(--security-ink)] md:text-xl">安全态势控制台</h1>
            </div>
          </div>

          <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-center md:justify-end">
            <div className="flex min-h-11 items-center justify-between gap-3 rounded-md border border-[var(--security-line)] bg-[rgba(8,17,15,0.82)] px-3 text-xs font-bold text-[var(--security-muted)] md:justify-start">
              <span className="inline-flex items-center gap-2 whitespace-nowrap">
                <span className="security-status-light" aria-hidden="true" />
                数据源
              </span>
              <span className="security-num text-[var(--security-ink)]">{sourceLabel}</span>
            </div>
            <nav className="grid grid-cols-3 gap-1 rounded-md border border-[var(--security-line)] bg-[rgba(5,10,9,0.84)] p-1 lg:hidden" aria-label="安全控制台主导航">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = active === item.id;
                return (
                  <Link
                    key={item.id}
                    href={item.href}
                    data-active={isActive ? "true" : "false"}
                    className="security-nav-link inline-flex items-center justify-center gap-1.5 px-2 text-sm font-bold"
                    aria-current={isActive ? "page" : undefined}
                  >
                    <Icon size={16} strokeWidth={2.4} aria-hidden="true" />
                    <span>{item.shortLabel}</span>
                  </Link>
                );
              })}
            </nav>
            <RefreshButton />
          </div>
        </div>
        {source === "sample" && (
          <div className="border-t border-[rgba(241,177,59,0.42)] bg-[rgba(39,26,8,0.9)]">
            <div className="mx-auto flex w-[94%] max-w-7xl items-start gap-2 py-2 text-xs font-semibold leading-5 text-[#ffd98a]">
              <TriangleAlert className="mt-0.5 shrink-0" size={15} strokeWidth={2.5} aria-hidden="true" />
              <span>{error || "当前为样例数据。配置后端地址、Cloudflare Zone ID 与只读 API Token 后，将切换为真实安全态势数据。"}</span>
            </div>
          </div>
        )}
      </header>

      <div className="mx-auto flex w-full max-w-[96rem] gap-0 lg:gap-6">
        <aside className="security-sidebar sticky top-[73px] hidden h-[calc(100vh-73px)] w-72 shrink-0 px-4 py-5 lg:block">
          <div className="mb-5 border-b border-[var(--security-line)] pb-4">
            <p className="security-kicker">Operations</p>
            <p className="mt-2 text-sm font-semibold leading-6 text-[var(--security-muted)]">
              这里保留研判与配置效率；首页只做个人化安全态势入口。
            </p>
          </div>
          <nav className="space-y-2" aria-label="安全控制台侧栏导航">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = active === item.id;
              return (
                <Link
                  key={item.id}
                  href={item.href}
                  data-active={isActive ? "true" : "false"}
                  className="security-nav-link flex items-center gap-3 px-3 py-2.5"
                  aria-current={isActive ? "page" : undefined}
                >
                  <Icon className="shrink-0" size={18} strokeWidth={2.4} aria-hidden="true" />
                  <span className="min-w-0">
                    <span className="block text-sm font-extrabold">{item.label}</span>
                    <span className="block truncate text-xs font-semibold text-[var(--security-soft)]">{item.desc}</span>
                  </span>
                </Link>
              );
            })}
          </nav>
        </aside>

        <div className="security-shell-content security-enter min-w-0 flex-1 pb-8 lg:pr-5">{children}</div>
      </div>
    </div>
  );
}
