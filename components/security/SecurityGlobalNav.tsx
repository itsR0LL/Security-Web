"use client";

import Link from "next/link";

type SecurityNavItem = {
  key: "home" | "situation" | "events" | "analysis";
  label: string;
  shortLabel: string;
  href: string;
};

type SecurityGlobalNavProps = {
  active: SecurityNavItem["key"];
};

const navItems: SecurityNavItem[] = [
  { key: "home", label: "安全首页", shortLabel: "首页", href: "/security" },
  { key: "situation", label: "态势总览", shortLabel: "态势", href: "/security/situation" },
  { key: "events", label: "安全事件", shortLabel: "事件", href: "/security/events" },
  { key: "analysis", label: "智能分析", shortLabel: "分析", href: "/security/analysis" },
];

export function SecurityGlobalNav({ active }: SecurityGlobalNavProps) {
  return (
    <>
      <nav className="security-global-nav" aria-label="安全平台页面路径">
        {navItems.map((item) => (
          <Link
            key={item.key}
            href={item.href}
            data-active={active === item.key}
            aria-current={active === item.key ? "page" : undefined}
          >
            <span>{item.shortLabel}</span>
            <strong>{item.label}</strong>
          </Link>
        ))}
      </nav>
      <Link href="/security/settings" className="security-settings-terminal" aria-label="打开安全设置">
        <span className="security-settings-terminal-lock" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
        </span>
        <span className="security-settings-terminal-scan" aria-hidden="true" />
        <span className="security-settings-terminal-kicker">SYS</span>
        <strong>Settings</strong>
        <span className="security-settings-terminal-meta">CONFIG / READY</span>
      </Link>
    </>
  );
}
