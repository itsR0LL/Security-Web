"use client";

import Link from "next/link";

type SecurityNavItem = {
  key: "home" | "situation" | "events" | "analysis" | "settings";
  label: string;
  shortLabel: string;
  href: string;
};

type SecurityGlobalNavProps = {
  active: SecurityNavItem["key"];
};

const navItems: SecurityNavItem[] = [
  { key: "home", label: "首页", shortLabel: "HOME", href: "/security" },
  { key: "situation", label: "态势", shortLabel: "VISUAL", href: "/security/situation" },
  { key: "events", label: "事件", shortLabel: "EVENTS", href: "/security/events" },
  { key: "analysis", label: "分析", shortLabel: "ANALYSIS", href: "/security/analysis" },
  { key: "settings", label: "设置", shortLabel: "CONFIG", href: "/security/settings" },
];

export function SecurityGlobalNav({ active }: SecurityGlobalNavProps) {
  return (
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
  );
}
