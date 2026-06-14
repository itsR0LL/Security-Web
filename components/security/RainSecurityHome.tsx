"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { ParticleGlobe } from "@/components/security/ParticleGlobe";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { RouteHoverPopover } from "@/components/security/RouteHoverPopover";
import { useRainCursor } from "@/components/security/useRainCursor";
import type { SecurityOverview, SyncStatusValue } from "@/lib/security-data";

type RainSecurityHomeProps = {
  overview: SecurityOverview;
  source: "api" | "sample";
  error?: string;
};

const syncStatusLabel: Record<SyncStatusValue, string> = {
  success: "接口回放",
  failed: "降级",
  partial: "部分同步",
  sample: "样例仿真",
  degraded: "降级",
  stale: "保留数据",
};

const railNavItems = [
  {
    href: "/security/situation",
    label: "VISUAL",
    cn: "态势",
    effect: "trace",
    code: "TRACE-021",
    desc: "3D / 2D 安全态势",
    meta: "globe attack flow",
    hud: ["GLOBE READY", "ATTACK FLOW", "SOURCE POINT", "TARGET CHENGDU", "2D MAP", "OPEN VISUAL"],
  },
  {
    href: "/security/events",
    label: "EVENTS",
    cn: "事件",
    effect: "scan",
    code: "EVENT-064",
    desc: "检索、检查并复制告警文本",
    meta: "latest event stream",
    hud: ["FILTER READY", "TIME RANGE", "RISK LEVEL", "EVENT DETAIL", "RAW JSON", "MESSAGE TEXT"],
  },
  {
    href: "/security/analysis",
    label: "ANALYSIS",
    cn: "分析",
    effect: "radar",
    code: "ANALYZE-031",
    desc: "攻击聚合、来源习惯与规则建议",
    meta: "attack intelligence layer",
    hud: ["CLUSTER", "SOURCE HABIT", "RULE TREND", "EVIDENCE", "DRAFT RULE", "OPEN ANALYSIS"],
  },
  {
    label: "PASS",
    cn: "预留",
    effect: "tower",
    code: "PASS-04",
    desc: "后续功能预留",
    meta: "reserved extension slot",
    hud: ["RESERVED", "NO ROUTE", "WAITING", "FUTURE MODULE", "KEEP SLOT", "PASS"],
  },
  {
    label: "PASS",
    cn: "预留",
    effect: "ecg",
    code: "PASS-05",
    desc: "后续功能预留",
    meta: "reserved extension slot",
    hud: ["RESERVED", "NO ROUTE", "WAITING", "FUTURE MODULE", "KEEP SLOT", "PASS"],
  },
  {
    label: "PASS",
    cn: "预留",
    effect: "focus",
    code: "PASS-06",
    desc: "后续功能预留",
    meta: "reserved extension slot",
    hud: ["RESERVED", "NO ROUTE", "WAITING", "FUTURE MODULE", "KEEP SLOT", "PASS"],
  },
];

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "等待同步";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

export function RainSecurityHome({ overview, source, error }: RainSecurityHomeProps) {
  const { cursorRef } = useRainCursor();
  const [routeHover, setRouteHover] = useState<GlobeRouteHover | null>(null);
  const latestTraffic = overview.trafficTrend.at(-1);
  const highEvents = overview.recentEvents.filter((event) => event.riskLevel === "high" || event.riskLevel === "critical");
  const modeLabel = error ? "降级展示" : source === "api" ? syncStatusLabel[overview.sync.status] : "样例仿真";
  const totalBandwidth = useMemo(
    () => overview.trafficTrend.reduce((total, point) => total + point.bandwidthMb, 0),
    [overview.trafficTrend],
  );
  const blockedOrChallenged = overview.recentEvents.filter((event) =>
    ["block", "challenge", "managed_challenge"].includes(event.action),
  ).length;
  const sourceLocations = useMemo(
    () => new Set(overview.globePoints.map((point) => `${point.country}:${point.city || point.clientIp}`)).size,
    [overview.globePoints],
  );

  return (
    <main className="rain-home rain-home-clean">
      <div ref={cursorRef} className="rain-cursor" aria-hidden="true">
        <span className="rain-cursor-x" />
        <span className="rain-cursor-y" />
        <span className="rain-cursor-dot" />
      </div>

      <div className="rain-left-dot" aria-hidden="true" />
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />

      <div className="rain-home-corner rain-home-corner-left">
        <span>SECURITY STUDIO</span>
        <strong>{overview.monitoredHost}</strong>
      </div>
      <div className="rain-home-corner rain-home-corner-right">
        <span>生成时间 {formatTime(overview.generatedAt)}</span>
        <strong>{modeLabel}</strong>
      </div>

      <nav className="rain-right-panel rain-home-rail-nav" aria-label="安全平台首页导航">
        {railNavItems.map((item, index) => {
          const columnContent = (
            <>
            <span className="rain-vertical-word" aria-hidden="true">
              {item.label.split("").map((letter, letterIndex) => (
                <span
                  key={`${letter}-${letterIndex}`}
                  data-letter={letter}
                  style={{ "--char-delay": `${letterIndex * 46}ms` } as CSSProperties}
                >
                  {letter}
                </span>
              ))}
            </span>
            <span className="rain-column-hud" aria-hidden="true">
              <span className="rain-column-corner rain-column-corner-tl" />
              <span className="rain-column-corner rain-column-corner-br" />
              <span className="rain-column-label">
                <i />
                {item.cn}
              </span>
              <span className="rain-column-scan" />
              <span className="rain-ecg-line" />
              <span className="rain-ripple rain-ripple-1" />
              <span className="rain-ripple rain-ripple-2" />
              <span className="rain-ripple rain-ripple-3" />
              <span className="rain-data-hud">
                <i />
                {item.code}
              </span>
              <span className="rain-task-container">
                {item.hud.map((line, lineIndex) => (
                  <span
                    key={`${item.href}:hud:${lineIndex}`}
                    className="rain-task-item"
                    style={{ "--task-delay": `${lineIndex * 160}ms` } as CSSProperties}
                  >
                    <i />
                    <span>{line}</span>
                  </span>
                ))}
              </span>
            </span>
            </>
          );

          if (item.href) {
            return (
              <Link
                key={`${item.label}:home-rail:${index}`}
                href={item.href}
                className={`rain-column rain-column-${index}`}
                data-effect={item.effect}
                aria-label={`${item.cn}: ${item.desc}`}
              >
                {columnContent}
              </Link>
            );
          }

          return (
            <button
              key={`${item.label}:home-rail:${index}`}
              type="button"
              className={`rain-column rain-column-${index}`}
              data-effect={item.effect}
              data-reserved="true"
              aria-disabled="true"
              aria-label={`${item.cn}: ${item.desc}`}
            >
              {columnContent}
            </button>
          );
        })}
      </nav>

      <section className="rain-left-panel rain-sim-panel" aria-label="安全态势主视觉">
        <div className="rain-home-frame" aria-hidden="true">
          <div className="rain-home-frame-top">
            <span>成都目标点</span>
            <span>{overview.globePoints.length} 条来源航线</span>
          </div>
          <div className="rain-home-frame-left">
            <p>展示口径</p>
            <strong>{modeLabel}</strong>
            <span>{overview.monitoredHost}</span>
            <p>仿真覆盖</p>
            <strong>全部</strong>
            <span>访问 / 攻击 / 异常</span>
            <p>来源窗口</p>
            <strong>24H</strong>
            <span>{formatTime(overview.sync.lastSyncAt)} 来源刷新</span>
          </div>
          <div className="rain-home-frame-right">
            <p>请求量</p>
            <strong>{latestTraffic?.requests.toLocaleString("zh-CN") ?? "0"}</strong>
            <span>{latestTraffic?.cachedPercent ?? 0}% 缓存命中</span>
            <p>吞吐量</p>
            <strong>{latestTraffic?.bandwidthMb ?? 0}MB</strong>
            <span>{totalBandwidth.toLocaleString("zh-CN")}MB 展示窗口</span>
            <p>处置 / 航线</p>
            <strong>{blockedOrChallenged}/{sourceLocations}</strong>
            <span>{highEvents.length} 条高风险</span>
          </div>
          <div className="rain-home-flow-strip">
            <span>流量吞吐</span>
            <strong>{latestTraffic?.bandwidthMb ?? 0}MB</strong>
            <span>源站 {latestTraffic?.originMb ?? 0}MB</span>
          </div>
          <div className="rain-home-frame-bottom">
            <div className="rain-home-env">
              <span>展示口径 / {modeLabel}</span>
              <span>来源刷新 / {formatTime(overview.sync.lastSyncAt)} / 每 {overview.sync.refreshIntervalHours} 小时滚动</span>
            </div>
          </div>
        </div>

        <div className="rain-globe-reserve">
          <ParticleGlobe points={overview.globePoints} onRouteHover={setRouteHover} />
        </div>
        <RouteHoverPopover hover={routeHover} layout="home" />
      </section>

      <div className="rain-mobile-title">
        <p>安全态势</p>
        <h1>R0L1DEHOME</h1>
      </div>
    </main>
  );
}
