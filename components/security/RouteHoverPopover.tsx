"use client";

import type { CSSProperties } from "react";
import type { GlobeRouteHover } from "@/components/security/ParticleGlobe";
import { resolveTrafficKind } from "@/lib/security-data";
import { formatCountryDisplayName } from "@/lib/security-locale";

type RouteHoverLayout = "home" | "situation";

type RouteHoverPopoverProps = {
  hover: GlobeRouteHover | null;
  layout?: RouteHoverLayout;
};

const POPOVER_WIDTH = 264;
const POPOVER_HEIGHT = 188;
const EDGE_GUTTER = 18;

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

function localizedCountryName(value?: string) {
  return formatCountryDisplayName(value) || "N/A";
}

function localizedPlaceName(country?: string, locality?: string) {
  const displayLocality = locality?.trim();
  if (!country?.trim()) return displayLocality || "";
  const displayCountry = localizedCountryName(country);
  if (!displayLocality) return displayCountry;
  return `${displayCountry} / ${displayLocality}`;
}

function clampCss(min: number, preferred: number, max: number) {
  return clamp(preferred, min, Math.max(min, max));
}

function homeRailStart(width: number, height: number) {
  if (width <= 900) {
    return width;
  }

  if (width <= 1180) {
    return clamp(width * 0.67, 720, 860);
  }

  if (width >= 2200 && height >= 1180) {
    return width * 0.65;
  }

  return Math.max(980, width * 0.65);
}

function situationPanelStart(width: number) {
  if (width <= 1180) {
    return width;
  }

  const rightInset = clamp(width * 0.05, 34, 92);
  const panelWidth = Math.max(258, Math.min(310, width * 0.18));
  return width - rightInset - panelWidth - 18;
}

function routePopoverStyle(hover: GlobeRouteHover, layout: RouteHoverLayout) {
  if (typeof window === "undefined") {
    return {
      left: hover.x + 22,
      top: hover.y - 88,
      placement: "right" as const,
    };
  }

  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const avoidRight =
    layout === "home" ? homeRailStart(viewportWidth, viewportHeight) : situationPanelStart(viewportWidth);
  const absoluteMaxLeft = viewportWidth - POPOVER_WIDTH - EDGE_GUTTER;
  const safeMaxLeft = Math.min(absoluteMaxLeft, avoidRight - POPOVER_WIDTH - 24);
  const preferredRight = hover.x + 22;
  const preferredLeft = hover.x - POPOVER_WIDTH - 26;
  const shouldFlip = preferredRight > safeMaxLeft;
  const left = clampCss(EDGE_GUTTER, shouldFlip ? preferredLeft : preferredRight, safeMaxLeft);
  const top = clampCss(26, hover.y - 88, viewportHeight - POPOVER_HEIGHT - 26);

  return {
    left,
    top,
    placement: shouldFlip ? ("left" as const) : ("right" as const),
  };
}

export function RouteHoverPopover({ hover, layout = "home" }: RouteHoverPopoverProps) {
  if (!hover) {
    return null;
  }

  const { left, top, placement } = routePopoverStyle(hover, layout);
  const hoverThroughput = hover.point.throughputMb
    ? `${hover.point.throughputMb.toFixed(1)} MB`
    : `${Math.max(1, Math.round(hover.point.count * 0.42))} MB`;
  const hoverRouteLabel = `${localizedPlaceName(hover.point.country, hover.point.city) || hover.point.clientIp} -> 成都`;
  const trafficKind = resolveTrafficKind(hover.point);
  const isVisit = trafficKind === "visit";

  return (
    <div
      className="rain-route-popover"
      data-risk={hover.point.riskLevel}
      data-placement={placement}
      data-layout={layout}
      style={{ left: `${left}px`, top: `${top}px` } as CSSProperties}
    >
      <div className="rain-route-popover-inner">
        <span className="rain-route-kicker">
          {isVisit ? "访问轨迹" : hover.kind === "flight" ? "飞线路径" : "来源定位"}
        </span>
        <strong>{hoverRouteLabel}</strong>
        <div className="rain-route-meta">
          <span>类型</span>
          <b>{isVisit ? "访问" : "攻击"}</b>
          <span>动作</span>
          <b>{hover.point.action?.toUpperCase() ?? (isVisit ? "ALLOW" : "LOG")}</b>
          <span>{isVisit ? "次数" : "请求"}</span>
          <b>{isVisit ? hover.point.count : `${hover.point.method ?? "GET"} / ${hover.point.statusCode ?? "-"}`}</b>
          <span>吞吐</span>
          <b>{hoverThroughput}</b>
        </div>
        <p>{isVisit ? `${localizedCountryName(hover.point.country)} 请求分布` : hover.point.path ?? hover.point.eventType}</p>
      </div>
    </div>
  );
}
