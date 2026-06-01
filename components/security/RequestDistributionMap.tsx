"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import type { GlobePoint, RankedItem, RiskLevel } from "@/lib/security-data";

type RequestDistributionMapProps = {
  points: GlobePoint[];
  countries: RankedItem[];
  source: "api" | "sample";
  error?: string;
  variant?: "page" | "embedded";
};

type Coordinate = [number, number];
type PolygonCoordinates = Coordinate[][];
type MultiPolygonCoordinates = Coordinate[][][];

type CountryFeature = {
  type: "Feature";
  properties?: {
    name?: string;
    NAME?: string;
  };
  geometry: {
    type: "Polygon" | "MultiPolygon";
    coordinates: PolygonCoordinates | MultiPolygonCoordinates;
  } | null;
};

type CountryFeatureCollection = {
  type: "FeatureCollection";
  features: CountryFeature[];
};

type MapParticle = {
  id: string;
  x: number;
  y: number;
  r: number;
  opacity: number;
  color?: string;
  delay?: number;
};

const MAP_WIDTH = 1440;
const MAP_HEIGHT = 720;

const riskColors: Record<RiskLevel, string> = {
  info: "#8ee8ff",
  low: "#b2f2bb",
  medium: "#ffd166",
  high: "#ff8a3d",
  critical: "#ff526f",
};

function snap(value: number, digits = 3) {
  return Number(value.toFixed(digits));
}

function project(longitude: number, latitude: number) {
  return {
    x: snap(((longitude + 180) / 360) * MAP_WIDTH),
    y: snap(((90 - latitude) / 180) * MAP_HEIGHT),
  };
}

function seeded(seed: number) {
  const value = Math.sin(seed * 12.9898) * 43758.5453;
  return value - Math.floor(value);
}

function eachRing(feature: CountryFeature, callback: (ring: Coordinate[]) => void) {
  if (!feature.geometry) {
    return;
  }

  if (feature.geometry.type === "Polygon") {
    (feature.geometry.coordinates as PolygonCoordinates).forEach(callback);
    return;
  }

  (feature.geometry.coordinates as MultiPolygonCoordinates).forEach((polygon) => polygon.forEach(callback));
}

function collectBoundaryParticles(features: CountryFeature[]) {
  const particles: MapParticle[] = [];
  const seen = new Set<string>();

  features.forEach((feature, featureIndex) => {
    eachRing(feature, (ring) => {
      for (let index = 0; index < ring.length; index += 1) {
        const current = ring[index];
        const next = ring[(index + 1) % ring.length];
        const [currentLongitude, currentLatitude] = current;
        const [nextLongitude, nextLatitude] = next;
        const longitudeDelta = nextLongitude - currentLongitude;
        const latitudeDelta = nextLatitude - currentLatitude;
        const crossesDateLine = Math.abs(longitudeDelta) > 28;
        const samples = crossesDateLine ? 1 : Math.max(1, Math.ceil(Math.max(Math.abs(longitudeDelta), Math.abs(latitudeDelta)) / 1.15));

        for (let sample = 0; sample < samples; sample += 1) {
          const t = sample / samples;
          const longitude = currentLongitude + longitudeDelta * t;
          const latitude = currentLatitude + latitudeDelta * t;
          const point = project(longitude, latitude);
          const key = `${Math.round(point.x * 1.5)},${Math.round(point.y * 1.5)}`;

          if (!seen.has(key)) {
            const seed = featureIndex * 10000 + index * 37 + sample;
            seen.add(key);
            particles.push({
              id: key,
              x: point.x,
              y: point.y,
              r: snap(0.58 + seeded(seed) * 0.64),
              opacity: snap(0.24 + seeded(seed + 7.7) * 0.46),
            });
          }
        }
      }
    });
  });

  return particles.slice(0, 18000);
}

function createGridParticles() {
  const particles: MapParticle[] = [];
  let id = 0;

  for (let longitude = -150; longitude <= 150; longitude += 30) {
    for (let latitude = -78; latitude <= 78; latitude += 6) {
      const point = project(longitude, latitude);
      particles.push({ id: `grid-${id++}`, x: point.x, y: point.y, r: 0.42, opacity: 0.18 });
    }
  }

  for (let latitude = -60; latitude <= 60; latitude += 30) {
    for (let longitude = -174; longitude <= 174; longitude += 6) {
      const point = project(longitude, latitude);
      particles.push({ id: `grid-${id++}`, x: point.x, y: point.y, r: 0.42, opacity: 0.16 });
    }
  }

  return particles;
}

function createEventParticles(point: GlobePoint, pointIndex: number) {
  const center = project(point.longitude, point.latitude);
  const color = riskColors[point.riskLevel] ?? "#b2f2bb";
  const particleCount = Math.max(18, Math.min(96, Math.round(14 + Math.sqrt(point.count) * 5.4)));
  const spread = Math.max(10, Math.min(34, 8 + Math.sqrt(point.count) * 2.4));
  const sizeBase = Math.max(1.2, Math.min(3.8, 0.95 + Math.sqrt(point.count) / 18));
  const particles: MapParticle[] = [];

  for (let index = 0; index < particleCount; index += 1) {
    const seed = (pointIndex + 1) * 1000 + index * 19;
    const angle = seeded(seed) * Math.PI * 2;
    const distance = Math.sqrt(seeded(seed + 3.1)) * spread;
    const isCore = index < Math.max(3, Math.round(particleCount * 0.1));
    const radius = isCore ? sizeBase + seeded(seed + 9.2) * 1.4 : Math.max(0.75, sizeBase * (0.42 + seeded(seed + 12.6) * 0.5));

    particles.push({
      id: `${point.id}-${index}`,
      x: snap(center.x + Math.cos(angle) * distance),
      y: snap(center.y + Math.sin(angle) * distance),
      r: snap(radius),
      opacity: snap(isCore ? 0.9 : 0.32 + seeded(seed + 21.8) * 0.42),
      color,
      delay: (index % 18) * 80 + pointIndex * 35,
    });
  }

  return particles;
}

function formatCompact(value: number) {
  return Intl.NumberFormat("zh-CN", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

export function RequestDistributionMap({ points, countries, source, error, variant = "page" }: RequestDistributionMapProps) {
  const [features, setFeatures] = useState<CountryFeature[]>([]);

  useEffect(() => {
    let mounted = true;

    fetch("/data/ne-110m-countries.geojson")
      .then((response) => response.json() as Promise<CountryFeatureCollection>)
      .then((collection) => {
        if (mounted) {
          setFeatures(collection.features);
        }
      })
      .catch(() => {
        if (mounted) {
          setFeatures([]);
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const rankedPoints = useMemo(
    () => [...points].sort((left, right) => right.count - left.count).slice(0, 24),
    [points],
  );
  const boundaryParticles = useMemo(() => collectBoundaryParticles(features), [features]);
  const gridParticles = useMemo(() => createGridParticles(), []);
  const eventParticles = useMemo(
    () => rankedPoints.flatMap((point, index) => createEventParticles(point, index)),
    [rankedPoints],
  );
  const totalRequests = rankedPoints.reduce((sum, point) => sum + point.count, 0);
  const highRiskCount = rankedPoints.filter((point) => point.riskLevel === "high" || point.riskLevel === "critical").length;
  const status = source === "api" && !error ? "LIVE" : "SAMPLE";

  const mapContent = (
    <>
      <section className="request-map-shell" aria-label="Cloudflare style request distribution map">
        <div className="request-map-status" aria-label="Data state">
          <span>{status}</span>
          <span>{boundaryParticles.length.toLocaleString("zh-CN")} BORDER PARTICLES</span>
          <span>{formatCompact(totalRequests)} REQUESTS</span>
          <span>{highRiskCount} HIGH+</span>
        </div>

        <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} role="img" aria-label="Request distribution by geography">
          <defs>
            <radialGradient id="request-map-pulse" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(255,255,255,0.92)" />
              <stop offset="40%" stopColor="rgba(178,242,187,0.62)" />
              <stop offset="100%" stopColor="rgba(178,242,187,0)" />
            </radialGradient>
            <filter id="request-map-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect className="request-map-water" width={MAP_WIDTH} height={MAP_HEIGHT} />
          <g className="request-map-grid-particles" aria-hidden="true">
            {gridParticles.map((particle) => (
              <circle
                key={particle.id}
                cx={particle.x}
                cy={particle.y}
                r={particle.r}
                style={{ "--particle-opacity": particle.opacity } as CSSProperties}
              />
            ))}
          </g>
          <g className="request-map-boundary-particles" aria-hidden="true">
            {boundaryParticles.map((particle) => (
              <circle
                key={particle.id}
                cx={particle.x}
                cy={particle.y}
                r={particle.r}
                style={{ "--particle-opacity": particle.opacity } as CSSProperties}
              />
            ))}
          </g>
          <g className="request-map-points">
            {rankedPoints.map((point) => {
              const color = riskColors[point.riskLevel] ?? "#b2f2bb";
              const pointParticles = eventParticles.filter((particle) => particle.id.startsWith(`${point.id}-`));

              return (
                <g
                  key={point.id}
                  role="img"
                  aria-label={`${point.city || point.country} / ${point.count} / ${point.riskLevel}`}
                  style={{ "--point-color": color } as CSSProperties}
                >
                  {pointParticles.map((particle) => (
                    <circle
                      key={particle.id}
                      className="request-map-event-particle"
                      cx={particle.x}
                      cy={particle.y}
                      r={particle.r}
                      style={
                        {
                          "--point-color": particle.color,
                          "--point-delay": `${particle.delay}ms`,
                          "--particle-opacity": particle.opacity,
                        } as CSSProperties
                      }
                    />
                  ))}
                </g>
              );
            })}
          </g>
        </svg>
      </section>

      <aside className="request-map-side" aria-label="Top request regions">
        <p>TOP REGIONS</p>
        {countries.slice(0, 5).map((country, index) => (
          <div key={`${country.label}-${index}`} className="request-map-region" data-risk={country.riskLevel ?? "info"}>
            <span>{String(index + 1).padStart(2, "0")}</span>
            <strong>{country.label}</strong>
            <em>{formatCompact(country.value)}</em>
          </div>
        ))}
      </aside>
    </>
  );

  if (variant === "embedded") {
    return <div className="request-map-embed">{mapContent}</div>;
  }

  return (
    <main className="rain-map-page">
      <div className="rain-grid" aria-hidden="true" />
      <div className="rain-glow" aria-hidden="true" />
      <div className="rain-left-dot" aria-hidden="true" />

      <header className="request-map-header">
        <div>
          <p>REQUEST DISTRIBUTION</p>
          <h1>2D Traffic Map</h1>
        </div>
        <nav aria-label="Map navigation">
          <Link href="/security/situation">SITUATION</Link>
          <Link href="/security/events">EVENTS</Link>
        </nav>
      </header>

      {mapContent}
    </main>
  );
}
