"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";
import { resolveTrafficKind, type GlobePoint, type RiskLevel, type TrafficKind } from "@/lib/security-data";

type ProjectionMode = "globe" | "map";

export type GlobeRouteHover = {
  point: GlobePoint;
  x: number;
  y: number;
  kind: "flight" | "source";
};

type ParticleGlobeProps = {
  points: GlobePoint[];
  projection?: ProjectionMode;
  controls?: boolean;
  onRouteHover?: (hover: GlobeRouteHover | null) => void;
};

type Coordinate = [number, number];
type PolygonCoordinates = Coordinate[][];
type MultiPolygonCoordinates = Coordinate[][][];

type CountryFeature = {
  type: "Feature";
  geometry: {
    type: "Polygon" | "MultiPolygon";
    coordinates: PolygonCoordinates | MultiPolygonCoordinates;
  } | null;
};

type CountryFeatureCollection = {
  type: "FeatureCollection";
  features: CountryFeature[];
};

type CloudTargets = {
  starts: Float32Array;
  globeTargets: Float32Array;
  mapTargets: Float32Array;
  scatter: Float32Array;
  colors: Float32Array;
};

type AnimatedCloud = CloudTargets & {
  geometry: THREE.BufferGeometry;
  material: THREE.PointsMaterial;
  sizeGlobe: number;
  sizeMap: number;
  opacityGlobe: number;
  opacityMap: number;
};

type AttackMarker = {
  point: GlobePoint;
  geometry: THREE.BufferGeometry;
  material: THREE.PointsMaterial;
  particles: THREE.Points;
  phase: number;
  baseSize: number;
  radiusOffset: number;
};

type TargetMarker = {
  geometry: THREE.BufferGeometry;
  material: THREE.PointsMaterial;
  particles: THREE.Points;
  baseSize: number;
  phase: number;
  radiusOffset: number;
};

type AttackFlight = {
  point: GlobePoint;
  kind: "attack" | "visit";
  beamGeometry: THREE.BufferGeometry;
  beamMaterial: THREE.PointsMaterial;
  beamPositions: Float32Array;
  beamColors: Float32Array;
  beamParticles: THREE.Points;
  impactGeometry: THREE.BufferGeometry;
  impactMaterial: THREE.PointsMaterial;
  impactPosition: Float32Array;
  impact: THREE.Points;
  phaseMs: number;
  durationMs: number;
  sampleCount: number;
  seed: number;
};

type ZoomApi = {
  zoomIn: () => void;
  zoomOut: () => void;
  reset: () => void;
};

const DEG = Math.PI / 180;
const GLOBE_RADIUS = 1.58;
const MAP_WIDTH_UNITS = 6.34;
const MAP_HEIGHT_UNITS = 3.16;
const CHENGDU = { latitude: 30.5728, longitude: 104.0668 };
const SURFACE_NORMAL = new THREE.Vector3(0, 0, 1);

const riskColors: Record<RiskLevel, string> = {
  info: "#8ee8ff",
  low: "#b2f2bb",
  medium: "#ffd166",
  high: "#ff8a3d",
  critical: "#ff526f",
};

const riskWeight: Record<RiskLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const attackActions = new Set<NonNullable<GlobePoint["action"]>>([
  "block",
  "blocked",
  "challenge",
  "managed_challenge",
  "js_challenge",
  "log",
  "simulate",
]);
const ATTACK_FLIGHT_LIMIT = 16;
const VISIT_FLIGHT_LIMIT = 6;

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function smooth(value: number) {
  return value * value * (3 - 2 * value);
}

function isAttackFlightPoint(point: GlobePoint) {
  return riskWeight[point.riskLevel] >= 2 || (point.action ? attackActions.has(point.action) : false);
}

function pointTrafficKind(point: GlobePoint): TrafficKind {
  if (point.sourceType === "normal_visit") {
    return "visit";
  }

  if (point.trafficKind) {
    return point.trafficKind;
  }

  return resolveTrafficKind(point);
}

function isVisitFlightPoint(point: GlobePoint) {
  return !isAttackFlightPoint(point) && pointTrafficKind(point) === "visit";
}

function pickVisitFlightPoints(points: GlobePoint[], skippedPointIds: Set<string>) {
  const visitPoints = points
    .filter((point) => !skippedPointIds.has(point.id) && isVisitFlightPoint(point))
    .sort((left, right) => right.count - left.count);
  const selectedPoints: GlobePoint[] = [];
  const selectedPointIds = new Set<string>();
  const selectedCountries = new Set<string>();

  for (const point of visitPoints) {
    if (selectedPoints.length >= VISIT_FLIGHT_LIMIT) {
      return selectedPoints;
    }

    const countryKey = point.country.trim() || point.id;
    if (selectedCountries.has(countryKey)) {
      continue;
    }

    selectedPoints.push(point);
    selectedPointIds.add(point.id);
    selectedCountries.add(countryKey);
  }

  for (const point of visitPoints) {
    if (selectedPoints.length >= VISIT_FLIGHT_LIMIT) {
      break;
    }

    if (selectedPointIds.has(point.id)) {
      continue;
    }

    selectedPoints.push(point);
    selectedPointIds.add(point.id);
  }

  return selectedPoints;
}

function wrapMapX(value: number) {
  const half = MAP_WIDTH_UNITS / 2;
  return ((((value + half) % MAP_WIDTH_UNITS) + MAP_WIDTH_UNITS) % MAP_WIDTH_UNITS) - half;
}

function lonLatToVector3(longitude: number, latitude: number, radius = GLOBE_RADIUS) {
  const phi = (90 - latitude) * DEG;
  const theta = (longitude + 180) * DEG;

  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function lonLatToMapVector3(longitude: number, latitude: number, z = 0) {
  return new THREE.Vector3(
    (longitude / 180) * (MAP_WIDTH_UNITS / 2),
    (latitude / 90) * (MAP_HEIGHT_UNITS / 2),
    z,
  );
}

function seeded(seed: number) {
  const value = Math.sin(seed * 12.9898) * 43758.5453;
  return value - Math.floor(value);
}

function randomSpherePoint(seed: number, radius: number) {
  const z = seeded(seed) * 2 - 1;
  const theta = seeded(seed + 17.31) * Math.PI * 2;
  const r = Math.sqrt(1 - z * z);

  return new THREE.Vector3(Math.cos(theta) * r * radius, z * radius, Math.sin(theta) * r * radius);
}

function pushVector(target: number[], vector: THREE.Vector3) {
  target.push(vector.x, vector.y, vector.z);
}

function createParticleTexture() {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const context = canvas.getContext("2d");

  if (context) {
    const gradient = context.createRadialGradient(32, 32, 0, 32, 32, 32);
    gradient.addColorStop(0, "rgba(220,255,241,0.84)");
    gradient.addColorStop(0.34, "rgba(178,242,187,0.66)");
    gradient.addColorStop(1, "rgba(178,242,187,0)");
    context.fillStyle = gradient;
    context.fillRect(0, 0, 64, 64);
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

function createTargetParticleTexture() {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const context = canvas.getContext("2d");

  if (context) {
    const gradient = context.createRadialGradient(32, 32, 0, 32, 32, 32);
    gradient.addColorStop(0, "rgba(255,255,255,0.96)");
    gradient.addColorStop(0.36, "rgba(245,255,250,0.74)");
    gradient.addColorStop(1, "rgba(245,255,250,0)");
    context.fillStyle = gradient;
    context.fillRect(0, 0, 64, 64);
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
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

function createBaseTargets(total = 980): CloudTargets {
  const starts: number[] = [];
  const globeTargets: number[] = [];
  const mapTargets: number[] = [];
  const scatter: number[] = [];
  const colors: number[] = [];
  const color = new THREE.Color("#315a4d");
  const columns = 49;
  const rows = Math.ceil(total / columns);

  for (let index = 0; index < total; index += 1) {
    const y = 1 - (index / (total - 1)) * 2;
    const radius = Math.sqrt(1 - y * y);
    const theta = index * Math.PI * (3 - Math.sqrt(5));
    const globe = new THREE.Vector3(Math.cos(theta) * radius, y, Math.sin(theta) * radius).multiplyScalar(
      GLOBE_RADIUS - 0.035,
    );
    const column = index % columns;
    const row = Math.floor(index / columns);
    const longitude = -180 + (column / (columns - 1)) * 360;
    const latitude = 78 - (row / Math.max(1, rows - 1)) * 156;

    pushVector(starts, randomSpherePoint(index + 1800, GLOBE_RADIUS + 1.8));
    pushVector(globeTargets, globe);
    pushVector(mapTargets, lonLatToMapVector3(longitude, latitude, -0.08));
    pushVector(scatter, randomSpherePoint(index + 7100, 0.42 + seeded(index + 99) * 0.28));
    colors.push(color.r, color.g, color.b);
  }

  return {
    starts: new Float32Array(starts),
    globeTargets: new Float32Array(globeTargets),
    mapTargets: new Float32Array(mapTargets),
    scatter: new Float32Array(scatter),
    colors: new Float32Array(colors),
  };
}

function collectBoundaryTargets(collection: CountryFeatureCollection): CloudTargets {
  const starts: number[] = [];
  const globeTargets: number[] = [];
  const mapTargets: number[] = [];
  const scatter: number[] = [];
  const colors: number[] = [];
  const seen = new Set<string>();
  const color = new THREE.Color("#d9fff1");

  collection.features.forEach((feature, featureIndex) => {
    eachRing(feature, (ring) => {
      for (let index = 0; index < ring.length; index += 1) {
        const current = ring[index];
        const next = ring[(index + 1) % ring.length];
        const [currentLongitude, currentLatitude] = current;
        const [nextLongitude, nextLatitude] = next;
        const longitudeDelta = nextLongitude - currentLongitude;
        const latitudeDelta = nextLatitude - currentLatitude;
        const crossesDateLine = Math.abs(longitudeDelta) > 28;
        const samples = crossesDateLine
          ? 1
          : Math.max(1, Math.ceil(Math.max(Math.abs(longitudeDelta), Math.abs(latitudeDelta)) / 1.28));

        for (let sample = 0; sample < samples; sample += 1) {
          const t = sample / samples;
          const longitude = currentLongitude + longitudeDelta * t;
          const latitude = currentLatitude + latitudeDelta * t;
          const key = `${longitude.toFixed(2)},${latitude.toFixed(2)}`;

          if (!seen.has(key)) {
            const seed = featureIndex * 10000 + index * 37 + sample;
            seen.add(key);
            pushVector(starts, randomSpherePoint(seed + 1, GLOBE_RADIUS + 1.9));
            pushVector(globeTargets, lonLatToVector3(longitude, latitude, GLOBE_RADIUS + 0.018));
            pushVector(mapTargets, lonLatToMapVector3(longitude, latitude, 0));
            pushVector(scatter, randomSpherePoint(seed + 3000, 0.5 + seeded(seed + 22) * 0.42));
            colors.push(color.r, color.g, color.b);
          }
        }
      }
    });
  });

  return {
    starts: new Float32Array(starts),
    globeTargets: new Float32Array(globeTargets),
    mapTargets: new Float32Array(mapTargets),
    scatter: new Float32Array(scatter),
    colors: new Float32Array(colors),
  };
}

function projectLocation(
  longitude: number,
  latitude: number,
  radiusOffset: number,
  projectionMix: number,
  mapOffsetX: number,
  mapOffsetY: number,
  mapZoom: number,
  floatOffset = 0,
) {
  const mapEase = smooth(projectionMix);
  const globe = lonLatToVector3(longitude, latitude, GLOBE_RADIUS + radiusOffset);
  const globeNormal = globe.clone().normalize();
  globe.addScaledVector(globeNormal, floatOffset);

  const mapTarget = lonLatToMapVector3(longitude, latitude, 0.06 + radiusOffset * 0.42 + floatOffset * 0.5);
  const map = new THREE.Vector3(
    wrapMapX(mapTarget.x + mapOffsetX) * mapZoom,
    clamp(mapTarget.y + mapOffsetY, -MAP_HEIGHT_UNITS * 0.62, MAP_HEIGHT_UNITS * 0.62) * mapZoom,
    mapTarget.z * (0.82 + mapZoom * 0.18),
  );

  return globe.lerp(map, mapEase);
}

function sampleRoute(
  point: GlobePoint,
  progress: number,
  projectionMix: number,
  mapOffsetX: number,
  mapOffsetY: number,
  mapZoom: number,
  seed: number,
) {
  const t = clamp(progress, 0, 1);
  const mapEase = smooth(projectionMix);
  const startNormal = lonLatToVector3(point.longitude, point.latitude, 1).normalize();
  const endNormal = lonLatToVector3(CHENGDU.longitude, CHENGDU.latitude, 1).normalize();
  const angle = clamp(startNormal.angleTo(endNormal), 0.0001, Math.PI - 0.0001);
  let routeAxis = startNormal.clone().cross(endNormal);

  if (routeAxis.lengthSq() < 0.000001) {
    routeAxis = new THREE.Vector3(0, 1, 0).cross(startNormal);
  }

  if (routeAxis.lengthSq() < 0.000001) {
    routeAxis = new THREE.Vector3(1, 0, 0).cross(startNormal);
  }

  routeAxis.normalize();
  const globeNormal = startNormal.clone().applyAxisAngle(routeAxis, angle * t).normalize();
  const globeHeight = GLOBE_RADIUS + 0.034 + Math.sin(Math.PI * t) * (0.105 + seeded(seed + 9) * 0.04);
  const globe = globeNormal.multiplyScalar(globeHeight);

  const mapStart = lonLatToMapVector3(point.longitude, point.latitude, 0.055);
  const mapEnd = lonLatToMapVector3(CHENGDU.longitude, CHENGDU.latitude, 0.055);
  let startX = mapStart.x;
  const deltaX = mapEnd.x - startX;

  if (deltaX > MAP_WIDTH_UNITS / 2) {
    startX += MAP_WIDTH_UNITS;
  } else if (deltaX < -MAP_WIDTH_UNITS / 2) {
    startX -= MAP_WIDTH_UNITS;
  }

  const mapLift = Math.sin(Math.PI * t) * (0.22 + seeded(seed + 31) * 0.18);
  const map = new THREE.Vector3(
    wrapMapX(THREE.MathUtils.lerp(startX, mapEnd.x, t) + mapOffsetX) * mapZoom,
    clamp(THREE.MathUtils.lerp(mapStart.y, mapEnd.y, t) + mapOffsetY, -MAP_HEIGHT_UNITS * 0.62, MAP_HEIGHT_UNITS * 0.62) * mapZoom,
    (0.055 + mapLift) * (0.82 + mapZoom * 0.18),
  );

  return globe.lerp(map, mapEase);
}

function createAttackMarker(point: GlobePoint, index: number, texture: THREE.Texture): AttackMarker {
  const riskLevel = point.riskLevel;
  const rank = riskWeight[riskLevel];
  const color = new THREE.Color(riskColors[riskLevel]);
  const baseSize = 0.052 + rank * 0.0045 + clamp(Math.sqrt(point.count) * 0.00085, 0, 0.009);
  const geometry = new THREE.BufferGeometry();
  const positions = new Float32Array(3);
  positions.fill(999);
  const material = new THREE.PointsMaterial({
    color,
    map: texture,
    size: baseSize,
    transparent: true,
    opacity: 0.92,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: true,
    sizeAttenuation: true,
  });
  geometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
  const particles = new THREE.Points(geometry, material);
  particles.frustumCulled = false;
  particles.renderOrder = 17;

  return {
    point,
    geometry,
    material,
    particles,
    phase: index * 0.72 + seeded(index + 88) * Math.PI,
    baseSize,
    radiusOffset: 0.026,
  };
}

function createTargetMarker(texture: THREE.Texture): TargetMarker {
  const geometry = new THREE.BufferGeometry();
  const positions = new Float32Array(3);
  positions.fill(999);
  const baseSize = 0.088;
  const material = new THREE.PointsMaterial({
    color: "#ffffff",
    map: texture,
    size: baseSize,
    transparent: true,
    opacity: 1,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: false,
    sizeAttenuation: true,
  });
  geometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
  const particles = new THREE.Points(geometry, material);
  particles.frustumCulled = false;
  particles.renderOrder = 24;

  return {
    geometry,
    material,
    particles,
    baseSize,
    phase: 0.42,
    radiusOffset: 0.038,
  };
}

function createAttackFlight(
  point: GlobePoint,
  index: number,
  texture: THREE.Texture,
  kind: AttackFlight["kind"] = "attack",
): AttackFlight {
  const isVisit = kind === "visit";
  const visualRiskLevel = isVisit ? (point.riskLevel === "low" ? "low" : "info") : point.riskLevel;
  const color = new THREE.Color(riskColors[visualRiskLevel] ?? "#b2f2bb").lerp(
    new THREE.Color(isVisit ? "#dffcff" : "#fff3d6"),
    isVisit ? 0.22 : 0.16,
  );
  const rank = riskWeight[point.riskLevel];
  const sampleCount = isVisit ? 72 : 96;
  const positions = new Float32Array(sampleCount * 3);
  const colors = new Float32Array(sampleCount * 3);
  positions.fill(999);
  const geometry = new THREE.BufferGeometry();
  const seed = (index + 1) * 971;

  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geometry.setDrawRange(0, sampleCount);

  const beamMaterial = new THREE.PointsMaterial({
    color: "#ffffff",
    map: texture,
    size: isVisit ? 0.017 + Math.min(rank, 1) * 0.001 : 0.028 + rank * 0.002,
    transparent: true,
    opacity: isVisit ? 0.42 : 0.7,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: false,
    sizeAttenuation: true,
    vertexColors: true,
  });
  const beamParticles = new THREE.Points(geometry, beamMaterial);
  beamParticles.frustumCulled = false;
  beamParticles.renderOrder = isVisit ? 18 : 20;

  const impactGeometry = new THREE.BufferGeometry();
  const impactPosition = new Float32Array(3);
  impactPosition.fill(999);
  const impactMaterial = new THREE.PointsMaterial({
    color,
    map: texture,
    size: isVisit ? 0.032 + Math.min(rank, 1) * 0.002 : 0.052 + rank * 0.004,
    transparent: true,
    opacity: 0,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: false,
    sizeAttenuation: true,
  });
  impactGeometry.setAttribute("position", new THREE.BufferAttribute(impactPosition, 3));
  const impact = new THREE.Points(impactGeometry, impactMaterial);
  impact.frustumCulled = false;
  impact.renderOrder = isVisit ? 19 : 21;
  impact.visible = false;

  return {
    point,
    kind,
    beamGeometry: geometry,
    beamMaterial,
    beamPositions: positions,
    beamColors: colors,
    beamParticles,
    impact,
    impactGeometry,
    impactMaterial,
    impactPosition,
    phaseMs: seeded(seed + 11) * (isVisit ? 6200 : 3600),
    durationMs: isVisit
      ? clamp(5600 + seeded(seed + 23) * 1700, 5200, 7800)
      : clamp(3600 - rank * 280 + seeded(seed + 23) * 900, 2400, 4200),
    sampleCount,
    seed,
  };
}

function makeCloud(
  targets: CloudTargets,
  material: THREE.PointsMaterial,
  sizeGlobe: number,
  sizeMap: number,
  opacityGlobe: number,
  opacityMap: number,
): AnimatedCloud {
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(targets.starts), 3));
  geometry.setAttribute("color", new THREE.Float32BufferAttribute(targets.colors, 3));

  return {
    ...targets,
    geometry,
    material,
    sizeGlobe,
    sizeMap,
    opacityGlobe,
    opacityMap,
  };
}

function renderCloud(
  cloud: AnimatedCloud,
  introProgress: number,
  projectionMix: number,
  mapOffsetX: number,
  mapOffsetY: number,
  mapZoom: number,
) {
  const position = cloud.geometry.getAttribute("position") as THREE.BufferAttribute;
  const array = position.array as Float32Array;
  const count = position.count;
  const intro = smooth(introProgress);
  const mapEase = smooth(projectionMix);
  const scatterWeight = Math.sin(mapEase * Math.PI);

  for (let index = 0; index < count; index += 1) {
    const offset = index * 3;
    const delay = seeded(index + 23) * 0.32;
    const localMapEase = smooth(clamp((projectionMix - delay) / (1 - delay), 0, 1));
    const dissolve = Math.sin(localMapEase * Math.PI);
    const scatterScale = Math.max(scatterWeight, dissolve) * (1.02 + seeded(index + 47) * 0.62);
    const mapX = wrapMapX(cloud.mapTargets[offset] + mapOffsetX) * mapZoom;
    const mapY = clamp(cloud.mapTargets[offset + 1] + mapOffsetY, -MAP_HEIGHT_UNITS * 0.62, MAP_HEIGHT_UNITS * 0.62) * mapZoom;
    const mapZ = cloud.mapTargets[offset + 2] * (0.82 + mapZoom * 0.18);
    const targetX =
      THREE.MathUtils.lerp(cloud.globeTargets[offset], mapX, localMapEase) +
      cloud.scatter[offset] * scatterScale;
    const targetY =
      THREE.MathUtils.lerp(cloud.globeTargets[offset + 1], mapY, localMapEase) +
      cloud.scatter[offset + 1] * scatterScale;
    const targetZ =
      THREE.MathUtils.lerp(cloud.globeTargets[offset + 2], mapZ, localMapEase) +
      cloud.scatter[offset + 2] * scatterScale;

    array[offset] = THREE.MathUtils.lerp(cloud.starts[offset], targetX, intro);
    array[offset + 1] = THREE.MathUtils.lerp(cloud.starts[offset + 1], targetY, intro);
    array[offset + 2] = THREE.MathUtils.lerp(cloud.starts[offset + 2], targetZ, intro);
  }

  cloud.material.size = THREE.MathUtils.lerp(cloud.sizeGlobe, cloud.sizeMap * Math.sqrt(mapZoom), mapEase);
  cloud.material.opacity = THREE.MathUtils.lerp(cloud.opacityGlobe, cloud.opacityMap, mapEase);
  position.needsUpdate = true;
}

function disposeMaterial(material: THREE.Material | THREE.Material[]) {
  if (Array.isArray(material)) {
    material.forEach((item) => item.dispose());
    return;
  }

  material.dispose();
}

function disposeObject(object: THREE.Object3D) {
  object.traverse((child) => {
    if (child instanceof THREE.Mesh || child instanceof THREE.Points || child instanceof THREE.LineSegments || child instanceof THREE.Line) {
      child.geometry.dispose();
      disposeMaterial(child.material);
      return;
    }

    if (child instanceof THREE.Sprite) {
      disposeMaterial(child.material);
    }
  });
}

export function ParticleGlobe({ points, projection = "globe", controls = false, onRouteHover }: ParticleGlobeProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const projectionRef = useRef<ProjectionMode>(projection);
  const routeHoverRef = useRef(onRouteHover);
  const zoomApiRef = useRef<ZoomApi | null>(null);

  useEffect(() => {
    projectionRef.current = projection;
  }, [projection]);

  useEffect(() => {
    routeHoverRef.current = onRouteHover;
  }, [onRouteHover]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) {
      return;
    }

    let disposed = false;
    let frame = 0;
    let width = Math.max(1, mount.clientWidth);
    let height = Math.max(1, mount.clientHeight);
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const clouds: AnimatedCloud[] = [];
    const attackMarkers: AttackMarker[] = [];
    const attackFlights: AttackFlight[] = [];

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(44, width / height, 0.1, 100);
    camera.position.set(0, 0, projectionRef.current === "map" ? 5.36 : 5.1);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    const particleTexture = createParticleTexture();
    const targetTexture = createTargetParticleTexture();
    const globeGroup = new THREE.Group();
    globeGroup.rotation.set(0.52, 2.84, 0.08);
    scene.add(globeGroup);

    const createMaterial = (size: number, opacity: number) =>
      new THREE.PointsMaterial({
        size,
        map: particleTexture,
        transparent: true,
        opacity,
        vertexColors: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });

    const addCloud = (cloud: AnimatedCloud) => {
      clouds.push(cloud);
      globeGroup.add(new THREE.Points(cloud.geometry, cloud.material));
    };

    addCloud(makeCloud(createBaseTargets(), createMaterial(0.012, 0.36), 0.012, 0.009, 0.36, 0.16));

    const targetMarker = createTargetMarker(targetTexture);
    globeGroup.add(targetMarker.particles);

    points.slice(0, 18).forEach((point, index) => {
      const marker = createAttackMarker(point, index, particleTexture);
      marker.particles.userData.hoverPoint = point;
      attackMarkers.push(marker);
      globeGroup.add(marker.particles);
    });

    const attackFlightPoints = points.filter(isAttackFlightPoint).slice(0, ATTACK_FLIGHT_LIMIT);
    const attackFlightPointIds = new Set(attackFlightPoints.map((point) => point.id));
    const visitFlightPoints = pickVisitFlightPoints(points, attackFlightPointIds);

    [
      ...attackFlightPoints.map((point) => ({ point, kind: "attack" as const })),
      ...visitFlightPoints.map((point) => ({ point, kind: "visit" as const })),
    ].forEach(({ point, kind }, index) => {
      const flight = createAttackFlight(point, index, particleTexture, kind);
      flight.beamParticles.userData.hoverPoint = point;
      flight.impact.userData.hoverPoint = point;
      attackFlights.push(flight);
      globeGroup.add(flight.beamParticles);
      globeGroup.add(flight.impact);
    });

    fetch("/data/ne-110m-countries.geojson")
      .then((response) => response.json() as Promise<CountryFeatureCollection>)
      .then((collection) => {
        if (disposed) {
          return;
        }

        const boundaryTargets = collectBoundaryTargets(collection);
        addCloud(makeCloud(boundaryTargets, createMaterial(0.015, 0.9), 0.015, 0.012, 0.9, 0.96));
      })
      .catch(() => {
        // Static geography is progressive: event clusters and arcs remain interactive if it is unavailable.
      });

    const resizeObserver = new ResizeObserver(([entry]) => {
      width = Math.max(1, entry.contentRect.width);
      height = Math.max(1, entry.contentRect.height);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    });
    resizeObserver.observe(mount);

    let targetRotationX = globeGroup.rotation.x;
    let targetRotationY = globeGroup.rotation.y;
    let dragging = false;
    let dragMode: "globe" | "map" | null = null;
    let lastX = 0;
    let lastY = 0;
    let projectionMix = projectionRef.current === "map" ? 1 : 0;
    let lastFrameTime = performance.now();
    let globeCameraDistance = 5.1;
    let targetGlobeCameraDistance = 5.1;
    let mapOffsetX = 0;
    let mapOffsetY = 0;
    let targetMapOffsetX = 0;
    let targetMapOffsetY = 0;
    let mapZoom = 1;
    let targetMapZoom = 1;
    let hoverKey: string | null = null;
    let hoverX = -999;
    let hoverY = -999;
    const hoverVector = new THREE.Vector3();

    const clearRouteHover = () => {
      if (!hoverKey) {
        return;
      }

      hoverKey = null;
      routeHoverRef.current?.(null);
    };

    const emitRouteHover = (point: GlobePoint, kind: GlobeRouteHover["kind"], event: PointerEvent) => {
      const nextKey = `${kind}:${point.id}`;
      const movedEnough = Math.abs(event.clientX - hoverX) > 8 || Math.abs(event.clientY - hoverY) > 8;

      if (nextKey === hoverKey && !movedEnough) {
        return;
      }

      hoverKey = nextKey;
      hoverX = event.clientX;
      hoverY = event.clientY;
      routeHoverRef.current?.({ point, kind, x: event.clientX, y: event.clientY });
    };

    const findNearestRouteHover = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      let nearestPoint: GlobePoint | null = null;
      let nearestKind: GlobeRouteHover["kind"] = "flight";
      let nearestDistance = Infinity;
      const flightThreshold = Math.max(18, Math.min(30, rect.width * 0.024));
      const sourceThreshold = Math.max(16, Math.min(26, rect.width * 0.018));

      globeGroup.updateMatrixWorld(true);

      const measureWorldPoint = (localX: number, localY: number, localZ: number) => {
        hoverVector.set(localX, localY, localZ);
        hoverVector.applyMatrix4(globeGroup.matrixWorld);
        hoverVector.project(camera);

        if (hoverVector.z < -1 || hoverVector.z > 1) {
          return Infinity;
        }

        const screenX = rect.left + (hoverVector.x * 0.5 + 0.5) * rect.width;
        const screenY = rect.top + (-hoverVector.y * 0.5 + 0.5) * rect.height;
        return Math.hypot(screenX - event.clientX, screenY - event.clientY);
      };

      attackFlights.forEach((flight) => {
        if (!flight.beamParticles.visible) {
          return;
        }

        for (let index = 0; index < flight.sampleCount; index += 6) {
          const offset = index * 3;
          if (flight.beamPositions[offset] > 900) {
            continue;
          }

          const distance = measureWorldPoint(
            flight.beamPositions[offset],
            flight.beamPositions[offset + 1],
            flight.beamPositions[offset + 2],
          );

          if (distance < nearestDistance) {
            nearestDistance = distance;
            nearestPoint = flight.point;
            nearestKind = "flight";
          }
        }
      });

      if (nearestPoint && nearestDistance <= flightThreshold) {
        return { point: nearestPoint, kind: nearestKind };
      }

      attackMarkers.forEach((marker) => {
        const position = marker.geometry.getAttribute("position") as THREE.BufferAttribute;
        const array = position.array as Float32Array;

        if (array[0] > 900) {
          return;
        }

        const distance = measureWorldPoint(array[0], array[1], array[2]);

        if (distance < nearestDistance) {
          nearestDistance = distance;
          nearestPoint = marker.point;
          nearestKind = "source";
        }
      });

      if (nearestPoint && nearestDistance <= sourceThreshold) {
        return { point: nearestPoint, kind: nearestKind };
      }

      return null;
    };

    const applyZoom = (direction: "in" | "out") => {
      const factor = direction === "in" ? 1.18 : 1 / 1.18;

      if (projectionRef.current === "map") {
        targetMapZoom = clamp(targetMapZoom * factor, 0.72, 2.85);
        return;
      }

      targetGlobeCameraDistance = clamp(targetGlobeCameraDistance / factor, 3.15, 7.35);
    };

    zoomApiRef.current = {
      zoomIn: () => applyZoom("in"),
      zoomOut: () => applyZoom("out"),
      reset: () => {
        targetGlobeCameraDistance = 5.1;
        targetMapZoom = 1;
        targetMapOffsetX = 0;
        targetMapOffsetY = 0;
      },
    };

    const onPointerDown = (event: PointerEvent) => {
      clearRouteHover();

      if (projectionRef.current === "map") {
        dragMode = "map";
        dragging = true;
        lastX = event.clientX;
        lastY = event.clientY;
        renderer.domElement.setPointerCapture(event.pointerId);
        return;
      }

      dragMode = "globe";
      dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      renderer.domElement.setPointerCapture(event.pointerId);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (!dragging) {
        const hover = findNearestRouteHover(event);

        if (hover) {
          emitRouteHover(hover.point, hover.kind, event);
        } else {
          clearRouteHover();
        }

        return;
      }

      if (dragMode === "map") {
        const visibleHeight = 2 * camera.position.z * Math.tan((camera.fov * DEG) / 2);
        const visibleWidth = visibleHeight * camera.aspect;
        const unitPerPixel = visibleWidth / Math.max(1, width);
        targetMapOffsetX += ((event.clientX - lastX) * unitPerPixel) / Math.max(0.72, mapZoom);
        targetMapOffsetY -= ((event.clientY - lastY) * unitPerPixel) / Math.max(0.72, mapZoom);
        targetMapOffsetY = clamp(targetMapOffsetY, -MAP_HEIGHT_UNITS * 0.34, MAP_HEIGHT_UNITS * 0.34);
      } else {
        targetRotationY += (event.clientX - lastX) * 0.006;
        targetRotationX += (event.clientY - lastY) * 0.004;
        targetRotationX = THREE.MathUtils.clamp(targetRotationX, -0.92, 0.92);
      }

      lastX = event.clientX;
      lastY = event.clientY;
    };

    const onPointerUp = (event: PointerEvent) => {
      dragging = false;
      dragMode = null;
      if (renderer.domElement.hasPointerCapture(event.pointerId)) {
        renderer.domElement.releasePointerCapture(event.pointerId);
      }
    };

    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const direction = event.deltaY < 0 ? "in" : "out";
      applyZoom(direction);
    };

    renderer.domElement.addEventListener("pointerdown", onPointerDown);
    renderer.domElement.addEventListener("pointermove", onPointerMove);
    renderer.domElement.addEventListener("pointerup", onPointerUp);
    renderer.domElement.addEventListener("pointercancel", onPointerUp);
    renderer.domElement.addEventListener("pointerleave", clearRouteHover);
    renderer.domElement.addEventListener("wheel", onWheel, { passive: false });

    const updateAttackMarkers = (elapsed: number, currentProjectionMix: number) => {
      const mapEase = smooth(currentProjectionMix);

      attackMarkers.forEach((marker) => {
        const positionAttribute = marker.geometry.getAttribute("position") as THREE.BufferAttribute;
        const array = positionAttribute.array as Float32Array;
        const floatOffset = (0.004 + riskWeight[marker.point.riskLevel] * 0.0008) * Math.sin(elapsed * 0.0017 + marker.phase);
        const pulse = 1 + Math.sin(elapsed * 0.002 + marker.phase * 1.7) * 0.08;
        const position = projectLocation(
          marker.point.longitude,
          marker.point.latitude,
          marker.radiusOffset,
          currentProjectionMix,
          mapOffsetX,
          mapOffsetY,
          mapZoom,
          floatOffset,
        );

        array[0] = position.x;
        array[1] = position.y;
        array[2] = position.z;
        positionAttribute.needsUpdate = true;
        marker.material.size = marker.baseSize * pulse * (1 + mapEase * 0.18);
        marker.material.opacity = 0.78 + Math.sin(elapsed * 0.0019 + marker.phase) * 0.1;
      });
    };

    const updateTargetMarker = (elapsed: number, currentProjectionMix: number) => {
      const mapEase = smooth(currentProjectionMix);
      const positionAttribute = targetMarker.geometry.getAttribute("position") as THREE.BufferAttribute;
      const array = positionAttribute.array as Float32Array;
      const floatOffset = 0.0045 * Math.sin(elapsed * 0.0015 + targetMarker.phase);
      const pulse = 1 + Math.sin(elapsed * 0.0022 + targetMarker.phase) * 0.045;
      const position = projectLocation(
        CHENGDU.longitude,
        CHENGDU.latitude,
        targetMarker.radiusOffset,
        currentProjectionMix,
        mapOffsetX,
        mapOffsetY,
        mapZoom,
        floatOffset,
      );

      array[0] = position.x;
      array[1] = position.y;
      array[2] = position.z;
      positionAttribute.needsUpdate = true;
      targetMarker.material.size = targetMarker.baseSize * pulse * (1 + mapEase * 0.12);
      targetMarker.material.opacity = 0.82 + Math.sin(elapsed * 0.0018 + targetMarker.phase) * 0.08;
    };

    const updateAttackFlights = (elapsed: number, currentProjectionMix: number) => {
      const mapEase = smooth(currentProjectionMix);
      const inverseGlobeRotation = globeGroup.quaternion.clone().invert();
      const viewDirection = camera.position.clone().normalize().applyQuaternion(inverseGlobeRotation).normalize();

      attackFlights.forEach((flight) => {
        const progress = ((elapsed + flight.phaseMs) % flight.durationMs) / flight.durationMs;
        const isVisit = flight.kind === "visit";
        const rank = riskWeight[flight.point.riskLevel];
        const visualRank = isVisit ? Math.min(rank, 1) : rank;
        const active = isVisit ? progress > 0.05 && progress < 0.96 : progress > 0.035 && progress < 0.99;
        const beamLength = isVisit ? 0.16 : 0.25 + rank * 0.014;
        const beamStart = Math.max(0, progress - beamLength);
        const beamSpan = Math.max(0.001, progress - beamStart);
        const visualRiskLevel = isVisit ? (flight.point.riskLevel === "low" ? "low" : "info") : flight.point.riskLevel;
        const baseColor = new THREE.Color(riskColors[visualRiskLevel]).lerp(
          new THREE.Color(isVisit ? "#dffcff" : "#fff0c6"),
          isVisit ? 0.2 : 0.14,
        );
        const sampleFlightRoute = (pathProgress: number) => {
          return sampleRoute(
            flight.point,
            pathProgress,
            currentProjectionMix,
            mapOffsetX,
            mapOffsetY,
            mapZoom,
            flight.seed,
          );
        };
        const fadeIn = smooth(clamp(progress / (isVisit ? 0.14 : 0.1), 0, 1));
        const fadeOut = 1 - smooth(clamp((progress - (isVisit ? 0.84 : 0.91)) / (isVisit ? 0.12 : 0.09), 0, 1));
        const lifecycle = active ? fadeIn * fadeOut : 0;

        for (let index = 0; index < flight.sampleCount; index += 1) {
          const localProgress = index / Math.max(1, flight.sampleCount - 1);
          const routeProgress = beamStart + beamSpan * localProgress;
          const position = sampleFlightRoute(routeProgress);
          const normal = position.clone().normalize().lerp(SURFACE_NORMAL, mapEase).normalize();
          const hemisphereVisibility =
            mapEase > 0.94 ? 1 : smooth(clamp((normal.dot(viewDirection) + 0.36) / 0.8, 0, 1));
          const frontVisibility = THREE.MathUtils.lerp(0.58, 1, hemisphereVisibility);
          const tail = Math.pow(localProgress, isVisit ? 2.75 : 2.35);
          const head = Math.exp(-Math.pow((localProgress - 0.985) / (isVisit ? 0.1 : 0.08), 2));
          const spark = isVisit ? 0.74 + seeded(flight.seed + index * 19) * 0.12 : 0.88 + seeded(flight.seed + index * 19) * 0.16;
          const offset = index * 3;
          const heat = isVisit ? clamp(head * 0.28 + tail * 0.1, 0, 0.34) : clamp(head * 0.6 + tail * 0.2, 0, 0.66);
          const hotColor = baseColor.clone().lerp(new THREE.Color(isVisit ? "#eaffff" : "#fff0bf"), heat);
          const intensity =
            lifecycle * frontVisibility * spark * (isVisit ? 0.016 + tail * 0.14 + head * 0.36 : 0.035 + tail * 0.48 + head * 1.1);

          flight.beamPositions[offset] = position.x;
          flight.beamPositions[offset + 1] = position.y;
          flight.beamPositions[offset + 2] = position.z;
          flight.beamColors[offset] = hotColor.r * intensity;
          flight.beamColors[offset + 1] = hotColor.g * intensity;
          flight.beamColors[offset + 2] = hotColor.b * intensity;
        }

        (flight.beamGeometry.getAttribute("position") as THREE.BufferAttribute).needsUpdate = true;
        (flight.beamGeometry.getAttribute("color") as THREE.BufferAttribute).needsUpdate = true;
        flight.beamParticles.visible = active;
        flight.beamMaterial.opacity = active ? (isVisit ? 0.32 + mapEase * 0.02 : 0.68 + rank * 0.035 + mapEase * 0.04) : 0;
        flight.beamMaterial.size = (isVisit ? 0.017 + visualRank * 0.001 : 0.028 + rank * 0.0022) * (1 + mapEase * (isVisit ? 0.08 : 0.14));

        const headPosition = sampleFlightRoute(progress);
        const headNormal = headPosition.clone().normalize().lerp(SURFACE_NORMAL, mapEase).normalize();
        const headVisibility =
          mapEase > 0.94 ? 1 : THREE.MathUtils.lerp(0.52, 1, smooth(clamp((headNormal.dot(viewDirection) + 0.36) / 0.8, 0, 1)));
        flight.impactPosition[0] = headPosition.x;
        flight.impactPosition[1] = headPosition.y;
        flight.impactPosition[2] = headPosition.z;
        (flight.impactGeometry.getAttribute("position") as THREE.BufferAttribute).needsUpdate = true;
        flight.impact.visible = active;
        flight.impactMaterial.opacity = lifecycle * headVisibility * (isVisit ? 0.24 + visualRank * 0.035 : 0.86 + rank * 0.055);
        flight.impactMaterial.size =
          (isVisit ? 0.032 + visualRank * 0.002 : 0.052 + rank * 0.004) *
          (1 + Math.sin(elapsed * (isVisit ? 0.0045 : 0.007) + flight.seed) * (isVisit ? 0.04 : 0.08));
      });
    };

    const startTime = performance.now();
    const animate = () => {
      const now = performance.now();
      const elapsed = now - startTime;
      const delta = Math.min(80, now - lastFrameTime);
      lastFrameTime = now;
      const desiredProjectionMix = projectionRef.current === "map" ? 1 : 0;
      const transitionStep = reducedMotion ? 1 : 1 - Math.pow(0.018, delta / 3200);

      projectionMix += (desiredProjectionMix - projectionMix) * transitionStep;
      if (Math.abs(desiredProjectionMix - projectionMix) < 0.001) {
        projectionMix = desiredProjectionMix;
      }

      const mapEase = smooth(projectionMix);
      const introProgress = reducedMotion ? 1 : clamp(elapsed / 1800, 0, 1);
      const interactionStep = reducedMotion ? 1 : 1 - Math.pow(0.035, delta / 420);
      globeCameraDistance += (targetGlobeCameraDistance - globeCameraDistance) * interactionStep;
      mapOffsetX += (targetMapOffsetX - mapOffsetX) * interactionStep;
      mapOffsetY += (targetMapOffsetY - mapOffsetY) * interactionStep;
      mapZoom += (targetMapZoom - mapZoom) * interactionStep;

      if (!reducedMotion && !dragging && mapEase < 0.45) {
        targetRotationY += 0.00125 * (1 - mapEase);
      }

      const desiredRotationX = THREE.MathUtils.lerp(targetRotationX, 0, mapEase);
      const desiredRotationY = THREE.MathUtils.lerp(targetRotationY, 0, mapEase);
      const desiredRotationZ = THREE.MathUtils.lerp(0.08, 0, mapEase);

      globeGroup.rotation.x += (desiredRotationX - globeGroup.rotation.x) * 0.08;
      globeGroup.rotation.y += (desiredRotationY - globeGroup.rotation.y) * 0.08;
      globeGroup.rotation.z += (desiredRotationZ - globeGroup.rotation.z) * 0.08;
      camera.position.z += (THREE.MathUtils.lerp(globeCameraDistance, 5.36, mapEase) - camera.position.z) * 0.08;

      clouds.forEach((cloud) => renderCloud(cloud, introProgress, projectionMix, mapOffsetX, mapOffsetY, mapZoom));
      updateAttackMarkers(elapsed, projectionMix);
      updateTargetMarker(elapsed, projectionMix);
      updateAttackFlights(reducedMotion ? 0 : elapsed, projectionMix);

      renderer.render(scene, camera);
      frame = window.requestAnimationFrame(animate);
    };
    animate();

    return () => {
      disposed = true;
      window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      renderer.domElement.removeEventListener("pointerdown", onPointerDown);
      renderer.domElement.removeEventListener("pointermove", onPointerMove);
      renderer.domElement.removeEventListener("pointerup", onPointerUp);
      renderer.domElement.removeEventListener("pointercancel", onPointerUp);
      renderer.domElement.removeEventListener("pointerleave", clearRouteHover);
      renderer.domElement.removeEventListener("wheel", onWheel);
      zoomApiRef.current = null;
      disposeObject(scene);
      particleTexture.dispose();
      targetTexture.dispose();
      renderer.dispose();

      if (renderer.domElement.parentElement === mount) {
        mount.removeChild(renderer.domElement);
      }
    };
  }, [points]);

  return (
    <div className="particle-globe" data-projection={projection} ref={mountRef}>
      {controls ? (
        <div className="particle-globe-controls" aria-label="缩放控制">
          <button type="button" aria-label="放大" onClick={() => zoomApiRef.current?.zoomIn()}>
            +
          </button>
          <button type="button" aria-label="缩小" onClick={() => zoomApiRef.current?.zoomOut()}>
            -
          </button>
          <button type="button" aria-label="重置缩放与位置" onClick={() => zoomApiRef.current?.reset()}>
            0
          </button>
        </div>
      ) : null}
    </div>
  );
}
