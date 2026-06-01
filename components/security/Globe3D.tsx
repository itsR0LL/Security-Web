"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { Crosshair, Filter, Globe2, LocateFixed, Radar, Route, Satellite, SignalHigh } from "lucide-react";
import type { GlobePoint } from "@/lib/security-data";
import { RiskBadge } from "./RiskBadge";

const chengdu = {
  label: "成都",
  latitude: 30.5728,
  longitude: 104.0668,
};

const threatStyles = {
  visit: { code: "VIS", label: "访问", color: "#38bdf8" },
  crawler: { code: "BOT", label: "爬虫", color: "#22c55e" },
  scan: { code: "SCN", label: "扫描", color: "#f97316" },
  probe: { code: "PRB", label: "探测", color: "#f43f5e" },
  injection: { code: "SQL", label: "注入", color: "#a855f7" },
  xss: { code: "XSS", label: "XSS", color: "#eab308" },
} as const;

type ThreatKind = keyof typeof threatStyles;

const filters = [
  { id: "all", label: "全部" },
  { id: "attack", label: "攻击/扫描" },
  { id: "high", label: "高风险" },
  { id: "traffic", label: "访问" },
] as const;

type FilterId = (typeof filters)[number]["id"];

function classifyThreat(point: GlobePoint): ThreatKind {
  if (point.eventType.includes("注入")) return "injection";
  if (point.eventType.toLowerCase().includes("xss")) return "xss";
  if (point.eventType.includes("敏感") || point.eventType.includes("目录")) return "probe";
  if (point.eventType.includes("扫描")) return "scan";
  if (point.eventType.includes("爬虫")) return "crawler";
  return "visit";
}

function latLonToVector3(latitude: number, longitude: number, radius: number) {
  const phi = (90 - latitude) * (Math.PI / 180);
  const theta = (longitude + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function createArc(start: THREE.Vector3, end: THREE.Vector3) {
  const angle = start.angleTo(end);
  const altitude = 2.18 + angle * 0.55;
  const mid = start.clone().add(end).normalize().multiplyScalar(altitude);
  const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
  return { curve, points: curve.getPoints(78) };
}

function matchesFilter(point: GlobePoint, filter: FilterId) {
  if (filter === "all") return true;
  if (filter === "high") return point.riskLevel === "high" || point.riskLevel === "critical";
  if (filter === "traffic") return point.riskLevel === "info" || point.eventType.includes("访问");
  return point.riskLevel !== "info" && !point.eventType.includes("正常");
}

function disposeMaterial(material: THREE.Material | THREE.Material[]) {
  if (Array.isArray(material)) {
    material.forEach((item) => item.dispose());
    return;
  }
  material.dispose();
}

function createStarField() {
  const starCount = 900;
  const positions = new Float32Array(starCount * 3);

  for (let index = 0; index < starCount; index += 1) {
    const radius = 10 + Math.random() * 18;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    positions[index * 3] = radius * Math.sin(phi) * Math.cos(theta);
    positions[index * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
    positions[index * 3 + 2] = radius * Math.cos(phi);
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));

  return new THREE.Points(
    geometry,
    new THREE.PointsMaterial({
      color: "#d8fff4",
      size: 0.018,
      transparent: true,
      opacity: 0.55,
      depthWrite: false,
    }),
  );
}

export function Globe3D({ points, variant = "panel" }: { points: GlobePoint[]; variant?: "panel" | "stage" }) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [filter, setFilter] = useState<FilterId>("all");
  const [failed, setFailed] = useState(false);
  const [clockLabel, setClockLabel] = useState("--:--:--");

  const filteredPoints = useMemo(() => points.filter((point) => matchesFilter(point, filter)), [filter, points]);
  const topPoint = filteredPoints[0] ?? points[0];
  const visibleRequestCount = useMemo(
    () => filteredPoints.reduce((total, point) => total + point.count, 0),
    [filteredPoints],
  );
  const highRiskCount = useMemo(
    () => filteredPoints.filter((point) => point.riskLevel === "high" || point.riskLevel === "critical").length,
    [filteredPoints],
  );

  const channelCounts = useMemo(() => {
    return filteredPoints.reduce<Record<ThreatKind, number>>(
      (accumulator, point) => {
        const kind = classifyThreat(point);
        accumulator[kind] += point.count;
        return accumulator;
      },
      { visit: 0, crawler: 0, scan: 0, probe: 0, injection: 0, xss: 0 },
    );
  }, [filteredPoints]);

  useEffect(() => {
    const updateClock = () => {
      setClockLabel(new Date().toLocaleTimeString("zh-CN", { hour12: false }));
    };
    updateClock();
    const timer = window.setInterval(updateClock, 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    let renderer: THREE.WebGLRenderer;
    let frame = 0;
    let width = mount.clientWidth || 860;
    let height = mount.clientHeight || 620;
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true });
    } catch {
      window.setTimeout(() => setFailed(true), 0);
      return;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(36, width / height, 0.1, 100);
    const globeGroup = new THREE.Group();
    const textureLoader = new THREE.TextureLoader();
    const animatedLines: THREE.LineDashedMaterial[] = [];
    const animatedPackets: Array<{
      curve: THREE.QuadraticBezierCurve3;
      marker: THREE.Mesh;
      offset: number;
      speed: number;
    }> = [];

    camera.position.set(0, 0.22, 6.05);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.94;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    renderer.setClearColor(0x000000, 0);
    renderer.domElement.style.touchAction = "none";
    mount.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight(0x5fffe2, 0.45);
    const keyLight = new THREE.DirectionalLight(0xffffff, 2.2);
    const rimLight = new THREE.DirectionalLight(0x11ffe3, 1.6);
    keyLight.position.set(5, 3, 7);
    rimLight.position.set(-5, 0.5, -4);
    scene.add(ambient, keyLight, rimLight, createStarField());

    const earthMap = textureLoader.load("/textures/earth-atmos-2048.jpg");
    const nightMap = textureLoader.load("/textures/earth-lights-2048.png");
    const cloudMap = textureLoader.load("/textures/earth-clouds-1024.png");
    [earthMap, nightMap, cloudMap].forEach((texture) => {
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = renderer.capabilities.getMaxAnisotropy();
    });

    const earthGeometry = new THREE.SphereGeometry(1.82, 96, 96);
    const earth = new THREE.Mesh(
      earthGeometry,
      new THREE.MeshPhongMaterial({
        map: earthMap,
        color: "#8ca19a",
        shininess: 18,
        specular: new THREE.Color("#1f3a35"),
      }),
    );
    globeGroup.add(earth);

    const nightLights = new THREE.Mesh(
      new THREE.SphereGeometry(1.824, 96, 96),
      new THREE.MeshBasicMaterial({
        map: nightMap,
        color: "#dffff5",
        transparent: true,
        opacity: 0.38,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    globeGroup.add(nightLights);

    const clouds = new THREE.Mesh(
      new THREE.SphereGeometry(1.85, 96, 96),
      new THREE.MeshLambertMaterial({
        map: cloudMap,
        transparent: true,
        opacity: 0.22,
        depthWrite: false,
      }),
    );
    globeGroup.add(clouds);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.98, 96, 96),
      new THREE.ShaderMaterial({
        uniforms: {
          glowColor: { value: new THREE.Color("#22ffe6") },
        },
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `,
        fragmentShader: `
          uniform vec3 glowColor;
          varying vec3 vNormal;
          void main() {
            float intensity = pow(0.58 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.2);
            gl_FragColor = vec4(glowColor, intensity * 0.42);
          }
        `,
        side: THREE.BackSide,
        blending: THREE.AdditiveBlending,
        transparent: true,
        depthWrite: false,
      }),
    );
    globeGroup.add(atmosphere);

    const destinationVector = latLonToVector3(chengdu.latitude, chengdu.longitude, 1.93);
    const destinationMarker = new THREE.Mesh(
      new THREE.SphereGeometry(0.06, 20, 20),
      new THREE.MeshBasicMaterial({ color: "#ecfeff" }),
    );
    destinationMarker.position.copy(destinationVector);
    globeGroup.add(destinationMarker);

    filteredPoints.forEach((point, index) => {
      const kind = classifyThreat(point);
      const style = threatStyles[kind];
      const sourceVector = latLonToVector3(point.latitude, point.longitude, 1.95);
      const markerSize = Math.min(0.11, 0.036 + point.count / 1400);

      const marker = new THREE.Mesh(
        new THREE.SphereGeometry(markerSize, 18, 18),
        new THREE.MeshBasicMaterial({
          color: style.color,
          transparent: true,
          opacity: point.riskLevel === "info" ? 0.75 : 1,
        }),
      );
      marker.position.copy(sourceVector);
      globeGroup.add(marker);

      const pulse = new THREE.Mesh(
        new THREE.RingGeometry(markerSize * 1.7, markerSize * 2.45, 28),
        new THREE.MeshBasicMaterial({
          color: style.color,
          transparent: true,
          opacity: 0.58,
          side: THREE.DoubleSide,
          blending: THREE.AdditiveBlending,
          depthWrite: false,
        }),
      );
      pulse.position.copy(sourceVector.clone().multiplyScalar(1.005));
      pulse.lookAt(sourceVector.clone().multiplyScalar(2.4));
      globeGroup.add(pulse);

      const { curve, points: arcPoints } = createArc(sourceVector, destinationVector);
      const arcGeometry = new THREE.BufferGeometry().setFromPoints(arcPoints);
      const arcMaterial = new THREE.LineDashedMaterial({
        color: style.color,
        transparent: true,
        opacity: point.riskLevel === "info" ? 0.34 : 0.76,
        dashSize: 0.075,
        gapSize: 0.048,
        linewidth: 1,
        blending: THREE.AdditiveBlending,
      });
      const arc = new THREE.Line(arcGeometry, arcMaterial);
      arc.computeLineDistances();
      globeGroup.add(arc);
      animatedLines.push(arcMaterial);

      const packet = new THREE.Mesh(
        new THREE.SphereGeometry(point.riskLevel === "critical" ? 0.035 : 0.026, 12, 12),
        new THREE.MeshBasicMaterial({
          color: style.color,
          transparent: true,
          opacity: point.riskLevel === "info" ? 0.48 : 0.95,
          blending: THREE.AdditiveBlending,
        }),
      );
      globeGroup.add(packet);
      animatedPackets.push({
        curve,
        marker: packet,
        offset: index / Math.max(1, filteredPoints.length),
        speed: point.riskLevel === "info" ? 0.045 : 0.075,
      });
    });

    globeGroup.rotation.set(-0.1, Math.PI * 0.92, 0);
    scene.add(globeGroup);

    let isDragging = false;
    let lastX = 0;
    let lastY = 0;
    const onPointerDown = (event: PointerEvent) => {
      isDragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
    };
    const onPointerMove = (event: PointerEvent) => {
      if (!isDragging) return;
      const deltaX = event.clientX - lastX;
      const deltaY = event.clientY - lastY;
      lastX = event.clientX;
      lastY = event.clientY;
      globeGroup.rotation.y += deltaX * 0.007;
      globeGroup.rotation.x = THREE.MathUtils.clamp(globeGroup.rotation.x + deltaY * 0.004, -0.7, 0.7);
    };
    const onPointerUp = () => {
      isDragging = false;
    };

    renderer.domElement.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);

    const resizeObserver = new ResizeObserver(() => {
      width = mount.clientWidth || 860;
      height = mount.clientHeight || 620;
      renderer.setSize(width, height);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    });
    resizeObserver.observe(mount);

    const clock = new THREE.Clock();
    const animate = () => {
      const elapsed = clock.getElapsedTime();

      if (!prefersReducedMotion) {
        globeGroup.rotation.y += isDragging ? 0 : 0.00115;
        clouds.rotation.y += 0.00075;
        animatedLines.forEach((material, index) => {
          (material as THREE.LineDashedMaterial & { dashOffset: number }).dashOffset = -(elapsed * (0.18 + index * 0.018));
        });
        animatedPackets.forEach((stream) => {
          const progress = (elapsed * stream.speed + stream.offset) % 1;
          stream.marker.position.copy(stream.curve.getPoint(progress));
        });
      } else {
        animatedPackets.forEach((stream) => {
          stream.marker.position.copy(stream.curve.getPoint(0.72));
        });
      }

      renderer.render(scene, camera);
      frame = requestAnimationFrame(animate);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      renderer.domElement.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Points) {
          object.geometry.dispose();
          disposeMaterial(object.material);
        }
      });
      earthMap.dispose();
      nightMap.dispose();
      cloudMap.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, [filteredPoints]);

  if (variant === "stage") {
    return (
      <section className="security-globe-stage relative min-h-[calc(100dvh-9rem)] overflow-hidden border-y border-[rgba(178,242,187,0.18)] bg-[#050807] text-white md:min-h-[calc(100dvh-5rem)]">
        <div className="pointer-events-none absolute inset-0 opacity-70 [background-image:radial-gradient(circle_at_1px_1px,rgba(178,242,187,0.25)_1px,transparent_0)] [background-size:24px_24px]" />
        <div className="pointer-events-none absolute inset-y-0 right-[18%] hidden w-px rotate-[13deg] bg-white/20 shadow-[80px_0_0_rgba(255,255,255,0.14),160px_0_0_rgba(255,255,255,0.12),240px_0_0_rgba(255,255,255,0.1)] md:block" />
        <div className="pointer-events-none absolute left-6 top-6 z-20 hidden font-mono text-[11px] font-bold leading-5 text-white/58 md:block">
          <p>TIME {clockLabel}</p>
          <p>SYSTEM_ONLINE</p>
        </div>

        <div className="relative z-10 grid min-h-[calc(100dvh-7rem)] grid-cols-1 md:min-h-[100dvh] xl:grid-cols-[320px_minmax(0,1fr)_240px]">
          <aside className="hidden border-r border-[rgba(178,242,187,0.18)] bg-black/8 p-6 pt-24 xl:order-1 xl:block">
            <div className="max-w-sm">
              <div className="mb-5 h-px w-32 bg-[#b2f2bb]" />
              <p className="font-mono text-xs font-bold text-[#b2f2bb]">BLOG_SECURITY_SIGNAL</p>
              <h2 className="mt-2 text-3xl font-black leading-tight text-white md:text-4xl">
                R0L1
                <br />
                DEHOME
              </h2>
              <p className="mt-4 text-sm font-semibold leading-7 text-white/58">
                访问与威胁只留下必要痕迹。地球负责呈现气质，事件页负责研判，设置页负责接入。
              </p>
            </div>

            <div className="mt-8 space-y-4">
              <StageReadout label="SOURCE" value={`${filteredPoints.length} points`} />
              <StageReadout label="REQUEST" value={visibleRequestCount.toLocaleString("zh-CN")} />
              <StageReadout label="HIGH_RISK" value={String(highRiskCount)} tone="danger" />
            </div>

            {topPoint && (
              <Link
                href={`/security/events?ip=${encodeURIComponent(topPoint.clientIp)}`}
                className="mt-8 block border border-[rgba(178,242,187,0.22)] bg-black/18 p-4 outline-none transition hover:border-[#b2f2bb] hover:bg-[#b2f2bb]/8 focus-visible:ring-2 focus-visible:ring-[#b2f2bb]"
              >
                <p className="font-mono text-[11px] font-bold text-[#b2f2bb]">LATEST TRACE</p>
                <p className="security-num mt-2 truncate text-base font-black text-white">{topPoint.clientIp}</p>
                <p className="mt-1 text-xs font-semibold text-white/48">
                  {topPoint.country} / {topPoint.city || topPoint.locationPrecision}
                </p>
                <div className="mt-3 flex items-center justify-between gap-3">
                  <RiskBadge level={topPoint.riskLevel} compact />
                  <span className="font-mono text-[11px] font-bold text-white/52">{topPoint.count} hits</span>
                </div>
              </Link>
            )}
          </aside>

          <div className="relative order-1 min-h-[calc(100dvh-10rem)] overflow-hidden md:min-h-[calc(100dvh-4.5rem)] xl:order-2">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_48%,rgba(178,242,187,0.18),transparent_34%),linear-gradient(90deg,rgba(178,242,187,0.08),transparent_28%,transparent_72%,rgba(255,255,255,0.04))]" />
            <div className="pointer-events-none absolute left-1/2 top-1/2 z-10 h-[68vw] max-h-[620px] min-h-[330px] w-[68vw] min-w-[330px] max-w-[620px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#b2f2bb]/10 bg-[conic-gradient(from_90deg,transparent_0deg,rgba(178,242,187,0.16)_28deg,transparent_62deg)] motion-safe:animate-[spin_22s_linear_infinite]" />
            <div className="pointer-events-none absolute left-4 top-24 z-20 max-w-[16rem] md:top-5 xl:hidden">
              <p className="font-mono text-[11px] font-black text-[#b2f2bb]">BLOG_SECURITY_SIGNAL</p>
              <h2 className="mt-2 text-4xl font-black leading-none text-white">
                R0L1
                <br />
                DEHOME
              </h2>
            </div>

            {!failed && (
              <div
                ref={mountRef}
                className="relative z-10 h-[calc(100dvh-10rem)] min-h-[520px] w-full md:h-[calc(100dvh-4.5rem)] md:min-h-[680px]"
                data-testid="security-globe-canvas"
              />
            )}
            {failed && (
              <div className="relative z-10 flex h-[560px] flex-col items-center justify-center gap-3 p-6 text-center text-white md:h-[680px]">
                <Radar size={36} />
                <p className="text-lg font-extrabold">WebGL 不可用，已切换为来源读数。</p>
              </div>
            )}

            <div className="pointer-events-none absolute left-4 top-4 z-20 border border-[#b2f2bb]/18 bg-black/26 px-3 py-2 font-mono text-[11px] font-bold text-[#b2f2bb]">
              TARGET / CHENGDU
            </div>

            <div className="absolute bottom-4 left-4 right-4 z-20">
              <div className="grid grid-cols-3 gap-px border border-[#b2f2bb]/18 bg-[#b2f2bb]/12 sm:grid-cols-6">
                {(Object.keys(threatStyles) as ThreatKind[]).map((kind) => (
                  <div key={kind} className="bg-black/58 px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[11px] font-black" style={{ color: threatStyles[kind].color }}>
                        {threatStyles[kind].code}
                      </span>
                      <span className="security-num text-[11px] font-black text-white/72">
                        {channelCounts[kind].toLocaleString("zh-CN")}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] font-semibold text-white/42">{threatStyles[kind].label}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <aside className="hidden border-l border-[rgba(178,242,187,0.18)] bg-black/8 p-6 pt-24 xl:order-3 xl:block">
            <p className="font-mono text-xs font-black text-[#b2f2bb]">FILTER_CHANNEL</p>
            <div className="mt-4 grid grid-cols-2 gap-2 xl:grid-cols-1" role="group" aria-label="地球态势筛选">
              {filters.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setFilter(item.id)}
                  aria-pressed={filter === item.id}
                  className={`min-h-11 border px-3 text-left font-mono text-xs font-black transition focus:outline-none focus:ring-2 focus:ring-[#b2f2bb] ${
                    filter === item.id
                      ? "border-[#b2f2bb] bg-[#b2f2bb] text-[#050807]"
                      : "border-[#b2f2bb]/22 bg-black/16 text-white/64 hover:border-[#b2f2bb]/70 hover:text-white"
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="mt-8 space-y-3">
              <p className="font-mono text-xs font-black text-[#b2f2bb]">TRACE_STREAM</p>
              {filteredPoints.slice(0, 5).map((point) => {
                const kind = classifyThreat(point);
                return (
                  <Link
                    key={point.id}
                    href={`/security/events?ip=${encodeURIComponent(point.clientIp)}`}
                    className="grid min-h-14 grid-cols-[10px_minmax(0,1fr)] gap-3 border-t border-[#b2f2bb]/12 py-3 outline-none hover:bg-white/[0.03] focus-visible:ring-2 focus-visible:ring-[#b2f2bb]"
                  >
                    <span className="mt-1 h-2.5 w-2.5 rounded-full" style={{ backgroundColor: threatStyles[kind].color }} />
                    <span className="min-w-0">
                      <span className="security-num block truncate text-xs font-black text-white">{point.clientIp}</span>
                      <span className="mt-1 block truncate text-[11px] font-semibold text-white/42">{point.city || point.country} / {threatStyles[kind].code}</span>
                    </span>
                  </Link>
                );
              })}
            </div>
          </aside>
        </div>
      </section>
    );
  }

  return (
    <section className="relative overflow-hidden rounded-lg border border-[#1d4d43] bg-[#030807] text-white shadow-[0_1px_0_rgba(255,255,255,0.08)]">
      <div className="pointer-events-none absolute inset-0 opacity-60 [background-image:linear-gradient(rgba(178,242,187,0.045)_1px,transparent_1px),linear-gradient(90deg,rgba(178,242,187,0.045)_1px,transparent_1px)] [background-size:34px_34px]" />
      <div className="pointer-events-none absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-[#b2f2bb] to-transparent opacity-70" />
      <div className="relative z-10 flex flex-col gap-4 border-b border-emerald-400/20 bg-[#06120f]/92 p-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="flex items-center gap-2 font-mono text-xs font-bold text-emerald-300">
            <Globe2 size={15} />
            GLOBAL INCIDENT SURFACE / 3D
          </p>
          <h2 className="mt-1 text-lg font-extrabold text-white">真实地球态势与入站威胁流</h2>
          <p className="mt-2 max-w-2xl text-sm font-medium leading-6 text-emerald-50/70">
            来源点按城市、地区、国家或估算坐标落点；彩色流线表示访问、扫描、探测与注入等不同事件类型，统一汇聚到成都。
          </p>
        </div>
        <div className="flex flex-wrap gap-2" role="group" aria-label="地球态势筛选">
          {filters.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setFilter(item.id)}
              aria-pressed={filter === item.id}
              className={`min-h-11 rounded-md px-3 font-mono text-xs font-bold transition focus:outline-none focus:ring-2 focus:ring-emerald-200/80 focus:ring-offset-2 focus:ring-offset-[#06120f] ${
                filter === item.id
                  ? "border border-emerald-300 bg-emerald-300 text-[#04100d]"
                  : "border border-emerald-300/25 bg-white/5 text-emerald-50 hover:border-emerald-300/60 hover:bg-emerald-300/10"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div className="relative z-10 grid min-h-[560px] grid-cols-1 lg:grid-cols-[minmax(0,1fr)_330px]">
        <div className="relative min-h-[420px] overflow-hidden bg-[#020706]">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_52%_45%,rgba(20,184,166,0.24),transparent_34%),linear-gradient(90deg,rgba(20,184,166,0.08),transparent_32%,transparent_68%,rgba(20,184,166,0.06))]" />
          <div className="pointer-events-none absolute inset-0 opacity-45 [background-image:linear-gradient(rgba(178,242,187,0.05)_1px,transparent_1px)] [background-size:100%_8px]" />
          <div className="pointer-events-none absolute left-1/2 top-1/2 z-10 h-[310px] w-[310px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-emerald-200/10 bg-[conic-gradient(from_90deg,transparent_0deg,rgba(178,242,187,0.22)_24deg,transparent_58deg)] motion-safe:animate-[spin_18s_linear_infinite] md:h-[430px] md:w-[430px]" />
          <div className="pointer-events-none absolute inset-x-4 top-4 z-20 flex items-start justify-between gap-3">
            <div className="rounded-md border border-emerald-300/20 bg-black/42 px-3 py-2 text-xs font-bold text-emerald-100 backdrop-blur-sm">
              <span className="inline-flex items-center gap-1.5">
                <LocateFixed size={14} />
                目的地：成都
              </span>
            </div>
            <div className="hidden rounded-md border border-emerald-300/20 bg-black/42 px-3 py-2 font-mono text-[11px] font-bold text-emerald-100 backdrop-blur-sm sm:block">
              <span className="mr-2 text-emerald-300">STREAM</span>
              {visibleRequestCount.toLocaleString("zh-CN")} / {filteredPoints.length} SRC
            </div>
          </div>
          {!failed && <div ref={mountRef} className="relative z-10 h-[420px] w-full md:h-[620px]" data-testid="security-globe-canvas" />}
          {failed && (
            <div className="relative z-10 flex h-[420px] flex-col items-center justify-center gap-3 p-6 text-center text-white md:h-[620px]">
              <Radar size={36} />
              <p className="text-lg font-extrabold">WebGL 不可用，已切换为来源列表。</p>
            </div>
          )}

          <div className="pointer-events-none absolute bottom-24 left-4 z-20 hidden max-w-[230px] rounded-md border border-emerald-300/20 bg-black/42 p-3 backdrop-blur-sm md:block">
            <p className="flex items-center gap-2 font-mono text-[11px] font-bold text-emerald-200">
              <SignalHigh size={13} />
              SIGNAL QUALITY
            </p>
            <div className="mt-3 space-y-2">
              {[
                ["POSITION", "城市优先 / 区域估算"],
                ["WINDOW", "Cloudflare Free 采样窗口"],
                ["TARGET", "r0l1dehome.asia"],
              ].map(([label, value]) => (
                <div key={label} className="flex items-center justify-between gap-3 border-t border-emerald-300/10 pt-2 font-mono text-[10px]">
                  <span className="text-emerald-300/70">{label}</span>
                  <span className="truncate text-emerald-50/70">{value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="absolute bottom-0 left-0 right-0 z-20 border-t border-emerald-300/20 bg-black/45 px-4 py-3 backdrop-blur-sm">
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
              {(Object.keys(threatStyles) as ThreatKind[]).map((kind) => (
                <div key={kind} className="rounded border border-emerald-300/20 bg-emerald-300/5 px-2 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-extrabold" style={{ color: threatStyles[kind].color }}>
                      {threatStyles[kind].code}
                    </span>
                    <span className="security-num text-[11px] font-bold text-emerald-50/80">
                      {channelCounts[kind].toLocaleString("zh-CN")}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] font-medium text-emerald-50/55">{threatStyles[kind].label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <aside className="border-t border-emerald-300/20 bg-[#081611] p-4 lg:border-l lg:border-t-0">
          <div className="rounded-md border border-emerald-300/25 bg-emerald-300/[0.08] p-4">
            <p className="flex items-center gap-2 font-mono text-xs font-bold text-emerald-200">
              <Route size={14} />
              当前筛选
            </p>
            <p className="security-num mt-2 text-2xl font-extrabold text-white">{filteredPoints.length} 个来源点</p>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <div className="rounded border border-emerald-300/15 bg-black/18 p-2">
                <p className="font-mono text-[10px] font-bold text-emerald-300/70">REQUESTS</p>
                <p className="security-num mt-1 font-extrabold text-emerald-50">{visibleRequestCount.toLocaleString("zh-CN")}</p>
              </div>
              <div className="rounded border border-rose-300/20 bg-rose-500/8 p-2">
                <p className="font-mono text-[10px] font-bold text-rose-200/80">HIGH RISK</p>
                <p className="security-num mt-1 font-extrabold text-rose-100">{highRiskCount}</p>
              </div>
            </div>
            <p className="mt-3 text-xs font-medium text-emerald-50/60">流线目的地固定为 {chengdu.label}</p>
          </div>

          {topPoint && (
            <Link href={`/security/events?ip=${encodeURIComponent(topPoint.clientIp)}`} className="mt-4 block rounded-md border border-emerald-300/20 bg-black/18 p-4 transition hover:border-emerald-300/50 focus:outline-none focus:ring-2 focus:ring-emerald-200/70 focus:ring-offset-2 focus:ring-offset-[#081611]">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="security-num truncate text-sm font-extrabold text-white">{topPoint.clientIp}</p>
                  <p className="mt-1 text-xs font-medium text-emerald-50/60">
                    {topPoint.country} {topPoint.city} / {topPoint.locationPrecision}
                  </p>
                </div>
                <RiskBadge level={topPoint.riskLevel} compact />
              </div>
              <p className="mt-3 text-xs font-medium leading-5 text-emerald-50/65">
                {topPoint.eventType}，样例窗口内 {topPoint.count} 次请求。
              </p>
            </Link>
          )}

          <div className="mt-4 flex items-center gap-2 font-mono text-xs font-bold text-emerald-200">
            <Satellite size={14} />
            来源事件
          </div>
          <div className="mt-3 max-h-72 space-y-2 overflow-auto pr-1">
            {filteredPoints.slice(0, 8).map((point) => {
              const kind = classifyThreat(point);
              return (
                <Link
                  key={point.id}
                  href={`/security/events?ip=${encodeURIComponent(point.clientIp)}`}
                  className="flex min-h-14 items-center gap-3 rounded-md border border-emerald-300/15 bg-white/[0.03] p-3 hover:bg-emerald-300/[0.08] focus:outline-none focus:ring-2 focus:ring-emerald-200/70 focus:ring-offset-2 focus:ring-offset-[#081611]"
                >
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: threatStyles[kind].color }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-extrabold text-white">{point.city || point.country}</span>
                    <span className="block truncate text-[11px] font-medium text-emerald-50/55">{point.eventType}</span>
                  </span>
                  <span className="rounded border border-emerald-300/20 px-1.5 py-0.5 font-mono text-[10px] font-bold" style={{ color: threatStyles[kind].color }}>
                    {threatStyles[kind].code}
                  </span>
                  <span className="security-num text-xs font-extrabold text-emerald-50/75">{point.count}</span>
                </Link>
              );
            })}
          </div>

          <div className="mt-4 rounded-md border border-emerald-300/15 bg-black/16 p-3 text-xs font-medium leading-5 text-emerald-50/60">
            <div className="mb-2 flex items-center gap-2 font-mono font-bold text-emerald-200">
              <Crosshair size={14} />
              说明
            </div>
            视觉层参考实时威胁地图的流线表达；事件数量、风险等级与筛选仍以当前平台本地数据为准。
          </div>

          <div className="mt-3 rounded-md border border-emerald-300/15 bg-black/16 p-3 text-xs font-medium leading-5 text-emerald-50/60">
            <div className="mb-2 flex items-center gap-2 font-mono font-bold text-emerald-200">
              <Filter size={14} />
              筛选方案
            </div>
            筛选只改变地球态势视图，事件研判仍从列表页进入，避免可视化替代原始明细。
          </div>
        </aside>
      </div>
    </section>
  );
}

function StageReadout({ label, value, tone = "default" }: { label: string; value: string; tone?: "default" | "danger" }) {
  return (
    <div className="border-l border-[#b2f2bb]/28 pl-3">
      <p className="font-mono text-[11px] font-bold text-white/40">{label}</p>
      <p className={`security-num mt-1 text-xl font-black ${tone === "danger" ? "text-[#ff6b6b]" : "text-white"}`}>{value}</p>
    </div>
  );
}
