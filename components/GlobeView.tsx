"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Globe, { type GlobeMethods } from "react-globe.gl";
import type { DdosFlow, HoneypotArc, HoneypotStats, LiveAlert, RansomwareVictim, Threat } from "@/lib/types";
import { KIND_COLOR, KIND_LABEL, VICTIM_COLOR, escapeHtml } from "@/lib/format";

const TEXTURES = "https://unpkg.com/three-globe@2.45.0/example/img";
const DDOS_COLOR = KIND_COLOR.ddos;
const HONEYPOT_COLOR = "#5ef0c0";

/** A live alert that has just fired at a real location. */
export interface Beacon {
  id: string;
  lat: number;
  lon: number;
  color: string;
  label: string;
  kind: LiveAlert["kind"];
  /** Pinned beacons (an event being inspected) stay lit instead of fading out. */
  pinned?: boolean;
}

interface Props {
  threats: Threat[];
  victims: RansomwareVictim[];
  beacons: Beacon[];
  flows: DdosFlow[];
  /** Zeropoint honeypot: attacker → sensor lines. */
  honeypotArcs: HoneypotArc[];
  sensor: HoneypotStats["sensor"];
  /** Fly to this beacon (follow-live mode). */
  follow: Beacon | null;
  selected: Threat | null;
  onSelect: (threat: Threat) => void;
  rotating: boolean;
}

/** DDoS flows and honeypot attacks share the arc layer. */
type Arc =
  | ({ type: "ddos" } & DdosFlow)
  | ({ type: "honeypot"; targetLat: number; targetLon: number; target: string } & HoneypotArc);

interface Ring {
  lat: number;
  lon: number;
  color: string;
  maxR: number;
  period: number;
  speed: number;
}

function fade(hex: string) {
  return (t: number) => `${hex}${Math.round((1 - t) * 255).toString(16).padStart(2, "0")}`;
}

function beaconElement(b: Beacon): HTMLElement {
  const el = document.createElement("div");
  el.className = b.pinned ? "beacon pinned" : "beacon";
  el.style.setProperty("--c", b.color);
  el.innerHTML = `<span class="beacon-beam"></span><span class="beacon-core"></span><span class="beacon-label">${escapeHtml(b.label)}</span>`;
  return el;
}

export default function GlobeView({ threats, victims, beacons, flows, honeypotArcs, sensor, follow, selected, onSelect, rotating }: Props) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 800, h: 800 });

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      setSize({ w: entry.contentRect.width, h: entry.contentRect.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Pull the camera back on narrow screens so the whole globe stays in view.
  const altitude = size.w < 500 ? 2.5 : 1.95;

  const onReady = () => {
    const g = globeRef.current;
    if (!g) return;
    const controls = g.controls();
    controls.autoRotate = rotating && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    controls.autoRotateSpeed = 0.3;
    controls.enableDamping = true;
    g.pointOfView({ lat: 25, lng: 10, altitude }, 0);
  };

  useEffect(() => {
    globeRef.current?.pointOfView({ altitude }, 600);
  }, [altitude]);

  useEffect(() => {
    const g = globeRef.current;
    if (g) g.controls().autoRotate = rotating && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, [rotating]);
  useEffect(() => {
    globeRef.current?.pointOfView(selected ? { lat: selected.lat, lng: selected.lon, altitude: 1.5 } : { lat: 25, lng: 10, altitude }, 900);
  }, [selected, altitude]);
  useEffect(() => {
    if (follow && !selected) globeRef.current?.pointOfView({ lat: follow.lat, lng: follow.lon, altitude: 1.7 }, 1200);
  }, [follow, selected]);

  const maxReports = useMemo(
    () => threats.reduce((m, t) => Math.max(m, t.reports), 1),
    [threats],
  );
  const maxShare = useMemo(() => flows.reduce((m, f) => Math.max(m, f.share), 1), [flows]);
  const arcs = useMemo<Arc[]>(
    () => [
      ...flows.map((f) => ({ type: "ddos" as const, ...f })),
      ...(sensor
        ? honeypotArcs.map((a) => ({
            type: "honeypot" as const,
            ...a,
            targetLat: sensor.lat,
            targetLon: sensor.lon,
            target: [sensor.city, sensor.country].filter(Boolean).join(", "),
          }))
        : []),
    ],
    [flows, honeypotArcs, sensor],
  );

  // Live beacons get a fast shockwave, ransomware victims a slow pulse,
  // and the selected indicator a strong ring.
  const rings = useMemo<Ring[]>(() => {
    const r: Ring[] = victims.map((v) => ({ lat: v.lat, lon: v.lon, color: VICTIM_COLOR, maxR: 2.2, period: 2200, speed: 2 }));
    for (const b of beacons) r.push({ lat: b.lat, lon: b.lon, color: b.color, maxR: 6, period: 900, speed: 5 });
    if (selected) r.push({ lat: selected.lat, lon: selected.lon, color: KIND_COLOR[selected.kind], maxR: 3.5, period: 700, speed: 3 });
    // The honeypot itself: a steady mint pulse where the attack lines land.
    if (sensor && honeypotArcs.length) r.push({ lat: sensor.lat, lon: sensor.lon, color: HONEYPOT_COLOR, maxR: 4, period: 1400, speed: 2.5 });
    return r;
  }, [victims, beacons, selected, sensor, honeypotArcs.length]);

  return (
    <div ref={wrapRef} className="globe-wrap">
      <Globe
        ref={globeRef}
        width={size.w}
        height={size.h}
        onGlobeReady={onReady}
        globeImageUrl={`${TEXTURES}/earth-night.jpg`}
        bumpImageUrl={`${TEXTURES}/earth-topology.png`}
        backgroundColor="rgba(0,0,0,0)"
        atmosphereColor="#3aa8ff"
        atmosphereAltitude={0.14}
        globeCurvatureResolution={2}
        onPointClick={(d) => onSelect(d as Threat)}
        // Every geolocated indicator as a pillar; height scales with report volume
        pointsData={threats}
        pointLat={(d) => (d as Threat).lat}
        pointLng={(d) => (d as Threat).lon}
        pointColor={(d) => KIND_COLOR[(d as Threat).kind]}
        pointAltitude={(d) =>
          0.008 + 0.045 * Math.sqrt((d as Threat).reports / maxReports)
        }
        pointRadius={(d) => (d as Threat).id === selected?.id ? 0.7 : 0.2}
        pointResolution={6}
        pointsMerge={false}
        pointsTransitionDuration={0}
        // Tooltips are HTML strings: every value from the payload goes through escapeHtml,
        // numbers included, so a tampered payload cannot inject markup.
        pointLabel={(d) => {
          const t = d as Threat;
          return `<div class="globe-tip">
            <b style="color:${KIND_COLOR[t.kind] ?? ""}">${escapeHtml(KIND_LABEL[t.kind] ?? "")}</b><br/>
            <code>${escapeHtml(`${t.ip}${t.port ? `:${t.port}` : ""}`)}</code><br/>
            ${escapeHtml([t.city, t.country].filter(Boolean).join(", "))}<br/>
            ${t.malware ? `Malware: ${escapeHtml(t.malware)}<br/>` : ""}
            ${t.activity ? `${escapeHtml(t.activity)}<br/>` : ""}
            ${t.kind === "scanner" && t.reports ? `Reports: ${escapeHtml(t.reports.toLocaleString())}<br/>` : ""}
            Feeds: ${escapeHtml(t.feeds.join(", "))}
          </div>`;
        }}
        // Ransomware leak-site victims (at country level)
        labelsData={victims}
        labelLat={(d) => (d as RansomwareVictim).lat}
        labelLng={(d) => (d as RansomwareVictim).lon}
        labelText={() => ""}
        labelDotRadius={0.45}
        labelColor={() => VICTIM_COLOR}
        labelAltitude={0.004}
        labelLabel={(d) => {
          const v = d as RansomwareVictim;
          return `<div class="globe-tip">
            <b style="color:${VICTIM_COLOR}">Ransomware victim claim</b><br/>
            ${escapeHtml(v.victim)}<br/>
            Group: ${escapeHtml(v.group)}<br/>
            ${escapeHtml(v.country)} · ${escapeHtml(v.sector)}
          </div>`;
        }}
        ringsData={rings}
        ringLat={(d) => (d as Ring).lat}
        ringLng={(d) => (d as Ring).lon}
        ringColor={(d: object) => fade((d as Ring).color)}
        ringMaxRadius={(d) => (d as Ring).maxR}
        ringPropagationSpeed={(d) => (d as Ring).speed}
        ringRepeatPeriod={(d) => (d as Ring).period}
        // Live alert beacons: beam of light + label, hidden when behind the globe
        htmlElementsData={beacons}
        htmlLat={(d) => (d as Beacon).lat}
        htmlLng={(d) => (d as Beacon).lon}
        htmlAltitude={0}
        htmlElement={(d) => beaconElement(d as Beacon)}
        htmlElementVisibilityModifier={(el, visible) => {
          el.style.opacity = visible ? "1" : "0";
        }}
        htmlTransitionDuration={0}
        // Real DDoS attack flows (Cloudflare Radar), thickness = share of attacks,
        // plus attacks on the Zeropoint honeypot (attacker → sensor)
        arcsData={arcs}
        arcStartLat={(d) => (d as Arc).type === "ddos" ? (d as DdosFlow).originLat : (d as HoneypotArc).lat}
        arcStartLng={(d) => (d as Arc).type === "ddos" ? (d as DdosFlow).originLon : (d as HoneypotArc).lon}
        arcEndLat={(d) => (d as Arc).targetLat}
        arcEndLng={(d) => (d as Arc).targetLon}
        arcColor={(d: object) => {
          const c = (d as Arc).type === "ddos" ? DDOS_COLOR : HONEYPOT_COLOR;
          return [`${c}22`, c];
        }}
        arcStroke={(d) => {
          const a = d as Arc;
          return a.type === "ddos" ? 0.25 + 1.2 * (a.share / maxShare) : 0.3;
        }}
        arcDashLength={0.35}
        arcDashGap={0.65}
        arcDashAnimateTime={(d) => {
          const a = d as Arc;
          return a.type === "honeypot" ? 2200 : a.layer === "L7" ? 2600 : 1800;
        }}
        arcAltitudeAutoScale={0.35}
        arcLabel={(d) => {
          const a = d as Arc;
          if (a.type === "honeypot") {
            return `<div class="globe-tip">
            <b style="color:${HONEYPOT_COLOR}">Attack on Zeropoint honeypot</b><br/>
            ${escapeHtml([a.city, a.country].filter(Boolean).join(", "))} → ${escapeHtml(a.target)}<br/>
            ${escapeHtml(`${a.attackers.toLocaleString()} attacker${a.attackers === 1 ? "" : "s"} · ${a.sessions.toLocaleString()} session${a.sessions === 1 ? "" : "s"}`)}
          </div>`;
          }
          return `<div class="globe-tip">
            <b style="color:${DDOS_COLOR}">DDoS · ${a.layer === "L3" ? "network layer" : "application layer"}</b><br/>
            ${escapeHtml(a.origin)} → ${escapeHtml(a.target)}<br/>
            ${escapeHtml(`${Number(a.share).toFixed(1)}% of ${a.layer} attacks · last 24h`)}
          </div>`;
        }}
      />
    </div>
  );
}
