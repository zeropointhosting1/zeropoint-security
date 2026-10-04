import type { LiveAlert, ThreatKind } from "./types";

export const KIND_COLOR: Record<ThreatKind, string> = {
  scanner: "#ffb020",
  malware: "#c48aff",
  reputation: "#78a8ef",
  botnet: "#ff3b6b",
  ddos: "#ff7a1a",
};
export const VICTIM_COLOR = "#ffe14d";
export const SAMPLE_COLOR = "#b5e853";
export const HONEYPOT_COLOR = "#5ef0c0";

export const KIND_LABEL: Record<ThreatKind, string> = {
  scanner: "Attacking host",
  malware: "Payload host",
  reputation: "Blocklisted IP",
  botnet: "Malware C2",
  ddos: "DDoS botnet",
};

export function alertColor(kind: LiveAlert["kind"]): string {
  if (kind === "ransomware") return VICTIM_COLOR;
  if (kind === "sample") return SAMPLE_COLOR;
  if (kind === "honeypot") return HONEYPOT_COLOR;
  return KIND_COLOR[kind];
}

export function alertLabel(kind: LiveAlert["kind"]): string {
  if (kind === "ransomware") return "Ransomware";
  if (kind === "sample") return "New sample";
  if (kind === "honeypot") return "Honeypot hit";
  return KIND_LABEL[kind];
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

export function compact(n: number): string {
  return Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function timeAgo(iso: string): string {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}
