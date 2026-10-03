"use client";

import { useEffect, useRef, useState } from "react";
import type { LiveAlert, Threat } from "@/lib/types";
import { KIND_LABEL, alertColor, alertLabel, timeAgo } from "@/lib/format";

interface Props {
  alert: LiveAlert;
  /** The merged indicator for this IP, if it is on the globe. */
  indicator: Threat | null;
  onClose: () => void;
  onInspectIndicator: (t: Threat) => void;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="ed-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="ed-copy"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

/** Full investigation view for one live event. */
export default function EventDetail({ alert: a, indicator, onClose, onInspectIndicator }: Props) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const color = alertColor(a.kind);
  const when = new Date(a.time);
  const ipQ = a.ip ? encodeURIComponent(a.ip) : "";
  const lookups: Array<[string, string]> = [];
  if (a.link) lookups.push([`View on ${a.source}`, a.link]);
  if (a.ip) {
    lookups.push(
      ["AbuseIPDB", `https://www.abuseipdb.com/check/${ipQ}`],
      ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${ipQ}`],
      ["Shodan", `https://www.shodan.io/host/${ipQ}`],
      ["GreyNoise", `https://viz.greynoise.io/ip/${ipQ}`],
    );
  }
  if (a.sha256) lookups.push(["VirusTotal", `https://www.virustotal.com/gui/file/${a.sha256}`]);
  if (a.group) lookups.push([`${a.group} on Ransomware.live`, `https://www.ransomware.live/group/${encodeURIComponent(a.group.toLowerCase())}`]);

  return (
    <div className="ed-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <section className="ed-panel" role="dialog" aria-modal="true" aria-labelledby="ed-title" style={{ ["--c" as string]: color }}>
        <header className="ed-head">
          <span className="badge live">{alertLabel(a.kind).toUpperCase()}</span>
          <button ref={closeRef} onClick={onClose} aria-label="Close event details">✕</button>
        </header>
        <h3 id="ed-title">{a.title}</h3>
        <p className="ed-sub">
          Published {timeAgo(a.time)} · {when.toLocaleString()} · {a.source}
        </p>

        <dl className="ed-grid">
          {a.ip && (
            <Row label="Indicator">
              <code>{a.ip}{a.port ? `:${a.port}` : ""}</code> <CopyButton text={a.ip} />
            </Row>
          )}
          {(a.city || a.country) && <Row label="Location">{[a.city, a.country].filter(Boolean).join(", ")}{a.countryCode ? ` (${a.countryCode})` : ""}</Row>}
          {a.malware && <Row label="Malware family">{a.malware}</Row>}
          {a.activity && <Row label="Activity">{a.activity}</Row>}
          {a.confidence !== undefined && <Row label="Source confidence">{a.confidence}%</Row>}
          {a.sha256 && (
            <Row label="SHA256">
              <code className="ed-hash">{a.sha256}</code> <CopyButton text={a.sha256} />
            </Row>
          )}
          {a.fileType && <Row label="File type">{a.fileType}</Row>}
          {a.group && <Row label="Ransomware group">{a.group}</Row>}
          {a.victim && <Row label="Claimed victim">{a.victim}</Row>}
          {a.sector && <Row label="Sector">{a.sector}</Row>}
          {a.domain && <Row label="Domain">{a.domain}</Row>}
          {typeof a.lat === "number" && typeof a.lon === "number" && (
            <Row label="Coordinates">{a.lat.toFixed(3)}, {a.lon.toFixed(3)}{a.kind === "ransomware" ? " (country level)" : " (approximate)"}</Row>
          )}
        </dl>

        {a.description && <p className="ed-desc">{a.description}</p>}

        {indicator && (
          <div className="ed-indicator">
            <div>
              <span className="eyebrow">ON THE GLOBE</span>
              <p>
                Classified as <b>{KIND_LABEL[indicator.kind]}</b>
                {indicator.feeds.length > 1 ? ` · corroborated by ${indicator.feeds.length} feeds: ${indicator.feeds.join(", ")}` : ` · ${indicator.source}`}
              </p>
            </div>
            <button onClick={() => onInspectIndicator(indicator)}>Inspect indicator →</button>
          </div>
        )}

        {lookups.length > 0 && (
          <div className="ed-links">
            <span className="eyebrow">INVESTIGATE</span>
            <div>
              {lookups.map(([label, href]) => (
                <a key={href} href={href} target="_blank" rel="noreferrer noopener">{label} ↗</a>
              ))}
            </div>
          </div>
        )}
        {a.kind === "ransomware" && <p className="ed-note">Ransomware leak-site claims are unverified statements by the criminal group.</p>}
      </section>
    </div>
  );
}
