"use client";
import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { LiveAlert, Threat, ThreatKind, ThreatPayload } from "@/lib/types";
import { KIND_LABEL, alertColor, alertLabel, compact, timeAgo } from "@/lib/format";
import { useLiveStream } from "./useLiveStream";
import EventDetail from "./EventDetail";
import type { Beacon } from "./GlobeView";

const GlobeView = dynamic(() => import("./GlobeView"), {
  ssr: false,
  loading: () => <div className="globe-loading">Establishing orbital view...</div>,
});

const EMPTY: Threat[] = [];
/** Warn when the collector has not uploaded fresh data for this long. */
const STALE_MS = 30 * 60_000;
/** Rendering tens of thousands of cards would freeze the page; search narrows the rest. */
const LIST_LIMIT = 200;
/** One filter drives the globe, live alerts, beacons and the indicator list. */
type Scope = "all" | ThreatKind | "ransomware";
const FILTERS: Array<[Scope, string]> = [
  ["all", "Everything"],
  ["ddos", "DDoS"],
  ["botnet", "Malware C2"],
  ["malware", "Payload hosts"],
  ["ransomware", "Ransomware"],
  ["scanner", "Attackers"],
  ["reputation", "Blocklisted"],
];
const inScope = (scope: Scope, kind: LiveAlert["kind"]) => scope === "all" || kind === scope;
const PENDING_SOURCES = ["DShield", "ThreatFox", "URLhaus", "IPsum", "CINS Army", "blocklist.de", "Ransomware.live", "CISA KEV"];

type Tab = "live" | "indicators" | "ransomware" | "vulnerabilities";

export default function Dashboard() {
  const [data, setData] = useState<ThreatPayload | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Scope>("all");
  const [openEvent, setOpenEvent] = useState<LiveAlert | null>(null);
  const [tab, setTab] = useState<Tab>("live");
  const [selected, setSelected] = useState<Threat | null>(null);
  const [rotating, setRotating] = useState(true);
  const [followLive, setFollowLive] = useState(false);
  const live = useLiveStream();
  const [ack, setAck] = useState<string[]>([]);
  const [, tick] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threats");
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Feed request failed");
      setData(json);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 300000);
    const clock = setInterval(() => tick((n) => n + 1), 10000);
    return () => {
      clearInterval(id);
      clearInterval(clock);
    };
  }, [load]);

  const threats = data?.threats ?? EMPTY;
  const visible = useMemo(() => {
    const q = query.toLowerCase();
    return threats.filter(
      (t) =>
        inScope(filter, t.kind) &&
        `${t.ip} ${t.country} ${t.city} ${t.malware ?? ""} ${t.activity ?? ""} ${t.feeds.join(" ")}`
          .toLowerCase()
          .includes(q),
    );
  }, [threats, filter, query]);

  const victims = data?.ransomware ?? [];
  const totals = data?.totals;
  const sources = data?.sources ?? [];
  const online = sources.filter((s) => s.status === "online").length;
  const topCountries = data?.topCountries ?? [];
  const topPorts = data?.topPorts ?? [];
  const topMalware = data?.topMalware ?? [];
  const ddosFlows = data?.ddosFlows ?? [];
  const ddosFamilies = data?.ddosFamilies ?? [];
  const showFlows = filter === "all" || filter === "ddos";
  const stream = useMemo(() => live.stream.filter((a) => inScope(filter, a.kind)), [live.stream, filter]);
  const indicatorByIp = useMemo(() => new Map(threats.map((t) => [t.ip, t])), [threats]);

  // An event being inspected gets a pinned beacon and the camera flies to it.
  const pinned = useMemo<Beacon | null>(
    () =>
      openEvent && typeof openEvent.lat === "number" && typeof openEvent.lon === "number"
        ? {
            id: `pin-${openEvent.id}`,
            lat: openEvent.lat,
            lon: openEvent.lon,
            color: alertColor(openEvent.kind),
            label: `${alertLabel(openEvent.kind)} · ${openEvent.countryCode ?? ""}`,
            kind: openEvent.kind,
            pinned: true,
          }
        : null,
    [openEvent],
  );
  const beacons = useMemo(
    () => [...live.beacons.filter((b) => inScope(filter, b.kind)), ...(pinned ? [pinned] : [])],
    [live.beacons, filter, pinned],
  );
  const closeEvent = useCallback(() => setOpenEvent(null), []);

  function openAlert(a: LiveAlert) {
    setOpenEvent(a);
    setSelected(null);
    setRotating(false);
  }

  function focus(t: Threat) {
    setSelected(t);
    setRotating(false);
  }

  const metrics: Array<[string, string, string, string]> = [
    ["TRACKED INDICATORS", totals ? compact(totals.indicators) : "—", `Malicious IPs across ${online || "—"} live feeds`, "var(--cyan)"],
    ["LIVE EVENTS", data ? compact(data.alerts.length) : "—", "Latest timestamped reports (24h)", "#ff4d6d"],
    ["DDOS BOTNET NODES", totals ? compact(totals.byKind.ddos) : "—", "Mirai, Mozi, Gafgyt & kin", "var(--orange)"],
    ["MALWARE INFRASTRUCTURE", totals ? compact(totals.byKind.botnet + totals.byKind.malware) : "—", "C2 servers & payload hosts", "var(--red)"],
    ["SOURCE COUNTRIES", totals ? String(totals.countries) : "—", "Observed hostile infrastructure", "var(--text)"],
    ["KNOWN EXPLOITED CVEs", data ? compact(data.kevTotal) : "—", "CISA vulnerability catalog", "var(--amber)"],
    ["RANSOMWARE CLAIMS", data ? String(victims.length) : "—", "Latest leak-site victims", "var(--yellow)"],
    ["ACTIVE ATTACKERS", totals ? compact(totals.byKind.scanner) : "—", "Scanning & brute-force sources", "var(--amber)"],
    ["NEW MALWARE SAMPLES", totals ? compact(totals.malwareSamples) : "—", "MalwareBazaar, last hour", "var(--purple)"],
    ["NEW CVEs · 7 DAYS", totals ? compact(totals.newCves7d) : "—", `NVD · plus ${totals ? totals.phishingUrls : "—"} live phishing URLs`, "var(--blue)"],
  ];

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Zeropoint Security home">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img className="brand-logo" src="/zeropoint-mark.png" alt="" width={52} height={52} />
          <div>
            <h1><b>ZERO</b>POINT<span> SECURITY</span></h1>
            <p>GLOBAL THREAT INTELLIGENCE</p>
          </div>
        </a>
        <div className="header-right">
          <span className={`status ${online ? "online" : ""}`}>
            <i />
            {loading && !data ? "SYNCING FEEDS" : online ? `${online}/${sources.length} FEEDS ONLINE` : "FEEDS UNAVAILABLE"}
          </span>
          <button onClick={load} disabled={loading}>{loading ? "Syncing..." : "↻ Refresh"}</button>
        </div>
      </header>

      <section className="intro">
        <div>
          <p className="eyebrow">INTELLIGENCE / GLOBAL OVERVIEW</p>
          <h2>A world in motion.<span> Every signal matters.</span></h2>
        </div>
        <span className="updated">{data ? `Last sync ${timeAgo(data.updatedAt)}` : "Connecting to public intelligence"}</span>
      </section>

      {data && Date.now() - Date.parse(data.updatedAt) > STALE_MS && (
        <div className="notice" role="status">
          Data is stale: the collector last synced {timeAgo(data.updatedAt)}. Live feeds resume when it reconnects.
        </div>
      )}

      {(error || !!data?.errors.length) && (
        <div className="notice" role="status">Some intelligence is unavailable. {error || data?.errors.join(" · ")}</div>
      )}

      <section className="metrics" aria-label="Intelligence summary">
        {metrics.map(([label, value, note, color]) => (
          <div className="metric" key={label}>
            <span>{label}</span>
            <strong style={{ color }}>{loading && !data ? "—" : value}</strong>
            <small>{note}</small>
          </div>
        ))}
      </section>

      <section className="workspace">
        <div className="map-panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">GLOBAL TELEMETRY</span>
              <h3>Threat landscape</h3>
            </div>
            <div className="scope" role="group" aria-label="Show">
              {FILTERS.map(([key, label]) => (
                <button key={key} aria-pressed={filter === key} className={`scope-${key} ${filter === key ? "active" : ""}`} onClick={() => setFilter(key)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="map-stage">
            <GlobeView
              threats={visible}
              victims={filter === "all" || filter === "ransomware" ? victims : []}
              beacons={beacons}
              flows={showFlows ? ddosFlows : []}
              follow={pinned ?? (followLive && live.latest && inScope(filter, live.latest.kind) ? live.latest : null)}
              selected={selected}
              onSelect={focus}
              rotating={rotating && !followLive}
            />
            <div className="map-coordinate">
              SOURCE INTELLIGENCE<br />
              <span>
                {visible.length.toLocaleString()} mapped signals
                {totals && totals.geolocated > threats.length ? ` · top of ${compact(totals.geolocated)}` : ""}
              </span>
            </div>
            <div className="live-ticker" aria-live="polite" aria-label="Live alerts">
              <div className="live-ticker-head">
                <span className={`live-dot ${live.connected ? "on" : ""}`} />
                LIVE ALERTS
                {live.pending > 0 && <small>{live.pending} queued</small>}
              </div>
              {stream.slice(0, 4).map((a) => (
                <button className="ticker-item" key={a.id} style={{ ["--c" as string]: alertColor(a.kind) }} onClick={() => openAlert(a)} title="Open event details">
                  <span className="ticker-kind">{alertLabel(a.kind)}</span>
                  <strong>{a.title}</strong>
                  <span className="ticker-meta">{a.detail} · {timeAgo(a.time)}</span>
                </button>
              ))}
              {!stream.length && (
                <div className="ticker-item muted">
                  {!live.connected ? "Connecting to live feeds..." : filter === "all" ? "Waiting for the next report..." : "Waiting for matching reports..."}
                </div>
              )}
            </div>
            <div className="map-controls">
              <button aria-pressed={rotating} onClick={() => setRotating(!rotating)}>{rotating ? "Ⅱ Pause orbit" : "▷ Resume orbit"}</button>
              <button aria-pressed={followLive} className={followLive ? "active" : ""} onClick={() => setFollowLive(!followLive)}>
                {followLive ? "◉ Following live" : "◎ Follow live"}
              </button>
              <button onClick={() => { setSelected(null); setOpenEvent(null); setFollowLive(false); setRotating(true); }}>Reset view</button>
            </div>
          </div>
          <div className="map-legend">
            <span><i className="red" /> Malware C2</span>
            <span><i className="orange" /> DDoS botnet</span>
            <span><i className="purple" /> Payload host</span>
            <span><i className="amber" /> Attacker</span>
            <span><i className="blue" /> Blocklisted</span>
            <span><i className="yellow" /> Ransomware victim</span>
            <span><i className="beacon-dot" /> Live beacon</span>
            <small>Drag to explore · Scroll to zoom · Select a signal</small>
          </div>

          {selected && (
            <div className="inspector">
              <div className="inspector-head">
                <span className="eyebrow">SELECTED INDICATOR</span>
                <button onClick={() => setSelected(null)} aria-label="Close indicator details">✕</button>
              </div>
              <h3>{selected.ip}{selected.port ? `:${selected.port}` : ""} <span className={`badge ${selected.kind}`}>{KIND_LABEL[selected.kind].toUpperCase()}</span></h3>
              <p>{selected.city ? `${selected.city}, ` : ""}{selected.country} · {selected.activity ?? selected.source}</p>
              <dl>
                <div><dt>Reported by</dt><dd>{selected.feeds.join(", ")}</dd></div>
                <div><dt>Last observed</dt><dd>{selected.lastSeen || "Not provided"}</dd></div>
                {selected.malware && <div><dt>Malware family</dt><dd>{selected.malware}</dd></div>}
                {selected.reports > 0 && <div><dt>{selected.source === "IPsum" ? "Blocklists" : "Reported records"}</dt><dd>{compact(selected.reports)}</dd></div>}
                {selected.confidence !== undefined && <div><dt>Source confidence</dt><dd>{selected.confidence}%</dd></div>}
              </dl>
              <button onClick={() => setAck((prev) => prev.includes(selected.id) ? prev.filter((id) => id !== selected.id) : [...prev, selected.id])}>
                {ack.includes(selected.id) ? "✓ Reviewed · Undo" : "Mark reviewed"}
              </button>
              <small>Review status lasts for this session.</small>
            </div>
          )}

          <div className="insights">
            <div className="geography">
              <div className="panel-title"><h3>Source distribution</h3><span className="eyebrow">ALL INDICATORS</span></div>
              {topCountries.length ? topCountries.slice(0, 8).map((c, i) => (
                <div className="country-row" key={c.cc}>
                  <span className="rank">{String(i + 1).padStart(2, "0")}</span>
                  <span>{c.name}</span>
                  <div className="bar-track"><i style={{ width: `${(c.count / topCountries[0].count) * 100}%` }} /></div>
                  <strong>{compact(c.count)}</strong>
                </div>
              )) : <p className="empty">{loading ? "Locating source infrastructure..." : "No geolocated indicators available."}</p>}
            </div>
            <div className="geography">
              <div className="panel-title"><h3>Malware families</h3><span className="eyebrow">C2 · HOSTS · SAMPLES</span></div>
              {topMalware.slice(0, 8).map((m, i) => (
                <div className="country-row" key={m.name}>
                  <span className="rank">{String(i + 1).padStart(2, "0")}</span>
                  <span>{m.name}</span>
                  <div className="bar-track red"><i style={{ width: `${(m.count / topMalware[0].count) * 100}%` }} /></div>
                  <strong>{compact(m.count)}</strong>
                </div>
              ))}
              {!topMalware.length && <p className="empty">{loading ? "Classifying malware..." : "No malware families reported."}</p>}
            </div>
            <div className="geography">
              <div className="panel-title"><h3>Most attacked ports</h3><span className="eyebrow">DSHIELD · TODAY</span></div>
              {topPorts.slice(0, 8).map((p, i) => (
                <div className="country-row" key={p.port}>
                  <span className="rank">{String(i + 1).padStart(2, "0")}</span>
                  <span>Port {p.port}</span>
                  <div className="bar-track amber"><i style={{ width: `${(p.records / topPorts[0].records) * 100}%` }} /></div>
                  <strong>{compact(p.records)}</strong>
                </div>
              ))}
              {!topPorts.length && <p className="empty">{loading ? "Reading sensor network..." : "Port data unavailable."}</p>}
            </div>
            <div className="geography">
              {ddosFlows.length ? (
                <>
                  <div className="panel-title"><h3>DDoS attack flows</h3><span className="eyebrow">CLOUDFLARE RADAR · 24H</span></div>
                  {ddosFlows.slice(0, 8).map((f, i) => (
                    <div className="country-row" key={f.id}>
                      <span className="rank">{f.layer}</span>
                      <span title={`${f.origin} → ${f.target}`}>{f.originCc} → {f.targetCc}</span>
                      <div className="bar-track orange"><i style={{ width: `${(f.share / ddosFlows[0].share) * 100}%` }} /></div>
                      <strong>{f.share.toFixed(1)}%</strong>
                    </div>
                  ))}
                </>
              ) : (
                <>
                  <div className="panel-title"><h3>DDoS botnets</h3><span className="eyebrow">{totals ? `${compact(totals.byKind.ddos)} NODES` : "NODES"}</span></div>
                  {ddosFamilies.map((f, i) => (
                    <div className="country-row" key={f.name}>
                      <span className="rank">{String(i + 1).padStart(2, "0")}</span>
                      <span>{f.name}</span>
                      <div className="bar-track orange"><i style={{ width: `${(f.count / ddosFamilies[0].count) * 100}%` }} /></div>
                      <strong>{compact(f.count)}</strong>
                    </div>
                  ))}
                  {!ddosFamilies.length && <p className="empty">{loading ? "Finding DDoS infrastructure..." : "No DDoS botnet nodes reported."}</p>}
                  <p className="hint">
                    {data?.ddosFlowsEnabled
                      ? "Cloudflare Radar is configured but returned no flows. Check the token's Radar permission."
                      : <>Add a free <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noreferrer">Cloudflare API token</a> as <code>CLOUDFLARE_API_TOKEN</code> in <code>.env.local</code> to draw live DDoS attack flows on the globe.</>}
                  </p>
                </>
              )}
            </div>
          </div>
        </div>

        <aside className="intel-panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">INVESTIGATION QUEUE</span>
              <h3>Intelligence alerts <span className="count">{tab === "live" ? stream.length : tab === "indicators" ? visible.length.toLocaleString() : tab === "ransomware" ? victims.length : data?.kev.length ?? 0}</span></h3>
            </div>
            <span className="signal-icon">⌁</span>
          </div>
          <div className="tabs">
            <button className={tab === "live" ? "active" : ""} onClick={() => setTab("live")}><span className={`live-dot ${live.connected ? "on" : ""}`} /> Live</button>
            <button className={tab === "indicators" ? "active" : ""} onClick={() => setTab("indicators")}>Indicators</button>
            <button className={tab === "ransomware" ? "active" : ""} onClick={() => setTab("ransomware")}>Ransomware</button>
            <button className={tab === "vulnerabilities" ? "active" : ""} onClick={() => setTab("vulnerabilities")}>Exploited CVEs</button>
          </div>

          {tab === "live" && (
            <>
              <p className="queue-note">
                Real reports streaming in the order feeds published them · source timestamps · feeds publish every few minutes
                {live.pending > 0 ? ` · ${live.pending} queued` : ""}
              </p>
              <div className="alert-list">
                {stream.map((a) => (
                  <button className={`alert-card live ${openEvent?.id === a.id ? "selected" : ""}`} key={a.id} style={{ ["--c" as string]: alertColor(a.kind) }} onClick={() => openAlert(a)}>
                    <div className="alert-top">
                      <span className="badge live">{alertLabel(a.kind).toUpperCase()}</span>
                      <span>{timeAgo(a.time)}</span>
                    </div>
                    <h4>{a.title}</h4>
                    <code>{a.detail}</code>
                    <div className="alert-bottom">
                      <span>{a.source}{a.countryCode ? ` · ${a.countryCode}` : ""}</span>
                      <span>Details →</span>
                    </div>
                  </button>
                ))}
                {!stream.length && (
                  <div className="empty">
                    <strong>{live.connected ? "Waiting for the next report..." : "Connecting to live feeds..."}</strong>
                    <p>New C2 servers, DDoS bots, malware samples and ransomware claims appear here as they are published.</p>
                  </div>
                )}
              </div>
            </>
          )}

          {tab === "indicators" && (
            <>
              <div className="filters">
                <input aria-label="Search indicators" placeholder="Search IP, country, malware, feed..." value={query} onChange={(e) => setQuery(e.target.value)} />
                <p className="scope-note">Showing: <b>{FILTERS.find(([k]) => k === filter)?.[1]}</b> · change with the filter above the globe</p>
              </div>
              <p className="queue-note">
                Ranked by severity, then number of corroborating feeds
                {visible.length > LIST_LIMIT ? ` · showing ${LIST_LIMIT} of ${visible.length.toLocaleString()}, search to narrow` : ""}
              </p>
              <div className="alert-list">
                {visible.slice(0, LIST_LIMIT).map((t) => (
                  <button key={t.id} className={`alert-card ${t.kind} ${selected?.id === t.id ? "selected" : ""}`} onClick={() => focus(t)}>
                    <div className="alert-top">
                      <span className={`badge ${t.kind}`}>{KIND_LABEL[t.kind].toUpperCase()}</span>
                      <span>{ack.includes(t.id) ? "✓ Reviewed" : t.countryCode}</span>
                    </div>
                    <h4>{(t.malware !== "Unknown malware" && t.malware) || t.activity || "Malicious host"}<span>↗</span></h4>
                    <code>{t.ip}{t.port ? `:${t.port}` : ""}</code>
                    <p>{t.city || t.country} · {t.malware ? t.activity : t.source}</p>
                    <div className="alert-bottom">
                      <span>
                        {t.feeds.length > 1
                          ? `Corroborated by ${t.feeds.length} feeds`
                          : t.kind === "scanner" && t.reports
                            ? `${compact(t.reports)} reports`
                            : t.confidence !== undefined
                              ? `${t.confidence}% source confidence`
                              : t.source}
                      </span>
                      <span>Inspect →</span>
                    </div>
                  </button>
                ))}
                {!visible.length && (
                  <div className="empty">
                    <strong>{loading ? "Collecting intelligence..." : filter === "ransomware" ? "Ransomware claims have no IP indicators" : "No matching indicators"}</strong>
                    <p>
                      {loading
                        ? "Public feeds may take a moment to respond."
                        : filter === "ransomware"
                          ? "See the Ransomware and Live tabs for victim claims."
                          : "Try another filter or refresh the feeds."}
                    </p>
                  </div>
                )}
              </div>
            </>
          )}

          {tab === "ransomware" && (
            <>
              <p className="queue-note">Victims claimed on ransomware leak sites · via Ransomware.live · unverified claims</p>
              <div className="alert-list">
                {victims.map((v) => (
                  <article className="alert-card victim" key={v.id}>
                    <div className="alert-top">
                      <span className="badge victim">{v.group.toUpperCase()}</span>
                      <span>{v.countryCode}</span>
                    </div>
                    <h4>{v.victim}</h4>
                    <p>{v.country} · {v.sector}</p>
                    <div className="alert-bottom">
                      <span>Discovered {v.discovered ? timeAgo(v.discovered) : "recently"}</span>
                    </div>
                  </article>
                ))}
                {!victims.length && <p className="empty">{loading ? "Loading ransomware claims..." : "Ransomware feed unavailable."}</p>}
              </div>
            </>
          )}

          {tab === "vulnerabilities" && (
            <>
              <p className="queue-note">Recent CISA additions · EPSS = 30-day exploitation probability</p>
              <div className="alert-list">
                {data?.kev.map((v) => (
                  <article className="alert-card vulnerability" key={v.cveID}>
                    <div className="alert-top"><span className="badge botnet">KNOWN EXPLOITED</span><span>{v.dateAdded}</span></div>
                    <h4><a href={`https://nvd.nist.gov/vuln/detail/${v.cveID}`} target="_blank" rel="noreferrer">{v.cveID} ↗</a></h4>
                    <strong>{v.vendorProject} {v.product}</strong>
                    <p>{v.shortDescription}</p>
                    <div className="alert-bottom">
                      <span>{v.epss !== undefined ? `EPSS ${(v.epss * 100).toFixed(1)}%` : "EPSS unavailable"}</span>
                      {v.knownRansomwareCampaignUse === "Known" && <span className="ransomware">Ransomware use</span>}
                    </div>
                  </article>
                ))}
                {!data?.kev.length && <p className="empty">{loading ? "Loading vulnerabilities..." : "Vulnerability feed unavailable."}</p>}
              </div>
            </>
          )}
        </aside>
      </section>

      <section className="source-strip">
        <span className="eyebrow">INTELLIGENCE NETWORK · {sources.length || "—"} SOURCES</span>
        {(sources.length ? sources : PENDING_SOURCES.map((name) => ({ name, status: "pending" as const, count: 0, url: "" }))).map((s) => (
          <span key={s.name} title={`${s.count.toLocaleString()} records returned`}>
            <i className={s.status} />
            {s.url ? <a href={s.url} target="_blank" rel="noreferrer">{s.name}</a> : s.name}
            <small>{s.status === "online" ? `${compact(s.count)} records` : s.status === "error" ? "Unavailable" : "Connecting"}</small>
          </span>
        ))}
      </section>
      {openEvent && (
        <EventDetail
          alert={openEvent}
          indicator={openEvent.ip ? indicatorByIp.get(openEvent.ip) ?? null : null}
          onClose={closeEvent}
          onInspectIndicator={(t) => { setOpenEvent(null); setTab("indicators"); focus(t); }}
        />
      )}
      <footer>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img className="footer-logo" src="/zeropoint-logo.png" alt="Zeropoint" width={150} height={136} />
        <span>
          Public threat intelligence, refreshed every 5 minutes. Indicators are source reports, not attacks against your
          network. IP locations are approximate (IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a>);
          ransomware victims are placed at country level.
        </span>
      </footer>
    </main>
  );
}
