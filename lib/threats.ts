import type {
  DdosFlow,
  FeedStatus,
  HoneypotArc,
  HoneypotStats,
  LiveAlert,
  RansomwareVictim,
  Threat,
  ThreatKind,
  ThreatPayload,
  Vulnerability,
} from "./types";
import { lookup as resolveHost } from "node:dns/promises";
import { getGeoReader, geoipError, lookup, type Geo } from "./geoip";
import centroids from "./country-centroids.json";

const UA = "zeropoint-security/1.0 (educational dashboard)";
const CACHE_MS = 5 * 60 * 1000;

/** How many indicators of each kind are sent to the browser (keeps the globe smooth). */
const GLOBE_QUOTA: Record<ThreatKind, number> = {
  botnet: 2000,
  ddos: 1200,
  malware: 1200,
  scanner: 1500,
  reputation: 1000,
};
const KIND_RANK: Record<ThreatKind, number> = { botnet: 0, ddos: 1, malware: 2, scanner: 3, reputation: 4 };
const emptyKinds = (): Record<ThreatKind, number> => ({ botnet: 0, ddos: 0, malware: 0, scanner: 0, reputation: 0 });

/** Malware families whose job is flooding targets (IoT/Linux DDoS botnets). */
const DDOS_FAMILY =
  /mirai|mozi|gafgyt|bashlite|aisuru|xorddos|xor\.ddos|tsunami|kaiten|moobot|rapperbot|fodcha|satori|hajime|dofloo|kimwolf|eleven11|condi|ddos/i;
const isDdos = (...names: Array<string | null | undefined>) => names.some((n) => !!n && DDOS_FAMILY.test(n));

/** Records published within this window stream into the live alert ticker. */
const ALERT_WINDOW_MS = 24 * 60 * 60 * 1000;
const ALERT_LIMIT = 400;

const FEEDS = {
  dshieldSources: "https://isc.sans.edu/api/sources/attacks/150?json",
  dshieldTop: "https://isc.sans.edu/api/topips/records/1000?json",
  dshieldPorts: "https://isc.sans.edu/api/topports/records/12?json",
  threatfox: "https://threatfox.abuse.ch/export/json/recent/",
  feodo: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
  urlhaus: "https://urlhaus.abuse.ch/downloads/json_recent/",
  bazaar: "https://bazaar.abuse.ch/export/csv/recent/",
  c2intel: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
  ipsum: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
  blocklistde: "https://lists.blocklist.de/lists/all.txt",
  greensnow: "https://blocklist.greensnow.co/greensnow.txt",
  cins: "https://cinsscore.com/list/ci-badguys.txt",
  etCompromised: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
  spamhausDrop: "https://www.spamhaus.org/drop/drop_v4.json",
  openphish: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
  ransomware: "https://api.ransomware.live/v2/recentvictims",
  kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  epss: "https://api.first.org/data/v1/epss?cve=",
  nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  // Optional: real DDoS origin→target flows. Needs a free Cloudflare token with Radar read access.
  radar: "https://api.cloudflare.com/client/v4/radar/attacks",
  // Zeropoint's own Cowrie honeypot on the OVH VPS; both files are rebuilt every 5 minutes.
  // stats.json is public (counts and top lists, no IPs). attackers.json needs HONEYPOT_TOKEN:
  // its IPs are only geolocated here and never published.
  honeypot: "https://hp.zeropointhosting.com/stats.json",
  honeypotAttackers: "https://hp.zeropointhosting.com/private/attackers.json",
  // Fallback only, if the local DB-IP database is unavailable. Free tier: 15 batches/minute.
  ipApi: "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon",
};

/** Source name of the Cowrie honeypot Zeropoint runs itself. */
const HONEYPOT = "Zeropoint honeypot";

let cached: { at: number; data: ThreatPayload } | null = null;
let inflight: Promise<ThreatPayload> | null = null;
const ipApiCache = new Map<string, Geo | null>();

async function request(url: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(url, {
    ...init,
    headers: { "User-Agent": UA, ...init?.headers },
    signal: AbortSignal.timeout(30_000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${new URL(url).hostname} responded ${res.status}`);
  return res;
}

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await request(url, { ...init, headers: { Accept: "application/json", ...init?.headers } });
  return res.json() as Promise<T>;
}

async function getText(url: string): Promise<string> {
  return (await request(url)).text();
}

/** DShield zero-pads octets in some endpoints ("074.050.061.103"). */
function normalizeIp(ip: string): string {
  return ip
    .trim()
    .split(".")
    .map((o) => String(parseInt(o, 10)))
    .join(".");
}

const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isPublicIPv4(ip: string): boolean {
  if (!IPV4.test(ip)) return false;
  const p = ip.split(".").map(Number);
  if (p.some((n) => n > 255)) return false;
  const [a, b] = p;
  return !(
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    a >= 224
  );
}

/** Pulls the IPv4 addresses out of a plain one-IP-per-line blocklist. */
function parseIpList(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const ip = line.trim().split(/[\s,;#]/)[0];
    if (ip && IPV4.test(ip)) out.push(ip);
  }
  return out;
}

type RawThreat = Omit<Threat, "lat" | "lon" | "country" | "countryCode" | "city" | "feeds"> & {
  /** When the source published this record; recent ones become live alerts. */
  alertTime?: string;
};

function fromIps(
  source: string,
  ips: string[],
  kind: ThreatKind,
  activity: string,
  extra: Partial<RawThreat> = {},
): RawThreat[] {
  return ips.map((ip) => ({
    id: `${source}-${ip}`,
    ip,
    kind,
    reports: 0,
    lastSeen: "",
    source,
    activity,
    ...extra,
  }));
}

// ---------------------------------------------------------------- IP feeds

async function fetchDShield(): Promise<RawThreat[]> {
  const [sources, top] = await Promise.all([
    getJson<Array<{ ip: string; attacks: number; count: number; lastseen: string }>>(
      FEEDS.dshieldSources,
    ),
    getJson<Array<{ source: string; reports: number; targets: number }>>(FEEDS.dshieldTop),
  ]);

  const byIp = new Map<string, RawThreat>();
  const today = new Date().toISOString().slice(0, 10);
  for (const s of sources) {
    const ip = normalizeIp(s.ip);
    byIp.set(ip, {
      id: `ds-${ip}`,
      ip,
      kind: "scanner",
      reports: Number(s.count) || 0,
      targets: Number(s.attacks) || 0,
      lastSeen: s.lastseen,
      source: "SANS ISC DShield",
      activity: "Attacking DShield sensors",
    });
  }
  for (const t of top) {
    const ip = normalizeIp(t.source);
    const existing = byIp.get(ip);
    if (existing) {
      existing.reports = Math.max(existing.reports, Number(t.reports) || 0);
      existing.targets = Math.max(existing.targets ?? 0, Number(t.targets) || 0);
    } else {
      byIp.set(ip, {
        id: `ds-${ip}`,
        ip,
        kind: "scanner",
        reports: Number(t.reports) || 0,
        targets: Number(t.targets) || 0,
        // topips is a rolling "today" list
        lastSeen: today,
        source: "SANS ISC DShield",
        activity: "Attacking DShield sensors",
      });
    }
  }
  return [...byIp.values()];
}

interface ThreatFoxIoc {
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  malware_printable: string;
  first_seen_utc: string;
  last_seen_utc: string | null;
  confidence_level: number;
  tags: string | null;
}

async function fetchThreatFox(): Promise<RawThreat[]> {
  // The "recent" export is keyed by IOC id: { "123": [ioc], ... }
  const data = await getJson<Record<string, ThreatFoxIoc[]>>(FEEDS.threatfox);
  const iocs = Object.values(data)
    .flat()
    .filter((r) => r.ioc_type === "ip:port")
    .sort((a, b) =>
      (b.last_seen_utc ?? b.first_seen_utc).localeCompare(a.last_seen_utc ?? a.first_seen_utc),
    );

  // Most recent report per IP wins.
  const byIp = new Map<string, RawThreat>();
  for (const r of iocs) {
    const [ip, port] = r.ioc_value.split(":");
    if (byIp.has(ip)) continue;
    const c2 = r.threat_type === "botnet_cc";
    const ddos = isDdos(r.malware_printable, r.tags);
    byIp.set(ip, {
      id: `tf-${ip}`,
      ip,
      kind: ddos ? "ddos" : c2 ? "botnet" : "malware",
      alertTime: r.first_seen_utc.replace(" ", "T") + "Z",
      reports: 0,
      confidence: r.confidence_level,
      malware: r.malware_printable,
      port: Number(port) || undefined,
      lastSeen: (r.last_seen_utc ?? r.first_seen_utc).replace(" ", "T") + "Z",
      source: "abuse.ch ThreatFox",
      activity: ddos
        ? c2 ? "DDoS botnet C2" : "DDoS bot payload"
        : c2 ? "Command & control" : "Payload delivery",
    });
  }
  return [...byIp.values()];
}

async function fetchFeodo(): Promise<RawThreat[]> {
  const rows = await getJson<
    Array<{ ip_address: string; port: number; malware: string; last_online: string; status: string }>
  >(FEEDS.feodo);
  return rows.map((r) => ({
    id: `feodo-${r.ip_address}`,
    ip: r.ip_address,
    port: r.port,
    malware: r.malware,
    kind: "botnet" as const,
    reports: 0,
    lastSeen: r.last_online,
    source: "Feodo Tracker",
    activity: `Botnet C2 (${r.status})`,
  }));
}

/** Architecture/format tags that say nothing about the malware family. */
const GENERIC_TAGS = new Set([
  "32-bit", "64-bit", "elf", "exe", "dll", "mips", "mipsel", "arm", "arm7", "aarch64", "x86",
  "x86-64", "sh", "sh4", "powerpc", "sparc", "m68k", "i686", "zip", "rar", "bash", "script",
  "opendir", "ascii", "doc", "apk", "msi", "ps1", "js", "vbs", "hta", "lnk",
]);

/** First tag that names a malware family; skips arch/format tags and IP-like tags ("94-154-43-69"). */
function familyFromTags(tags: string[] | null): string | undefined {
  const tag = (tags ?? []).find((t) => !GENERIC_TAGS.has(t.toLowerCase()) && !/^\d+[-.]\d+/.test(t));
  // URLhaus tags are often lowercase ("mirai"); capitalize for display.
  return tag && tag === tag.toLowerCase() ? tag[0].toUpperCase() + tag.slice(1) : tag;
}

async function fetchUrlhaus(): Promise<RawThreat[]> {
  const data = await getJson<
    Record<string, Array<{ url: string; url_status: string; dateadded: string; tags: string[] | null }>>
  >(FEEDS.urlhaus);
  // Online URLs first so they win the de-duplication.
  const rows = Object.values(data)
    .flat()
    .sort((a, b) => Number(b.url_status === "online") - Number(a.url_status === "online"));
  const byIp = new Map<string, RawThreat>();
  for (const r of rows) {
    const [host, port] = (r.url.split("/")[2] ?? "").split(":");
    if (!IPV4.test(host) || byIp.has(host)) continue;
    const ddos = isDdos(...(r.tags ?? []));
    const added = r.dateadded.replace(" UTC", "Z").replace(" ", "T");
    byIp.set(host, {
      id: `uh-${host}`,
      ip: host,
      kind: ddos ? "ddos" : "malware",
      reports: 0,
      malware: familyFromTags(r.tags),
      port: Number(port) || undefined,
      lastSeen: added,
      alertTime: added,
      source: "abuse.ch URLhaus",
      activity: ddos
        ? "Distributing DDoS bot"
        : r.url_status === "online" ? "Serving malware (online)" : "Malware distribution",
    });
  }
  return [...byIp.values()];
}

async function fetchIpsum(): Promise<RawThreat[]> {
  // "ip<TAB>score" where score = number of blocklists that include the IP.
  const out: RawThreat[] = [];
  for (const line of (await getText(FEEDS.ipsum)).split("\n")) {
    if (line.startsWith("#")) continue;
    const [ip, score] = line.trim().split(/\s+/);
    const n = Number(score);
    if (ip && n >= 3) {
      out.push({
        id: `ipsum-${ip}`,
        ip,
        kind: "reputation",
        reports: n,
        lastSeen: "",
        source: "IPsum",
        activity: `Listed on ${n} public blocklists`,
      });
    }
  }
  return out;
}

async function fetchSpamhausDrop(): Promise<RawThreat[]> {
  const out: RawThreat[] = [];
  for (const line of (await getText(FEEDS.spamhausDrop)).split("\n")) {
    if (!line.trim()) continue;
    const row = JSON.parse(line) as { cidr?: string };
    if (!row.cidr) continue; // trailing metadata record
    // Locate the netblock by its first host address.
    const parts = row.cidr.split("/")[0].split(".").map(Number);
    parts[3] += 1;
    out.push({
      id: `drop-${row.cidr}`,
      ip: parts.join("."),
      kind: "reputation",
      reports: 0,
      lastSeen: "",
      source: "Spamhaus DROP",
      activity: `Hijacked netblock ${row.cidr}`,
    });
  }
  return out;
}

const listFeed =
  (source: string, url: string, kind: ThreatKind, activity: string, extra?: Partial<RawThreat>) =>
  async () =>
    fromIps(source, parseIpList(await getText(url)), kind, activity, extra);

const IP_FEEDS: Array<{ name: string; url: string; run: () => Promise<RawThreat[]> }> = [
  { name: "SANS ISC DShield", url: "https://isc.sans.edu/", run: fetchDShield },
  { name: "abuse.ch ThreatFox", url: "https://threatfox.abuse.ch/", run: fetchThreatFox },
  { name: "Feodo Tracker", url: "https://feodotracker.abuse.ch/", run: fetchFeodo },
  { name: "abuse.ch URLhaus", url: "https://urlhaus.abuse.ch/", run: fetchUrlhaus },
  {
    name: "C2IntelFeeds",
    url: "https://github.com/drb-ra/C2IntelFeeds",
    run: listFeed("C2IntelFeeds", FEEDS.c2intel, "botnet", "Command & control", { malware: "Cobalt Strike" }),
  },
  {
    name: "blocklist.de",
    url: "https://www.blocklist.de/",
    run: listFeed("blocklist.de", FEEDS.blocklistde, "scanner", "Brute force / attacks (fail2ban)"),
  },
  {
    name: "GreenSnow",
    url: "https://greensnow.co/",
    run: listFeed("GreenSnow", FEEDS.greensnow, "scanner", "Scanning / brute force"),
  },
  {
    name: "CINS Army",
    url: "https://cinsscore.com/",
    run: listFeed("CINS Army", FEEDS.cins, "reputation", "Poor reputation (Sentinel IPS)"),
  },
  {
    name: "Emerging Threats",
    url: "https://rules.emergingthreats.net/",
    run: listFeed("Emerging Threats", FEEDS.etCompromised, "reputation", "Known compromised host"),
  },
  { name: "IPsum", url: "https://github.com/stamparm/ipsum", run: fetchIpsum },
  { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/", run: fetchSpamhausDrop },
];

// ---------------------------------------------------------------- other intel

async function fetchKev(): Promise<{ list: Vulnerability[]; total: number }> {
  const data = await getJson<{ count: number; vulnerabilities: Vulnerability[] }>(FEEDS.kev);
  const list = [...data.vulnerabilities]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 20)
    .map((v) => ({
      cveID: v.cveID,
      vendorProject: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      shortDescription: v.shortDescription,
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
    }));
  return { list, total: data.count };
}

/** Stable offset in [-spread/2, spread/2] so victims in one country don't stack on one pixel. */
function jitter(seed: string, spread: number): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return ((Math.abs(h) % 1000) / 1000 - 0.5) * spread;
}

async function fetchRansomware(): Promise<RansomwareVictim[]> {
  const rows = await getJson<
    Array<{
      victim: string;
      group: string;
      country: string;
      activity: string;
      discovered: string;
      attackdate: string;
      url?: string;
      domain?: string;
      description?: string;
    }>
  >(FEEDS.ransomware);
  const table = centroids as unknown as Record<string, [number, number, string]>;
  const out: RansomwareVictim[] = [];
  for (const r of rows) {
    const cc = (r.country ?? "").toUpperCase();
    const c = table[cc];
    if (!c) continue;
    const id = `rw-${r.group}-${r.victim}`;
    out.push({
      id,
      victim: r.victim,
      group: r.group,
      country: c[2],
      countryCode: cc,
      lat: c[0] + jitter(id, 3),
      lon: c[1] + jitter(`${id}#`, 3),
      sector: r.activity && r.activity !== "Not Found" ? r.activity : "Unknown sector",
      discovered: r.discovered || r.attackdate,
      url: r.url?.startsWith("https://www.ransomware.live/") ? r.url : undefined,
      domain: r.domain || undefined,
      description: r.description ? r.description.slice(0, 500) : undefined,
    });
  }
  return out;
}

async function fetchTopPorts(): Promise<ThreatPayload["topPorts"]> {
  const data = await getJson<Record<string, unknown>>(FEEDS.dshieldPorts);
  return Object.values(data)
    .filter((p): p is { targetport: number; records: number; sources: number } =>
      typeof p === "object" && p !== null && "targetport" in p,
    )
    .map((p) => ({ port: Number(p.targetport), records: Number(p.records), sources: Number(p.sources) }));
}

async function fetchBazaar(): Promise<{ count: number; signatures: Map<string, number>; alerts: LiveAlert[] }> {
  const signatures = new Map<string, number>();
  const alerts: LiveAlert[] = [];
  let count = 0;
  for (const line of (await getText(FEEDS.bazaar)).split("\n")) {
    if (!line.trim() || line.startsWith("#")) continue;
    count++;
    // Columns are quoted and ", "-separated:
    // 0 first_seen, 1 sha256, 6 file_type, 8 signature
    const cols = line.split('", "').map((s) => s.replace(/"/g, "").trim());
    const sig = cols[8];
    const named = !!sig && sig !== "n/a";
    if (named) signatures.set(sig, (signatures.get(sig) ?? 0) + 1);
    if (cols[0] && cols[1]) {
      alerts.push({
        id: `mb-${cols[1]}`,
        time: cols[0].replace(" ", "T") + "Z",
        kind: "sample",
        title: named ? `New ${sig} sample` : `New malware sample (.${cols[6] || "bin"})`,
        detail: `SHA256 ${cols[1].slice(0, 16)}…`,
        source: "MalwareBazaar",
        sha256: cols[1],
        fileType: cols[6] || undefined,
        malware: named ? sig : undefined,
        link: `https://bazaar.abuse.ch/sample/${cols[1]}/`,
      });
    }
  }
  return { count, signatures, alerts };
}

interface RadarPair {
  originCountryAlpha2: string;
  originCountryName: string;
  targetCountryAlpha2: string;
  targetCountryName: string;
  value: string;
}

/** Real share of DDoS attacks between country pairs over the last day (Cloudflare Radar). */
async function fetchDdosFlows(token: string): Promise<DdosFlow[]> {
  const table = centroids as unknown as Record<string, [number, number, string]>;
  const layers: Array<["L3" | "L7", string]> = [
    ["L3", `${FEEDS.radar}/layer3/top/attacks?limit=15&dateRange=1d&format=json`],
    ["L7", `${FEEDS.radar}/layer7/top/attacks?limit=15&dateRange=1d&format=json`],
  ];
  const out: DdosFlow[] = [];
  for (const [layer, url] of layers) {
    const data = await getJson<{ result?: { top_0?: RadarPair[] } }>(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    for (const p of data.result?.top_0 ?? []) {
      const o = table[p.originCountryAlpha2];
      const t = table[p.targetCountryAlpha2];
      if (!o || !t) continue;
      out.push({
        id: `${layer}-${p.originCountryAlpha2}-${p.targetCountryAlpha2}`,
        layer,
        originCc: p.originCountryAlpha2,
        origin: p.originCountryName,
        originLat: o[0],
        originLon: o[1],
        targetCc: p.targetCountryAlpha2,
        target: p.targetCountryName,
        targetLat: t[0],
        targetLon: t[1],
        share: Number(p.value) || 0,
      });
    }
  }
  return out;
}

async function fetchNvdWeek(): Promise<number> {
  const end = new Date();
  const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
  const fmt = (d: Date) => d.toISOString().replace("Z", "");
  const data = await getJson<{ totalResults: number }>(
    `${FEEDS.nvd}?resultsPerPage=1&pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}`,
  );
  return data.totalResults;
}

async function fetchOpenPhish(): Promise<number> {
  return (await getText(FEEDS.openphish)).split("\n").filter((l) => l.startsWith("http")).length;
}

/** Usernames, passwords and commands are typed by attackers: keep them short and printable. */
function cleanPairs(v: unknown): [string, number][] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((p): p is [unknown, unknown] => Array.isArray(p) && p.length === 2)
    .map(([k, n]): [string, number] => [String(k ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 120), Number(n)])
    .filter(([, n]) => Number.isFinite(n) && n > 0)
    .slice(0, 10);
}

interface HoneypotAttacker {
  ip: string;
  sessions: number;
  last: string;
}

/** Recent attacker IPs from the honeypot's private file. Used for geolocation only. */
async function fetchHoneypotAttackers(): Promise<HoneypotAttacker[]> {
  const token = process.env.HONEYPOT_TOKEN?.trim();
  if (!token) return [];
  const d = await getJson<unknown>(FEEDS.honeypotAttackers, { headers: { Authorization: `Bearer ${token}` } });
  if (!Array.isArray(d)) return [];
  const out: HoneypotAttacker[] = [];
  // stats.py writes at most 500; the cap keeps a tampered feed from flooding the collector.
  for (const a of (d as Array<Record<string, unknown>>).slice(0, 500)) {
    const ip = typeof a?.ip === "string" ? a.ip.trim() : "";
    if (!isPublicIPv4(ip)) continue;
    const last = typeof a.last === "string" && !Number.isNaN(Date.parse(a.last)) ? new Date(a.last).toISOString() : "";
    const sessions = Number(a.sessions);
    out.push({ ip, sessions: Number.isFinite(sessions) && sessions > 0 ? sessions : 1, last });
  }
  return out;
}

async function fetchHoneypot(): Promise<HoneypotStats> {
  const d = await getJson<Record<string, unknown>>(FEEDS.honeypot);
  const num = (k: string) => (Number.isFinite(Number(d[k])) ? Number(d[k]) : 0);
  return {
    sessions: num("sessions"),
    uniqueIps: num("unique_ips"),
    failed: num("failed"),
    success: num("success"),
    topUsers: cleanPairs(d.top_users),
    topPasswords: cleanPairs(d.top_passwords),
    topCommands: cleanPairs(d.top_commands),
    updated: typeof d.updated === "string" ? d.updated : "",
    // Filled in by build() once geolocation is ready.
    topCountries: [],
    sensor: null,
    arcs: [],
  };
}

// ---------------------------------------------------------------- geolocation fallback

async function geolocateViaIpApi(ips: string[]): Promise<void> {
  // Stay inside the free tier: at most 10 batches (1,000 new IPs) per refresh.
  const missing = ips.filter((ip) => !ipApiCache.has(ip)).slice(0, 1000);
  for (let i = 0; i < missing.length; i += 100) {
    const rows = await getJson<Array<{ status: string; query: string } & Partial<Geo>>>(FEEDS.ipApi, {
      method: "POST",
      body: JSON.stringify(missing.slice(i, i + 100)),
      headers: { "Content-Type": "application/json" },
    });
    for (const r of rows) {
      ipApiCache.set(
        r.query,
        r.status === "success" && typeof r.lat === "number" && typeof r.lon === "number"
          ? { country: r.country ?? "Unknown", countryCode: r.countryCode ?? "??", city: r.city ?? "", lat: r.lat, lon: r.lon }
          : null,
      );
    }
  }
}

// ---------------------------------------------------------------- assembly

type Settled<T> = { ok: true; v: T } | { ok: false; e: unknown };
const settle = <T>(p: Promise<T>): Promise<Settled<T>> =>
  p.then((v) => ({ ok: true as const, v }), (e) => ({ ok: false as const, e }));

/** The page for an IP at the feed that reported it. */
function sourceLink(feed: string, ip: string): string | undefined {
  const q = encodeURIComponent(ip);
  if (feed === "abuse.ch ThreatFox") return `https://threatfox.abuse.ch/browse.php?search=ioc%3A${q}`;
  if (feed === "abuse.ch URLhaus") return `https://urlhaus.abuse.ch/host/${q}/`;
  if (feed === "Feodo Tracker") return `https://feodotracker.abuse.ch/browse/host/${q}/`;
  return undefined;
}

function errorText(reason: unknown): string {
  return String((reason as Error)?.message ?? reason);
}

async function build(): Promise<ThreatPayload> {
  const errors: string[] = [];
  const sources: FeedStatus[] = [];

  const radarToken = process.env.CLOUDFLARE_API_TOKEN?.trim();
  const [ipResults, kev, ransomware, topPorts, bazaar, nvd, phish, reader, ddosFlows, honeypot, hpAttackers] = await Promise.all([
    Promise.all(IP_FEEDS.map((f) => settle(f.run()))),
    settle(fetchKev()),
    settle(fetchRansomware()),
    settle(fetchTopPorts()),
    settle(fetchBazaar()),
    settle(fetchNvdWeek()),
    settle(fetchOpenPhish()),
    getGeoReader(),
    radarToken ? settle(fetchDdosFlows(radarToken)) : Promise.resolve(null),
    settle(fetchHoneypot()),
    settle(fetchHoneypotAttackers()),
  ]);

  // Merge every IP feed: one record per IP, keeping the most severe classification
  // and crediting every feed that reported it.
  const byIp = new Map<string, RawThreat & { feeds: string[] }>();
  ipResults.forEach((r, i) => {
    const feed = IP_FEEDS[i];
    if (!r.ok) {
      errors.push(`${feed.name}: ${errorText(r.e)}`);
      sources.push({ name: feed.name, status: "error", count: 0, url: feed.url });
      return;
    }
    sources.push({ name: feed.name, status: "online", count: r.v.length, url: feed.url });
    for (const t of r.v) {
      if (!isPublicIPv4(t.ip)) continue;
      const existing = byIp.get(t.ip);
      if (!existing) {
        byIp.set(t.ip, { ...t, feeds: [feed.name] });
      } else {
        if (!existing.feeds.includes(feed.name)) existing.feeds.push(feed.name);
        if (KIND_RANK[t.kind] < KIND_RANK[existing.kind]) {
          byIp.set(t.ip, {
            ...t,
            feeds: existing.feeds,
            reports: Math.max(t.reports, existing.reports),
            malware: t.malware ?? existing.malware,
          });
        } else {
          existing.reports = Math.max(existing.reports, t.reports);
          existing.malware ??= t.malware;
        }
      }
    }
  });

  const raw = [...byIp.values()];
  let geo: (ip: string) => Geo | null | undefined;
  if (reader) {
    geo = (ip) => lookup(reader, ip);
  } else {
    errors.push(`DB-IP database unavailable (${geoipError ?? "unknown error"}); geolocating a subset via ip-api.com`);
    const priority = [...raw].sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind]);
    try {
      await geolocateViaIpApi(priority.map((t) => t.ip));
    } catch (e) {
      errors.push(`ip-api.com: ${errorText(e)}`);
    }
    geo = (ip) => ipApiCache.get(ip);
  }

  // Live alerts: every recently published record, including ones that lost the de-duplication.
  const now = Date.now();
  const recent = (time?: string) => {
    const t = time ? Date.parse(time) : NaN;
    return t > now - ALERT_WINDOW_MS && t <= now + 60_000;
  };
  const alerts: LiveAlert[] = [];
  ipResults.forEach((r, i) => {
    if (!r.ok) return;
    for (const t of r.v) {
      if (!recent(t.alertTime) || !isPublicIPv4(t.ip)) continue;
      const g = geo(t.ip);
      if (!g) continue;
      const family = t.malware && t.malware !== "Unknown malware" ? t.malware : "Malware";
      alerts.push({
        id: `al-${t.id}`,
        time: t.alertTime!,
        kind: t.kind,
        title: `${family} · ${t.activity ?? t.kind}`,
        detail: `${t.ip}${t.port ? `:${t.port}` : ""} · ${g.city ? `${g.city}, ` : ""}${g.country}`,
        source: IP_FEEDS[i].name,
        country: g.country,
        countryCode: g.countryCode,
        city: g.city || undefined,
        lat: g.lat,
        lon: g.lon,
        ip: t.ip,
        port: t.port,
        malware: t.malware && t.malware !== "Unknown malware" ? t.malware : undefined,
        activity: t.activity,
        confidence: t.confidence,
        link: sourceLink(IP_FEEDS[i].name, t.ip),
      });
    }
  });
  if (ransomware.ok) {
    for (const v of ransomware.v) {
      if (!recent(v.discovered)) continue;
      alerts.push({
        id: `al-${v.id}`,
        time: v.discovered,
        kind: "ransomware",
        title: `${v.group} claims a new victim`,
        detail: `${v.victim} · ${v.country}`,
        source: "Ransomware.live",
        country: v.country,
        countryCode: v.countryCode,
        lat: v.lat,
        lon: v.lon,
        group: v.group,
        victim: v.victim,
        sector: v.sector,
        domain: v.domain,
        description: v.description,
        link: v.url,
      });
    }
  }
  if (bazaar.ok) alerts.push(...bazaar.v.alerts.filter((a) => recent(a.time)));
  alerts.sort((a, b) => b.time.localeCompare(a.time));

  const all: Threat[] = [];
  for (const { alertTime: _published, ...t } of raw) {
    const g = geo(t.ip);
    if (g) all.push({ ...t, ...g });
  }

  // Stats cover every geolocated indicator; the globe gets a ranked subset per kind.
  const byKind = emptyKinds();
  const countries = new Map<string, { cc: string; name: string; count: number }>();
  // Keyed case-insensitively: feeds disagree on casing ("mirai" vs "Mirai").
  const malwareCounts = new Map<string, { name: string; count: number }>();
  const countMalware = (name: string, n: number) => {
    const key = name.toLowerCase();
    const entry = malwareCounts.get(key) ?? { name, count: 0 };
    if (entry.name === entry.name.toLowerCase()) entry.name = name; // prefer a capitalized spelling
    entry.count += n;
    malwareCounts.set(key, entry);
  };
  const ddosFamilies = new Map<string, { name: string; count: number }>();
  const ddosCountries = new Map<string, { cc: string; name: string; count: number }>();
  for (const t of all) {
    byKind[t.kind]++;
    const c = countries.get(t.countryCode) ?? { cc: t.countryCode, name: t.country, count: 0 };
    c.count++;
    countries.set(t.countryCode, c);
    if (t.malware && (t.kind === "botnet" || t.kind === "ddos" || t.kind === "malware")) {
      countMalware(t.malware, 1);
    }
    if (t.kind === "ddos") {
      const dc = ddosCountries.get(t.countryCode) ?? { cc: t.countryCode, name: t.country, count: 0 };
      dc.count++;
      ddosCountries.set(t.countryCode, dc);
      const name = t.malware && !/unknown/i.test(t.malware) ? t.malware : "Unattributed";
      const key = name.toLowerCase();
      const f = ddosFamilies.get(key) ?? { name, count: 0 };
      f.count++;
      ddosFamilies.set(key, f);
    }
  }

  // Honeypot: attacker IPs are geolocated, then dropped. Only cities and countries are
  // published, as attack lines to the sensor, live alerts and a country ranking.
  if (honeypot.ok) {
    try {
      const { address } = await resolveHost(new URL(FEEDS.honeypot).hostname, { family: 4 });
      const g = geo(address);
      if (g) honeypot.v.sensor = { lat: g.lat, lon: g.lon, city: g.city, country: g.country };
    } catch (e) {
      errors.push(`Honeypot location: ${errorText(e)}`);
    }
    if (!hpAttackers.ok) errors.push(`${HONEYPOT} attackers: ${errorText(hpAttackers.e)}`);
    const places = new Map<string, HoneypotArc>();
    const countries = new Map<string, number>();
    for (const a of hpAttackers.ok ? hpAttackers.v : []) {
      const g = geo(a.ip);
      if (!g) continue;
      countries.set(g.country, (countries.get(g.country) ?? 0) + 1);
      const key = `${g.countryCode}|${g.city}`;
      const p = places.get(key);
      if (p) {
        p.attackers += 1;
        p.sessions += a.sessions;
        if (a.last > p.lastSeen) p.lastSeen = a.last;
      } else {
        places.set(key, { lat: g.lat, lon: g.lon, city: g.city, country: g.country, countryCode: g.countryCode, attackers: 1, sessions: a.sessions, lastSeen: a.last });
      }
    }
    const recentFirst = [...places.values()].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
    honeypot.v.topCountries = [...countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (honeypot.v.sensor) honeypot.v.arcs = recentFirst.slice(0, 150);
    for (const p of recentFirst) {
      if (!recent(p.lastSeen)) break;
      const where = p.city ? `${p.city}, ${p.country}` : p.country;
      alerts.push({
        id: `al-hp-${p.countryCode}-${p.city}-${p.lastSeen}`,
        time: p.lastSeen,
        kind: "scanner",
        title: "Honeypot hit · SSH/Telnet attack",
        detail: `${where} · ${p.attackers} attacker${p.attackers === 1 ? "" : "s"}`,
        source: HONEYPOT,
        country: p.country,
        countryCode: p.countryCode,
        city: p.city || undefined,
        lat: p.lat,
        lon: p.lon,
        activity: "SSH/Telnet login attempts on the Zeropoint honeypot",
      });
    }
    alerts.sort((a, b) => b.time.localeCompare(a.time));
  }

  const ranked = [...all].sort(
    (a, b) =>
      KIND_RANK[a.kind] - KIND_RANK[b.kind] ||
      b.feeds.length - a.feeds.length ||
      b.reports - a.reports ||
      b.lastSeen.localeCompare(a.lastSeen),
  );
  const taken = emptyKinds();
  const threats = ranked.filter((t) => taken[t.kind]++ < GLOBE_QUOTA[t.kind]);

  // CISA KEV, enriched with FIRST EPSS exploitation probability
  const kevUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
  const epssUrl = "https://www.first.org/epss/";
  if (kev.ok) {
    sources.push({ name: "CISA KEV", status: "online", count: kev.v.total, url: kevUrl });
    try {
      const scores = await getJson<{ data: { cve: string; epss: string }[] }>(
        FEEDS.epss + kev.v.list.map((v) => v.cveID).join(","),
      );
      for (const v of kev.v.list) {
        const score = scores.data.find((s) => s.cve === v.cveID);
        if (score && Number.isFinite(Number(score.epss))) v.epss = Number(score.epss);
      }
      sources.push({ name: "FIRST EPSS", status: "online", count: scores.data.length, url: epssUrl });
    } catch (e) {
      sources.push({ name: "FIRST EPSS", status: "error", count: 0, url: epssUrl });
      errors.push(`EPSS: ${errorText(e)}`);
    }
  } else {
    errors.push(`CISA KEV: ${errorText(kev.e)}`);
    sources.push({ name: "CISA KEV", status: "error", count: 0, url: kevUrl });
    sources.push({ name: "FIRST EPSS", status: "error", count: 0, url: epssUrl });
  }

  const extra: Array<[string, string, Settled<unknown>, number]> = [
    ["Ransomware.live", "https://www.ransomware.live/", ransomware, ransomware.ok ? ransomware.v.length : 0],
    ["DShield ports", "https://isc.sans.edu/data/port.html", topPorts, topPorts.ok ? topPorts.v.length : 0],
    ["MalwareBazaar", "https://bazaar.abuse.ch/", bazaar, bazaar.ok ? bazaar.v.count : 0],
    ["NVD", "https://nvd.nist.gov/", nvd, nvd.ok ? nvd.v : 0],
    ["OpenPhish", "https://openphish.com/", phish, phish.ok ? phish.v : 0],
    [HONEYPOT, FEEDS.honeypot, honeypot, honeypot.ok ? honeypot.v.sessions : 0],
  ];
  if (ddosFlows) {
    extra.push(["Cloudflare Radar", "https://radar.cloudflare.com/security/network-layer", ddosFlows, ddosFlows.ok ? ddosFlows.v.length : 0]);
  }
  for (const [name, url, r, count] of extra) {
    sources.push({ name, url, status: r.ok ? "online" : "error", count });
    if (!r.ok) errors.push(`${name}: ${errorText(r.e)}`);
  }

  // Fold freshly submitted MalwareBazaar samples into the malware-family ranking.
  if (bazaar.ok) {
    for (const [sig, n] of bazaar.v.signatures) countMalware(sig, n);
  }

  return {
    sources,
    honeypot: honeypot.ok ? honeypot.v : null,
    threats,
    ransomware: ransomware.ok ? ransomware.v : [],
    alerts: alerts.slice(0, ALERT_LIMIT),
    ddosFlows: ddosFlows?.ok ? ddosFlows.v : [],
    ddosFlowsEnabled: !!radarToken,
    totals: {
      indicators: raw.length,
      geolocated: all.length,
      countries: countries.size,
      byKind,
      phishingUrls: phish.ok ? phish.v : 0,
      malwareSamples: bazaar.ok ? bazaar.v.count : 0,
      newCves7d: nvd.ok ? nvd.v : 0,
    },
    topCountries: [...countries.values()].sort((a, b) => b.count - a.count).slice(0, 15),
    topPorts: topPorts.ok ? topPorts.v : [],
    ddosFamilies: [...ddosFamilies.values()].sort((a, b) => b.count - a.count).slice(0, 8),
    ddosCountries: [...ddosCountries.values()].sort((a, b) => b.count - a.count).slice(0, 8),
    topMalware: [...malwareCounts.values()]
      .filter((m) => m.name !== "Unknown malware")
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    kev: kev.ok ? kev.v.list : [],
    kevTotal: kev.ok ? kev.v.total : 0,
    updatedAt: new Date().toISOString(),
    errors,
  };
}

/** Returns cached threat data, refreshing from upstream feeds at most every 5 minutes. */
export async function getThreatData(): Promise<ThreatPayload> {
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.data;
  if (!inflight) {
    inflight = build()
      .then((data) => {
        // Don't let a fully failed refresh wipe out good data we already have.
        if (data.threats.length > 0 || !cached) cached = { at: Date.now(), data };
        return cached?.data ?? data;
      })
      .finally(() => {
        inflight = null;
      });
  }
  return inflight;
}
