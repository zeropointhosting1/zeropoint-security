/**
 * botnet = malware C2, ddos = DDoS botnet node (Mirai, Mozi, Gafgyt…), malware = payload host,
 * scanner = active attacker, reputation = blocklisted IP/netblock
 */
export type ThreatKind = "botnet" | "ddos" | "malware" | "scanner" | "reputation";

/** A real, geolocated threat source pulled from a public intel feed. */
export interface Threat {
  id: string;
  ip: string;
  kind: ThreatKind;
  lat: number;
  lon: number;
  country: string;
  countryCode: string;
  city: string;
  /** Number of reports / attack records attributed to this IP. */
  reports: number;
  /** Number of distinct targets hit (DShield only). */
  targets?: number;
  malware?: string;
  port?: number;
  asName?: string;
  lastSeen: string;
  /** Primary feed (the highest-severity one that reported this IP). */
  source: string;
  /** Every feed that lists this IP — more feeds means higher confidence. */
  feeds: string[];
  /** Short description of the activity, e.g. "SSH brute force" or "Hijacked netblock". */
  activity?: string;
  confidence?: number;
}

export interface Vulnerability {
  epss?: number;
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse: string;
}

/** A ransomware leak-site claim, placed at the victim country's centroid. */
export interface RansomwareVictim {
  id: string;
  victim: string;
  group: string;
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
  sector: string;
  discovered: string;
  /** Victim page on ransomware.live. */
  url?: string;
  domain?: string;
  description?: string;
}

/** A single timestamped event from a feed, streamed into the live alert ticker. */
export interface LiveAlert {
  id: string;
  /** ISO timestamp reported by the source. */
  time: string;
  kind: ThreatKind | "ransomware" | "sample";
  title: string;
  detail: string;
  source: string;
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
  city?: string;
  // Investigation details (present when the source provides them)
  ip?: string;
  port?: number;
  malware?: string;
  activity?: string;
  confidence?: number;
  sha256?: string;
  fileType?: string;
  group?: string;
  victim?: string;
  sector?: string;
  domain?: string;
  description?: string;
  /** The record's page at the source. */
  link?: string;
}

/** Share of global DDoS attacks between two countries (Cloudflare Radar, last 24h). */
export interface DdosFlow {
  id: string;
  layer: "L3" | "L7";
  originCc: string;
  origin: string;
  originLat: number;
  originLon: number;
  targetCc: string;
  target: string;
  targetLat: number;
  targetLon: number;
  /** Percentage of all attacks at that layer. */
  share: number;
}

export interface FeedStatus {
  name: string;
  status: "online" | "error";
  count: number;
  url: string;
}

/** Zeropoint's own Cowrie SSH/Telnet honeypot. Strings are attacker-supplied. */
export interface HoneypotStats {
  sessions: number;
  uniqueIps: number;
  failed: number;
  success: number;
  topUsers: [string, number][];
  topPasswords: [string, number][];
  topCommands: [string, number][];
  /** Attacker IPs with the last two octets masked by the honeypot. */
  topIps: [string, number][];
  updated: string;
}

export interface ThreatPayload {
  sources: FeedStatus[];
  /** Null when the honeypot feed is unreachable. */
  honeypot: HoneypotStats | null;
  ransomware: RansomwareVictim[];
  alerts: LiveAlert[];
  /** Empty unless CLOUDFLARE_API_TOKEN is configured. */
  ddosFlows: DdosFlow[];
  ddosFlowsEnabled: boolean;
  /** Totals across every indicator collected, not just those sent to the globe. */
  totals: {
    indicators: number;
    geolocated: number;
    countries: number;
    byKind: Record<ThreatKind, number>;
    phishingUrls: number;
    malwareSamples: number;
    newCves7d: number;
  };
  topCountries: { cc: string; name: string; count: number }[];
  topPorts: { port: number; records: number; sources: number }[];
  topMalware: { name: string; count: number }[];
  ddosFamilies: { name: string; count: number }[];
  ddosCountries: { cc: string; name: string; count: number }[];
  threats: Threat[];
  kev: Vulnerability[];
  kevTotal: number;
  updatedAt: string;
  errors: string[];
}

