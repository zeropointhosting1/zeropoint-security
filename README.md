# Zeropoint Security

A global threat-intelligence dashboard built with Next.js, React and Three.js. It aggregates 18 free public intelligence sources into an interactive Earth with searchable indicators, source inspection, ransomware claims, session review status, and known-exploited vulnerabilities.

## Run

```bash
npm install
npm run dev
npm run build
```

On Windows PowerShell with script execution disabled, use `npm.cmd` instead of `npm`. Open http://localhost:3000.

On first start the server downloads the free DB-IP city database (~60 MB compressed, ~125 MB on disk) into `data/`. It refreshes monthly. Until it's ready, a subset of IPs is geolocated through ip-api.com.

### Deploy (Cloudflare Pages)

`npm run build` produces a static site in `out/`. It then runs `scripts/collect.ts`, which fetches every feed once and writes `out/api/threats` and `out/api/alerts` as a data snapshot. In Cloudflare Pages, set the build command to `npm run build` and the output directory to `out`. The data refreshes on each rebuild. The live `/api` routes (`route.dev.ts`) only run under `npm run dev`.

### Live data (collector VM → Supabase)

In production, `wrangler.jsonc` deploys `worker/index.ts`, which serves `/api/threats` and `/api/alerts` from Supabase (`public.snapshots`). If Supabase is unreachable or empty, it falls back to the build snapshot. An Ubuntu VM keeps Supabase fresh by running `scripts/collect.ts --upload` every 5 minutes. The VM needs no inbound ports.

1. Run `supabase/setup.sql` once in the Supabase SQL Editor, with `CHANGE_ME` replaced by a strong password. Never commit the password.
2. On the VM, install Node 22, create a `zeropoint` system user, and clone the repo to `/opt/zeropoint/app`. Then run `sudo -u zeropoint bash -c 'cd /opt/zeropoint/app && npm ci'`.
3. Create `/etc/zeropoint/collector.env` (root-owned, mode 600) with one line: `SUPABASE_DB_URL=postgresql://zeropoint_collector.<project-ref>:<password>@<session-pooler-host>:5432/postgres`. The user must be `zeropoint_collector`, never `postgres`.
4. Copy `deploy/zeropoint-collector.{service,timer}` to `/etc/systemd/system/`, then run `systemctl daemon-reload`, `systemctl start zeropoint-collector` (a test run), and `systemctl enable --now zeropoint-collector.timer`.

Check the logs with `journalctl -u zeropoint-collector`. To update the VM, run `sudo -u zeropoint bash -c 'cd /opt/zeropoint/app && git pull && npm ci'`. The GitHub Actions workflow in `.github/workflows/collect.yml` is a manual-only alternative.

### Optional: live DDoS attack flows

Copy `.env.local.example` to `.env.local` and set `CLOUDFLARE_API_TOKEN`. Use a free token with **Account · Radar · Read** from https://dash.cloudflare.com/profile/api-tokens. Then restart the server. The globe draws Cloudflare Radar's top layer 3 and layer 7 DDoS origin → target country pairs for the last 24 hours, with arc thickness showing each pair's share of attacks. Without a token, the DDoS panel shows DDoS botnet infrastructure instead.

## Intelligence sources

All sources are free and need no API key.

| Source | Data | Shown as |
| --- | --- | --- |
| [SANS ISC DShield](https://isc.sans.edu/api/) | IPs attacking the DShield sensor network, plus the most-attacked ports | Attacker |
| [abuse.ch ThreatFox](https://threatfox.abuse.ch/) | Recent C2 and payload IP:port indicators with confidence | Malware C2 / Payload host |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Botnet C2 IPs | Malware C2 |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch/) | IP-hosted malware distribution URLs | Payload host |
| [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | Cobalt Strike C2 IPs (30 days) | Malware C2 |
| [blocklist.de](https://www.blocklist.de/) | fail2ban-reported attack sources | Attacker |
| [GreenSnow](https://greensnow.co/) | Scanning and brute-force sources | Attacker |
| [CINS Army](https://cinsscore.com/) | Poor-reputation IPs | Blocklisted |
| [Emerging Threats](https://rules.emergingthreats.net/) | Known compromised hosts | Blocklisted |
| [IPsum](https://github.com/stamparm/ipsum) | IPs on 3+ public blocklists | Blocklisted |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked netblocks | Blocklisted |
| [Ransomware.live](https://www.ransomware.live/) | Latest victims claimed on leak sites | Ransomware victim (country level) |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Malware samples submitted in the last hour | Malware families |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited vulnerability catalog; latest 20 shown | Exploited CVEs |
| [FIRST EPSS](https://api.first.org/epss/) | 30-day exploitation probability for those CVEs | Exploited CVEs |
| [NVD](https://nvd.nist.gov/) | CVEs published in the last 7 days | Metric |
| [OpenPhish](https://openphish.com/) | Live phishing URLs | Metric |
| [Cloudflare Radar](https://radar.cloudflare.com/security/network-layer) (optional, free token) | Top DDoS origin → target country pairs, 24h | DDoS flow arcs |
| [DB-IP Lite](https://db-ip.com) | Offline IP geolocation (CC BY 4.0) | — |

**DDoS botnets:** ThreatFox and URLhaus records from DDoS families (Mirai, Mozi, Gafgyt/Bashlite, Aisuru, XorDDoS, Tsunami, Moobot, RapperBot, etc., plus anything tagged `ddos`) are classified as **DDoS botnet** nodes.

## How it works

- Feeds are fetched server-side, cached for five minutes, and refreshed automatically. Each feed fails on its own and is reported in the source strip, so one outage never blanks the dashboard.
- **One record per IP.** When several feeds list the same IP, it becomes a single indicator. It keeps the most severe classification (C2 > payload host > attacker > blocklisted) and credits every reporting feed. "Corroborated by N feeds" is a useful confidence signal.
- All ~45k indicators are geolocated and counted in the metrics, country, malware and port panels. The globe and queue get a ranked subset (up to 5,700) so the page stays smooth; search and filters work within that subset.
- Ransomware victims carry only a country, so they're placed near the country centroid with a small fixed offset.
- **Live alerts and beacons:** records published in the last 24 hours become live alerts. These include new C2 servers and DDoS bots (ThreatFox, URLhaus), new malware samples (MalwareBazaar) and ransomware claims. The browser polls `/api/alerts` every minute and streams new events in the order they were published, each with its source timestamp. Geolocated events fire a beacon on the globe: a light beam, a shockwave and a label. **Follow live** flies the camera to each one. The feeds publish in batches every few minutes, so events typically appear 5–15 minutes after the source reports them.
- Indicators describe public source reports, not observed attacks against your network. No randomized attacks or invented attack destinations are displayed.

**Filter:** the pill bar above the globe (Everything, DDoS, Malware C2, Payload hosts, Ransomware, Attackers, Blocklisted) filters everything together: globe points, beacons, DDoS arcs, the live ticker, the Live tab and the indicator list.

**Event details:** click any live alert in the ticker or the Live tab to open its investigation drawer. It shows the source timestamp, indicator (IP:port or SHA256, with copy buttons), location, malware family, activity, ransomware group/victim/sector, and the merged globe indicator with every corroborating feed. It also links to the record at its source and to AbuseIPDB, VirusTotal, Shodan and GreyNoise. The globe flies to the event and pins a beacon there until the drawer closes.

**Attack lines (source → target):** the lines are real Cloudflare Radar DDoS flows between countries and need `CLOUDFLARE_API_TOKEN` (see above). The other feeds identify attackers but not their victims, so no line is drawn without real target data.

Select a card or globe point to focus its location and inspect its feeds, activity, last observation, malware, or report count. Mark reviewed applies only to the current session. Orbit controls respect reduced-motion preferences.

ip-api.com (fallback only) is HTTP and non-commercial on its free tier. Check each feed's terms before any commercial deployment.

## Structure

- `components/Dashboard.tsx`: dashboard, filters, investigation details, ransomware and CVEs
- `components/GlobeView.tsx`: client-only Three.js globe, beacons and DDoS arcs
- `components/EventDetail.tsx`: event investigation drawer
- `components/useLiveStream.ts`: polls live alerts and paces them into the ticker and beacons
- `app/api/alerts/route.ts`: lightweight live-alerts endpoint
- `lib/threats.ts`: upstream fetching, de-duplication, enrichment and cache
- `lib/geoip.ts`: DB-IP database download and offline lookups
- `instrumentation.ts`: warms the geolocation database at server start
- `app/api/threats/route.ts`: JSON endpoint
- `app/globals.css`: responsive dashboard styling
- `public/zeropoint-logo.png`, `public/zeropoint-mark.png`, `app/icon.png`: logo, header mark and favicon (transparent cut-outs of the Zeropoint logo)
