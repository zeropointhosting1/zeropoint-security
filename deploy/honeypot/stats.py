"""Builds the Zeropoint honeypot feeds from Cowrie's JSON log. Runs every 5 minutes (cron).

Public  /var/www/honeypot/stats.json                  counts and top lists, no IP addresses
Private /var/www/honeypot-private/attackers.json      attacker IPs and per-session details;
        served by Caddy only with the collector's bearer token. The collector geolocates the IPs
        and publishes locations only.
"""
import collections, datetime, glob, json, os

LOG_GLOB = os.environ.get("COWRIE_LOGS", "/opt/cowrie/var/log/cowrie/cowrie.json*")
PUBLIC_OUT = os.environ.get("PUBLIC_OUT", "/var/www/honeypot/stats.json")
PRIVATE_OUT = os.environ.get("PRIVATE_OUT", "/var/www/honeypot-private/attackers.json")
# IPs to leave out (your own tests): one per line in this file, kept only on the VPS.
IGNORE_FILE = os.environ.get("IGNORE_FILE", "/opt/cowrie/ignore-ips.txt")
try:
    IGNORE = {l.split("#")[0].strip() for l in open(IGNORE_FILE)} - {""}
except FileNotFoundError:
    IGNORE = set()

c = collections.Counter
users, pwds, cmds, ips = c(), c(), c(), c()
totals = {"sessions": 0, "failed": 0, "success": 0}
att = {}  # ip -> [sessions, first_seen, last_seen]
sess = {}  # cowrie session id -> details

for f in glob.glob(LOG_GLOB):
    for line in open(f, errors="ignore"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("src_ip") in IGNORE:
            continue
        ev, sid, t = e.get("eventid", ""), e.get("session", ""), e.get("timestamp", "")
        if ev == "cowrie.session.connect":
            ip = e.get("src_ip", "")
            totals["sessions"] += 1
            ips[ip] += 1
            a = att.setdefault(ip, [0, t, t])
            a[0] += 1; a[1] = min(a[1], t); a[2] = max(a[2], t)
            sess[sid] = {"id": sid, "ip": ip, "start": t, "protocol": e.get("protocol", "ssh"), "logins": [], "commands": []}
        elif ev.startswith("cowrie.login."):
            ok = ev.endswith("success")
            totals["success" if ok else "failed"] += 1
            u, p = e.get("username", ""), e.get("password", "")
            users[u] += 1; pwds[p] += 1
            if sid in sess and len(sess[sid]["logins"]) < 10:
                sess[sid]["logins"].append([u[:64], p[:64], ok])
        elif ev == "cowrie.command.input":
            cmd = e.get("input", "")[:160]
            cmds[cmd[:120]] += 1
            if sid in sess and len(sess[sid]["commands"]) < 15:
                sess[sid]["commands"].append(cmd)


def write(path, data):
    json.dump(data, open(path + ".tmp", "w"))
    os.replace(path + ".tmp", path)


write(PUBLIC_OUT, {
    **totals,
    "updated": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "unique_ips": len(ips),
    "top_users": users.most_common(10),
    "top_passwords": pwds.most_common(10),
    "top_commands": cmds.most_common(10),
})
recent_ips = sorted(att.items(), key=lambda kv: kv[1][2], reverse=True)[:500]
recent_sessions = sorted(sess.values(), key=lambda s: s["start"], reverse=True)[:500]
write(PRIVATE_OUT, {
    "attackers": [{"ip": ip, "sessions": a[0], "first": a[1], "last": a[2]} for ip, a in recent_ips],
    "sessions": recent_sessions,
})
