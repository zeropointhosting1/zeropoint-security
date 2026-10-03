import fs from "node:fs";
import path from "node:path";
import postgres from "postgres";
import { getThreatData } from "../lib/threats";

/**
 * Fetches every feed once and produces the same JSON the dev /api routes serve:
 *   threats (full payload)   alerts (live alerts only)
 *
 *   tsx scripts/collect.ts [outDir]   write files (default out/api; `npm run build` ships them as a snapshot)
 *   tsx scripts/collect.ts --upload   upsert into Supabase public.snapshots, which the Worker serves
 *
 * --upload needs SUPABASE_DB_URL for the zeropoint_collector role from supabase/setup.sql, which can
 * only write that one table. Never give the collector the service_role key.
 */
async function main() {
  try {
    process.loadEnvFile(".env.local"); // local runs; the server's systemd unit sets the env instead
  } catch {}

  const upload = process.argv.includes("--upload");
  const outDir = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? path.join("out", "api");

  const data = await getThreatData();
  // An empty payload would blank the live site; fail so the last good data stays up.
  if (data.threats.length === 0) {
    throw new Error(`No indicators collected: ${data.errors.join("; ")}`);
  }
  const files = {
    threats: JSON.stringify(data),
    alerts: JSON.stringify({ alerts: data.alerts, updatedAt: data.updatedAt }),
  };

  if (upload) {
    await uploadToSupabase(files);
  } else {
    fs.mkdirSync(outDir, { recursive: true });
    for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(outDir, name), body);
  }

  const failed = data.sources.filter((s) => s.status === "error").map((s) => s.name);
  console.log(
    `${upload ? "Uploaded" : "Wrote"} ${data.threats.length} indicators and ${data.alerts.length} alerts ` +
      `to ${upload ? "Supabase" : outDir}` +
      (failed.length ? ` (feeds failed: ${failed.join(", ")})` : ""),
  );
}

async function uploadToSupabase(files: Record<"threats" | "alerts", string>) {
  const url = process.env.SUPABASE_DB_URL?.trim();
  if (!url) throw new Error("SUPABASE_DB_URL is not set");
  const sql = postgres(url, { max: 1, ssl: "require", prepare: false, connect_timeout: 30 });
  try {
    // One transaction, so the site never serves alerts from a newer run than threats.
    await sql.begin(async (tx) => {
      for (const name of ["threats", "alerts"] as const) {
        await tx`
          insert into public.snapshots (name, payload, updated_at)
          values (${name}, ${files[name]}::json, now())
          on conflict (name) do update set payload = excluded.payload, updated_at = excluded.updated_at`;
      }
    });
  } finally {
    await sql.end();
  }
}

main().then(
  () => process.exit(0),
  (e: Error) => {
    console.error(e.message);
    process.exit(1);
  },
);
