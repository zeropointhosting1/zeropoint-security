import fs from "node:fs";
import path from "node:path";
import { getThreatData } from "../lib/threats";

/**
 * Fetches every feed once and writes the same JSON the dev /api routes serve:
 *   <outDir>/threats  (full payload)   <outDir>/alerts  (live alerts only)
 * `npm run build` runs this into out/api so the static Cloudflare Pages site ships a snapshot.
 * Usage: tsx scripts/collect.ts [outDir]   (default: out/api)
 */
async function main() {
  try {
    process.loadEnvFile(".env.local"); // optional CLOUDFLARE_API_TOKEN, as `next dev` would load it
  } catch {}

  const outDir = process.argv[2] ?? path.join("out", "api");
  const data = await getThreatData();
  // An empty snapshot would blank the live site; fail so Pages keeps the previous deployment.
  if (data.threats.length === 0) {
    throw new Error(`No indicators collected: ${data.errors.join("; ")}`);
  }

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "threats"), JSON.stringify(data));
  fs.writeFileSync(
    path.join(outDir, "alerts"),
    JSON.stringify({ alerts: data.alerts, updatedAt: data.updatedAt }),
  );
  const failed = data.sources.filter((s) => s.status === "error").map((s) => s.name);
  console.log(
    `Wrote ${data.threats.length} indicators and ${data.alerts.length} alerts to ${outDir}` +
      (failed.length ? ` (feeds failed: ${failed.join(", ")})` : ""),
  );
}

main().then(
  () => process.exit(0),
  (e: Error) => {
    console.error(e.message);
    process.exit(1);
  },
);
