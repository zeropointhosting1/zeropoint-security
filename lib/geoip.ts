import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { open, type CityResponse, type Reader } from "maxmind";

/**
 * Offline IP geolocation using the free DB-IP "IP to City Lite" database
 * (CC BY 4.0, https://db-ip.com). Lookups are local, so there is no rate limit
 * and tens of thousands of feed IPs can be placed on the globe instantly.
 * The database (~125 MB) downloads automatically on first use and refreshes monthly.
 */

export interface Geo {
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lon: number;
}

const DB_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DB_DIR, "dbip-city-lite.mmdb");
const MAX_AGE_MS = 35 * 24 * 60 * 60 * 1000;

let readerPromise: Promise<Reader<CityResponse> | null> | null = null;
export let geoipError: string | null = null;

function monthStamp(offset: number): string {
  const d = new Date();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - offset);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

async function download(): Promise<void> {
  fs.mkdirSync(DB_DIR, { recursive: true });
  const tmp = `${DB_PATH}.download`;
  // The new month's file appears a little after the 1st, so fall back to last month.
  for (const offset of [0, 1]) {
    const url = `https://download.db-ip.com/free/dbip-city-lite-${monthStamp(offset)}.mmdb.gz`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5 * 60_000) });
    if (!res.ok || !res.body) continue;
    await pipeline(
      Readable.fromWeb(res.body as import("node:stream/web").ReadableStream),
      createGunzip(),
      fs.createWriteStream(tmp),
    );
    fs.renameSync(tmp, DB_PATH);
    return;
  }
  throw new Error("DB-IP database download failed");
}

function isStale(): boolean {
  try {
    return Date.now() - fs.statSync(DB_PATH).mtimeMs > MAX_AGE_MS;
  } catch {
    return true;
  }
}

export function getGeoReader(): Promise<Reader<CityResponse> | null> {
  readerPromise ??= (async () => {
    if (isStale()) {
      try {
        await download();
      } catch (e) {
        // A stale database is still far better than none.
        if (!fs.existsSync(DB_PATH)) throw e;
      }
    }
    const reader = await open<CityResponse>(DB_PATH);
    geoipError = null;
    return reader;
  })().catch((e: Error) => {
    geoipError = e.message;
    readerPromise = null; // retry on the next refresh
    return null;
  });
  return readerPromise;
}

export function lookup(reader: Reader<CityResponse>, ip: string): Geo | null {
  let r: CityResponse | null;
  try {
    r = reader.get(ip);
  } catch {
    return null;
  }
  const loc = r?.location;
  if (!r || !loc || typeof loc.latitude !== "number" || typeof loc.longitude !== "number") {
    return null;
  }
  return {
    country: r.country?.names?.en ?? "Unknown",
    countryCode: r.country?.iso_code ?? "??",
    city: r.city?.names?.en ?? "",
    lat: loc.latitude,
    lon: loc.longitude,
  };
}
