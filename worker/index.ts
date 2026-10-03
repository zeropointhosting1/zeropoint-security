/**
 * Cloudflare Worker for security.zeropointhosting.com.
 * Static files come from the `npm run build` export (ASSETS). /api/threats and /api/alerts are
 * read from Supabase (public.snapshots, kept fresh by scripts/collect.ts --upload) and fall back
 * to the build-time snapshot in out/api/* if Supabase is unreachable or empty.
 */
interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  SUPABASE_URL: string;
  /** Publishable (anon) key: RLS limits it to reading public.snapshots. */
  SUPABASE_PUBLISHABLE_KEY: string;
}

interface Ctx {
  waitUntil(promise: Promise<unknown>): void;
}

const SNAPSHOTS: Record<string, "threats" | "alerts"> = {
  "/api/threats": "threats",
  "/api/alerts": "alerts",
};

/** Edge cache lifetime; the collector uploads every 5 minutes. */
const CACHE_SECONDS = 30;

export default {
  async fetch(request: Request, env: Env, ctx: Ctx): Promise<Response> {
    const url = new URL(request.url);
    const name = SNAPSHOTS[url.pathname];
    if (!name || request.method !== "GET") return env.ASSETS.fetch(request);

    const cache = (caches as unknown as { default: Cache }).default;
    const cacheKey = new Request(`${url.origin}${url.pathname}`);
    const hit = await cache.match(cacheKey);
    if (hit) return hit;

    try {
      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_snapshot?name=${name}`, {
        headers: { apikey: env.SUPABASE_PUBLISHABLE_KEY, Accept: "application/json" },
      });
      // The stored JSON is passed through as text; parsing 2 MB here would waste Worker CPU.
      const body = res.ok ? await res.text() : "";
      if (body && body !== "null") {
        const out = new Response(body, {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
          },
        });
        ctx.waitUntil(cache.put(cacheKey, out.clone()));
        return out;
      }
    } catch {
      // Fall through to the bundled snapshot.
    }
    return env.ASSETS.fetch(request);
  },
};
