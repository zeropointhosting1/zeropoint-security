/** Warm the offline geolocation database at server start so the first request is fast. */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { getGeoReader } = await import("./lib/geoip");
    void getGeoReader();
  }
}
