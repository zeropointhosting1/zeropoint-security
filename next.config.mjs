import { PHASE_PRODUCTION_BUILD } from "next/constants.js";

/** @type {(phase: string) => import('next').NextConfig} */
export default function nextConfig(phase) {
  const isBuild = phase === PHASE_PRODUCTION_BUILD;
  return {
    reactStrictMode: true,
    // maxmind reads the .mmdb from disk at runtime; keep it out of the bundle.
    serverExternalPackages: ["maxmind"],
    // Production builds are a static export for Cloudflare Pages (served from `out/`).
    // The live /api routes are `route.dev.ts`, so only `next dev` picks them up; the build
    // writes out/api/* snapshots with scripts/collect.ts instead.
    ...(isBuild
      ? { output: "export" }
      : { pageExtensions: ["dev.ts", "tsx", "ts", "jsx", "js"] }),
  };
}
