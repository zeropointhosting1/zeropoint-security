/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // maxmind reads the .mmdb from disk at runtime; keep it out of the bundle.
  serverExternalPackages: ["maxmind"],
};

export default nextConfig;
