import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  // Next 16's CLI parser is unreliable under Node 24; use the TypeScript
  // compiler API (the same pinned package) for deterministic production builds.
  experimental: { useTypeScriptCli: false },
};

export default nextConfig;
