import type { NextConfig } from "next";

const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // In production Caddy routes /api to the API. The rewrite exists for local `next dev` only.
  async rewrites() {
    if (process.env.NODE_ENV === "production") return [];
    return [{ source: "/api/:path*", destination: `${process.env.API_ORIGIN ?? "http://127.0.0.1:8000"}/api/:path*` }];
  },
};

export default config;
