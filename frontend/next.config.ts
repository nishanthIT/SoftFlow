import type { NextConfig } from 'next';
const api = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8100';
const config: NextConfig = {
  output: 'standalone', distDir: process.env.NEXT_DIST_DIR || '.next',
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${api}/api/:path*` },
      { source: '/health/:path*', destination: `${api}/health/:path*` },
    ];
  },
};
export default config;
