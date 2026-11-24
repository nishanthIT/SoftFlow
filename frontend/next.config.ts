import type { NextConfig } from 'next';
const api = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8100';
const config: NextConfig = {
  output: 'standalone', distDir: process.env.NEXT_DIST_DIR || '.next',
  // The launcher serves standalone/server.js from this frontend. Do not let
  // unrelated package-lock.json files in the checkout or home change its path.
  outputFileTracingRoot: __dirname,
  poweredByHeader:false,
  async headers(){return [{source:'/:path*',headers:[
    {key:'X-Content-Type-Options',value:'nosniff'},
    {key:'X-Frame-Options',value:'DENY'},
    {key:'Referrer-Policy',value:'same-origin'},
    {key:'Permissions-Policy',value:'camera=(), microphone=(), geolocation=()'},
  ]}]},
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${api}/api/:path*` },
      { source: '/health/:path*', destination: `${api}/health/:path*` },
    ];
  },
};
export default config;
