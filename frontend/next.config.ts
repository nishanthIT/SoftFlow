import type { NextConfig } from 'next';
const config: NextConfig = { output: 'standalone', async rewrites() { return [{ source: '/api/:path*', destination: `${process.env.API_INTERNAL_URL || 'http://localhost:8000'}/api/:path*` },{ source: '/health/:path*', destination: `${process.env.API_INTERNAL_URL || 'http://localhost:8000'}/health/:path*` }]; } };
export default config;
