/** @type {import('next').NextConfig} */

// CSP configuration for static headers
const getStaticCSPHeader = () => {
  // Basic CSP for static responses (will be enhanced by middleware)
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://js.stripe.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://nominatim.openstreetmap.org https://api.opencagedata.com https://*.googleapis.com https://*.cognitiveservices.azure.com https://api.duckduckgo.com https://duckduckgo.com https://api.stripe.com https://checkout.stripe.com",
    "frame-src 'self' https://js.stripe.com https://hooks.stripe.com",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://checkout.stripe.com",
    'upgrade-insecure-requests',
  ].join('; ')
}

const nextConfig = {
  // Image optimization configuration
  images: {
    formats: ['image/webp', 'image/avif'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    domains: ['nominatim.openstreetmap.org', 'api.opencagedata.com'],
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
    minimumCacheTTL: 60,
    unoptimized: false,
  },

  webpack: (config, { isServer }) => {
    if (!isServer) {
      // Don't resolve Node.js modules on the client-side
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        crypto: false,
        stream: false,
        url: false,
        zlib: false,
        http: false,
        https: false,
        assert: false,
        os: false,
        path: false,
        dns: false,
        child_process: false,
        worker_threads: false,
        perf_hooks: false,
        inspector: false,
        async_hooks: false,
        cluster: false,
        dgram: false,
        module: false,
        readline: false,
        repl: false,
        v8: false,
        vm: false,
        constants: false,
        events: false,
        util: false,
        querystring: false,
        punycode: false,
        buffer: false,
      }
    }
    return config
  },

  // Enhanced security headers with CSP
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: getStaticCSPHeader(),
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            key: 'Cross-Origin-Embedder-Policy',
            value: 'credentialless',
          },
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin',
          },
          {
            key: 'Cross-Origin-Resource-Policy',
            value: 'same-origin',
          },
        ],
      },
      {
        source: '/api/webhooks/stripe',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: 'https://api.stripe.com',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'POST',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value: 'stripe-signature, content-type',
          },
        ],
      },
      {
        source: '/api/payments/:path*',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
        ],
      },
    ]
  },

  // Production optimizations
  swcMinify: true,
  compress: true,
  poweredByHeader: false,
  generateEtags: false,

  // Enable standalone output for Docker deployment
  output: 'standalone',

  // Experimental features for better build performance
  experimental: {
    // Modern experimental features
    optimizePackageImports: ['lucide-react'],
  },

  // Configure static export behavior
  trailingSlash: false,

  // Temporarily disable TypeScript checking during build
  typescript: {
    ignoreBuildErrors: true,
  },

  // Disable ESLint during build
  eslint: {
    ignoreDuringBuilds: true,
  },
}

module.exports = nextConfig
