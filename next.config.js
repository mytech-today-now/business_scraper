/** @type {import('next').NextConfig} */

// Note: CSP is now handled entirely by middleware to ensure proper nonce support
// Static CSP headers removed to prevent conflicts with dynamic nonce-based CSP

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

    // Ensure proper handling of lucide-react imports
    try {
      config.resolve.alias = {
        ...config.resolve.alias,
        'lucide-react': require.resolve('lucide-react'),
      }
    } catch (error) {
      console.warn('lucide-react not found, skipping alias configuration')
    }

    return config
  },

  // Basic security headers (CSP handled by middleware for proper nonce support)
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // CSP removed - handled by middleware with proper nonce support
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
          // COEP disabled to allow Stripe.js loading
          // {
          //   key: 'Cross-Origin-Embedder-Policy',
          //   value: 'unsafe-none',
          // },
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
  compress: true,
  poweredByHeader: false,
  generateEtags: false,

  // Enable standalone output for Docker deployment (only in production)
  output: process.env.NODE_ENV === 'production' ? 'standalone' : undefined,

  // Experimental features for better build performance
  experimental: {
    // Re-enable lucide-react optimization with proper configuration
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
