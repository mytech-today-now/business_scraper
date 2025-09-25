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

    // Enhanced webpack optimizations for performance
    if (!isServer) {
      // Optimize bundle splitting
      config.optimization = {
        ...config.optimization,
        splitChunks: {
          chunks: 'all',
          cacheGroups: {
            vendor: {
              test: /[\\/]node_modules[\\/]/,
              name: 'vendors',
              chunks: 'all',
              priority: 10,
            },
            common: {
              name: 'common',
              minChunks: 2,
              chunks: 'all',
              priority: 5,
              reuseExistingChunk: true,
            },
            // Separate chunk for large libraries
            react: {
              test: /[\\/]node_modules[\\/](react|react-dom)[\\/]/,
              name: 'react',
              chunks: 'all',
              priority: 20,
            },
            charts: {
              test: /[\\/]node_modules[\\/](recharts|react-window|react-virtualized)[\\/]/,
              name: 'charts',
              chunks: 'all',
              priority: 15,
            }
          }
        }
      }

      // Enable tree shaking for better bundle optimization
      config.optimization.usedExports = true
      config.optimization.sideEffects = false

      // Minimize bundle size
      if (process.env.NODE_ENV === 'production') {
        config.optimization.minimize = true
      }
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

  // Ensure environment variables are available in standalone mode
  env: {
    DATABASE_URL: process.env.DATABASE_URL,
    DB_HOST: process.env.DB_HOST,
    DB_PORT: process.env.DB_PORT,
    DB_NAME: process.env.DB_NAME,
    DB_USER: process.env.DB_USER,
    DB_PASSWORD: process.env.DB_PASSWORD,
    DB_TYPE: process.env.DB_TYPE,
    POSTGRES_PASSWORD: process.env.POSTGRES_PASSWORD,
    // Build-time configuration
    IS_BUILD_TIME: process.env.IS_BUILD_TIME,
    DISABLE_DATABASE: process.env.DISABLE_DATABASE,
    SKIP_RETENTION_POLICIES: process.env.SKIP_RETENTION_POLICIES,
    SKIP_BACKGROUND_JOBS: process.env.SKIP_BACKGROUND_JOBS,
    SKIP_DATA_MIGRATIONS: process.env.SKIP_DATA_MIGRATIONS,
    BUILD_LOG_LEVEL: process.env.BUILD_LOG_LEVEL,
    // Authentication variables for client-side access
    ENABLE_AUTH: process.env.ENABLE_AUTH,
    ADMIN_USERNAME: process.env.ADMIN_USERNAME,
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
    ADMIN_PASSWORD_HASH: process.env.ADMIN_PASSWORD_HASH,
    ADMIN_PASSWORD_SALT: process.env.ADMIN_PASSWORD_SALT,
    // Stripe payment variables for client-side access
    STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
    PAYMENT_SUCCESS_URL: process.env.PAYMENT_SUCCESS_URL,
    PAYMENT_CANCEL_URL: process.env.PAYMENT_CANCEL_URL,
    // Debug and development variables
    NEXT_PUBLIC_DEBUG: process.env.NEXT_PUBLIC_DEBUG,
    // NODE_ENV is managed by Next.js and cannot be overridden
  },

  // Experimental features configuration
  experimental: {
    // External packages for server components
    serverComponentsExternalPackages: ['nodemailer', 'puppeteer-core', '@tensorflow/tfjs'],
    // Enhanced package imports optimization for better tree shaking
    optimizePackageImports: [
      'lucide-react',
      'natural',
      'compromise',
      'simple-statistics',
      'lighthouse',
      'recharts',
      'date-fns',
      'react-window',
      'react-virtualized-auto-sizer',
      'react-window-infinite-loader',
      'react-table',
      'zod',
      'axios',
      'lodash-es'
    ],
    // Enable optimized CSS loading
    optimizeCss: true,
    // Enable SWC minification for better performance
    swcMinify: true,
    // Enable modern JavaScript output
    modularizeImports: {
      'lucide-react': {
        transform: 'lucide-react/dist/esm/icons/{{member}}'
      },
      'lodash': {
        transform: 'lodash/{{member}}'
      }
    }
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
