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
    // Bundle analyzer for build analysis
    if (process.env.ANALYZE === 'true') {
      const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer')
      config.plugins.push(
        new BundleAnalyzerPlugin({
          analyzerMode: 'static',
          openAnalyzer: false,
          reportFilename: isServer ? '../analyze/server.html' : '../analyze/client.html'
        })
      )
    }

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

        // Additional production optimizations
        config.optimization.concatenateModules = true
        config.optimization.providedExports = true
        config.optimization.mangleExports = true
      }

      // Improve build performance
      config.cache = {
        type: 'filesystem',
        buildDependencies: {
          config: [__filename]
        }
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

  // SECURITY FIX: Only expose safe, client-side environment variables
  // Server-side secrets are accessed directly via process.env in server components/API routes
  env: {
    // Build-time configuration (safe for client-side)
    IS_BUILD_TIME: process.env.IS_BUILD_TIME,
    DISABLE_DATABASE: process.env.DISABLE_DATABASE,
    SKIP_RETENTION_POLICIES: process.env.SKIP_RETENTION_POLICIES,
    SKIP_BACKGROUND_JOBS: process.env.SKIP_BACKGROUND_JOBS,
    SKIP_DATA_MIGRATIONS: process.env.SKIP_DATA_MIGRATIONS,
    BUILD_LOG_LEVEL: process.env.BUILD_LOG_LEVEL,

    // Public configuration (safe for client-side)
    ENABLE_AUTH: process.env.ENABLE_AUTH,

    // Stripe publishable keys (designed to be public)
    STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY,
    NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY,

    // Payment URLs (safe for client-side)
    PAYMENT_SUCCESS_URL: process.env.PAYMENT_SUCCESS_URL,
    PAYMENT_CANCEL_URL: process.env.PAYMENT_CANCEL_URL,

    // Debug variables (already properly prefixed)
    NEXT_PUBLIC_DEBUG: process.env.NEXT_PUBLIC_DEBUG,

    // NOTE: Sensitive variables removed for security:
    // - DATABASE_URL, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_TYPE, POSTGRES_PASSWORD
    // - ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT
    // - STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
    // These are now accessed server-side only via process.env
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
    swcMinify: true
  },

  // Modular imports configuration (moved outside experimental)
  modularizeImports: {
    'lucide-react': {
      transform: 'lucide-react/dist/esm/icons/{{member}}'
    },
    'lodash': {
      transform: 'lodash/{{member}}'
    }
  },

  // Configure static export behavior
  trailingSlash: false,

  // Enable TypeScript checking during build for security
  typescript: {
    ignoreBuildErrors: false,
    // Force TypeScript checking to run during build
    tsconfigPath: './tsconfig.json',
  },

  // Enable ESLint during build (violations have been resolved)
  eslint: {
    ignoreDuringBuilds: false,
    // Ensure ESLint runs on all directories
    dirs: ['src', 'pages', 'components', '__tests__'],
  },
}

module.exports = nextConfig
