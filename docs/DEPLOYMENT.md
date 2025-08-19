# Deployment Guide - Business Scraper App

This guide covers deployment options and configurations for the Business Scraper App.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Build Process](#build-process)
3. [Environment Configuration](#environment-configuration)
4. [Deployment Platforms](#deployment-platforms)
5. [Performance Optimization](#performance-optimization)
6. [Security Considerations](#security-considerations)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

### System Requirements

- **Node.js**: Version 18.0 or higher
- **npm**: Version 8.0 or higher (or yarn 1.22+)
- **Memory**: Minimum 2GB RAM for build process
- **Storage**: At least 1GB free space for dependencies and build artifacts

### Browser Support

- **Chrome**: Version 90+
- **Firefox**: Version 88+
- **Safari**: Version 14+
- **Edge**: Version 90+
- **Mobile**: iOS Safari 14+, Chrome Mobile 90+

## Build Process

### Development Build

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Access at http://localhost:3000
```

### Production Build

```bash
# Install dependencies
npm ci --only=production

# Build for production
npm run build

# Start production server
npm start
```

### Build Optimization

The build process includes:

- **Code Splitting**: Automatic route-based splitting
- **Tree Shaking**: Removal of unused code
- **Minification**: JavaScript and CSS compression
- **Image Optimization**: Next.js Image component optimization
- **Bundle Analysis**: Use `npm run analyze` to inspect bundle size

### Build Configuration

**next.config.js**:
```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: true,
  },
  webpack: (config) => {
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
    };
    return config;
  },
  // Production optimizations
  swcMinify: true,
  compress: true,
  poweredByHeader: false,
  generateEtags: false,
};

module.exports = nextConfig;
```

## Environment Configuration

### Environment Variables

Create `.env.local` for local development or `.env.production` for production:

```env
# Application Settings
NEXT_PUBLIC_APP_NAME=Business Scraper App
NEXT_PUBLIC_APP_VERSION=1.0.0
NODE_ENV=production

# API Keys (Optional)
GOOGLE_MAPS_API_KEY=your_google_maps_api_key
OPENCAGE_API_KEY=your_opencage_api_key
BING_SEARCH_API_KEY=your_bing_search_api_key
YANDEX_SEARCH_API_KEY=your_yandex_search_api_key

# Scraping Configuration
SCRAPING_TIMEOUT=30000
SCRAPING_MAX_RETRIES=3
SCRAPING_DELAY_MS=1000
SEARCH_ENGINE_TIMEOUT=10000
MAX_SEARCH_RESULTS=50

# Security
NEXT_PUBLIC_CSP_NONCE=auto-generated

# Performance
NEXT_PUBLIC_ENABLE_SW=true
NEXT_PUBLIC_CACHE_DURATION=3600000
```

### Configuration Validation

Validate environment variables at build time:

```javascript
// config/env.js
const requiredEnvVars = [
  'NODE_ENV',
  'NEXT_PUBLIC_APP_NAME',
];

const optionalEnvVars = [
  'GOOGLE_MAPS_API_KEY',
  'OPENCAGE_API_KEY',
];

function validateEnv() {
  const missing = requiredEnvVars.filter(
    (envVar) => !process.env[envVar]
  );
  
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`
    );
  }
}

module.exports = { validateEnv };
```

## Deployment Platforms

### Vercel (Recommended)

**Advantages:**
- Zero-configuration deployment
- Automatic HTTPS
- Global CDN
- Serverless functions support
- Built-in analytics

**Deployment Steps:**

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Deploy**:
   ```bash
   vercel
   ```

3. **Configure Environment Variables**:
   - Go to Vercel Dashboard
   - Navigate to Project Settings > Environment Variables
   - Add production environment variables

4. **Custom Domain** (Optional):
   - Add domain in Vercel Dashboard
   - Configure DNS records

**vercel.json Configuration**:
```json
{
  "framework": "nextjs",
  "buildCommand": "npm run build",
  "devCommand": "npm run dev",
  "installCommand": "npm install",
  "functions": {
    "app/api/**/*.js": {
      "maxDuration": 30
    }
  },
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        }
      ]
    }
  ]
}
```

### Netlify

**Deployment Steps:**

1. **Build Configuration** (`netlify.toml`):
   ```toml
   [build]
     command = "npm run build"
     publish = "out"
   
   [build.environment]
     NODE_VERSION = "18"
   
   [[headers]]
     for = "/*"
     [headers.values]
       X-Frame-Options = "DENY"
       X-XSS-Protection = "1; mode=block"
       X-Content-Type-Options = "nosniff"
   ```

2. **Deploy**:
   ```bash
   # Build static export
   npm run build
   npm run export
   
   # Deploy to Netlify
   npx netlify deploy --prod --dir=out
   ```

### Docker Deployment

**Dockerfile**:
```dockerfile
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --only=production

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED 1
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
```

**Docker Compose** (`docker-compose.yml`):
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - NEXT_PUBLIC_APP_NAME=Business Scraper App
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### AWS Deployment

**Using AWS Amplify:**

1. **Install Amplify CLI**:
   ```bash
   npm install -g @aws-amplify/cli
   ```

2. **Initialize Project**:
   ```bash
   amplify init
   ```

3. **Deploy**:
   ```bash
   amplify add hosting
   amplify publish
   ```

**Using AWS EC2:**

1. **Launch EC2 Instance** (Ubuntu 20.04 LTS)
2. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install nodejs npm nginx
   ```

3. **Deploy Application**:
   ```bash
   git clone <repository>
   cd business-scraper-app
   npm install
   npm run build
   ```

4. **Configure Nginx**:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

## Performance Optimization

### Build Optimizations

1. **Bundle Analysis**:
   ```bash
   npm run analyze
   ```

2. **Code Splitting**:
   ```javascript
   // Dynamic imports for large components
   const ResultsTable = dynamic(() => import('./ResultsTable'), {
     loading: () => <Skeleton />,
   });
   ```

3. **Image Optimization**:
   ```javascript
   import Image from 'next/image';
   
   <Image
     src="/logo.png"
     alt="Logo"
     width={200}
     height={100}
     priority
   />
   ```

### Runtime Optimizations

1. **Service Worker** (if enabled):
   ```javascript
   // public/sw.js
   self.addEventListener('fetch', (event) => {
     if (event.request.destination === 'document') {
       event.respondWith(
         caches.match(event.request)
           .then(response => response || fetch(event.request))
       );
     }
   });
   ```

2. **Caching Strategy**:
   ```javascript
   // Cache API responses
   const cache = new Map();
   
   async function fetchWithCache(url, ttl = 3600000) {
     const cached = cache.get(url);
     if (cached && Date.now() - cached.timestamp < ttl) {
       return cached.data;
     }
     
     const data = await fetch(url).then(r => r.json());
     cache.set(url, { data, timestamp: Date.now() });
     return data;
   }
   ```

### CDN Configuration

**Cloudflare Settings:**
- Enable Auto Minify (CSS, JS, HTML)
- Enable Brotli compression
- Set Browser Cache TTL to 4 hours
- Enable Always Online

## Security Considerations

### Content Security Policy

```javascript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: `
      default-src 'self';
      script-src 'self' 'unsafe-eval' 'unsafe-inline';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      font-src 'self';
      connect-src 'self' https://api.duckduckgo.com https://nominatim.openstreetmap.org;
    `.replace(/\s{2,}/g, ' ').trim()
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};
```

### Environment Security

1. **Secrets Management**:
   - Use platform-specific secret management
   - Never commit API keys to version control
   - Rotate API keys regularly

2. **HTTPS Enforcement**:
   ```javascript
   // Redirect HTTP to HTTPS
   if (process.env.NODE_ENV === 'production' && !req.secure) {
     return res.redirect(301, `https://${req.headers.host}${req.url}`);
   }
   ```

## Monitoring and Maintenance

### Health Checks

```javascript
// pages/api/health.js
export default function handler(req, res) {
  const healthcheck = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: Date.now(),
    environment: process.env.NODE_ENV,
  };
  
  try {
    res.status(200).json(healthcheck);
  } catch (error) {
    healthcheck.message = error;
    res.status(503).json(healthcheck);
  }
}
```

### Error Tracking

**Sentry Integration**:
```javascript
// sentry.client.config.js
import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0,
});
```

### Performance Monitoring

1. **Web Vitals**:
   ```javascript
   // pages/_app.js
   export function reportWebVitals(metric) {
     console.log(metric);
     // Send to analytics service
   }
   ```

2. **Custom Metrics**:
   ```javascript
   // Track scraping performance
   const startTime = performance.now();
   await scraperService.scrapeWebsite(url);
   const duration = performance.now() - startTime;
   
   analytics.track('scraping_duration', { duration, url });
   ```

### Backup and Recovery

1. **Data Backup**:
   - IndexedDB data is stored locally
   - Implement export functionality for user data
   - Regular configuration backups

2. **Disaster Recovery**:
   - Multiple deployment environments
   - Automated rollback procedures
   - Database replication (if using external DB)

---

For platform-specific deployment instructions, refer to the respective platform documentation.
