/**
 * Centralized Content Security Policy (CSP) Configuration
 * Business Scraper Application - Enhanced Security Implementation
 */

import { logger } from '@/utils/logger'
import { generateSecureNonce } from '@/utils/crypto'

export interface CSPConfig {
  // Core directives
  defaultSrc: string[]
  scriptSrc: string[]
  styleSrc: string[]
  imgSrc: string[]
  fontSrc: string[]
  connectSrc: string[]

  // Security directives
  objectSrc: string[]
  mediaSrc: string[]
  frameSrc: string[]
  frameAncestors: string[]
  baseUri: string[]
  formAction: string[]

  // Worker and manifest
  workerSrc: string[]
  manifestSrc: string[]
  childSrc: string[]

  // Security features
  upgradeInsecureRequests: boolean
  blockAllMixedContent: boolean

  // Reporting
  reportUri?: string
  reportTo?: string
}

/**
 * Environment-specific CSP configurations
 */
const cspConfigs: Record<string, CSPConfig> = {
  development: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-eval'", // Required for Next.js development
      "'unsafe-inline'", // Required for development hot reload and React DevTools
      // Note: In development, we use unsafe-inline for easier debugging
      // Nonces are not used in development to avoid conflicts with unsafe-inline
      'https://js.stripe.com', // Stripe.js library
      'https://vercel.live', // Vercel development tools
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Required for CSS-in-JS, Tailwind, and React inline styles in development
      // Note: In development, we use unsafe-inline for easier debugging
      // Nonces are not used in development to avoid conflicts with unsafe-inline
    ],
    imgSrc: [
      "'self'",
      'data:',
      'blob:',
      'https:', // Allow all HTTPS images in development
    ],
    fontSrc: ["'self'", 'data:'],
    connectSrc: [
      "'self'",
      'ws://localhost:*', // WebSocket for development
      'http://localhost:*', // Local development servers
      'https://nominatim.openstreetmap.org', // Geocoding service
      'https://api.opencagedata.com', // Geocoding service
      'https://*.googleapis.com', // Google APIs
      'https://*.cognitiveservices.azure.com', // Azure services
      'https://api.duckduckgo.com', // Search API
      'https://duckduckgo.com', // Search service
      'https://api.stripe.com', // Stripe API
      'https://checkout.stripe.com', // Stripe Checkout
      'https://js.stripe.com', // Stripe.js library
    ],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'self'", 'https://js.stripe.com', 'https://hooks.stripe.com', 'https://checkout.stripe.com'],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'self'", 'blob:'],
    manifestSrc: ["'self'"],
    childSrc: ["'self'"],
    upgradeInsecureRequests: false, // Allow HTTP in development
    blockAllMixedContent: false,
    reportUri: '/api/csp-report',
  },

  production: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-eval'", // Still needed for some Next.js features
      "'nonce-{nonce}'", // Use nonces for inline scripts
      'https://js.stripe.com', // Stripe.js library
      // Add specific hashes for known safe inline scripts (updated with current violations)
      "'sha256-Q+8tPsjVtiDsjF/Cv8FMOpg2Yg91oKFKDAJat1PPb2g='",
      "'sha256-x6H1bC+RRVj8E0k3vb6/WKyN24h5doxTA+DpnEW+glI='",
      "'sha256-w5bq2yF5OAaXG6HURdITkIBCp4xw6B/EMtny4WSHt+s='",
      "'sha256-JL/y8kA7Q8QthoFHPhMwHvXDIs8tNuM/yotj5L9sjdI='",
      "'sha256-3hiRNYmbR1ph5hd0c32tNycNet1m3ac0HyEXQXEGJyQ='",
      "'sha256-3QcKhPKGFSJ3p54YDwQ88l5Wvq88en250fatWxsL/NY='",
      // Additional hashes from console violations
      "'sha256-dyzCnHa/jBIBK24sOTThWknRfCH9dOwxEfkI5ncCmjA='",
      "'sha256-3Jo+kaAFL9InHda238UqrgJCIyhTOvTz0irzB6vhDK0='",
      "'sha256-6GzLhHSjaZcGUzFDzkfHLHGNka2lY3DfhCBteNxRPyU='",
      "'sha256-JTWJpbXq8BOpW73/Z/q3955e75Sg8pHZ83hhuSlOz5w='",
      "'sha256-q0DFzdS56c2q1C0qsJfPbfLEEe7Hn8kwIx+W4ZKBGbs='",
      "'sha256-BGpzNjr9NuUr69xKfNtJ7M+GUjku1mQG9t1u5x4Ayng='",
      "'sha256-novOumJTR/bLM3a87imJruNYYuV1Mewp9v6XNg0LT2g='",
      "'sha256-li15+uLSlqLclRNFUz4D5UwK6yKiknaCrlcj+q8+zW0='",
      "'sha256-lUog9ElEAEf90cQXdvoDgK8diTTAXYqu++aPBXOmZrg='",
      "'sha256-6k72MmYzwHn9tPy8L25fiipaDpw6IH65REwaAMn8JC4='",
      "'sha256-1vPpzEwO0H5nfl6olZiRgSqKPtPz2ZveWRM/fhJ19Pc='",
      // Additional hashes from recent console violations
      "'sha256-2lt0bFJlc5Kaphf4LkrOMIrdaHAEYNx8N9WCufhBrCo='",
      "'sha256-oolAXs2Cdo3WdBhu4uUyDkOe8GFEQ1wq7uqTsMiKW9U='",
      "'sha256-z05Y9BUQz7PEpWh9sitkqC+x0N4+SQix0AsyRlpYy7Q='",
      "'sha256-JM7ucALGjjhHJ6z0bfjR6Dx5+OvnghD+JZoXdsywlzM='",
      "'sha256-VySdMvYwvSwI5wjrw1P0Bfo7JRandOP0fPX3lt9vjaI='",
    ],
    styleSrc: [
      "'self'",
      "'nonce-{nonce}'", // Use nonces for inline styles
      "'unsafe-inline'", // Temporarily allow for compatibility - will be removed after full CSP implementation
      // Add specific hashes for known safe inline styles
      "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
      "'sha256-Nqnn8clbgv+5l0PgxcTOldg8mkMKrFn4TvPL+rYUUGg='",
      "'sha256-13vrThxdyT64GcXoTNGVoRRoL0a7EGBmOJ+lemEWyws='",
      "'sha256-QZ52fjvWgIOIOPr+gRIJZ7KjzNeTBm50Z+z9dH4N1/8='",
      "'sha256-yOU6eaJ75xfag0gVFUvld5ipLRGUy94G17B1uL683EU='",
      "'sha256-OpTmykz0m3o5HoX53cykwPhUeU4OECxHQlKXpB0QJPQ='",
      "'sha256-SSIM0kI/u45y4gqkri9aH+la6wn2R+xtcBj3Lzh7qQo='",
      "'sha256-ZH/+PJIjvP1BctwYxclIuiMu1wItb0aasjpXYXOmU0Y='",
      "'sha256-58jqDtherY9NOM+ziRgSqQY0078tAZ+qtTBjMgbM9po='",
      "'sha256-7Ri/I+PfhgtpcL7hT4A0VJKI6g3pK0ZvIN09RQV4ZhI='",
    ],
    imgSrc: [
      "'self'",
      'data:',
      'blob:',
      'https://nominatim.openstreetmap.org', // Specific image sources only
      'https://api.opencagedata.com',
      // Next.js assets are served from same origin ('self' covers them)
    ],
    fontSrc: ["'self'", 'data:'],
    connectSrc: [
      "'self'", // CRITICAL: Allow same-origin connections for EventSource/fetch/XHR
      'https://nominatim.openstreetmap.org', // Geocoding service
      'https://api.opencagedata.com', // Geocoding service
      'https://*.googleapis.com', // Google APIs
      'https://*.cognitiveservices.azure.com', // Azure services
      'https://api.duckduckgo.com', // Search API
      'https://duckduckgo.com', // Search service
      'https://api.stripe.com', // Stripe API
      'https://checkout.stripe.com', // Stripe Checkout
      'https://js.stripe.com', // Stripe.js
      'https://js.stripe.com/basil/', // Stripe.js basil
    ],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'self'", 'https://js.stripe.com', 'https://hooks.stripe.com', 'https://checkout.stripe.com'],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'self'", 'blob:'],
    manifestSrc: ["'self'"],
    childSrc: ["'self'"],
    upgradeInsecureRequests: true,
    blockAllMixedContent: true,
    reportUri: '/api/csp-report',
  },

  test: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'blob:'],
    fontSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'self'"],
    manifestSrc: ["'self'"],
    childSrc: ["'self'"],
    upgradeInsecureRequests: false,
    blockAllMixedContent: false,
  },
}

/**
 * Generate a cryptographically secure nonce for CSP
 */
export function generateCSPNonce(): string {
  return generateSecureNonce()
}

/**
 * Get CSP configuration for current environment
 */
export function getCSPConfig(environment?: string): CSPConfig {
  const env = environment || process.env.NODE_ENV || 'development'
  const config = cspConfigs[env] || cspConfigs.development

  logger.debug('CSP Config', `Using CSP configuration for environment: ${env}`)
  return config
}

/**
 * Build CSP header string from configuration
 */
export function buildCSPHeader(config: CSPConfig, nonce?: string): string {
  const directives: string[] = []
  const isDevelopment = process.env.NODE_ENV === 'development'

  // Replace nonce placeholders with actual nonce (only in production)
  const replaceNonce = (sources: string[]) => {
    if (isDevelopment) {
      // In development, don't add nonces to preserve unsafe-inline functionality
      return sources.filter(src => !src.includes('{nonce}'))
    }
    return sources.map(src => src.replace('{nonce}', nonce || ''))
  }

  // Core directives
  if (config.defaultSrc.length) {
    directives.push(`default-src ${config.defaultSrc.join(' ')}`)
  }

  if (config.scriptSrc.length) {
    directives.push(`script-src ${replaceNonce(config.scriptSrc).join(' ')}`)
  }

  if (config.styleSrc.length) {
    directives.push(`style-src ${replaceNonce(config.styleSrc).join(' ')}`)
  }

  if (config.imgSrc.length) {
    directives.push(`img-src ${config.imgSrc.join(' ')}`)
  }

  if (config.fontSrc.length) {
    directives.push(`font-src ${config.fontSrc.join(' ')}`)
  }

  if (config.connectSrc.length) {
    directives.push(`connect-src ${config.connectSrc.join(' ')}`)
  }

  // Security directives
  if (config.objectSrc.length) {
    directives.push(`object-src ${config.objectSrc.join(' ')}`)
  }

  if (config.mediaSrc.length) {
    directives.push(`media-src ${config.mediaSrc.join(' ')}`)
  }

  if (config.frameSrc.length) {
    directives.push(`frame-src ${config.frameSrc.join(' ')}`)
  }

  if (config.frameAncestors.length) {
    directives.push(`frame-ancestors ${config.frameAncestors.join(' ')}`)
  }

  if (config.baseUri.length) {
    directives.push(`base-uri ${config.baseUri.join(' ')}`)
  }

  if (config.formAction.length) {
    directives.push(`form-action ${config.formAction.join(' ')}`)
  }

  // Worker and manifest directives
  if (config.workerSrc.length) {
    directives.push(`worker-src ${config.workerSrc.join(' ')}`)
  }

  if (config.manifestSrc.length) {
    directives.push(`manifest-src ${config.manifestSrc.join(' ')}`)
  }

  if (config.childSrc.length) {
    directives.push(`child-src ${config.childSrc.join(' ')}`)
  }

  // Security features
  if (config.upgradeInsecureRequests) {
    directives.push('upgrade-insecure-requests')
  }

  if (config.blockAllMixedContent) {
    directives.push('block-all-mixed-content')
  }

  // Reporting
  if (config.reportUri) {
    directives.push(`report-uri ${config.reportUri}`)
  }

  if (config.reportTo) {
    directives.push(`report-to ${config.reportTo}`)
  }

  const cspHeader = directives.join('; ')
  logger.debug('CSP Config', `Generated CSP header: ${cspHeader}`)

  return cspHeader
}

/**
 * Get the complete CSP header for the current environment
 */
export function getCSPHeader(nonce?: string): string {
  const config = getCSPConfig()
  return buildCSPHeader(config, nonce)
}

/**
 * Validate CSP configuration
 */
export function validateCSPConfig(config: CSPConfig): { isValid: boolean; errors: string[] } {
  const errors: string[] = []

  // Check required directives
  if (!config.defaultSrc.length) {
    errors.push('default-src directive is required')
  }

  if (!config.objectSrc.includes("'none'")) {
    errors.push('object-src should be set to none for security')
  }

  if (!config.frameAncestors.includes("'none'") && !config.frameAncestors.includes("'self'")) {
    errors.push('frame-ancestors should be restricted')
  }

  // Check for unsafe directives in production
  if (process.env.NODE_ENV === 'production') {
    if (
      config.scriptSrc.includes("'unsafe-inline'") &&
      !config.scriptSrc.includes("'nonce-{nonce}'")
    ) {
      errors.push('unsafe-inline in script-src should be replaced with nonces in production')
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
  }
}

/**
 * CSP violation reporting interface
 */
export interface CSPViolationReport {
  'csp-report': {
    'document-uri': string
    referrer: string
    'violated-directive': string
    'effective-directive': string
    'original-policy': string
    disposition: string
    'blocked-uri': string
    'line-number': number
    'column-number': number
    'source-file': string
    'status-code': number
    'script-sample': string
  }
}

/**
 * Log CSP violation for monitoring
 */
export function logCSPViolation(report: CSPViolationReport): void {
  const violation = report['csp-report']

  logger.warn('CSP Violation', {
    directive: violation['violated-directive'],
    blockedUri: violation['blocked-uri'],
    documentUri: violation['document-uri'],
    sourceFile: violation['source-file'],
    lineNumber: violation['line-number'],
    columnNumber: violation['column-number'],
    scriptSample: violation['script-sample'],
  })

  // In production, you might want to send this to a monitoring service
  if (process.env.NODE_ENV === 'production') {
    // TODO: Send to monitoring service (e.g., Sentry, DataDog)
  }
}
