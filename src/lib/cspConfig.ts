/**
 * Centralized Content Security Policy (CSP) Configuration
 * Business Scraper Application - Enhanced Security Implementation
 */

import { logger } from '@/utils/logger'

/**
 * Generate a cryptographically secure nonce using Web Crypto API (Edge Runtime compatible)
 */
function generateSecureNonce(): string {
  // Fallback for environments without crypto.getRandomValues
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    // Use Math.random as fallback (less secure but functional)
    const array = new Uint8Array(16)
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256)
    }
    return btoa(String.fromCharCode(...array))
  }

  // Use Web Crypto API
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array))
}

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
      "'unsafe-inline'", // Required for development hot reload
      "'nonce-{nonce}'" // Placeholder for dynamic nonce
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Required for CSS-in-JS and Tailwind
      "'nonce-{nonce}'" // Placeholder for dynamic nonce
    ],
    imgSrc: [
      "'self'",
      "data:",
      "blob:",
      "https:" // Allow all HTTPS images in development
    ],
    fontSrc: ["'self'", "data:"],
    connectSrc: [
      "'self'",
      "ws://localhost:*", // WebSocket for development
      "http://localhost:*", // Local development servers
      "https://nominatim.openstreetmap.org", // Geocoding service
      "https://api.opencagedata.com", // Geocoding service
      "https://*.googleapis.com", // Google APIs
      "https://*.cognitiveservices.azure.com", // Azure services
      "https://api.duckduckgo.com", // Search API
      "https://duckduckgo.com" // Search service
    ],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'self'", "blob:"],
    manifestSrc: ["'self'"],
    childSrc: ["'self'"],
    upgradeInsecureRequests: false, // Allow HTTP in development
    blockAllMixedContent: false,
    reportUri: "/api/csp-report"
  },
  
  production: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-eval'", // Still needed for some Next.js features
      "'nonce-{nonce}'" // Use nonces for inline scripts
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Required for Tailwind and CSS-in-JS
      "'nonce-{nonce}'" // Use nonces for inline styles
    ],
    imgSrc: [
      "'self'",
      "data:",
      "blob:",
      "https://nominatim.openstreetmap.org", // Specific image sources only
      "https://api.opencagedata.com",
      // Next.js image optimization domains
      "/_next/image*", // Next.js image optimization endpoint
      "/_next/static/*" // Next.js static assets
    ],
    fontSrc: ["'self'", "data:"],
    connectSrc: [
      "'self'",
      "https://nominatim.openstreetmap.org", // Geocoding service
      "https://api.opencagedata.com", // Geocoding service
      "https://*.googleapis.com", // Google APIs
      "https://*.cognitiveservices.azure.com", // Azure services
      "https://api.duckduckgo.com", // Search API
      "https://duckduckgo.com" // Search service
    ],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'self'", "blob:"],
    manifestSrc: ["'self'"],
    childSrc: ["'self'"],
    upgradeInsecureRequests: true,
    blockAllMixedContent: true,
    reportUri: "/api/csp-report"
  },
  
  test: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    fontSrc: ["'self'", "data:"],
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
    blockAllMixedContent: false
  }
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
  
  // Replace nonce placeholders with actual nonce
  const replaceNonce = (sources: string[]) => 
    sources.map(src => src.replace('{nonce}', nonce || ''))
  
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
    if (config.scriptSrc.includes("'unsafe-inline'") && !config.scriptSrc.includes("'nonce-{nonce}'")) {
      errors.push('unsafe-inline in script-src should be replaced with nonces in production')
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
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
    scriptSample: violation['script-sample']
  })
  
  // In production, you might want to send this to a monitoring service
  if (process.env.NODE_ENV === 'production') {
    // TODO: Send to monitoring service (e.g., Sentry, DataDog)
  }
}
