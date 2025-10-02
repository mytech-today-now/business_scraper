/**
 * Hardened Security Configuration
 * P0 - Critical Security Configuration for Production Deployment
 * 
 * This file implements comprehensive security hardening across the business scraper application
 * including CSP enhancement, session security, input validation, and threat detection.
 */

import { logger } from '@/utils/logger'

export interface HardenedSecurityConfig {
  // Content Security Policy Enhancement
  csp: {
    productionCSP: string[]
    reportOnly: boolean
    reportUri: string
    violationThreshold: number
  }

  // Session Security Hardening
  session: {
    httpOnly: boolean
    secure: boolean
    sameSite: 'strict' | 'lax' | 'none'
    maxAge: number
    path: string
    domain?: string
    regenerateOnAuth: boolean
    rollingExpiration: boolean
  }

  // API Security Enhancement
  apiSecurity: {
    rateLimit: {
      windowMs: number
      max: number
      message: string
      standardHeaders: boolean
      legacyHeaders: boolean
    }
    helmet: {
      contentSecurityPolicy: boolean
      crossOriginEmbedderPolicy: boolean
      crossOriginOpenerPolicy: boolean
      crossOriginResourcePolicy: { policy: string }
      dnsPrefetchControl: boolean
      frameguard: { action: string }
      hidePoweredBy: boolean
      hsts: {
        maxAge: number
        includeSubDomains: boolean
        preload: boolean
      }
      ieNoOpen: boolean
      noSniff: boolean
      originAgentCluster: boolean
      permittedCrossDomainPolicies: boolean
      referrerPolicy: { policy: string }
      xssFilter: boolean
    }
  }

  // Input Validation Enhancement
  inputValidation: {
    enableDOMPurify: boolean
    enableValidator: boolean
    maxInputLength: number
    allowedTags: string[]
    allowedAttributes: { [key: string]: string[] }
    sanitizeOptions: {
      ALLOWED_TAGS: string[]
      ALLOWED_ATTR: string[]
      ALLOW_DATA_ATTR: boolean
      ALLOW_UNKNOWN_PROTOCOLS: boolean
    }
  }

  // Security Monitoring
  monitoring: {
    enabled: boolean
    threatDetection: boolean
    auditLogging: boolean
    realTimeAlerts: boolean
    complianceMode: string
    retentionPeriod: number
  }

  // Encryption Settings
  encryption: {
    masterKeyLength: number
    algorithm: string
    keyDerivationIterations: number
    saltLength: number
    ivLength: number
  }

  // Compliance Settings
  compliance: {
    soc2TypeII: boolean
    gdprCompliance: boolean
    pciDssLevel1: boolean
    owaspTop10Protection: boolean
  }
}

/**
 * Production-ready hardened security configuration
 */
export const hardenedSecurityConfig: HardenedSecurityConfig = {
  // Enhanced Content Security Policy
  csp: {
    productionCSP: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://js.stripe.com https://checkout.stripe.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self' https://api.stripe.com",
      "frame-src https://js.stripe.com https://hooks.stripe.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests"
    ],
    reportOnly: false,
    reportUri: '/api/csp-report',
    violationThreshold: 10
  },

  // Hardened Session Configuration
  session: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000, // 30 minutes
    path: '/',
    domain: process.env.NODE_ENV === 'production' ? process.env.DOMAIN : undefined,
    regenerateOnAuth: true,
    rollingExpiration: true
  },

  // Enhanced API Security
  apiSecurity: {
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP',
      standardHeaders: true,
      legacyHeaders: false
    },
    helmet: {
      contentSecurityPolicy: true,
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: true,
      crossOriginResourcePolicy: { policy: "cross-origin" },
      dnsPrefetchControl: true,
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      ieNoOpen: true,
      noSniff: true,
      originAgentCluster: true,
      permittedCrossDomainPolicies: false,
      referrerPolicy: { policy: "no-referrer" },
      xssFilter: true
    }
  },

  // Comprehensive Input Validation
  inputValidation: {
    enableDOMPurify: true,
    enableValidator: true,
    maxInputLength: 10000,
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    allowedAttributes: {
      'a': ['href', 'title'],
      '*': ['class']
    },
    sanitizeOptions: {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href', 'title', 'class'],
      ALLOW_DATA_ATTR: false,
      ALLOW_UNKNOWN_PROTOCOLS: false
    }
  },

  // Security Monitoring Configuration
  monitoring: {
    enabled: true,
    threatDetection: true,
    auditLogging: true,
    realTimeAlerts: true,
    complianceMode: 'SOC2_TYPE_II',
    retentionPeriod: 90 * 24 * 60 * 60 * 1000 // 90 days
  },

  // Enhanced Encryption Settings
  encryption: {
    masterKeyLength: 64,
    algorithm: 'aes-256-gcm',
    keyDerivationIterations: 100000,
    saltLength: 32,
    ivLength: 16
  },

  // Compliance Configuration
  compliance: {
    soc2TypeII: true,
    gdprCompliance: true,
    pciDssLevel1: true,
    owaspTop10Protection: true
  }
}

/**
 * Get environment-specific security configuration
 */
export function getHardenedSecurityConfig(environment?: string): HardenedSecurityConfig {
  const env = environment || process.env.NODE_ENV || 'development'
  
  if (env === 'development') {
    // Relaxed settings for development
    return {
      ...hardenedSecurityConfig,
      session: {
        ...hardenedSecurityConfig.session,
        secure: false,
        sameSite: 'lax'
      },
      csp: {
        ...hardenedSecurityConfig.csp,
        reportOnly: true
      }
    }
  }

  return hardenedSecurityConfig
}

/**
 * Validate security configuration
 */
export function validateHardenedSecurityConfig(config: HardenedSecurityConfig): {
  isValid: boolean
  errors: string[]
  warnings: string[]
} {
  const errors: string[] = []
  const warnings: string[] = []

  // Validate CSP configuration
  if (!config.csp.productionCSP.includes("object-src 'none'")) {
    errors.push('CSP must include object-src none for security')
  }

  if (!config.csp.productionCSP.includes("frame-ancestors 'none'")) {
    errors.push('CSP must include frame-ancestors none for clickjacking protection')
  }

  // Validate session security
  if (process.env.NODE_ENV === 'production') {
    if (!config.session.secure) {
      errors.push('Session cookies must be secure in production')
    }
    if (config.session.sameSite !== 'strict') {
      warnings.push('Consider using strict SameSite for maximum security')
    }
  }

  // Validate encryption settings
  if (config.encryption.masterKeyLength < 32) {
    errors.push('Master key length must be at least 32 bytes')
  }

  if (config.encryption.keyDerivationIterations < 100000) {
    warnings.push('Consider using at least 100,000 iterations for key derivation')
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings
  }
}

/**
 * Log security configuration status
 */
export function logSecurityConfigStatus(): void {
  const config = getHardenedSecurityConfig()
  const validation = validateHardenedSecurityConfig(config)

  logger.info('Security Config', {
    environment: process.env.NODE_ENV,
    isValid: validation.isValid,
    errorsCount: validation.errors.length,
    warningsCount: validation.warnings.length,
    complianceMode: config.monitoring.complianceMode
  })

  if (validation.errors.length > 0) {
    logger.error('Security Config Errors', { errors: validation.errors })
  }

  if (validation.warnings.length > 0) {
    logger.warn('Security Config Warnings', { warnings: validation.warnings })
  }
}
