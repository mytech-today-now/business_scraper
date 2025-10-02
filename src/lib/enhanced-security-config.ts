/**
 * Enhanced Security Configuration
 * Centralized security settings for the authentication system
 */

export interface EnhancedSecurityConfig {
  // Session Management
  sessionTimeout: number
  sessionRenewalThreshold: number
  maxSessionRenewals: number
  sessionCleanupInterval: number
  
  // JWT Configuration
  jwtSecret: string
  jwtAlgorithm: string
  jwtIssuer: string
  jwtAudience: string
  jwtSessionLifetime: number
  jwtRenewalLifetime: number
  
  // IP Security
  strictIPBinding: boolean
  ipChangeTolerance: boolean
  ipHashSalt: string
  
  // Device Fingerprinting
  requireDeviceFingerprint: boolean
  deviceFingerprintComponents: string[]
  fingerprintHashLength: number
  
  // Rate Limiting
  rateLimiting: {
    login: {
      windowMs: number
      maxAttempts: number
      lockoutDuration: number
      progressiveLockout: boolean
    }
    sessionValidation: {
      windowMs: number
      maxAttempts: number
      lockoutDuration: number
      progressiveLockout: boolean
    }
    passwordReset: {
      windowMs: number
      maxAttempts: number
      lockoutDuration: number
      progressiveLockout: boolean
    }
  }
  
  // Account Lockout
  accountLockout: {
    maxFailedAttempts: number
    lockoutDuration: number
    progressiveMultiplier: number
    maxLockoutDuration: number
    resetAfterSuccess: boolean
  }
  
  // Suspicious Activity Detection
  suspiciousActivity: {
    enabled: boolean
    riskThreshold: number
    autoBlockThreshold: number
    monitoringWindow: number
    patternDetection: {
      rapidAttempts: boolean
      userAgentAnalysis: boolean
      timingAnalysis: boolean
      geolocationTracking: boolean
    }
  }
  
  // CSRF Protection
  csrf: {
    tokenLength: number
    tokenExpiry: number
    strictSameSite: boolean
    secureOnly: boolean
  }
  
  // Encryption
  encryption: {
    algorithm: string
    keyLength: number
    ivLength: number
    saltLength: number
    iterations: number
  }
  
  // Audit and Logging
  audit: {
    logAllAttempts: boolean
    logSuccessfulAuth: boolean
    logFailedAuth: boolean
    logSuspiciousActivity: boolean
    retentionPeriod: number
  }
  
  // Compliance
  compliance: {
    soc2: boolean
    gdpr: boolean
    hipaa: boolean
    pci: boolean
  }
}

// Default enhanced security configuration
export const enhancedSecurityConfig: EnhancedSecurityConfig = {
  // Session Management
  sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
  sessionRenewalThreshold: 5 * 60 * 1000, // 5 minutes
  maxSessionRenewals: 10,
  sessionCleanupInterval: 60 * 60 * 1000, // 1 hour
  
  // JWT Configuration
  jwtSecret: process.env.JWT_SESSION_SECRET || 'your-super-secure-session-secret-key-change-in-production',
  jwtAlgorithm: 'HS256',
  jwtIssuer: 'business-scraper-auth',
  jwtAudience: 'business-scraper-app',
  jwtSessionLifetime: 24 * 60 * 60, // 24 hours in seconds
  jwtRenewalLifetime: 7 * 24 * 60 * 60, // 7 days in seconds
  
  // IP Security
  strictIPBinding: true,
  ipChangeTolerance: false,
  ipHashSalt: process.env.IP_HASH_SALT || 'secure-ip-salt-change-in-production',
  
  // Device Fingerprinting
  requireDeviceFingerprint: true,
  deviceFingerprintComponents: [
    'user-agent',
    'accept-language',
    'accept-encoding',
    'screen-resolution',
    'timezone'
  ],
  fingerprintHashLength: 32,
  
  // Rate Limiting
  rateLimiting: {
    login: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      progressiveLockout: true
    },
    sessionValidation: {
      windowMs: 5 * 60 * 1000, // 5 minutes
      maxAttempts: 50,
      lockoutDuration: 5 * 60 * 1000, // 5 minutes
      progressiveLockout: false
    },
    passwordReset: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxAttempts: 3,
      lockoutDuration: 60 * 60 * 1000, // 1 hour
      progressiveLockout: true
    }
  },
  
  // Account Lockout
  accountLockout: {
    maxFailedAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    progressiveMultiplier: 2,
    maxLockoutDuration: 24 * 60 * 60 * 1000, // 24 hours
    resetAfterSuccess: true
  },
  
  // Suspicious Activity Detection
  suspiciousActivity: {
    enabled: true,
    riskThreshold: 5,
    autoBlockThreshold: 8,
    monitoringWindow: 24 * 60 * 60 * 1000, // 24 hours
    patternDetection: {
      rapidAttempts: true,
      userAgentAnalysis: true,
      timingAnalysis: true,
      geolocationTracking: true
    }
  },
  
  // CSRF Protection
  csrf: {
    tokenLength: 32,
    tokenExpiry: 60 * 60 * 1000, // 1 hour
    strictSameSite: true,
    secureOnly: process.env.NODE_ENV === 'production'
  },
  
  // Encryption
  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 16,
    saltLength: 16,
    iterations: 100000
  },
  
  // Audit and Logging
  audit: {
    logAllAttempts: true,
    logSuccessfulAuth: true,
    logFailedAuth: true,
    logSuspiciousActivity: true,
    retentionPeriod: 90 * 24 * 60 * 60 * 1000 // 90 days
  },
  
  // Compliance
  compliance: {
    soc2: true,
    gdpr: true,
    hipaa: false,
    pci: false
  }
}

/**
 * Get security configuration with environment overrides
 */
export function getEnhancedSecurityConfig(): EnhancedSecurityConfig {
  return {
    ...enhancedSecurityConfig,
    // Override with environment variables if available
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '') || enhancedSecurityConfig.sessionTimeout,
    jwtSecret: process.env.JWT_SESSION_SECRET || enhancedSecurityConfig.jwtSecret,
    strictIPBinding: process.env.STRICT_IP_BINDING === 'true' || enhancedSecurityConfig.strictIPBinding,
    requireDeviceFingerprint: process.env.REQUIRE_DEVICE_FINGERPRINT === 'true' || enhancedSecurityConfig.requireDeviceFingerprint,
    suspiciousActivity: {
      ...enhancedSecurityConfig.suspiciousActivity,
      enabled: process.env.SUSPICIOUS_ACTIVITY_DETECTION !== 'false'
    }
  }
}

/**
 * Validate security configuration
 */
export function validateSecurityConfig(config: EnhancedSecurityConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  
  // Validate JWT secret
  if (!config.jwtSecret || config.jwtSecret.length < 32) {
    errors.push('JWT secret must be at least 32 characters long')
  }
  
  // Validate session timeout
  if (config.sessionTimeout < 5 * 60 * 1000) {
    errors.push('Session timeout must be at least 5 minutes')
  }
  
  // Validate rate limiting
  if (config.rateLimiting.login.maxAttempts < 1) {
    errors.push('Login max attempts must be at least 1')
  }
  
  // Validate lockout duration
  if (config.accountLockout.lockoutDuration < 60 * 1000) {
    errors.push('Account lockout duration must be at least 1 minute')
  }
  
  // Validate suspicious activity thresholds
  if (config.suspiciousActivity.riskThreshold > config.suspiciousActivity.autoBlockThreshold) {
    errors.push('Risk threshold cannot be higher than auto-block threshold')
  }
  
  return {
    valid: errors.length === 0,
    errors
  }
}

/**
 * Get production-ready security configuration
 */
export function getProductionSecurityConfig(): EnhancedSecurityConfig {
  const config = getEnhancedSecurityConfig()
  
  // Production-specific overrides
  return {
    ...config,
    strictIPBinding: true,
    requireDeviceFingerprint: true,
    csrf: {
      ...config.csrf,
      secureOnly: true,
      strictSameSite: true
    },
    suspiciousActivity: {
      ...config.suspiciousActivity,
      enabled: true,
      autoBlockThreshold: 7 // More aggressive in production
    },
    audit: {
      ...config.audit,
      logAllAttempts: true,
      retentionPeriod: 180 * 24 * 60 * 60 * 1000 // 180 days for production
    }
  }
}
