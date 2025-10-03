/**
 * Security Testing Configuration
 * 
 * Comprehensive configuration for security testing infrastructure including
 * vulnerability scanning, penetration testing, and security monitoring.
 */

export interface SecurityTestingConfig {
  // Vulnerability Scanning
  vulnerabilityScanning: {
    enabled: boolean
    snykToken?: string
    auditLevel: 'low' | 'moderate' | 'high' | 'critical'
    failOnVulnerabilities: boolean
    excludeDevDependencies: boolean
    severityThreshold: 'low' | 'medium' | 'high' | 'critical'
  }

  // Penetration Testing
  penetrationTesting: {
    enabled: boolean
    targetUrl: string
    testCategories: string[]
    maxConcurrentTests: number
    timeoutMs: number
    reportFormat: 'json' | 'html' | 'sarif'
  }

  // Security Monitoring
  securityMonitoring: {
    enabled: boolean
    realTimeAlerts: boolean
    logLevel: 'debug' | 'info' | 'warn' | 'error'
    retentionDays: number
    alertThresholds: {
      failedLogins: number
      suspiciousActivity: number
      rateLimitExceeded: number
    }
  }

  // Compliance Testing
  complianceTesting: {
    enabled: boolean
    standards: ('SOC2' | 'GDPR' | 'HIPAA' | 'PCI')[]
    auditTrail: boolean
    dataEncryption: boolean
    accessControls: boolean
  }

  // Security Headers Testing
  securityHeaders: {
    enabled: boolean
    requiredHeaders: string[]
    cspValidation: boolean
    hstsValidation: boolean
    frameOptionsValidation: boolean
  }

  // Authentication Testing
  authenticationTesting: {
    enabled: boolean
    bruteForceProtection: boolean
    sessionManagement: boolean
    passwordPolicies: boolean
    mfaValidation: boolean
  }

  // Input Validation Testing
  inputValidationTesting: {
    enabled: boolean
    sqlInjection: boolean
    xssProtection: boolean
    csrfProtection: boolean
    fileUploadSecurity: boolean
  }
}

// Default security testing configuration
export const defaultSecurityTestingConfig: SecurityTestingConfig = {
  vulnerabilityScanning: {
    enabled: true,
    snykToken: process.env.SNYK_TOKEN,
    auditLevel: 'high',
    failOnVulnerabilities: process.env.NODE_ENV === 'production',
    excludeDevDependencies: process.env.NODE_ENV === 'production',
    severityThreshold: 'high'
  },

  penetrationTesting: {
    enabled: true,
    targetUrl: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
    testCategories: [
      'authentication',
      'authorization',
      'input-validation',
      'session-management',
      'data-protection',
      'security-headers'
    ],
    maxConcurrentTests: 5,
    timeoutMs: 30000,
    reportFormat: 'json'
  },

  securityMonitoring: {
    enabled: true,
    realTimeAlerts: process.env.NODE_ENV === 'production',
    logLevel: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
    retentionDays: 90,
    alertThresholds: {
      failedLogins: 5,
      suspiciousActivity: 3,
      rateLimitExceeded: 10
    }
  },

  complianceTesting: {
    enabled: true,
    standards: ['SOC2', 'GDPR'],
    auditTrail: true,
    dataEncryption: true,
    accessControls: true
  },

  securityHeaders: {
    enabled: true,
    requiredHeaders: [
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy'
    ],
    cspValidation: true,
    hstsValidation: process.env.NODE_ENV === 'production',
    frameOptionsValidation: true
  },

  authenticationTesting: {
    enabled: true,
    bruteForceProtection: true,
    sessionManagement: true,
    passwordPolicies: true,
    mfaValidation: false // Enable when MFA is implemented
  },

  inputValidationTesting: {
    enabled: true,
    sqlInjection: true,
    xssProtection: true,
    csrfProtection: true,
    fileUploadSecurity: true
  }
}

/**
 * Get security testing configuration with environment overrides
 */
export function getSecurityTestingConfig(): SecurityTestingConfig {
  const config = { ...defaultSecurityTestingConfig }

  // Environment-specific overrides
  if (process.env.SECURITY_SCAN_ENABLED === 'false') {
    config.vulnerabilityScanning.enabled = false
    config.penetrationTesting.enabled = false
  }

  if (process.env.VULNERABILITY_THRESHOLD) {
    config.vulnerabilityScanning.severityThreshold = process.env.VULNERABILITY_THRESHOLD as any
  }

  if (process.env.SNYK_TOKEN) {
    config.vulnerabilityScanning.snykToken = process.env.SNYK_TOKEN
  }

  return config
}

/**
 * Validate security testing configuration
 */
export function validateSecurityTestingConfig(config: SecurityTestingConfig): string[] {
  const errors: string[] = []

  if (config.vulnerabilityScanning.enabled && !config.vulnerabilityScanning.snykToken) {
    errors.push('SNYK_TOKEN is required when vulnerability scanning is enabled')
  }

  if (config.penetrationTesting.enabled && !config.penetrationTesting.targetUrl) {
    errors.push('Target URL is required when penetration testing is enabled')
  }

  if (config.securityMonitoring.retentionDays < 1) {
    errors.push('Security monitoring retention days must be at least 1')
  }

  return errors
}

/**
 * Security test categories and their descriptions
 */
export const securityTestCategories = {
  'vulnerability-scanning': 'Automated dependency vulnerability scanning',
  'penetration-testing': 'Simulated attack scenarios and security testing',
  'authentication': 'Authentication and authorization security tests',
  'input-validation': 'Input validation and injection attack prevention',
  'session-management': 'Session security and management tests',
  'data-protection': 'Data encryption and protection validation',
  'security-headers': 'HTTP security headers validation',
  'compliance': 'Regulatory compliance testing (SOC2, GDPR, etc.)',
  'monitoring': 'Security monitoring and alerting tests'
} as const

export type SecurityTestCategory = keyof typeof securityTestCategories

/**
 * Security test severity levels
 */
export enum SecurityTestSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Security test result interface
 */
export interface SecurityTestResult {
  category: SecurityTestCategory
  testName: string
  severity: SecurityTestSeverity
  passed: boolean
  vulnerabilityFound: boolean
  description: string
  recommendation?: string
  cveIds?: string[]
  affectedPackages?: string[]
  fixAvailable?: boolean
  timestamp: Date
}

/**
 * Security testing metrics
 */
export interface SecurityTestingMetrics {
  totalTests: number
  passedTests: number
  failedTests: number
  vulnerabilitiesFound: number
  criticalVulnerabilities: number
  highVulnerabilities: number
  mediumVulnerabilities: number
  lowVulnerabilities: number
  testDuration: number
  lastRunTimestamp: Date
}
