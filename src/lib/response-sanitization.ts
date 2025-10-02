/**
 * Response Sanitization Middleware
 * Comprehensive data filtering and protection for API responses
 */

import { NextResponse } from 'next/server'
import { logger } from '@/utils/logger'

/**
 * Data classification levels
 */
export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  SECRET = 'secret'
}

/**
 * Sensitive field patterns and their classifications
 */
export const SENSITIVE_FIELD_PATTERNS = {
  // Authentication & Security - CRITICAL: Always remove these
  password: DataClassification.SECRET,
  password_hash: DataClassification.SECRET,
  password_salt: DataClassification.SECRET,
  passwordhash: DataClassification.SECRET,
  passwordsalt: DataClassification.SECRET,
  secret: DataClassification.SECRET,
  token: DataClassification.SECRET,
  api_key: DataClassification.SECRET,
  apikey: DataClassification.SECRET,
  private_key: DataClassification.SECRET,
  privatekey: DataClassification.SECRET,
  session_id: DataClassification.SECRET, // Enhanced: Always remove session IDs
  sessionid: DataClassification.SECRET,
  sessionId: DataClassification.SECRET,
  csrf_token: DataClassification.SECRET, // Enhanced: Treat as secret
  csrftoken: DataClassification.SECRET,
  csrfToken: DataClassification.SECRET,
  auth_token: DataClassification.SECRET,
  authtoken: DataClassification.SECRET,
  access_token: DataClassification.SECRET,
  accesstoken: DataClassification.SECRET,
  refresh_token: DataClassification.SECRET,
  refreshtoken: DataClassification.SECRET,

  // Personal Information
  ssn: DataClassification.RESTRICTED,
  social_security_number: DataClassification.RESTRICTED,
  tax_id: DataClassification.RESTRICTED,
  passport: DataClassification.RESTRICTED,
  drivers_license: DataClassification.RESTRICTED,

  // Financial Information
  credit_card: DataClassification.RESTRICTED,
  card_number: DataClassification.RESTRICTED,
  cvv: DataClassification.RESTRICTED,
  bank_account: DataClassification.RESTRICTED,
  routing_number: DataClassification.RESTRICTED,

  // Internal System Data - Enhanced patterns
  database_url: DataClassification.INTERNAL,
  databaseurl: DataClassification.INTERNAL,
  connection_string: DataClassification.INTERNAL,
  connectionstring: DataClassification.INTERNAL,
  internal_id: DataClassification.INTERNAL,
  internalid: DataClassification.INTERNAL,
  system_config: DataClassification.INTERNAL,
  systemconfig: DataClassification.INTERNAL,
  internal_config: DataClassification.INTERNAL,
  internalconfig: DataClassification.INTERNAL,
  internalConfig: DataClassification.INTERNAL,
  debug_info: DataClassification.INTERNAL,
  debuginfo: DataClassification.INTERNAL,
  stack_trace: DataClassification.INTERNAL,
  stacktrace: DataClassification.INTERNAL,
  error_stack: DataClassification.INTERNAL,
  errorstack: DataClassification.INTERNAL,

  // Enhanced: Internal configuration and limits
  max_results: DataClassification.INTERNAL,
  maxresults: DataClassification.INTERNAL,
  rate_limit: DataClassification.INTERNAL,
  ratelimit: DataClassification.INTERNAL,
  internal_limit: DataClassification.INTERNAL,
  internallimit: DataClassification.INTERNAL,
  system_limit: DataClassification.INTERNAL,
  systemlimit: DataClassification.INTERNAL,
  config_value: DataClassification.INTERNAL,
  configvalue: DataClassification.INTERNAL,

  // Enhanced: Database and infrastructure details
  table_name: DataClassification.INTERNAL,
  tablename: DataClassification.INTERNAL,
  schema_name: DataClassification.INTERNAL,
  schemaname: DataClassification.INTERNAL,
  server_config: DataClassification.INTERNAL,
  serverconfig: DataClassification.INTERNAL,

  // User Data
  email: DataClassification.CONFIDENTIAL,
  phone: DataClassification.CONFIDENTIAL,
  address: DataClassification.CONFIDENTIAL,
  ip_address: DataClassification.CONFIDENTIAL,
  ipaddress: DataClassification.CONFIDENTIAL,
}

/**
 * PII detection patterns
 */
export const PII_PATTERNS = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
  ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
  creditCard: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
  ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
}

/**
 * Sanitization configuration
 */
export interface SanitizationConfig {
  enablePIIDetection: boolean
  enableFieldClassification: boolean
  enableDataMasking: boolean
  maxClassificationLevel: DataClassification
  customSensitiveFields: string[]
  preserveStructure: boolean
  logSanitization: boolean
}

/**
 * Default sanitization configuration - Enhanced for security
 */
export const DEFAULT_SANITIZATION_CONFIG: SanitizationConfig = {
  enablePIIDetection: true,
  enableFieldClassification: true,
  enableDataMasking: true,
  maxClassificationLevel: DataClassification.INTERNAL, // Enhanced: More restrictive default
  customSensitiveFields: [
    // Enhanced: Additional sensitive fields to always remove
    'sessionActive',
    'session_active',
    'sessionCreated',
    'session_created',
    'internalLimits',
    'internal_limits',
    'systemCapabilities',
    'system_capabilities',
    'configDetails',
    'config_details',
    'debugMode',
    'debug_mode',
    'developmentMode',
    'development_mode',
  ],
  preserveStructure: true,
  logSanitization: process.env.NODE_ENV === 'development',
}

/**
 * Sanitization result
 */
export interface SanitizationResult {
  sanitizedData: any
  removedFields: string[]
  maskedFields: string[]
  piiDetected: string[]
  classificationViolations: string[]
}

/**
 * Main response sanitization class
 */
export class ResponseSanitizer {
  private config: SanitizationConfig

  constructor(config: Partial<SanitizationConfig> = {}) {
    this.config = { ...DEFAULT_SANITIZATION_CONFIG, ...config }
  }

  /**
   * Sanitize response data
   */
  sanitize(data: any, context?: string): SanitizationResult {
    const result: SanitizationResult = {
      sanitizedData: null,
      removedFields: [],
      maskedFields: [],
      piiDetected: [],
      classificationViolations: [],
    }

    try {
      result.sanitizedData = this.sanitizeValue(data, '', result)
      
      if (this.config.logSanitization && (result.removedFields.length > 0 || result.maskedFields.length > 0)) {
        logger.info('Response Sanitization', 'Data sanitized', {
          context,
          removedFields: result.removedFields,
          maskedFields: result.maskedFields,
          piiDetected: result.piiDetected,
          classificationViolations: result.classificationViolations,
        })
      }
    } catch (error) {
      logger.error('Response Sanitization', 'Sanitization failed', error)
      result.sanitizedData = this.config.preserveStructure ? {} : null
    }

    return result
  }

  /**
   * Sanitize a value recursively
   */
  private sanitizeValue(value: any, path: string, result: SanitizationResult): any {
    if (value === null || value === undefined) {
      return value
    }

    if (typeof value === 'string') {
      return this.sanitizeString(value, path, result)
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      return value
    }

    if (Array.isArray(value)) {
      return value.map((item, index) => 
        this.sanitizeValue(item, `${path}[${index}]`, result)
      )
    }

    if (typeof value === 'object') {
      return this.sanitizeObject(value, path, result)
    }

    return value
  }

  /**
   * Sanitize string values
   */
  private sanitizeString(value: string, path: string, result: SanitizationResult): string {
    let sanitized = value

    if (this.config.enablePIIDetection) {
      sanitized = this.detectAndMaskPII(sanitized, path, result)
    }

    return sanitized
  }

  /**
   * Sanitize object values
   */
  private sanitizeObject(obj: any, path: string, result: SanitizationResult): any {
    const sanitized: any = {}

    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = path ? `${path}.${key}` : key
      
      if (this.shouldRemoveField(key, value, fieldPath)) {
        result.removedFields.push(fieldPath)
        continue
      }

      if (this.shouldMaskField(key, value, fieldPath)) {
        sanitized[key] = this.maskValue(value, key)
        result.maskedFields.push(fieldPath)
        continue
      }

      sanitized[key] = this.sanitizeValue(value, fieldPath, result)
    }

    return sanitized
  }

  /**
   * Check if field should be removed - Enhanced security checks
   */
  private shouldRemoveField(key: string, value: any, path: string): boolean {
    const lowerKey = key.toLowerCase()

    // Enhanced: Always remove session-related fields regardless of environment
    const alwaysRemovePatterns = [
      'sessionid', 'session_id', 'session-id',
      'password', 'secret', 'token', 'key',
      'hash', 'salt', 'csrf'
    ]

    for (const pattern of alwaysRemovePatterns) {
      if (lowerKey.includes(pattern)) {
        return true
      }
    }

    // Check against sensitive field patterns
    for (const [pattern, classification] of Object.entries(SENSITIVE_FIELD_PATTERNS)) {
      if (lowerKey.includes(pattern.toLowerCase())) {
        if (this.isClassificationViolation(classification)) {
          return true
        }
      }
    }

    // Check custom sensitive fields
    if (this.config.customSensitiveFields.some(field =>
      lowerKey.includes(field.toLowerCase())
    )) {
      return true
    }

    // Enhanced: Remove fields with sensitive values
    if (typeof value === 'string') {
      // Remove fields containing session tokens or IDs
      if (value.match(/^[a-f0-9]{32,}$/i) || // Hex strings (likely tokens)
          value.match(/^[A-Za-z0-9+/]{20,}={0,2}$/)) { // Base64 strings (likely tokens)
        return true
      }
    }

    return false
  }

  /**
   * Check if field should be masked
   */
  private shouldMaskField(key: string, value: any, path: string): boolean {
    if (!this.config.enableDataMasking) {
      return false
    }

    const lowerKey = key.toLowerCase()
    
    // Mask fields that are confidential but not restricted/secret
    for (const [pattern, classification] of Object.entries(SENSITIVE_FIELD_PATTERNS)) {
      if (lowerKey.includes(pattern.toLowerCase())) {
        if (classification === DataClassification.CONFIDENTIAL) {
          return true
        }
      }
    }

    return false
  }

  /**
   * Check if classification violates maximum allowed level
   */
  private isClassificationViolation(classification: DataClassification): boolean {
    const levels = [
      DataClassification.PUBLIC,
      DataClassification.INTERNAL,
      DataClassification.CONFIDENTIAL,
      DataClassification.RESTRICTED,
      DataClassification.SECRET,
    ]

    const maxIndex = levels.indexOf(this.config.maxClassificationLevel)
    const fieldIndex = levels.indexOf(classification)

    return fieldIndex > maxIndex
  }

  /**
   * Mask a value
   */
  private maskValue(value: any, key: string): string {
    if (typeof value !== 'string') {
      return '[MASKED]'
    }

    const lowerKey = key.toLowerCase()
    
    if (lowerKey.includes('email')) {
      return this.maskEmail(value)
    }
    
    if (lowerKey.includes('phone')) {
      return this.maskPhone(value)
    }
    
    if (value.length <= 4) {
      return '*'.repeat(value.length)
    }
    
    return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2)
  }

  /**
   * Mask email address
   */
  private maskEmail(email: string): string {
    const [local, domain] = email.split('@')
    if (!domain) return '[MASKED_EMAIL]'
    
    const maskedLocal = local.length > 2 
      ? local.substring(0, 2) + '*'.repeat(local.length - 2)
      : '*'.repeat(local.length)
    
    return `${maskedLocal}@${domain}`
  }

  /**
   * Mask phone number
   */
  private maskPhone(phone: string): string {
    const digits = phone.replace(/\D/g, '')
    if (digits.length >= 10) {
      return `***-***-${digits.slice(-4)}`
    }
    return '[MASKED_PHONE]'
  }

  /**
   * Detect and mask PII in strings
   */
  private detectAndMaskPII(text: string, path: string, result: SanitizationResult): string {
    let sanitized = text

    for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
      const matches = text.match(pattern)
      if (matches) {
        result.piiDetected.push(`${type} in ${path}`)
        sanitized = sanitized.replace(pattern, (match) => {
          switch (type) {
            case 'email':
              return this.maskEmail(match)
            case 'phone':
              return this.maskPhone(match)
            case 'creditCard':
              return `****-****-****-${match.slice(-4)}`
            case 'ssn':
              return `***-**-${match.slice(-4)}`
            default:
              return '[MASKED_PII]'
          }
        })
      }
    }

    return sanitized
  }
}

/**
 * Create sanitized response
 */
export function createSanitizedResponse(
  data: any,
  status: number = 200,
  config?: Partial<SanitizationConfig>,
  context?: string
): NextResponse {
  const sanitizer = new ResponseSanitizer(config)
  const result = sanitizer.sanitize(data, context)
  
  return NextResponse.json(result.sanitizedData, { status })
}

/**
 * Response sanitization middleware wrapper
 */
export function withResponseSanitization(
  handler: (...args: any[]) => Promise<NextResponse>,
  config?: Partial<SanitizationConfig>
) {
  return async (...args: any[]): Promise<NextResponse> => {
    try {
      const response = await handler(...args)
      
      // Only sanitize JSON responses
      const contentType = response.headers.get('content-type')
      if (!contentType?.includes('application/json')) {
        return response
      }

      // Extract and sanitize response data
      const responseData = await response.json()
      const sanitizer = new ResponseSanitizer(config)
      const result = sanitizer.sanitize(responseData, 'API Response')
      
      // Create new response with sanitized data
      const sanitizedResponse = NextResponse.json(result.sanitizedData, {
        status: response.status,
        statusText: response.statusText,
      })
      
      // Copy headers
      response.headers.forEach((value, key) => {
        sanitizedResponse.headers.set(key, value)
      })
      
      return sanitizedResponse
    } catch (error) {
      logger.error('Response Sanitization', 'Middleware error', error)
      return handler(...args)
    }
  }
}

/**
 * Enhanced error message sanitization
 */
export function sanitizeErrorMessage(error: any, context?: string): string {
  if (!error) return 'Unknown error occurred'

  let message = error instanceof Error ? error.message : String(error)

  // Remove sensitive patterns from error messages
  const sensitivePatterns = [
    /password[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[^\s]+/gi,
    /token[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[^\s]+/gi,
    /secret[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[^\s]+/gi,
    /key[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[^\s]+/gi,
    /session[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[^\s]+/gi,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email addresses
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, // IP addresses
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, // UUIDs
    /\b[A-Za-z0-9+/]{20,}={0,2}\b/g, // Base64 strings
    /\b[a-f0-9]{32,}\b/gi, // Hex strings
  ]

  for (const pattern of sensitivePatterns) {
    message = message.replace(pattern, '[REDACTED]')
  }

  // Remove stack traces in production
  if (process.env.NODE_ENV === 'production') {
    message = message.split('\n')[0] // Only keep first line
  }

  // Generic error message for production if still contains sensitive data
  if (process.env.NODE_ENV === 'production' &&
      (message.toLowerCase().includes('database') ||
       message.toLowerCase().includes('connection') ||
       message.toLowerCase().includes('internal') ||
       message.toLowerCase().includes('config'))) {
    return 'An internal error occurred. Please try again later.'
  }

  return message
}

/**
 * Enhanced session data sanitization
 */
export function sanitizeSessionData(sessionData: any): any {
  if (!sessionData || typeof sessionData !== 'object') {
    return null
  }

  const sanitizer = new ResponseSanitizer({
    maxClassificationLevel: DataClassification.PUBLIC,
    customSensitiveFields: [
      'id', 'sessionId', 'session_id', 'token', 'csrfToken', 'csrf_token'
    ]
  })

  const result = sanitizer.sanitize(sessionData, 'Session Data')
  return result.sanitizedData
}

/**
 * Enhanced API response wrapper with comprehensive sanitization
 */
export function createSecureApiResponse(
  data: any,
  status: number = 200,
  options: {
    sanitizeSession?: boolean
    removeInternalConfig?: boolean
    context?: string
  } = {}
): NextResponse {
  const config: Partial<SanitizationConfig> = {
    maxClassificationLevel: DataClassification.INTERNAL,
    enablePIIDetection: true,
    enableFieldClassification: true,
    enableDataMasking: true,
    customSensitiveFields: [
      ...(DEFAULT_SANITIZATION_CONFIG.customSensitiveFields || []),
      ...(options.removeInternalConfig ? [
        'capabilities', 'limits', 'maxResults', 'internalLimits',
        'systemConfig', 'debugInfo', 'configDetails'
      ] : [])
    ]
  }

  return createSanitizedResponse(data, status, config, options.context)
}

// Export singleton instance
export const responseSanitizer = new ResponseSanitizer()
