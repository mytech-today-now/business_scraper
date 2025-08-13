/**
 * Database Security Hardening Module
 * Business Scraper Application - Enhanced Database Security
 */

import crypto from 'crypto'
import { Pool, PoolClient } from 'pg'
import { logger } from '@/utils/logger'

/**
 * SQL injection patterns to detect and prevent
 */
const SQL_INJECTION_PATTERNS = [
  // Comment patterns (always suspicious in user input)
  /(--|\/\*|\*\/|#)/,

  // Boolean-based injection (suspicious equality patterns)
  /(\b(OR|AND)\b\s*\d+\s*=\s*\d+)/i,
  /(\b(OR|AND)\b\s*['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/i,
  /(\b1\s*=\s*1\b|\b0\s*=\s*0\b)/i,

  // Union-based injection
  /(\bUNION\b.*\bSELECT\b)/i,

  // Time-based injection
  /(\b(SLEEP|WAITFOR|DELAY)\b\s*\()/i,

  // Stacked queries (semicolon followed by SQL keywords)
  /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)/i,

  // Function-based injection (suspicious functions)
  /(\b(LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)\b)/i,

  // Database information gathering
  /(\b(information_schema|sys\.tables|pg_tables)\b)/i,

  // Hex encoding attempts (often used in injection)
  /(0x[0-9a-fA-F]{8,})/,

  // SQL wildcards in suspicious contexts
  /(['"]%.*%['"]|['"]_.*_['"])/,

  // Suspicious string concatenation
  /(\|\||CONCAT\s*\(.*\+.*\))/i
]

/**
 * Dangerous SQL keywords that should be escaped or blocked
 */
const DANGEROUS_SQL_KEYWORDS = [
  'EXEC', 'EXECUTE', 'SP_', 'XP_', 'OPENROWSET', 'OPENDATASOURCE',
  'BULK', 'BACKUP', 'RESTORE', 'SHUTDOWN', 'RECONFIGURE'
]

/**
 * Database security configuration
 */
export interface DatabaseSecurityConfig {
  enableSQLInjectionProtection: boolean
  enableQueryLogging: boolean
  enableConnectionEncryption: boolean
  maxQueryLength: number
  queryTimeoutMs: number
  enableParameterValidation: boolean
  logSuspiciousQueries: boolean
  blockDangerousKeywords: boolean
}

/**
 * Default security configuration
 */
export const defaultDatabaseSecurityConfig: DatabaseSecurityConfig = {
  enableSQLInjectionProtection: true,
  enableQueryLogging: process.env.NODE_ENV === 'development',
  enableConnectionEncryption: process.env.NODE_ENV === 'production',
  maxQueryLength: 10000,
  queryTimeoutMs: 30000,
  enableParameterValidation: true,
  logSuspiciousQueries: true,
  blockDangerousKeywords: true
}

/**
 * Query validation result
 */
export interface QueryValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
  sanitizedQuery?: string
}

/**
 * Database security service
 */
export class DatabaseSecurityService {
  private config: DatabaseSecurityConfig
  private suspiciousQueryCount = 0
  private lastSuspiciousQueryTime = 0

  constructor(config: DatabaseSecurityConfig = defaultDatabaseSecurityConfig) {
    this.config = config
  }

  /**
   * Validate SQL query for security issues
   */
  validateQuery(query: string, parameters?: any[]): QueryValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    // Check query length
    if (query.length > this.config.maxQueryLength) {
      errors.push(`Query exceeds maximum length of ${this.config.maxQueryLength} characters`)
    }

    // Check for SQL injection patterns (but be smarter about parameterized queries)
    if (this.config.enableSQLInjectionProtection) {
      // First check if this looks like a properly parameterized query
      const hasParameters = /\$\d+/.test(query) // PostgreSQL style parameters
      const isBasicCRUD = /^\s*(SELECT|INSERT|UPDATE|DELETE)\b/i.test(query)

      // If it's a basic CRUD operation with parameters, be less strict
      if (hasParameters && isBasicCRUD) {
        // Only check for the most dangerous patterns
        const dangerousPatterns = [
          /(--|\/\*|\*\/|#)/,
          /;\s*(DROP|CREATE|ALTER|EXEC)/i,
          /(\bUNION\b.*\bSELECT\b)/i,
          /(\b1\s*=\s*1\b|\b0\s*=\s*0\b)/i
        ]

        for (const pattern of dangerousPatterns) {
          if (pattern.test(query)) {
            errors.push('Query contains potentially dangerous SQL injection patterns')
            this.logSuspiciousQuery(query, 'SQL injection pattern detected')
            break
          }
        }
      } else {
        // For non-parameterized queries, check all patterns
        for (const pattern of SQL_INJECTION_PATTERNS) {
          if (pattern.test(query)) {
            errors.push('Query contains potentially dangerous SQL injection patterns')
            this.logSuspiciousQuery(query, 'SQL injection pattern detected')
            break
          }
        }
      }
    }

    // Check for dangerous keywords
    if (this.config.blockDangerousKeywords) {
      const upperQuery = query.toUpperCase()
      for (const keyword of DANGEROUS_SQL_KEYWORDS) {
        if (upperQuery.includes(keyword)) {
          errors.push(`Query contains dangerous keyword: ${keyword}`)
          this.logSuspiciousQuery(query, `Dangerous keyword: ${keyword}`)
        }
      }
    }

    // Validate parameters
    if (this.config.enableParameterValidation && parameters) {
      const paramValidation = this.validateParameters(parameters)
      if (!paramValidation.isValid) {
        errors.push(...paramValidation.errors)
        warnings.push(...paramValidation.warnings)
      }
    }

    // Check for unparameterized user input
    if (this.containsUnparameterizedInput(query)) {
      warnings.push('Query may contain unparameterized user input')
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      sanitizedQuery: this.sanitizeQuery(query)
    }
  }

  /**
   * Validate query parameters
   */
  private validateParameters(parameters: any[]): { isValid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = []
    const warnings: string[] = []

    for (let i = 0; i < parameters.length; i++) {
      const param = parameters[i]
      
      // Check for null/undefined
      if (param === null || param === undefined) {
        continue // Allow null values
      }

      // Check string parameters for injection patterns
      if (typeof param === 'string') {
        // Check for SQL injection in parameters
        for (const pattern of SQL_INJECTION_PATTERNS) {
          if (pattern.test(param)) {
            errors.push(`Parameter ${i + 1} contains potentially dangerous content`)
            this.logSuspiciousQuery(param, `Dangerous parameter content at index ${i}`)
            break
          }
        }

        // Check for excessively long strings
        if (param.length > 1000) {
          warnings.push(`Parameter ${i + 1} is unusually long (${param.length} characters)`)
        }
      }

      // Check for object injection
      if (typeof param === 'object' && param !== null) {
        try {
          JSON.stringify(param)
        } catch (error) {
          errors.push(`Parameter ${i + 1} contains non-serializable object`)
        }
      }
    }

    return { isValid: errors.length === 0, errors, warnings }
  }

  /**
   * Check if query contains unparameterized input
   */
  private containsUnparameterizedInput(query: string): boolean {
    // Look for string concatenation patterns that might indicate unparameterized input
    const suspiciousPatterns = [
      /'\s*\+\s*'/,  // String concatenation
      /"\s*\+\s*"/,  // String concatenation
      /\$\{[^}]+\}/,  // Template literals
      /`[^`]*\$\{[^}]+\}[^`]*`/  // Template strings
    ]

    return suspiciousPatterns.some(pattern => pattern.test(query))
  }

  /**
   * Sanitize SQL query
   */
  private sanitizeQuery(query: string): string {
    // Remove comments
    let sanitized = query.replace(/--.*/g, '')
    sanitized = sanitized.replace(/\/\*.*?\*\//gs, '')
    
    // Normalize whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim()
    
    return sanitized
  }

  /**
   * Log suspicious query activity
   */
  private logSuspiciousQuery(query: string, reason: string): void {
    if (!this.config.logSuspiciousQueries) {
      return
    }

    this.suspiciousQueryCount++
    this.lastSuspiciousQueryTime = Date.now()

    logger.warn('DatabaseSecurity', 'Suspicious query detected', {
      reason,
      query: query.substring(0, 200), // Log first 200 chars only
      timestamp: new Date().toISOString(),
      suspiciousQueryCount: this.suspiciousQueryCount
    })

    // Alert if too many suspicious queries in short time
    if (this.suspiciousQueryCount > 5) {
      logger.error('DatabaseSecurity', 'Multiple suspicious queries detected - possible attack', {
        count: this.suspiciousQueryCount,
        timeWindow: Date.now() - this.lastSuspiciousQueryTime
      })
    }
  }

  /**
   * Create secure database connection configuration
   */
  static createSecureConnectionConfig(baseConfig: any): any {
    const secureConfig = { ...baseConfig }

    // Enable SSL in production
    if (process.env.NODE_ENV === 'production') {
      secureConfig.ssl = {
        rejectUnauthorized: true,
        ca: process.env.DB_SSL_CA,
        cert: process.env.DB_SSL_CERT,
        key: process.env.DB_SSL_KEY
      }
    }

    // Set secure connection timeouts
    secureConfig.connectionTimeoutMillis = Math.min(secureConfig.connectionTimeoutMillis || 5000, 10000)
    secureConfig.idleTimeoutMillis = Math.min(secureConfig.idleTimeoutMillis || 30000, 60000)
    secureConfig.query_timeout = Math.min(secureConfig.query_timeout || 30000, 60000)

    // Limit connection pool size
    secureConfig.max = Math.min(secureConfig.max || 10, 20)
    secureConfig.min = Math.max(secureConfig.min || 2, 1)

    return secureConfig
  }

  /**
   * Escape SQL identifier (table/column names)
   */
  static escapeIdentifier(identifier: string): string {
    // Remove any non-alphanumeric characters except underscore
    const cleaned = identifier.replace(/[^a-zA-Z0-9_]/g, '')
    
    // Ensure it doesn't start with a number
    if (/^\d/.test(cleaned)) {
      throw new Error('SQL identifier cannot start with a number')
    }
    
    // Check against reserved words
    const reservedWords = [
      'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
      'TABLE', 'INDEX', 'VIEW', 'TRIGGER', 'FUNCTION', 'PROCEDURE'
    ]
    
    if (reservedWords.includes(cleaned.toUpperCase())) {
      throw new Error(`"${cleaned}" is a reserved SQL keyword`)
    }
    
    return `"${cleaned}"`
  }

  /**
   * Generate secure random ID
   */
  static generateSecureId(): string {
    return crypto.randomBytes(16).toString('hex')
  }

  /**
   * Hash sensitive data for storage
   */
  static hashSensitiveData(data: string, salt?: string): { hash: string; salt: string } {
    const actualSalt = salt || crypto.randomBytes(32).toString('hex')
    const hash = crypto.pbkdf2Sync(data, actualSalt, 100000, 64, 'sha512').toString('hex')
    
    return { hash, salt: actualSalt }
  }

  /**
   * Verify hashed data
   */
  static verifySensitiveData(data: string, hash: string, salt: string): boolean {
    const verifyHash = crypto.pbkdf2Sync(data, salt, 100000, 64, 'sha512').toString('hex')
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verifyHash, 'hex'))
  }

  /**
   * Get security statistics
   */
  getSecurityStats(): {
    suspiciousQueryCount: number
    lastSuspiciousQueryTime: number
    securityConfig: DatabaseSecurityConfig
  } {
    return {
      suspiciousQueryCount: this.suspiciousQueryCount,
      lastSuspiciousQueryTime: this.lastSuspiciousQueryTime,
      securityConfig: { ...this.config }
    }
  }

  /**
   * Reset security counters
   */
  resetSecurityCounters(): void {
    this.suspiciousQueryCount = 0
    this.lastSuspiciousQueryTime = 0
  }
}

// Export singleton instance
export const databaseSecurityService = new DatabaseSecurityService()
