/**
 * Database Input Validation Schemas
 * Comprehensive Zod schemas for SQL injection prevention and data validation
 * Business Scraper Application - Security Enhancement
 */

import { z } from 'zod'

/**
 * Base validation patterns for common database inputs
 */
const SQL_INJECTION_PATTERNS = [
  /(--|\/\*|\*\/|#)/,
  /(\b(OR|AND)\b\s*\d+\s*=\s*\d+)/i,
  /(\b1\s*=\s*1\b|\b0\s*=\s*0\b)/i,
  /(\bUNION\b.*\bSELECT\b)/i,
  /(\b(SLEEP|WAITFOR|DELAY)\b\s*\()/i,
  /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)/i,
  /(\b(LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)\b)/i,
  // Additional patterns for common SQL injection attempts
  /(\'\s*OR\s*\'\w*\'\s*=\s*\'\w*)/i,  // ' OR 'a'='a
  /(\'\s*OR\s*\'\d*\'\s*=\s*\'\d*)/i,  // ' OR '1'='1
  /(\d+\'\s*OR\s*\'\w*\'\s*=\s*\'\w*)/i, // 1' OR 'a'='a
  /(\d+\'\s*OR\s*\'\d*\'\s*=\s*\'\d*)/i, // 1' OR '1'='1
  /(0x[0-9a-fA-F]+)/i, // Hexadecimal values
]

/**
 * Validates input for SQL safety
 */
function validateSqlSafety(input: string): { isValid: boolean; errors: string[] } {
  const errors: string[] = []

  if (!input || typeof input !== 'string') {
    return { isValid: true, errors: [] }
  }

  // Check for SQL injection patterns
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      errors.push(`Input contains potentially dangerous SQL pattern: ${pattern.source}`)
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  }
}

/**
 * Custom Zod validator for SQL injection prevention
 */
const sqlInjectionSafe = z.string().refine(
  (value) => {
    if (!value) return true // Allow empty strings
    
    // Check against SQL injection patterns
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        return false
      }
    }
    return true
  },
  {
    message: 'Input contains potentially dangerous SQL patterns',
  }
)

/**
 * Safe string validator with length limits and SQL injection protection
 */
const safeString = (maxLength: number = 255) =>
  z.string()
    .max(maxLength, `String must be ${maxLength} characters or less`)
    .trim()
    .refine(
      (value) => {
        const result = validateSqlSafety(value)
        return result.isValid
      },
      {
        message: 'String contains potentially dangerous SQL patterns',
      }
    )

/**
 * Safe text validator for longer content with SQL injection protection
 */
const safeText = (maxLength: number = 10000) =>
  z.string()
    .max(maxLength, `Text must be ${maxLength} characters or less`)
    .trim()
    .refine(
      (value) => {
        const result = validateSqlSafety(value)
        return result.isValid
      },
      {
        message: 'Text contains potentially dangerous SQL patterns',
      }
    )

/**
 * Email validation with SQL injection protection
 */
const safeEmail = z
  .string()
  .email('Invalid email format')
  .max(320, 'Email must be 320 characters or less')
  .refine(
    (value) => !SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value)),
    { message: 'Email contains invalid characters' }
  )

/**
 * URL validation with SQL injection protection
 */
const safeUrl = z
  .string()
  .url('Invalid URL format')
  .max(2048, 'URL must be 2048 characters or less')
  .refine(
    (value) => !SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value)),
    { message: 'URL contains invalid characters' }
  )

/**
 * Phone number validation with SQL injection protection
 */
const safePhone = z
  .string()
  .regex(/^[\d\s\-\+\(\)\.]+$/, 'Invalid phone number format')
  .max(20, 'Phone number must be 20 characters or less')
  .refine(
    (value) => !SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value)),
    { message: 'Phone number contains invalid characters' }
  )

/**
 * UUID validation
 */
const safeUuid = z
  .string()
  .uuid('Invalid UUID format')

/**
 * Safe integer with bounds
 */
const safeInteger = (min: number = 0, max: number = Number.MAX_SAFE_INTEGER) =>
  z.number().int().min(min).max(max)

/**
 * Safe float with bounds
 */
const safeFloat = (min: number = 0, max: number = Number.MAX_SAFE_INTEGER) =>
  z.number().min(min).max(max)

/**
 * Campaign data validation schema
 */
export const CampaignInputSchema = z.object({
  id: safeUuid.optional(),
  name: safeString(255),
  description: safeText(1000).optional(),
  industries: z.array(safeString(100)).max(50, 'Too many industries'),
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, 'Invalid ZIP code format'),
  searchRadius: safeInteger(1, 500),
  searchDepth: safeInteger(1, 10),
  pagesPerSite: safeInteger(1, 100),
  status: z.enum(['active', 'paused', 'completed', 'cancelled']),
  settings: z.record(z.unknown()).optional(),
})

/**
 * Business record validation schema
 */
export const BusinessInputSchema = z.object({
  id: safeUuid.optional(),
  campaignId: safeUuid,
  name: safeString(255),
  email: safeEmail.optional(),
  phone: safePhone.optional(),
  website: safeUrl.optional(),
  address: safeText(500).optional(),
  confidenceScore: safeFloat(0, 1).optional(),
  contactPerson: safeString(255).optional(),
  coordinates: z.object({
    lat: safeFloat(-90, 90),
    lng: safeFloat(-180, 180),
  }).optional(),
  industry: safeString(100).optional(),
  businessDescription: safeText(2000).optional(),
  socialMedia: z.record(safeUrl).optional(),
  businessHours: z.record(safeString(100)).optional(),
  employeeCount: safeInteger(0, 1000000).optional(),
  annualRevenue: safeInteger(0, Number.MAX_SAFE_INTEGER).optional(),
  foundedYear: safeInteger(1800, new Date().getFullYear()).optional(),
})

/**
 * Session data validation schema
 */
export const SessionInputSchema = z.object({
  id: safeUuid.optional(),
  campaignId: safeUuid,
  status: z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']),
  progress: z.object({
    totalBusinesses: safeInteger(0),
    processedBusinesses: safeInteger(0),
    validBusinesses: safeInteger(0),
    errors: safeInteger(0),
  }),
  settings: z.object({
    industries: z.array(safeString(100)),
    zipCode: z.string().regex(/^\d{5}(-\d{4})?$/),
    searchRadius: safeInteger(1, 500),
    maxResults: safeInteger(1, 10000),
  }),
  results: z.object({
    businesses: z.array(BusinessInputSchema),
    errors: z.array(safeString(1000)),
    warnings: z.array(safeString(1000)),
  }).optional(),
  metadata: z.record(z.unknown()).optional(),
})

/**
 * Setting data validation schema
 */
export const SettingInputSchema = z.object({
  key: safeString(100),
  value: z.unknown(),
  type: z.enum(['string', 'number', 'boolean', 'object', 'array']),
  category: safeString(50).optional(),
  description: safeText(500).optional(),
})

/**
 * Filter validation schemas
 */
export const CampaignFiltersSchema = z.object({
  status: z.enum(['active', 'paused', 'completed', 'cancelled']).optional(),
  industry: safeString(100).optional(),
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/).optional(),
  createdAfter: z.date().optional(),
  createdBefore: z.date().optional(),
})

export const BusinessFiltersSchema = z.object({
  industry: safeString(100).optional(),
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/).optional(),
  hasEmail: z.boolean().optional(),
  hasPhone: z.boolean().optional(),
  validated: z.boolean().optional(),
  createdAfter: z.date().optional(),
  createdBefore: z.date().optional(),
  minConfidenceScore: safeFloat(0, 1).optional(),
})

export const SessionFiltersSchema = z.object({
  status: z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']).optional(),
  campaignId: safeUuid.optional(),
  startedAfter: z.date().optional(),
  startedBefore: z.date().optional(),
})

/**
 * Query parameter validation schema
 */
export const QueryParameterSchema = z.object({
  text: safeText(5000), // Limit query length for DoS prevention
  params: z.array(z.union([
    z.string().max(10000).refine( // Limit individual parameter length
      (value) => !SQL_INJECTION_PATTERNS.some(pattern => pattern.test(value)),
      { message: 'Parameter contains dangerous SQL patterns' }
    ),
    z.number(),
    z.boolean(),
    z.null(),
    z.undefined(),
    z.date(),
  ])).max(50).optional(), // Limit parameter count for DoS prevention
})

/**
 * Database operation validation schema
 */
export const DatabaseOperationSchema = z.object({
  operation: z.enum(['SELECT', 'INSERT', 'UPDATE', 'DELETE']),
  table: safeString(100),
  conditions: z.record(z.unknown()).optional(),
  data: z.record(z.unknown()).optional(),
})

/**
 * Validation helper functions
 */
export class DatabaseValidationService {
  /**
   * Validate campaign input data
   */
  static validateCampaignInput(data: unknown) {
    return CampaignInputSchema.safeParse(data)
  }

  /**
   * Validate business input data
   */
  static validateBusinessInput(data: unknown) {
    return BusinessInputSchema.safeParse(data)
  }

  /**
   * Validate session input data
   */
  static validateSessionInput(data: unknown) {
    return SessionInputSchema.safeParse(data)
  }

  /**
   * Validate setting input data
   */
  static validateSettingInput(data: unknown) {
    return SettingInputSchema.safeParse(data)
  }

  /**
   * Validate query parameters
   */
  static validateQueryParameters(data: unknown) {
    // Handle null/undefined data
    if (!data || typeof data !== 'object') {
      return { success: false, error: { errors: [{ message: 'Invalid query data' }] } }
    }

    const queryData = data as { text?: string; params?: any[] }

    // Normalize data to handle null/undefined values
    const normalizedData = {
      text: queryData.text || '',
      params: queryData.params || []
    }

    return QueryParameterSchema.safeParse(normalizedData)
  }

  /**
   * Validate database operation
   */
  static validateDatabaseOperation(data: unknown) {
    return DatabaseOperationSchema.safeParse(data)
  }

  /**
   * Validate any string for SQL injection patterns
   */
  static validateSqlSafety(input: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = []
    
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        errors.push('Input contains potentially dangerous SQL patterns')
        break
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    }
  }
}

// Export individual schemas for direct use
export {
  safeString,
  safeText,
  safeEmail,
  safeUrl,
  safePhone,
  safeUuid,
  safeInteger,
  safeFloat,
  sqlInjectionSafe,
}
