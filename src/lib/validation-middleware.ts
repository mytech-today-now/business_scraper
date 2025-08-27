/**
 * Input Validation Middleware for API Routes
 * Provides comprehensive input validation and sanitization
 */

import { NextRequest, NextResponse } from 'next/server'
import { sanitizeInput, validateInput, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

export interface ValidationRule {
  field: string
  required?: boolean
  type?: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'url' | 'email' | 'zipcode'
  minLength?: number
  maxLength?: number
  min?: number
  max?: number
  pattern?: RegExp
  allowedValues?: any[]
  sanitize?: boolean
  custom?: (value: any) => { valid: boolean; error?: string }
}

export interface ValidationSchema {
  body?: ValidationRule[]
  query?: ValidationRule[]
  params?: ValidationRule[]
}

/**
 * Validation middleware wrapper
 */
export function withValidation(
  handler: (request: NextRequest, validatedData?: any) => Promise<NextResponse>,
  schema: ValidationSchema
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const ip = getClientIP(request)
    const pathname = request.nextUrl.pathname

    try {
      const validatedData: any = {}

      // Validate request body
      if (schema.body && ['POST', 'PUT', 'PATCH'].includes(request.method)) {
        const bodyValidation = await validateRequestBody(request, schema.body)
        if (bodyValidation.errors.length > 0) {
          logger.warn(
            'Validation',
            `Body validation failed for ${pathname} from IP: ${ip}`,
            bodyValidation.errors
          )
          return NextResponse.json(
            {
              error: 'Validation failed',
              details: bodyValidation.errors,
            },
            { status: 400 }
          )
        }
        validatedData.body = bodyValidation.data
      }

      // Validate query parameters
      if (schema.query) {
        const queryValidation = validateQueryParams(request, schema.query)
        if (queryValidation.errors.length > 0) {
          logger.warn(
            'Validation',
            `Query validation failed for ${pathname} from IP: ${ip}`,
            queryValidation.errors
          )
          return NextResponse.json(
            {
              error: 'Invalid query parameters',
              details: queryValidation.errors,
            },
            { status: 400 }
          )
        }
        validatedData.query = queryValidation.data
      }

      // Call handler with validated data
      return handler(request, validatedData)
    } catch (error) {
      logger.error('Validation', `Validation error for ${pathname}`, error)
      return NextResponse.json({ error: 'Validation error' }, { status: 500 })
    }
  }
}

/**
 * Validate request body against rules
 */
async function validateRequestBody(
  request: NextRequest,
  rules: ValidationRule[]
): Promise<{ data: any; errors: string[] }> {
  const errors: string[] = []
  let data: any = {}

  try {
    const contentType = request.headers.get('content-type')

    if (!contentType?.includes('application/json')) {
      errors.push('Content-Type must be application/json')
      return { data, errors }
    }

    const body = await request.json()
    data = validateData(body, rules, errors)
  } catch (error) {
    errors.push('Invalid JSON in request body')
  }

  return { data, errors }
}

/**
 * Validate query parameters against rules
 */
function validateQueryParams(
  request: NextRequest,
  rules: ValidationRule[]
): { data: any; errors: string[] } {
  const errors: string[] = []
  const url = new URL(request.url)
  const queryParams: Record<string, any> = {}

  // Convert URLSearchParams to object
  for (const [key, value] of url.searchParams.entries()) {
    queryParams[key] = value
  }

  const data = validateData(queryParams, rules, errors)
  return { data, errors }
}

/**
 * Core validation logic
 */
function validateData(
  data: Record<string, any>,
  rules: ValidationRule[],
  errors: string[]
): Record<string, any> {
  const validatedData: Record<string, any> = {}

  for (const rule of rules) {
    let value = data[rule.field]

    // Check required fields
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push(`${rule.field} is required`)
      continue
    }

    // Skip validation if field is not provided and not required
    if (value === undefined || value === null) {
      continue
    }

    // Sanitize string inputs
    if (rule.sanitize !== false && typeof value === 'string') {
      value = sanitizeInput(value)
    }

    // Type validation and conversion
    const typeValidation = validateType(value, rule)
    if (!typeValidation.valid) {
      errors.push(`${rule.field}: ${typeValidation.error}`)
      continue
    }
    value = typeValidation.value

    // Length validation for strings
    if (typeof value === 'string') {
      if (rule.minLength && value.length < rule.minLength) {
        errors.push(`${rule.field} must be at least ${rule.minLength} characters`)
        continue
      }
      if (rule.maxLength && value.length > rule.maxLength) {
        errors.push(`${rule.field} must be no more than ${rule.maxLength} characters`)
        continue
      }
    }

    // Numeric range validation
    if (typeof value === 'number') {
      if (rule.min !== undefined && value < rule.min) {
        errors.push(`${rule.field} must be at least ${rule.min}`)
        continue
      }
      if (rule.max !== undefined && value > rule.max) {
        errors.push(`${rule.field} must be no more than ${rule.max}`)
        continue
      }
    }

    // Pattern validation
    if (rule.pattern && typeof value === 'string' && !rule.pattern.test(value)) {
      errors.push(`${rule.field} format is invalid`)
      continue
    }

    // Allowed values validation
    if (rule.allowedValues && !rule.allowedValues.includes(value)) {
      errors.push(`${rule.field} must be one of: ${rule.allowedValues.join(', ')}`)
      continue
    }

    // Custom validation
    if (rule.custom) {
      const customResult = rule.custom(value)
      if (!customResult.valid) {
        errors.push(`${rule.field}: ${customResult.error || 'Custom validation failed'}`)
        continue
      }
    }

    // Security validation for strings
    if (typeof value === 'string') {
      const securityValidation = validateInput(value)
      if (!securityValidation.isValid) {
        errors.push(`${rule.field}: ${securityValidation.errors.join(', ')}`)
        continue
      }
    }

    validatedData[rule.field] = value
  }

  return validatedData
}

/**
 * Validate and convert types
 */
function validateType(
  value: any,
  rule: ValidationRule
): { valid: boolean; value: any; error?: string } {
  if (!rule.type) {
    return { valid: true, value }
  }

  switch (rule.type) {
    case 'string':
      if (typeof value !== 'string') {
        return { valid: false, error: 'must be a string' }
      }
      return { valid: true, value }

    case 'number':
      const num = Number(value)
      if (isNaN(num)) {
        return { valid: false, error: 'must be a valid number' }
      }
      return { valid: true, value: num }

    case 'boolean':
      if (typeof value === 'boolean') {
        return { valid: true, value }
      }
      if (typeof value === 'string') {
        const lower = value.toLowerCase()
        if (lower === 'true' || lower === '1') {
          return { valid: true, value: true }
        }
        if (lower === 'false' || lower === '0') {
          return { valid: true, value: false }
        }
      }
      return { valid: false, error: 'must be a boolean' }

    case 'array':
      if (!Array.isArray(value)) {
        return { valid: false, error: 'must be an array' }
      }
      return { valid: true, value }

    case 'object':
      if (typeof value !== 'object' || Array.isArray(value) || value === null) {
        return { valid: false, error: 'must be an object' }
      }
      return { valid: true, value }

    case 'url':
      if (typeof value !== 'string') {
        return { valid: false, error: 'must be a string' }
      }
      try {
        new URL(value)
        return { valid: true, value }
      } catch {
        return { valid: false, error: 'must be a valid URL' }
      }

    case 'email':
      if (typeof value !== 'string') {
        return { valid: false, error: 'must be a string' }
      }
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailPattern.test(value)) {
        return { valid: false, error: 'must be a valid email address' }
      }
      return { valid: true, value }

    case 'zipcode':
      if (typeof value !== 'string') {
        return { valid: false, error: 'must be a string' }
      }
      const zipPattern = /^\d{5}(-\d{4})?$/
      if (!zipPattern.test(value)) {
        return { valid: false, error: 'must be a valid ZIP code (12345 or 12345-6789)' }
      }
      return { valid: true, value }

    default:
      return { valid: true, value }
  }
}

/**
 * Common validation schemas for reuse
 */
export const commonSchemas = {
  search: {
    body: [
      { field: 'query', required: true, type: 'string' as const, minLength: 1, maxLength: 500 },
      { field: 'location', type: 'string' as const, maxLength: 200 },
      { field: 'maxResults', type: 'number' as const, min: 1, max: 10000 },
      { field: 'industry', type: 'string' as const, maxLength: 100 },
    ],
  },

  scrape: {
    body: [
      { field: 'url', required: true, type: 'url' as const },
      { field: 'depth', type: 'number' as const, min: 1, max: 5 },
      { field: 'maxPages', type: 'number' as const, min: 1, max: 50 },
    ],
  },

  geocode: {
    body: [
      { field: 'address', required: true, type: 'string' as const, minLength: 3, maxLength: 500 },
    ],
  },

  auth: {
    body: [
      { field: 'username', required: true, type: 'string' as const, minLength: 1, maxLength: 50 },
      { field: 'password', required: true, type: 'string' as const, minLength: 1, maxLength: 200 },
    ],
  },
}

/**
 * Create a validation error response
 */
export function createValidationErrorResponse(errors: string[]): NextResponse {
  return NextResponse.json(
    {
      error: 'Validation failed',
      details: errors,
    },
    { status: 400 }
  )
}
