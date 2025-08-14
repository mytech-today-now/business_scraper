/**
 * API Security Middleware and Utilities
 * Provides comprehensive security controls for API endpoints
 */

import { NextRequest, NextResponse } from 'next/server'
import { getSession, getClientIP, sanitizeInput, validateInput } from '@/lib/security'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { logger } from '@/utils/logger'

export interface SecurityOptions {
  requireAuth?: boolean
  requireCSRF?: boolean
  rateLimit?: 'general' | 'scraping' | 'auth' | 'upload' | 'export'
  validateInput?: boolean
  logRequests?: boolean
}

export interface ValidationRule {
  field: string
  required?: boolean
  type?: 'string' | 'number' | 'boolean' | 'array' | 'object'
  minLength?: number
  maxLength?: number
  pattern?: RegExp
  allowedValues?: (string | number | boolean)[]
}

/**
 * Comprehensive API security middleware
 */
export function withApiSecurity(
  handler: (request: NextRequest) => Promise<NextResponse>,
  options: SecurityOptions = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const {
      requireAuth = false,
      requireCSRF = false,
      rateLimit = 'general',
      validateInput = true,
      logRequests = true
    } = options

    const ip = getClientIP(request)
    const method = request.method
    const pathname = request.nextUrl.pathname

    try {
      // Log request if enabled
      if (logRequests) {
        logger.info('API Security', `${method} ${pathname} from IP: ${ip}`)
      }

      // Rate limiting check
      const rateLimitResult = advancedRateLimitService.checkApiRateLimit(request, rateLimit)
      if (!rateLimitResult.allowed) {
        logger.warn('API Security', `Rate limit exceeded for ${pathname} from IP: ${ip}`)
        return NextResponse.json(
          { 
            error: 'Rate limit exceeded',
            retryAfter: rateLimitResult.retryAfter 
          },
          { 
            status: 429,
            headers: {
              'Retry-After': String(rateLimitResult.retryAfter || 60),
              'X-RateLimit-Remaining': String(rateLimitResult.remaining),
              'X-RateLimit-Reset': String(rateLimitResult.resetTime)
            }
          }
        )
      }

      // Authentication check
      if (requireAuth) {
        const authResult = await checkAuthentication(request)
        if (authResult) {
          return authResult
        }
      }

      // CSRF protection for state-changing requests
      if (requireCSRF && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        const csrfResult = await checkCSRFProtection(request)
        if (csrfResult) {
          return csrfResult
        }
      }

      // Input validation for requests with body
      if (validateInput && ['POST', 'PUT', 'PATCH'].includes(method)) {
        const validationResult = await validateRequestInput(request)
        if (validationResult) {
          return validationResult
        }
      }

      // Call the actual handler
      const response = await handler(request)

      // Add security headers
      addSecurityHeaders(response)

      return response

    } catch (error) {
      logger.error('API Security', `Security middleware error for ${pathname}`, error)
      return NextResponse.json(
        { error: 'Internal server error' },
        { status: 500 }
      )
    }
  }
}

/**
 * Check authentication for protected endpoints
 */
async function checkAuthentication(request: NextRequest): Promise<NextResponse | null> {
  const sessionId = request.cookies.get('session-id')?.value

  if (!sessionId) {
    logger.warn('API Security', `Authentication required but no session provided from IP: ${getClientIP(request)}`)
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    )
  }

  const session = getSession(sessionId)
  if (!session || !session.isValid) {
    logger.warn('API Security', `Invalid session attempt from IP: ${getClientIP(request)}`)
    const response = NextResponse.json(
      { error: 'Invalid session' },
      { status: 401 }
    )
    response.cookies.delete('session-id')
    return response
  }

  return null
}

/**
 * Check CSRF protection for state-changing requests
 */
async function checkCSRFProtection(request: NextRequest): Promise<NextResponse | null> {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) {
    return null // No session, no CSRF check needed
  }

  const csrfToken = request.headers.get('X-CSRF-Token') || 
                   request.cookies.get('csrf-token')?.value

  if (!csrfToken) {
    logger.warn('API Security', `CSRF token missing from IP: ${getClientIP(request)}`)
    return NextResponse.json(
      { error: 'CSRF token required' },
      { status: 403 }
    )
  }

  if (!csrfProtectionService.validateCSRFToken(sessionId, csrfToken)) {
    logger.warn('API Security', `Invalid CSRF token from IP: ${getClientIP(request)}`)
    return NextResponse.json(
      { error: 'Invalid CSRF token' },
      { status: 403 }
    )
  }

  return null
}

/**
 * Validate request input for common security issues
 */
async function validateRequestInput(request: NextRequest): Promise<NextResponse | null> {
  try {
    const contentType = request.headers.get('content-type')
    
    if (!contentType?.includes('application/json')) {
      return null // Skip validation for non-JSON requests
    }

    const body = await request.json()
    
    // Basic validation for common injection patterns
    const validateObject = (obj: any, path = ''): string[] => {
      const errors: string[] = []
      
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key
        
        if (typeof value === 'string') {
          const sanitized = sanitizeInput(value)
          const validation = validateInput(sanitized)
          
          if (!validation.isValid) {
            errors.push(`${currentPath}: ${validation.errors.join(', ')}`)
          }
        } else if (typeof value === 'object' && value !== null) {
          errors.push(...validateObject(value, currentPath))
        }
      }
      
      return errors
    }

    const validationErrors = validateObject(body)
    
    if (validationErrors.length > 0) {
      logger.warn('API Security', `Input validation failed from IP: ${getClientIP(request)}`, validationErrors)
      return NextResponse.json(
        { 
          error: 'Invalid input detected',
          details: validationErrors
        },
        { status: 400 }
      )
    }

    return null

  } catch (error) {
    logger.warn('API Security', `Failed to parse request body from IP: ${getClientIP(request)}`)
    return NextResponse.json(
      { error: 'Invalid JSON in request body' },
      { status: 400 }
    )
  }
}

/**
 * Add security headers to response
 */
function addSecurityHeaders(response: NextResponse): void {
  // Prevent MIME type sniffing
  response.headers.set('X-Content-Type-Options', 'nosniff')
  
  // Prevent clickjacking
  response.headers.set('X-Frame-Options', 'DENY')
  
  // XSS protection
  response.headers.set('X-XSS-Protection', '1; mode=block')
  
  // Referrer policy
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  
  // Remove server information
  response.headers.delete('Server')
  response.headers.delete('X-Powered-By')
}

/**
 * Validate request parameters against rules
 */
export function validateParameters(
  params: Record<string, any>,
  rules: ValidationRule[]
): { isValid: boolean; errors: string[] } {
  const errors: string[] = []

  for (const rule of rules) {
    const value = params[rule.field]

    // Check required fields
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push(`${rule.field} is required`)
      continue
    }

    // Skip validation if field is not provided and not required
    if (value === undefined || value === null) {
      continue
    }

    // Type validation
    if (rule.type) {
      const actualType = Array.isArray(value) ? 'array' : typeof value
      if (actualType !== rule.type) {
        errors.push(`${rule.field} must be of type ${rule.type}`)
        continue
      }
    }

    // String-specific validations
    if (typeof value === 'string') {
      if (rule.minLength && value.length < rule.minLength) {
        errors.push(`${rule.field} must be at least ${rule.minLength} characters`)
      }
      if (rule.maxLength && value.length > rule.maxLength) {
        errors.push(`${rule.field} must be no more than ${rule.maxLength} characters`)
      }
      if (rule.pattern && !rule.pattern.test(value)) {
        errors.push(`${rule.field} format is invalid`)
      }
    }

    // Allowed values validation
    if (rule.allowedValues && !rule.allowedValues.includes(value)) {
      errors.push(`${rule.field} must be one of: ${rule.allowedValues.join(', ')}`)
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  }
}

/**
 * Create a secure error response that doesn't leak information
 */
export function createSecureErrorResponse(
  error: any,
  defaultMessage: string = 'Internal server error',
  statusCode: number = 500
): NextResponse {
  // In production, don't expose detailed error information
  const isDevelopment = process.env.NODE_ENV === 'development'
  
  const errorResponse = {
    error: defaultMessage,
    ...(isDevelopment && error instanceof Error && {
      details: error.message,
      stack: error.stack
    })
  }

  return NextResponse.json(errorResponse, { status: statusCode })
}
