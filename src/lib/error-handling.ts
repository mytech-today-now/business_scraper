/**
 * Enhanced Secure Error Handling for API Routes
 * Prevents information leakage while providing useful debugging information
 * Includes comprehensive data sanitization and PII protection
 */

import { NextRequest, NextResponse } from 'next/server'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import { responseSanitizer, DataClassification } from '@/lib/response-sanitization'

export interface ErrorContext {
  endpoint: string
  method: string
  ip: string
  userAgent?: string
  sessionId?: string
  userId?: string
  workspaceId?: string
}

export interface SecureErrorOptions {
  logError?: boolean
  includeStack?: boolean
  customMessage?: string
  statusCode?: number
  sanitizeResponse?: boolean
  classification?: DataClassification
  includeErrorId?: boolean
}

/**
 * Create a secure error response that doesn't leak sensitive information
 */
export function createSecureErrorResponse(
  error: any,
  context: ErrorContext,
  options: SecureErrorOptions = {}
): NextResponse {
  const {
    logError = true,
    includeStack = false,
    customMessage,
    statusCode = 500,
    sanitizeResponse = true,
    classification = DataClassification.INTERNAL,
    includeErrorId = true,
  } = options

  const isDevelopment = process.env.NODE_ENV === 'development'
  const errorId = generateErrorId()

  // Enhanced error logging with sanitization
  if (logError) {
    const logData = {
      errorId,
      endpoint: context.endpoint,
      method: context.method,
      ip: sanitizeIPForLogging(context.ip),
      userAgent: context.userAgent,
      sessionId: context.sessionId,
      userId: context.userId,
      workspaceId: context.workspaceId,
      error: error instanceof Error
        ? {
            name: error.name,
            message: sanitizeErrorForLogging(error.message),
            stack: isDevelopment ? error.stack : undefined,
          }
        : sanitizeErrorForLogging(String(error)),
      timestamp: new Date().toISOString(),
      classification,
    }

    logger.error('Secure Error Handler', `Error ${errorId} at ${context.endpoint}`, logData)
  }

  // Create base error response
  let errorResponse: any = {
    error: customMessage || getGenericErrorMessage(statusCode),
    timestamp: new Date().toISOString(),
  }

  // Add error ID only if requested and not in production for sensitive errors
  if (includeErrorId && !(process.env.NODE_ENV === 'production' && statusCode >= 500)) {
    errorResponse.errorId = errorId
  }

  // In development, include more details
  if (isDevelopment) {
    if (error instanceof Error) {
      errorResponse.debug = {
        name: error.name,
        message: sanitizeErrorMessage(error.message),
        ...(includeStack && { stack: error.stack }),
        endpoint: context.endpoint,
        method: context.method,
      }
    }
  }

  // Sanitize the entire response if requested
  if (sanitizeResponse) {
    const sanitizationResult = responseSanitizer.sanitize(errorResponse, `Error Response - ${context.endpoint}`)
    errorResponse = sanitizationResult.sanitizedData
  }

  const response = NextResponse.json(errorResponse, { status: statusCode })

  // Add comprehensive security headers
  addSecurityHeaders(response)

  return response
}

/**
 * Error handling middleware wrapper
 */
export function withErrorHandling(handler: (request: NextRequest) => Promise<NextResponse>) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const context: ErrorContext = {
      endpoint: request.nextUrl.pathname,
      method: request.method,
      ip: getClientIP(request),
      userAgent: request.headers.get('user-agent') || undefined,
      sessionId: request.cookies.get('session-id')?.value,
    }

    try {
      return await handler(request)
    } catch (error) {
      // Handle different types of errors
      if (error instanceof ValidationError) {
        return createSecureErrorResponse(error, context, {
          customMessage: 'Validation failed',
          statusCode: 400,
        })
      }

      if (error instanceof AuthenticationError) {
        return createSecureErrorResponse(error, context, {
          customMessage: 'Authentication required',
          statusCode: 401,
        })
      }

      if (error instanceof AuthorizationError) {
        return createSecureErrorResponse(error, context, {
          customMessage: 'Access denied',
          statusCode: 403,
        })
      }

      if (error instanceof NotFoundError) {
        return createSecureErrorResponse(error, context, {
          customMessage: 'Resource not found',
          statusCode: 404,
        })
      }

      if (error instanceof RateLimitError) {
        return createSecureErrorResponse(error, context, {
          customMessage: 'Rate limit exceeded',
          statusCode: 429,
        })
      }

      // Generic server error
      return createSecureErrorResponse(error, context, {
        customMessage: 'Internal server error',
        statusCode: 500,
      })
    }
  }
}

/**
 * Custom error classes
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public details?: any
  ) {
    super(message)
    this.name = 'ValidationError'
  }
}

export class AuthenticationError extends Error {
  constructor(message: string = 'Authentication required') {
    super(message)
    this.name = 'AuthenticationError'
  }
}

export class AuthorizationError extends Error {
  constructor(message: string = 'Access denied') {
    super(message)
    this.name = 'AuthorizationError'
  }
}

export class NotFoundError extends Error {
  constructor(message: string = 'Resource not found') {
    super(message)
    this.name = 'NotFoundError'
  }
}

export class RateLimitError extends Error {
  constructor(
    message: string = 'Rate limit exceeded',
    public retryAfter?: number
  ) {
    super(message)
    this.name = 'RateLimitError'
  }
}

/**
 * Generate a unique error ID for tracking
 */
function generateErrorId(): string {
  const timestamp = Date.now().toString(36)
  const random = Math.random().toString(36).substring(2, 8)
  return `err_${timestamp}_${random}`
}

/**
 * Get generic error message based on status code
 */
function getGenericErrorMessage(statusCode: number): string {
  switch (statusCode) {
    case 400:
      return 'Bad request'
    case 401:
      return 'Authentication required'
    case 403:
      return 'Access denied'
    case 404:
      return 'Resource not found'
    case 405:
      return 'Method not allowed'
    case 409:
      return 'Conflict'
    case 422:
      return 'Unprocessable entity'
    case 429:
      return 'Rate limit exceeded'
    case 500:
      return 'Internal server error'
    case 502:
      return 'Bad gateway'
    case 503:
      return 'Service unavailable'
    case 504:
      return 'Gateway timeout'
    default:
      return 'An error occurred'
  }
}

/**
 * Enhanced error message sanitization to prevent information leakage
 */
export function sanitizeErrorMessage(message: string): string {
  if (!message || typeof message !== 'string') {
    return 'An error occurred'
  }

  let sanitized = message

  // Remove file paths and system paths
  sanitized = sanitized.replace(/\/[^\s]+\.(js|ts|jsx|tsx|py|java|cpp|c|h)/g, '[file]')
  sanitized = sanitized.replace(/[A-Z]:\\[^\s]+/g, '[path]')
  sanitized = sanitized.replace(/~\/[^\s]+/g, '[path]')

  // Remove database connection strings and credentials
  sanitized = sanitized.replace(/postgresql:\/\/[^\s]+/g, '[database]')
  sanitized = sanitized.replace(/mongodb:\/\/[^\s]+/g, '[database]')
  sanitized = sanitized.replace(/mysql:\/\/[^\s]+/g, '[database]')
  sanitized = sanitized.replace(/redis:\/\/[^\s]+/g, '[database]')

  // Remove API keys, tokens, and secrets
  sanitized = sanitized.replace(/[a-zA-Z0-9]{32,}/g, '[token]')
  sanitized = sanitized.replace(/sk-[a-zA-Z0-9]+/g, '[api-key]')
  sanitized = sanitized.replace(/Bearer\s+[a-zA-Z0-9]+/g, 'Bearer [token]')

  // Remove IP addresses
  sanitized = sanitized.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[ip]')

  // Remove email addresses
  sanitized = sanitized.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')

  // Remove phone numbers
  sanitized = sanitized.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[phone]')

  // Remove credit card numbers
  sanitized = sanitized.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[card]')

  // Remove SSNs
  sanitized = sanitized.replace(/\b\d{3}-?\d{2}-?\d{4}\b/g, '[ssn]')

  // Remove UUIDs
  sanitized = sanitized.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[uuid]')

  // Remove stack trace patterns
  sanitized = sanitized.replace(/at\s+[^\s]+\s+\([^)]+\)/g, 'at [function] ([location])')
  sanitized = sanitized.replace(/\s+at\s+[^\n]+/g, ' at [location]')

  // Remove internal error codes and references
  sanitized = sanitized.replace(/Error:\s*[A-Z0-9_]+:/g, 'Error:')
  sanitized = sanitized.replace(/Code:\s*[A-Z0-9_]+/g, 'Code: [code]')

  return sanitized
}

/**
 * Sanitize error message for logging (less aggressive than public sanitization)
 */
export function sanitizeErrorForLogging(message: string): string {
  if (!message || typeof message !== 'string') {
    return 'An error occurred'
  }

  let sanitized = message

  // Only remove the most sensitive information for logging
  sanitized = sanitized.replace(/password[=:]\s*[^\s]+/gi, 'password=[REDACTED]')
  sanitized = sanitized.replace(/token[=:]\s*[^\s]+/gi, 'token=[REDACTED]')
  sanitized = sanitized.replace(/key[=:]\s*[^\s]+/gi, 'key=[REDACTED]')
  sanitized = sanitized.replace(/secret[=:]\s*[^\s]+/gi, 'secret=[REDACTED]')

  // Remove API keys and long tokens
  sanitized = sanitized.replace(/sk-[a-zA-Z0-9]+/g, 'sk-[REDACTED]')
  sanitized = sanitized.replace(/Bearer\s+[a-zA-Z0-9]{20,}/g, 'Bearer [REDACTED]')

  return sanitized
}

/**
 * Sanitize IP address for logging
 */
export function sanitizeIPForLogging(ip: string): string {
  if (!ip || typeof ip !== 'string') {
    return '[unknown]'
  }

  // Mask last octet of IPv4 addresses
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    const parts = ip.split('.')
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`
  }

  // For IPv6 or other formats, just return a generic placeholder
  return '[ip-masked]'
}

/**
 * Sanitize context data for logging
 */
export function sanitizeContextForLogging(context: ErrorContext): Partial<ErrorContext> {
  return {
    endpoint: context.endpoint,
    method: context.method,
    ip: sanitizeIPForLogging(context.ip),
    userAgent: context.userAgent?.substring(0, 100), // Truncate user agent
    sessionId: context.sessionId ? '[session-present]' : undefined,
    userId: context.userId ? '[user-present]' : undefined,
    workspaceId: context.workspaceId ? '[workspace-present]' : undefined,
  }
}

/**
 * Add comprehensive security headers to response
 */
export function addSecurityHeaders(response: NextResponse): void {
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-XSS-Protection', '1; mode=block')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')

  // Remove potentially sensitive headers
  response.headers.delete('Server')
  response.headers.delete('X-Powered-By')
}

/**
 * Log security event for error monitoring
 */
export function logSecurityEvent(eventType: string, context: ErrorContext, details?: any): void {
  logger.warn('Security Event', `${eventType} detected`, {
    eventType,
    endpoint: context.endpoint,
    method: context.method,
    ip: context.ip,
    userAgent: context.userAgent,
    sessionId: context.sessionId,
    timestamp: new Date().toISOString(),
    ...details,
  })
}

/**
 * Handle database errors securely
 */
export function handleDatabaseError(error: any, context: ErrorContext): NextResponse {
  // Log the full error for debugging
  logger.error('Database Error', 'Database operation failed', {
    endpoint: context.endpoint,
    ip: context.ip,
    error:
      error instanceof Error
        ? {
            name: error.name,
            message: error.message,
            stack: error.stack,
          }
        : error,
  })

  // Return generic error to client
  return createSecureErrorResponse(new Error('Database operation failed'), context, {
    customMessage: 'A database error occurred',
    statusCode: 500,
  })
}

/**
 * Handle external API errors securely
 */
export function handleExternalApiError(
  error: any,
  context: ErrorContext,
  apiName: string
): NextResponse {
  logger.error('External API Error', `${apiName} API error`, {
    endpoint: context.endpoint,
    ip: context.ip,
    apiName,
    error:
      error instanceof Error
        ? {
            name: error.name,
            message: error.message,
          }
        : error,
  })

  return createSecureErrorResponse(new Error(`${apiName} service error`), context, {
    customMessage: 'External service temporarily unavailable',
    statusCode: 503,
  })
}
