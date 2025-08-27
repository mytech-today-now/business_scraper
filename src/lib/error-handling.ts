/**
 * Secure Error Handling for API Routes
 * Prevents information leakage while providing useful debugging information
 */

import { NextRequest, NextResponse } from 'next/server'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

export interface ErrorContext {
  endpoint: string
  method: string
  ip: string
  userAgent?: string
  sessionId?: string
}

export interface SecureErrorOptions {
  logError?: boolean
  includeStack?: boolean
  customMessage?: string
  statusCode?: number
}

/**
 * Create a secure error response that doesn't leak sensitive information
 */
export function createSecureErrorResponse(
  error: any,
  context: ErrorContext,
  options: SecureErrorOptions = {}
): NextResponse {
  const { logError = true, includeStack = false, customMessage, statusCode = 500 } = options

  const isDevelopment = process.env.NODE_ENV === 'development'
  const errorId = generateErrorId()

  // Log the error with full details
  if (logError) {
    logger.error('API Error', `Error ${errorId} at ${context.endpoint}`, {
      errorId,
      endpoint: context.endpoint,
      method: context.method,
      ip: context.ip,
      userAgent: context.userAgent,
      sessionId: context.sessionId,
      error:
        error instanceof Error
          ? {
              name: error.name,
              message: error.message,
              stack: error.stack,
            }
          : error,
    })
  }

  // Create safe error response
  const errorResponse: any = {
    error: customMessage || getGenericErrorMessage(statusCode),
    errorId,
    timestamp: new Date().toISOString(),
  }

  // In development, include more details
  if (isDevelopment) {
    if (error instanceof Error) {
      errorResponse.details = {
        name: error.name,
        message: error.message,
        ...(includeStack && { stack: error.stack }),
      }
    }
  }

  const response = NextResponse.json(errorResponse, { status: statusCode })

  // Add security headers
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')

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
 * Sanitize error message to prevent information leakage
 */
export function sanitizeErrorMessage(message: string): string {
  // Remove file paths
  message = message.replace(/\/[^\s]+\.(js|ts|jsx|tsx)/g, '[file]')

  // Remove database connection strings
  message = message.replace(/postgresql:\/\/[^\s]+/g, '[database]')
  message = message.replace(/mongodb:\/\/[^\s]+/g, '[database]')

  // Remove API keys and tokens
  message = message.replace(/[a-zA-Z0-9]{32,}/g, '[token]')

  // Remove IP addresses
  message = message.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[ip]')

  // Remove email addresses
  message = message.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')

  return message
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
