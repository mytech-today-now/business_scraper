/**
 * Standardized API Error Handling Utilities
 * Provides consistent error handling patterns for API routes and client-side API calls
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'
import { 
  createSecureErrorResponse, 
  withErrorHandling as withApiErrorHandling,
  ErrorContext 
} from '@/lib/error-handling'

/**
 * Standard error response format for client-side API calls
 */
export interface ApiErrorResponse {
  error: string
  errorId?: string
  timestamp: string
  details?: any
}

/**
 * Standard success response format for client-side API calls
 */
export interface ApiSuccessResponse<T = any> {
  success: true
  data: T
  timestamp: string
}

/**
 * Wrapper for API route handlers with standardized error handling
 */
export function withStandardErrorHandling(
  handler: (request: NextRequest) => Promise<NextResponse>
) {
  return withApiErrorHandling(handler)
}

/**
 * Create a standardized success response
 */
export function createSuccessResponse<T>(
  data: T,
  status: number = 200
): NextResponse {
  const response: ApiSuccessResponse<T> = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  }

  return NextResponse.json(response, { status })
}

/**
 * Create a standardized error response for client-side consumption
 */
export function createErrorResponse(
  message: string,
  status: number = 500,
  details?: any
): NextResponse {
  const errorId = generateErrorId()
  
  const response: ApiErrorResponse = {
    error: message,
    errorId,
    timestamp: new Date().toISOString(),
    ...(details && { details })
  }

  return NextResponse.json(response, { status })
}

/**
 * Handle async operations in API routes with consistent error handling
 */
export async function handleAsyncApiOperation<T>(
  operation: () => Promise<T>,
  context: {
    operationName: string
    endpoint: string
    request?: NextRequest
  }
): Promise<{ success: true; data: T } | { success: false; error: NextResponse }> {
  try {
    const data = await operation()
    return { success: true, data }
  } catch (error) {
    const errorContext: ErrorContext = {
      endpoint: context.endpoint,
      method: context.request?.method || 'UNKNOWN',
      ip: context.request ? getClientIP(context.request) : 'unknown',
      userAgent: context.request?.headers.get('user-agent') || undefined
    }

    logger.error('API Operation', `${context.operationName} failed`, {
      operation: context.operationName,
      endpoint: context.endpoint,
      error: error instanceof Error ? {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : error
    })

    const errorResponse = createSecureErrorResponse(
      error instanceof Error ? error : new Error(String(error)),
      errorContext,
      {
        customMessage: `${context.operationName} failed`,
        statusCode: 500
      }
    )

    return { success: false, error: errorResponse }
  }
}

/**
 * Client-side API call wrapper with standardized error handling
 */
export async function makeApiCall<T = any>(
  url: string,
  options: RequestInit = {},
  context: {
    operation: string
    component?: string
    retries?: number
  } = { operation: 'API Call' }
): Promise<{ success: true; data: T } | { success: false; error: ApiErrorResponse }> {
  const { operation, component = 'ApiClient', retries = 0 } = context
  const maxRetries = 3
  
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({
        error: `HTTP ${response.status}: ${response.statusText}`,
        timestamp: new Date().toISOString()
      }))

      throw new ApiError(
        errorData.error || `Request failed with status ${response.status}`,
        response.status,
        errorData
      )
    }

    const data = await response.json()
    
    // Handle API responses that have success/error structure
    if (data.success === false) {
      throw new ApiError(data.error || 'API operation failed', 400, data)
    }

    logger.debug(component, `${operation} completed successfully`, {
      url,
      method: options.method || 'GET',
      status: response.status
    })

    return { success: true, data: data.data || data }
  } catch (error) {
    const apiError = error instanceof ApiError ? error : new ApiError(
      error instanceof Error ? error.message : String(error),
      500
    )

    logger.error(component, `${operation} failed`, {
      url,
      method: options.method || 'GET',
      retries,
      error: {
        name: apiError.name,
        message: apiError.message,
        status: apiError.status,
        details: apiError.details
      }
    })

    // Retry logic for certain errors
    if (retries < maxRetries && isRetryableError(apiError)) {
      logger.info(component, `Retrying ${operation} (attempt ${retries + 1}/${maxRetries})`)
      
      await new Promise(resolve => setTimeout(resolve, 1000 * (retries + 1)))
      
      return makeApiCall(url, options, {
        ...context,
        retries: retries + 1
      })
    }

    return {
      success: false,
      error: {
        error: apiError.message,
        errorId: generateErrorId(),
        timestamp: new Date().toISOString(),
        details: apiError.details
      }
    }
  }
}

/**
 * Custom API Error class
 */
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number = 500,
    public details?: any
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/**
 * Check if an error is retryable
 */
function isRetryableError(error: ApiError): boolean {
  // Retry on network errors, timeouts, and 5xx server errors
  return (
    error.status >= 500 ||
    error.status === 408 || // Request Timeout
    error.status === 429 || // Too Many Requests
    error.message.includes('network') ||
    error.message.includes('timeout') ||
    error.message.includes('ECONNRESET') ||
    error.message.includes('ETIMEDOUT')
  )
}

/**
 * Get client IP from request (helper function)
 */
function getClientIP(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for')
  const realIp = request.headers.get('x-real-ip')
  
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }
  
  if (realIp) {
    return realIp
  }
  
  return 'unknown'
}

/**
 * Generate unique error ID
 */
function generateErrorId(): string {
  return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

/**
 * Validate API request body with error handling
 */
export async function validateRequestBody<T>(
  request: NextRequest,
  validator: (body: any) => T | Promise<T>
): Promise<{ success: true; data: T } | { success: false; error: NextResponse }> {
  try {
    const body = await request.json()
    const validatedData = await validator(body)
    return { success: true, data: validatedData }
  } catch (error) {
    logger.warn('API Validation', 'Request body validation failed', {
      endpoint: request.nextUrl.pathname,
      error: error instanceof Error ? error.message : String(error)
    })

    return {
      success: false,
      error: createErrorResponse(
        'Invalid request body',
        400,
        error instanceof Error ? error.message : String(error)
      )
    }
  }
}

/**
 * Rate limiting error handler
 */
export function createRateLimitErrorResponse(
  retryAfter: number
): NextResponse {
  return createErrorResponse(
    'Rate limit exceeded',
    429,
    { retryAfter }
  )
}

/**
 * Authentication error handler
 */
export function createAuthErrorResponse(
  message: string = 'Authentication required'
): NextResponse {
  return createErrorResponse(message, 401)
}

/**
 * Authorization error handler
 */
export function createAuthorizationErrorResponse(
  message: string = 'Access denied'
): NextResponse {
  return createErrorResponse(message, 403)
}

/**
 * Validation error handler
 */
export function createValidationErrorResponse(
  message: string,
  details?: any
): NextResponse {
  return createErrorResponse(message, 400, details)
}
