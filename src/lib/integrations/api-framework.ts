/**
 * API Framework
 * Comprehensive RESTful API framework for external integrations
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  ApiFrameworkConfig,
  ApiRequestContext,
  ApiResponse,
  ApiPermission
} from '@/types/integrations'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { apiMetricsService } from '@/lib/analytics/api-metrics'

/**
 * API Framework configuration
 */
const defaultConfig: ApiFrameworkConfig = {
  version: 'v1',
  baseUrl: '/api/v1',
  authentication: {
    methods: ['oauth2', 'api_key'],
    defaultMethod: 'api_key'
  },
  rateLimit: {
    global: {
      requestsPerMinute: 1000,
      requestsPerHour: 10000
    },
    perClient: {
      requestsPerMinute: 100,
      requestsPerHour: 1000
    }
  },
  cors: {
    enabled: true,
    origins: ['*'], // Configure based on environment
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    headers: ['Content-Type', 'Authorization', 'X-API-Key']
  },
  logging: {
    level: 'info',
    includeRequestBody: false,
    includeResponseBody: false,
    sensitiveFields: ['password', 'token', 'key', 'secret']
  },
  monitoring: {
    enabled: true,
    metricsEndpoint: '/api/v1/metrics',
    healthEndpoint: '/api/v1/health'
  }
}

/**
 * API Framework class
 */
export class ApiFramework {
  private config: ApiFrameworkConfig
  private requestMetrics: Map<string, any> = new Map()
  private rateLimitStore: Map<string, any> = new Map()

  constructor(config: Partial<ApiFrameworkConfig> = {}) {
    this.config = { ...defaultConfig, ...config }
  }

  /**
   * Create API handler with middleware
   */
  createHandler<T = any>(
    handler: (request: NextRequest, context: ApiRequestContext) => Promise<ApiResponse<T>>,
    options: {
      permissions?: ApiPermission[]
      rateLimit?: {
        requestsPerMinute?: number
        requestsPerHour?: number
      }
      validation?: {
        body?: any
        query?: any
        params?: any
      }
      cache?: {
        ttl?: number
        key?: string
      }
    } = {}
  ) {
    return async (request: NextRequest): Promise<NextResponse> => {
      const startTime = Date.now()
      const requestId = this.generateRequestId()
      const ip = getClientIP(request)
      const method = request.method
      const pathname = request.nextUrl.pathname

      try {
        // Create request context
        const context: ApiRequestContext = {
          requestId,
          permissions: [],
          rateLimit: {
            remaining: 0,
            resetTime: 0
          },
          startTime,
          metadata: {
            ip,
            method,
            pathname,
            userAgent: request.headers.get('user-agent') || ''
          }
        }

        // Apply CORS
        if (this.config.cors.enabled && method === 'OPTIONS') {
          return this.handleCors(request)
        }

        // Authentication
        const authResult = await this.authenticate(request)
        if (!authResult.success) {
          return this.createErrorResponse(authResult.error || 'Authentication failed', 401, requestId)
        }

        context.clientId = authResult.clientId
        context.userId = authResult.userId
        context.permissions = authResult.permissions || []

        // Authorization
        if (options.permissions && options.permissions.length > 0) {
          const hasPermission = options.permissions.some(permission => 
            context.permissions.includes(permission)
          )
          
          if (!hasPermission) {
            return this.createErrorResponse('Insufficient permissions', 403, requestId)
          }
        }

        // Rate limiting with enhanced metrics
        const rateLimitResult = await this.checkRateLimit(context, options.rateLimit)
        if (!rateLimitResult.allowed) {
          // Record rate limit hit
          apiMetricsService.recordRequest(
            context.clientId || 'anonymous',
            pathname,
            method,
            429,
            Date.now() - startTime,
            0,
            { ip, userAgent: context.metadata.userAgent, rateLimitHit: true }
          )

          return this.createErrorResponse('Rate limit exceeded', 429, requestId, {
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': rateLimitResult.resetTime.toString()
          })
        }

        context.rateLimit = {
          remaining: rateLimitResult.remaining,
          resetTime: rateLimitResult.resetTime
        }

        // Input validation
        if (options.validation) {
          const validationResult = await this.validateInput(request, options.validation)
          if (!validationResult.valid) {
            return this.createErrorResponse(
              `Validation failed: ${validationResult.errors.join(', ')}`, 
              400, 
              requestId
            )
          }
        }

        // Execute handler
        const result = await handler(request, context)

        const duration = Date.now() - startTime
        const statusCode = result.success ? 200 : 400

        // Record metrics with enhanced analytics
        apiMetricsService.recordRequest(
          context.clientId || 'anonymous',
          pathname,
          method,
          statusCode,
          duration,
          JSON.stringify(result).length,
          { ip, userAgent: context.metadata.userAgent }
        )

        // Record legacy metrics
        this.recordMetrics(context, duration, 'success')

        // Create response
        return this.createSuccessResponse(result, requestId, {
          'X-RateLimit-Remaining': context.rateLimit.remaining.toString(),
          'X-RateLimit-Reset': context.rateLimit.resetTime.toString()
        })

      } catch (error) {
        const duration = Date.now() - startTime
        const statusCode = 500

        logger.error('ApiFramework', `API request failed: ${pathname}`, {
          requestId,
          method,
          pathname,
          ip,
          duration,
          error: error instanceof Error ? error.message : 'Unknown error'
        })

        // Record error metrics with enhanced analytics
        apiMetricsService.recordRequest(
          'anonymous', // May not have client context in error cases
          pathname,
          method,
          statusCode,
          duration,
          0,
          { ip, userAgent: request.headers.get('user-agent') || '' }
        )

        // Record legacy error metrics
        this.recordMetrics({ requestId, metadata: { ip, method, pathname } } as ApiRequestContext, duration, 'error')

        return this.createErrorResponse(
          error instanceof Error ? error.message : 'Internal server error',
          statusCode,
          requestId
        )
      }
    }
  }

  /**
   * Handle CORS preflight requests
   */
  private handleCors(request: NextRequest): NextResponse {
    const response = new NextResponse(null, { status: 200 })
    
    if (this.config.cors.enabled) {
      response.headers.set('Access-Control-Allow-Origin', this.config.cors.origins.join(', '))
      response.headers.set('Access-Control-Allow-Methods', this.config.cors.methods.join(', '))
      response.headers.set('Access-Control-Allow-Headers', this.config.cors.headers.join(', '))
      response.headers.set('Access-Control-Max-Age', '86400')
    }
    
    return response
  }

  /**
   * Authenticate request
   */
  private async authenticate(request: NextRequest): Promise<{
    success: boolean
    clientId?: string
    userId?: string
    permissions?: ApiPermission[]
    error?: string
  }> {
    const authHeader = request.headers.get('authorization')
    const apiKey = request.headers.get('x-api-key')

    // API Key authentication
    if (apiKey) {
      return this.authenticateApiKey(apiKey)
    }

    // OAuth 2.0 authentication
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.substring(7)
      return this.authenticateOAuth(token)
    }

    // For now, allow unauthenticated access with limited permissions
    return {
      success: true,
      clientId: 'anonymous',
      userId: 'anonymous',
      permissions: ['read:businesses']
    }
  }

  /**
   * Authenticate API key
   */
  private async authenticateApiKey(apiKey: string): Promise<{
    success: boolean
    clientId?: string
    userId?: string
    permissions?: ApiPermission[]
    error?: string
  }> {
    // TODO: Implement API key validation
    // For now, return success for demo purposes
    return {
      success: true,
      clientId: 'api-client',
      userId: 'api-user',
      permissions: ['read:businesses', 'write:businesses', 'read:exports', 'write:exports']
    }
  }

  /**
   * Authenticate OAuth token
   */
  private async authenticateOAuth(token: string): Promise<{
    success: boolean
    clientId?: string
    userId?: string
    permissions?: ApiPermission[]
    error?: string
  }> {
    // TODO: Implement OAuth token validation
    // For now, return success for demo purposes
    return {
      success: true,
      clientId: 'oauth-client',
      userId: 'oauth-user',
      permissions: ['read:businesses', 'write:businesses', 'read:exports', 'write:exports']
    }
  }

  /**
   * Check rate limits using enhanced metrics service
   */
  private async checkRateLimit(
    context: ApiRequestContext,
    customLimits?: { requestsPerMinute?: number; requestsPerHour?: number }
  ): Promise<{
    allowed: boolean
    remaining: number
    resetTime: number
  }> {
    const clientId = context.clientId || context.metadata.ip || 'anonymous'

    const limits = {
      requestsPerMinute: customLimits?.requestsPerMinute || this.config.rateLimit.perClient.requestsPerMinute,
      requestsPerHour: customLimits?.requestsPerHour || this.config.rateLimit.perClient.requestsPerHour
    }

    // Use enhanced metrics service for rate limiting
    const rateLimitResult = apiMetricsService.checkRateLimit(clientId, limits)

    return {
      allowed: rateLimitResult.allowed,
      remaining: Math.min(rateLimitResult.remaining.minute, rateLimitResult.remaining.hour),
      resetTime: Math.min(rateLimitResult.resetTime.minute, rateLimitResult.resetTime.hour)
    }
  }

  /**
   * Validate input
   */
  private async validateInput(
    request: NextRequest,
    validation: { body?: any; query?: any; params?: any }
  ): Promise<{
    valid: boolean
    errors: string[]
  }> {
    const errors: string[] = []

    // TODO: Implement comprehensive input validation
    // For now, basic validation
    if (validation.body && request.method !== 'GET') {
      try {
        await request.json()
      } catch {
        errors.push('Invalid JSON body')
      }
    }

    return {
      valid: errors.length === 0,
      errors
    }
  }

  /**
   * Create success response
   */
  private createSuccessResponse<T>(
    data: ApiResponse<T>,
    requestId: string,
    headers: Record<string, string> = {}
  ): NextResponse {
    const response = NextResponse.json(data)
    
    // Add standard headers
    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-API-Version', this.config.version)
    
    // Add custom headers
    Object.entries(headers).forEach(([key, value]) => {
      response.headers.set(key, value)
    })

    // Add CORS headers
    if (this.config.cors.enabled) {
      response.headers.set('Access-Control-Allow-Origin', this.config.cors.origins.join(', '))
    }

    return response
  }

  /**
   * Create error response
   */
  private createErrorResponse(
    message: string,
    status: number,
    requestId: string,
    headers: Record<string, string> = {}
  ): NextResponse {
    const errorResponse: ApiResponse = {
      success: false,
      error: {
        code: `HTTP_${status}`,
        message
      },
      metadata: {
        requestId,
        timestamp: new Date().toISOString(),
        version: this.config.version
      }
    }

    const response = NextResponse.json(errorResponse, { status })
    
    // Add standard headers
    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-API-Version', this.config.version)
    
    // Add custom headers
    Object.entries(headers).forEach(([key, value]) => {
      response.headers.set(key, value)
    })

    // Add CORS headers
    if (this.config.cors.enabled) {
      response.headers.set('Access-Control-Allow-Origin', this.config.cors.origins.join(', '))
    }

    return response
  }

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Record metrics
   */
  private recordMetrics(
    context: ApiRequestContext,
    duration: number,
    status: 'success' | 'error'
  ): void {
    const key = `${context.metadata.method}:${context.metadata.pathname}`
    const existing = this.requestMetrics.get(key) || {
      count: 0,
      totalDuration: 0,
      successCount: 0,
      errorCount: 0
    }

    existing.count++
    existing.totalDuration += duration
    
    if (status === 'success') {
      existing.successCount++
    } else {
      existing.errorCount++
    }

    this.requestMetrics.set(key, existing)
  }

  /**
   * Get API metrics
   */
  getMetrics(): any {
    const metrics: any = {}
    
    for (const [endpoint, data] of this.requestMetrics.entries()) {
      metrics[endpoint] = {
        ...data,
        averageDuration: data.totalDuration / data.count,
        successRate: (data.successCount / data.count) * 100
      }
    }

    return metrics
  }

  /**
   * Get health status
   */
  getHealthStatus(): any {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: this.config.version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      metrics: this.getMetrics()
    }
  }
}

// Export singleton instance
export const apiFramework = new ApiFramework()
