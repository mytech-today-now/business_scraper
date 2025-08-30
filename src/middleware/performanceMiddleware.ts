/**
 * Performance Middleware
 * Business Scraper Application - Automatic Performance Tracking
 */

import { NextApiRequest, NextApiResponse } from 'next'
import { NextRequest, NextResponse } from 'next/server'
import { monitoringService } from '@/model/monitoringService'
import { logger } from '@/utils/logger'

/**
 * Performance middleware for Next.js API routes (Pages Router)
 */
export function performanceMiddleware(
  req: NextApiRequest,
  res: NextApiResponse,
  next: () => void
): void {
  const startTime = Date.now()
  const endpoint = req.url || 'unknown'

  // Track request start
  logger.debug('Performance', `Request started: ${req.method} ${endpoint}`)

  // Override res.end to capture response time
  const originalEnd = res.end
  res.end = function(chunk?: any, encoding?: any) {
    const duration = Date.now() - startTime
    const statusCode = res.statusCode

    // Record API response time
    monitoringService.recordApiResponseTime(endpoint, duration, statusCode)

    // Log slow requests
    if (duration > 1000) {
      logger.warn('Performance', `Slow request detected: ${req.method} ${endpoint} took ${duration}ms`)
    }

    // Call original end method
    originalEnd.call(this, chunk, encoding)
  }

  next()
}

/**
 * Performance middleware for Next.js App Router
 */
export function appRouterPerformanceMiddleware(request: NextRequest): NextResponse | Promise<NextResponse> {
  const startTime = Date.now()
  const endpoint = request.nextUrl.pathname
  const method = request.method

  // Track request start
  logger.debug('Performance', `App Router request started: ${method} ${endpoint}`)

  // Create response and add performance tracking
  const response = NextResponse.next()

  // Add performance tracking to response headers for client-side monitoring
  response.headers.set('X-Request-Start-Time', startTime.toString())
  response.headers.set('X-Request-ID', `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`)

  // Schedule async performance recording
  setImmediate(async () => {
    const duration = Date.now() - startTime
    const statusCode = response.status

    try {
      await monitoringService.recordApiResponseTime(endpoint, duration, statusCode)

      // Log slow requests
      if (duration > 1000) {
        logger.warn('Performance', `Slow App Router request: ${method} ${endpoint} took ${duration}ms`)
      }
    } catch (error) {
      logger.error('Performance', 'Failed to record API performance metric', error)
    }
  })

  return response
}

/**
 * Database query performance wrapper
 */
export function withDatabasePerformanceTracking<T>(
  queryName: string,
  queryFunction: () => Promise<T>
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    const startTime = Date.now()

    try {
      const result = await queryFunction()
      const duration = Date.now() - startTime

      await monitoringService.recordDatabaseQueryTime(queryName, duration)

      if (duration > 500) {
        logger.warn('Performance', `Slow database query: ${queryName} took ${duration}ms`)
      }

      logger.debug('Performance', `Database query completed: ${queryName} in ${duration}ms`)
      resolve(result)
    } catch (error) {
      const duration = Date.now() - startTime
      await monitoringService.recordDatabaseQueryTime(queryName, duration)

      logger.error('Performance', `Database query failed: ${queryName} after ${duration}ms`, error)
      reject(error)
    }
  })
}

/**
 * Payment processing performance wrapper
 */
export function withPaymentPerformanceTracking<T>(
  operation: string,
  paymentFunction: () => Promise<T>
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    const startTime = Date.now()

    try {
      const result = await paymentFunction()
      const duration = Date.now() - startTime

      await monitoringService.recordPaymentProcessingTime(duration, true)

      logger.info('Performance', `Payment operation completed: ${operation} in ${duration}ms`)
      resolve(result)
    } catch (error) {
      const duration = Date.now() - startTime
      await monitoringService.recordPaymentProcessingTime(duration, false)

      logger.error('Performance', `Payment operation failed: ${operation} after ${duration}ms`, error)
      reject(error)
    }
  })
}

/**
 * Generic operation performance wrapper
 */
export function withPerformanceTracking<T>(
  operationName: string,
  operation: () => Promise<T>,
  options?: {
    slowThreshold?: number
    metricName?: string
    tags?: Record<string, string>
  }
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    const startTime = Date.now()
    const slowThreshold = options?.slowThreshold || 1000
    const metricName = options?.metricName || 'operation_duration'

    try {
      const result = await operation()
      const duration = Date.now() - startTime

      // Record custom metric
      await monitoringService.recordMetric(metricName, duration, 'ms', {
        operation: operationName,
        success: 'true',
        ...options?.tags
      })

      if (duration > slowThreshold) {
        logger.warn('Performance', `Slow operation: ${operationName} took ${duration}ms`)
      }

      logger.debug('Performance', `Operation completed: ${operationName} in ${duration}ms`)
      resolve(result)
    } catch (error) {
      const duration = Date.now() - startTime

      // Record failed operation metric
      await monitoringService.recordMetric(metricName, duration, 'ms', {
        operation: operationName,
        success: 'false',
        error: error instanceof Error ? error.message : 'unknown',
        ...options?.tags
      })

      logger.error('Performance', `Operation failed: ${operationName} after ${duration}ms`, error)
      reject(error)
    }
  })
}

/**
 * Scraping operation performance wrapper
 */
export function withScrapingPerformanceTracking<T>(
  url: string,
  scrapingFunction: () => Promise<T>
): Promise<T> {
  return withPerformanceTracking(
    `scraping_${new URL(url).hostname}`,
    scrapingFunction,
    {
      slowThreshold: 30000, // 30 seconds for scraping operations
      metricName: 'scraping_duration',
      tags: {
        url: url,
        domain: new URL(url).hostname
      }
    }
  )
}

/**
 * Cache operation performance wrapper
 */
export function withCachePerformanceTracking<T>(
  cacheKey: string,
  cacheOperation: () => Promise<T>,
  operationType: 'get' | 'set' | 'delete' | 'clear'
): Promise<T> {
  return withPerformanceTracking(
    `cache_${operationType}`,
    cacheOperation,
    {
      slowThreshold: 100, // 100ms for cache operations
      metricName: 'cache_operation_duration',
      tags: {
        operation: operationType,
        cache_key: cacheKey
      }
    }
  )
}

/**
 * File operation performance wrapper
 */
export function withFilePerformanceTracking<T>(
  fileName: string,
  fileOperation: () => Promise<T>,
  operationType: 'read' | 'write' | 'delete' | 'upload' | 'download'
): Promise<T> {
  return withPerformanceTracking(
    `file_${operationType}`,
    fileOperation,
    {
      slowThreshold: 5000, // 5 seconds for file operations
      metricName: 'file_operation_duration',
      tags: {
        operation: operationType,
        file_name: fileName
      }
    }
  )
}

/**
 * API client performance wrapper for external API calls
 */
export function withExternalApiPerformanceTracking<T>(
  apiName: string,
  endpoint: string,
  apiCall: () => Promise<T>
): Promise<T> {
  return withPerformanceTracking(
    `external_api_${apiName}`,
    apiCall,
    {
      slowThreshold: 5000, // 5 seconds for external API calls
      metricName: 'external_api_duration',
      tags: {
        api_name: apiName,
        endpoint: endpoint
      }
    }
  )
}

/**
 * Middleware factory for custom performance tracking
 */
export function createPerformanceMiddleware(options?: {
  slowThreshold?: number
  enableLogging?: boolean
  metricPrefix?: string
}) {
  const slowThreshold = options?.slowThreshold || 1000
  const enableLogging = options?.enableLogging !== false
  const metricPrefix = options?.metricPrefix || 'custom'

  return function customPerformanceMiddleware(
    req: NextApiRequest,
    res: NextApiResponse,
    next: () => void
  ): void {
    const startTime = Date.now()
    const endpoint = req.url || 'unknown'

    if (enableLogging) {
      logger.debug('Performance', `Custom middleware: ${req.method} ${endpoint}`)
    }

    const originalEnd = res.end
    res.end = function(chunk?: any, encoding?: any) {
      const duration = Date.now() - startTime
      const statusCode = res.statusCode

      // Record custom metric
      monitoringService.recordMetric(`${metricPrefix}_response_time`, duration, 'ms', {
        endpoint,
        method: req.method || 'unknown',
        status_code: statusCode.toString()
      })

      if (duration > slowThreshold && enableLogging) {
        logger.warn('Performance', `Slow custom request: ${req.method} ${endpoint} took ${duration}ms`)
      }

      originalEnd.call(this, chunk, encoding)
    }

    next()
  }
}
