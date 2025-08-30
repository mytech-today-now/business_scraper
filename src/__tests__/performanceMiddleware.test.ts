/**
 * Performance Middleware Unit Tests
 * Business Scraper Application - Performance Tracking Middleware Tests
 */

import { NextApiRequest, NextApiResponse } from 'next'
import { NextRequest, NextResponse } from 'next/server'
import {
  performanceMiddleware,
  appRouterPerformanceMiddleware,
  withDatabasePerformanceTracking,
  withPaymentPerformanceTracking,
  withPerformanceTracking,
  withScrapingPerformanceTracking,
  createPerformanceMiddleware
} from '@/middleware/performanceMiddleware'

// Mock dependencies
jest.mock('@/model/monitoringService', () => ({
  monitoringService: {
    recordApiResponseTime: jest.fn(),
    recordDatabaseQueryTime: jest.fn(),
    recordPaymentProcessingTime: jest.fn(),
    recordMetric: jest.fn(),
  }
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }
}))

import { monitoringService } from '@/model/monitoringService'
import { logger } from '@/utils/logger'

describe('Performance Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('performanceMiddleware (Pages Router)', () => {
    it('should track API response time', (done) => {
      const req = {
        method: 'GET',
        url: '/api/test'
      } as NextApiRequest

      const res = {
        statusCode: 200,
        end: jest.fn()
      } as unknown as NextApiResponse

      const next = jest.fn()

      // Override res.end to simulate response completion
      const originalEnd = res.end
      res.end = function(chunk?: any, encoding?: any) {
        // Simulate some processing time
        setTimeout(() => {
          expect(monitoringService.recordApiResponseTime).toHaveBeenCalledWith(
            '/api/test',
            expect.any(Number),
            200
          )
          expect(logger.debug).toHaveBeenCalledWith(
            'Performance',
            'Request started: GET /api/test'
          )
          done()
        }, 10)
        
        return originalEnd.call(this, chunk, encoding)
      }

      performanceMiddleware(req, res, next)
      
      expect(next).toHaveBeenCalled()
      
      // Simulate response end
      res.end()
    })

    it('should log slow requests', (done) => {
      const req = {
        method: 'POST',
        url: '/api/slow'
      } as NextApiRequest

      const res = {
        statusCode: 200,
        end: jest.fn()
      } as unknown as NextApiResponse

      const next = jest.fn()

      const originalEnd = res.end
      res.end = function(chunk?: any, encoding?: any) {
        // Simulate slow response
        setTimeout(() => {
          expect(logger.warn).toHaveBeenCalledWith(
            'Performance',
            expect.stringContaining('Slow request detected')
          )
          done()
        }, 1100) // More than 1000ms threshold
        
        return originalEnd.call(this, chunk, encoding)
      }

      performanceMiddleware(req, res, next)
      res.end()
    })
  })

  describe('appRouterPerformanceMiddleware', () => {
    it('should track App Router request performance', () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'GET'
      })

      const response = appRouterPerformanceMiddleware(request)

      expect(response).toBeInstanceOf(NextResponse)
      expect(logger.debug).toHaveBeenCalledWith(
        'Performance',
        'App Router request started: GET /api/test'
      )

      // Check that performance headers are set
      const headers = (response as NextResponse).headers
      expect(headers.get('X-Request-Start-Time')).toBeDefined()
      expect(headers.get('X-Request-ID')).toBeDefined()
    })
  })

  describe('withDatabasePerformanceTracking', () => {
    it('should track successful database operations', async () => {
      const queryName = 'test_query'
      const mockResult = { rows: [], rowCount: 0 }
      const queryFunction = jest.fn().mockResolvedValue(mockResult)

      const result = await withDatabasePerformanceTracking(queryName, queryFunction)

      expect(result).toBe(mockResult)
      expect(queryFunction).toHaveBeenCalled()
      expect(monitoringService.recordDatabaseQueryTime).toHaveBeenCalledWith(
        queryName,
        expect.any(Number)
      )
      expect(logger.debug).toHaveBeenCalledWith(
        'Performance',
        expect.stringContaining('Database query completed')
      )
    })

    it('should track failed database operations', async () => {
      const queryName = 'failing_query'
      const error = new Error('Database connection failed')
      const queryFunction = jest.fn().mockRejectedValue(error)

      await expect(withDatabasePerformanceTracking(queryName, queryFunction)).rejects.toThrow(error)

      expect(monitoringService.recordDatabaseQueryTime).toHaveBeenCalledWith(
        queryName,
        expect.any(Number)
      )
      expect(logger.error).toHaveBeenCalledWith(
        'Performance',
        expect.stringContaining('Database query failed'),
        error
      )
    })

    it('should log slow database queries', async () => {
      const queryName = 'slow_query'
      const queryFunction = jest.fn().mockImplementation(() => 
        new Promise(resolve => setTimeout(() => resolve({}), 600)) // 600ms
      )

      await withDatabasePerformanceTracking(queryName, queryFunction)

      expect(logger.warn).toHaveBeenCalledWith(
        'Performance',
        expect.stringContaining('Slow database query')
      )
    })
  })

  describe('withPaymentPerformanceTracking', () => {
    it('should track successful payment operations', async () => {
      const operation = 'process_payment'
      const mockResult = { transactionId: '123', status: 'success' }
      const paymentFunction = jest.fn().mockResolvedValue(mockResult)

      const result = await withPaymentPerformanceTracking(operation, paymentFunction)

      expect(result).toBe(mockResult)
      expect(monitoringService.recordPaymentProcessingTime).toHaveBeenCalledWith(
        expect.any(Number),
        true
      )
      expect(logger.info).toHaveBeenCalledWith(
        'Performance',
        expect.stringContaining('Payment operation completed')
      )
    })

    it('should track failed payment operations', async () => {
      const operation = 'process_payment'
      const error = new Error('Payment gateway error')
      const paymentFunction = jest.fn().mockRejectedValue(error)

      await expect(withPaymentPerformanceTracking(operation, paymentFunction)).rejects.toThrow(error)

      expect(monitoringService.recordPaymentProcessingTime).toHaveBeenCalledWith(
        expect.any(Number),
        false
      )
      expect(logger.error).toHaveBeenCalledWith(
        'Performance',
        expect.stringContaining('Payment operation failed'),
        error
      )
    })
  })

  describe('withPerformanceTracking', () => {
    it('should track generic operations with custom options', async () => {
      const operationName = 'custom_operation'
      const mockResult = 'operation result'
      const operation = jest.fn().mockResolvedValue(mockResult)
      const options = {
        slowThreshold: 500,
        metricName: 'custom_metric',
        tags: { type: 'test' }
      }

      const result = await withPerformanceTracking(operationName, operation, options)

      expect(result).toBe(mockResult)
      expect(monitoringService.recordMetric).toHaveBeenCalledWith(
        'custom_metric',
        expect.any(Number),
        'ms',
        expect.objectContaining({
          operation: operationName,
          success: 'true',
          type: 'test'
        })
      )
    })

    it('should use default options when not provided', async () => {
      const operationName = 'default_operation'
      const operation = jest.fn().mockResolvedValue('result')

      await withPerformanceTracking(operationName, operation)

      expect(monitoringService.recordMetric).toHaveBeenCalledWith(
        'operation_duration',
        expect.any(Number),
        'ms',
        expect.objectContaining({
          operation: operationName,
          success: 'true'
        })
      )
    })
  })

  describe('withScrapingPerformanceTracking', () => {
    it('should track scraping operations with domain extraction', async () => {
      const url = 'https://example.com/page'
      const scrapingFunction = jest.fn().mockResolvedValue({ data: 'scraped' })

      await withScrapingPerformanceTracking(url, scrapingFunction)

      expect(monitoringService.recordMetric).toHaveBeenCalledWith(
        'scraping_duration',
        expect.any(Number),
        'ms',
        expect.objectContaining({
          url,
          domain: 'example.com'
        })
      )
    })
  })

  describe('createPerformanceMiddleware', () => {
    it('should create custom middleware with specified options', (done) => {
      const options = {
        slowThreshold: 200,
        enableLogging: true,
        metricPrefix: 'custom'
      }

      const customMiddleware = createPerformanceMiddleware(options)

      const req = {
        method: 'GET',
        url: '/api/custom'
      } as NextApiRequest

      const res = {
        statusCode: 200,
        end: jest.fn()
      } as unknown as NextApiResponse

      const next = jest.fn()

      const originalEnd = res.end
      res.end = function(chunk?: any, encoding?: any) {
        setTimeout(() => {
          expect(monitoringService.recordMetric).toHaveBeenCalledWith(
            'custom_response_time',
            expect.any(Number),
            'ms',
            expect.objectContaining({
              endpoint: '/api/custom',
              method: 'GET'
            })
          )
          done()
        }, 10)
        
        return originalEnd.call(this, chunk, encoding)
      }

      customMiddleware(req, res, next)
      res.end()
    })

    it('should use default options when none provided', () => {
      const defaultMiddleware = createPerformanceMiddleware()
      expect(typeof defaultMiddleware).toBe('function')
    })
  })

  describe('Error Handling', () => {
    it('should handle monitoring service errors gracefully', async () => {
      const error = new Error('Monitoring service error')
      ;(monitoringService.recordDatabaseQueryTime as jest.Mock).mockRejectedValue(error)

      const queryFunction = jest.fn().mockResolvedValue('result')

      // Should not throw even if monitoring fails
      const result = await withDatabasePerformanceTracking('test', queryFunction)
      expect(result).toBe('result')
      expect(queryFunction).toHaveBeenCalled()
    })
  })
})
