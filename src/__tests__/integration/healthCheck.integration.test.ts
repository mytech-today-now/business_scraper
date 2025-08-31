/**
 * Health Check Integration Tests
 * Business Scraper Application - Health Check API Integration Tests
 */

import { NextRequest } from 'next/server'
import { GET as healthCheckHandler } from '@/app/api/health/route'
import { GET as detailedHealthHandler } from '@/app/api/health/detailed/route'
import { GET as metricsHandler } from '@/app/api/metrics/route'

// Mock dependencies
jest.mock('@/model/monitoringService', () => ({
  monitoringService: {
    getSystemHealth: jest.fn(),
    getMetrics: jest.fn(),
    getActiveAlerts: jest.fn(),
    getAllAlerts: jest.fn(),
    recordMetric: jest.fn(),
  },
}))

jest.mock('@/lib/database', () => ({
  checkDatabaseConnection: jest.fn(),
}))

jest.mock('@/lib/config-validator', () => ({
  performConfigHealthCheck: jest.fn(),
}))

jest.mock('@/lib/config', () => ({
  getConfig: jest.fn(),
}))

jest.mock('@/lib/metrics', () => ({
  metrics: {
    initialize: jest.fn(),
    getMetrics: jest.fn(),
  },
}))

import { monitoringService } from '@/model/monitoringService'
import { checkDatabaseConnection } from '@/lib/database'
import { performConfigHealthCheck } from '@/lib/config-validator'
import { getConfig } from '@/lib/config'
import { metrics } from '@/lib/metrics'

describe('Health Check Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()

    // Setup default mocks
    ;(getConfig as jest.Mock).mockReturnValue({
      app: {
        environment: 'test',
        version: '1.0.0',
      },
    })
    ;(checkDatabaseConnection as jest.Mock).mockResolvedValue({
      connected: true,
    })
    ;(performConfigHealthCheck as jest.Mock).mockResolvedValue({
      status: 'healthy',
    })
    ;(monitoringService.getSystemHealth as jest.Mock).mockReturnValue({
      overall: 'healthy',
      services: [
        {
          service: 'database',
          status: 'healthy',
          responseTime: 50,
          lastCheck: new Date(),
        },
      ],
      activeAlerts: 0,
      lastUpdated: new Date(),
    })
    ;(metrics.initialize as jest.Mock).mockResolvedValue(undefined)
    ;(metrics.getMetrics as jest.Mock).mockResolvedValue('# Prometheus metrics')
  })

  describe('Basic Health Check Endpoint', () => {
    it('should return healthy status when all systems are operational', async () => {
      const request = new NextRequest('http://localhost:3000/api/health')

      const response = await healthCheckHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toMatchObject({
        status: 'healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
        environment: 'test',
        version: '1.0.0',
        checks: {
          database: 'healthy',
          configuration: 'healthy',
          memory: expect.any(String),
        },
        monitoring: {
          overall: 'healthy',
          services: 1,
          activeAlerts: 0,
          lastUpdated: expect.any(String),
        },
      })
    })

    it('should return unhealthy status when database is down', async () => {
      ;(checkDatabaseConnection as jest.Mock).mockRejectedValue(new Error('Connection failed'))
      ;(monitoringService.getSystemHealth as jest.Mock).mockReturnValue({
        overall: 'unhealthy',
        services: [
          {
            service: 'database',
            status: 'unhealthy',
            responseTime: 0,
            lastCheck: new Date(),
            error: 'Connection failed',
          },
        ],
        activeAlerts: 1,
        lastUpdated: new Date(),
      })

      const request = new NextRequest('http://localhost:3000/api/health')

      const response = await healthCheckHandler(request)
      const data = await response.json()

      expect(response.status).toBe(503)
      expect(data.status).toBe('unhealthy')
      expect(data.checks.database).toBe('unhealthy')
      expect(data.monitoring.overall).toBe('unhealthy')
    })

    it('should return warning status when configuration has issues', async () => {
      ;(performConfigHealthCheck as jest.Mock).mockResolvedValue({
        status: 'warning',
      })

      const request = new NextRequest('http://localhost:3000/api/health')

      const response = await healthCheckHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.status).toBe('warning')
      expect(data.checks.configuration).toBe('warning')
    })

    it('should handle memory usage monitoring', async () => {
      // Mock process.memoryUsage for consistent testing
      const originalMemoryUsage = process.memoryUsage
      process.memoryUsage = jest.fn().mockReturnValue({
        rss: 100 * 1024 * 1024, // 100MB
        heapTotal: 50 * 1024 * 1024, // 50MB
        heapUsed: 40 * 1024 * 1024, // 40MB
        external: 5 * 1024 * 1024, // 5MB
        arrayBuffers: 1 * 1024 * 1024, // 1MB
      })

      const request = new NextRequest('http://localhost:3000/api/health')

      const response = await healthCheckHandler(request)
      const data = await response.json()

      expect(data.checks.memory).toBe('healthy')
      expect(data.memory).toMatchObject({
        rss: 100,
        heapTotal: 50,
        heapUsed: 40,
        external: 5,
      })

      // Restore original function
      process.memoryUsage = originalMemoryUsage
    })
  })

  describe('Detailed Health Check Endpoint', () => {
    beforeEach(() => {
      ;(monitoringService.getMetrics as jest.Mock).mockReturnValue([
        {
          id: 'metric1',
          name: 'api_response_time',
          value: 150,
          unit: 'ms',
          timestamp: new Date(),
          tags: { endpoint: '/api/test' },
        },
        {
          id: 'metric2',
          name: 'database_query_time',
          value: 50,
          unit: 'ms',
          timestamp: new Date(),
          tags: { query_type: 'select' },
        },
      ])
      ;(monitoringService.getActiveAlerts as jest.Mock).mockReturnValue([
        {
          id: 'alert1',
          type: 'performance',
          severity: 'medium',
          title: 'Slow API Response',
          description: 'API response time exceeded warning threshold',
          timestamp: new Date(),
          metric: 'api_response_time',
          value: 1500,
          threshold: 1000,
        },
      ])
      ;(monitoringService.getAllAlerts as jest.Mock).mockReturnValue([
        {
          id: 'alert1',
          type: 'performance',
          severity: 'medium',
          title: 'Slow API Response',
          description: 'API response time exceeded warning threshold',
          timestamp: new Date(),
          resolved: false,
        },
        {
          id: 'alert2',
          type: 'error',
          severity: 'high',
          title: 'Database Error',
          description: 'Database connection failed',
          timestamp: new Date(),
          resolved: true,
          resolvedAt: new Date(),
        },
      ])
    })

    it('should return detailed health information with metrics', async () => {
      const request = new NextRequest(
        'http://localhost:3000/api/health/detailed?metrics=true&timeWindow=24'
      )

      const response = await detailedHealthHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toMatchObject({
        status: 'healthy',
        timestamp: expect.any(String),
        responseTime: expect.any(Number),
        uptime: expect.any(Number),
        version: expect.any(String),
        environment: expect.any(String),
        overview: {
          totalServices: expect.any(Number),
          healthyServices: expect.any(Number),
          degradedServices: expect.any(Number),
          unhealthyServices: expect.any(Number),
          activeAlerts: expect.any(Number),
          lastUpdated: expect.any(String),
        },
        services: expect.any(Array),
        metrics: {
          timeWindow: '24 hours',
          totalMetrics: expect.any(Number),
          uniqueMetrics: expect.any(Number),
          summary: expect.any(Object),
        },
      })
    })

    it('should return detailed health information with alerts', async () => {
      const request = new NextRequest('http://localhost:3000/api/health/detailed?alerts=true')

      const response = await detailedHealthHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.alerts).toMatchObject({
        active: expect.any(Array),
        summary: {
          total: 2,
          active: 1,
          resolved: 1,
          bySeverity: {
            critical: expect.any(Number),
            high: expect.any(Number),
            medium: expect.any(Number),
            low: expect.any(Number),
          },
          byType: {
            performance: expect.any(Number),
            error: expect.any(Number),
            security: expect.any(Number),
            business: expect.any(Number),
          },
        },
      })
    })

    it('should handle custom health check parameters via POST', async () => {
      const requestBody = {
        includeMetrics: true,
        includeAlerts: true,
        timeWindow: 12,
        services: ['database'],
        metricNames: ['api_response_time'],
      }

      const request = new NextRequest('http://localhost:3000/api/health/detailed', {
        method: 'POST',
        body: JSON.stringify(requestBody),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await detailedHealthHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.requestedParameters).toMatchObject(requestBody)
      expect(data.services).toHaveLength(1)
      expect(data.services[0].name).toBe('database')
    })
  })

  describe('Metrics Endpoint Integration', () => {
    it('should return Prometheus format by default', async () => {
      const request = new NextRequest('http://localhost:3000/api/metrics')

      const response = await metricsHandler(request)
      const text = await response.text()

      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Type')).toContain('text/plain')
      expect(text).toContain('# Prometheus metrics')
    })

    it('should return JSON format when requested', async () => {
      ;(monitoringService.getMetrics as jest.Mock).mockReturnValue([
        {
          id: 'metric1',
          name: 'test_metric',
          value: 100,
          unit: 'ms',
          timestamp: new Date(),
        },
      ])

      const request = new NextRequest('http://localhost:3000/api/metrics?format=json')

      const response = await metricsHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toMatchObject({
        timestamp: expect.any(String),
        system: {
          status: 'healthy',
          services: expect.any(Array),
          activeAlerts: expect.any(Number),
        },
        metrics: expect.any(Array),
        alerts: expect.any(Array),
        prometheus: expect.any(String),
      })
    })

    it('should exclude monitoring data when requested', async () => {
      const request = new NextRequest('http://localhost:3000/api/metrics?monitoring=false')

      const response = await metricsHandler(request)
      const text = await response.text()

      expect(response.status).toBe(200)
      expect(text).toBe('# Prometheus metrics') // Should not include monitoring metrics
    })
  })

  describe('Error Handling', () => {
    it('should handle monitoring service failures gracefully', async () => {
      ;(monitoringService.getSystemHealth as jest.Mock).mockImplementation(() => {
        throw new Error('Monitoring service error')
      })

      const request = new NextRequest('http://localhost:3000/api/health')

      const response = await healthCheckHandler(request)

      expect(response.status).toBe(503)
    })

    it('should handle metrics service failures', async () => {
      ;(metrics.initialize as jest.Mock).mockRejectedValue(
        new Error('Metrics initialization failed')
      )

      const request = new NextRequest('http://localhost:3000/api/metrics')

      const response = await metricsHandler(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to retrieve metrics')
    })
  })
})
