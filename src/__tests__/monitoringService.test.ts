/**
 * MonitoringService Unit Tests
 * Business Scraper Application - Comprehensive Performance Monitoring Tests
 */

import { MonitoringService, PerformanceMetric, HealthCheck, Alert } from '@/model/monitoringService'

// Mock dependencies
jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }
}))

jest.mock('@/lib/securityLogger', () => ({
  securityLogger: {
    logSecurityEvent: jest.fn(),
  }
}))

describe('MonitoringService', () => {
  let monitoringService: MonitoringService

  beforeEach(() => {
    // Create a new instance for each test to avoid state pollution
    monitoringService = new MonitoringService()
    jest.clearAllMocks()
  })

  afterEach(() => {
    // Clean up any intervals
    monitoringService.stopHealthChecks()
  })

  describe('Metric Recording', () => {
    it('should record a performance metric successfully', async () => {
      const metricName = 'test_metric'
      const value = 100
      const unit = 'ms'
      const tags = { endpoint: '/api/test' }

      await monitoringService.recordMetric(metricName, value, unit, tags)

      const metrics = monitoringService.getMetrics(metricName)
      expect(metrics).toHaveLength(1)
      expect(metrics[0]).toMatchObject({
        name: metricName,
        value,
        unit,
        tags
      })
      expect(metrics[0].id).toBeDefined()
      expect(metrics[0].timestamp).toBeInstanceOf(Date)
    })

    it('should record API response time metrics', async () => {
      const endpoint = '/api/test'
      const duration = 250
      const statusCode = 200

      await monitoringService.recordApiResponseTime(endpoint, duration, statusCode)

      const metrics = monitoringService.getMetrics('api_response_time')
      expect(metrics).toHaveLength(1)
      expect(metrics[0]).toMatchObject({
        name: 'api_response_time',
        value: duration,
        unit: 'ms',
        tags: {
          endpoint,
          status_code: statusCode.toString()
        }
      })
    })

    it('should record database query time metrics', async () => {
      const query = 'SELECT * FROM users'
      const duration = 150

      await monitoringService.recordDatabaseQueryTime(query, duration)

      const metrics = monitoringService.getMetrics('database_query_time')
      expect(metrics).toHaveLength(1)
      expect(metrics[0]).toMatchObject({
        name: 'database_query_time',
        value: duration,
        unit: 'ms',
        tags: {
          query_type: 'select'
        }
      })
    })

    it('should record payment processing time metrics', async () => {
      const duration = 2000
      const success = true

      await monitoringService.recordPaymentProcessingTime(duration, success)

      const metrics = monitoringService.getMetrics('payment_processing_time')
      expect(metrics).toHaveLength(1)
      expect(metrics[0]).toMatchObject({
        name: 'payment_processing_time',
        value: duration,
        unit: 'ms',
        tags: {
          success: 'true'
        }
      })
    })

    it('should record payment failure metrics', async () => {
      const duration = 1500
      const success = false

      await monitoringService.recordPaymentProcessingTime(duration, success)

      const paymentMetrics = monitoringService.getMetrics('payment_processing_time')
      const failureMetrics = monitoringService.getMetrics('payment_failures')

      expect(paymentMetrics).toHaveLength(1)
      expect(failureMetrics).toHaveLength(1)
      expect(failureMetrics[0]).toMatchObject({
        name: 'payment_failures',
        value: 1,
        unit: 'count'
      })
    })

    it('should limit metrics storage to 1000 per type', async () => {
      const metricName = 'test_metric'

      // Record 1100 metrics
      for (let i = 0; i < 1100; i++) {
        await monitoringService.recordMetric(metricName, i, 'count')
      }

      const metrics = monitoringService.getMetrics(metricName)
      expect(metrics).toHaveLength(1000)
      // Should keep the most recent 1000
      expect(metrics[0].value).toBe(100) // First kept metric
      expect(metrics[999].value).toBe(1099) // Last metric
    })
  })

  describe('Health Checks', () => {
    it('should perform health check for a service', async () => {
      const serviceName = 'database'

      const healthCheck = await monitoringService.performHealthCheck(serviceName)

      expect(healthCheck).toMatchObject({
        service: serviceName,
        status: 'healthy',
        lastCheck: expect.any(Date),
        responseTime: expect.any(Number)
      })
    })

    it('should get system health overview', () => {
      const systemHealth = monitoringService.getSystemHealth()

      expect(systemHealth).toMatchObject({
        overall: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
        services: expect.any(Array),
        activeAlerts: expect.any(Number),
        lastUpdated: expect.any(Date)
      })
    })

    it('should mark system as unhealthy when services are unhealthy', async () => {
      // Mock a service health check to fail
      const originalCheckServiceHealth = (monitoringService as any).checkServiceHealth
      ;(monitoringService as any).checkServiceHealth = jest.fn().mockRejectedValue(new Error('Service down'))

      await monitoringService.performHealthCheck('database')
      const systemHealth = monitoringService.getSystemHealth()

      expect(systemHealth.overall).toBe('unhealthy')

      // Restore original method
      ;(monitoringService as any).checkServiceHealth = originalCheckServiceHealth
    })
  })

  describe('Alert Management', () => {
    it('should create an alert', async () => {
      const alertData = {
        type: 'performance' as const,
        severity: 'high' as const,
        title: 'High Response Time',
        description: 'API response time exceeded threshold',
        metric: 'api_response_time',
        value: 5000,
        threshold: 3000
      }

      const alert = await monitoringService.createAlert(alertData)

      expect(alert).toMatchObject({
        ...alertData,
        id: expect.any(String),
        timestamp: expect.any(Date),
        resolved: false
      })

      const activeAlerts = monitoringService.getActiveAlerts()
      expect(activeAlerts).toHaveLength(1)
      expect(activeAlerts[0].id).toBe(alert.id)
    })

    it('should resolve an alert', async () => {
      const alert = await monitoringService.createAlert({
        type: 'performance',
        severity: 'medium',
        title: 'Test Alert',
        description: 'Test alert description'
      })

      await monitoringService.resolveAlert(alert.id, 'test-user')

      const allAlerts = monitoringService.getAllAlerts()
      const resolvedAlert = allAlerts.find(a => a.id === alert.id)

      expect(resolvedAlert?.resolved).toBe(true)
      expect(resolvedAlert?.resolvedAt).toBeInstanceOf(Date)

      const activeAlerts = monitoringService.getActiveAlerts()
      expect(activeAlerts).toHaveLength(0)
    })

    it('should create critical alert for unhealthy service', async () => {
      // Mock a service health check to fail
      const originalCheckServiceHealth = (monitoringService as any).checkServiceHealth
      ;(monitoringService as any).checkServiceHealth = jest.fn().mockRejectedValue(new Error('Service down'))

      await monitoringService.performHealthCheck('database')

      const activeAlerts = monitoringService.getActiveAlerts()
      expect(activeAlerts.length).toBeGreaterThan(0)
      
      const serviceAlert = activeAlerts.find(alert => 
        alert.title.includes('database') && alert.severity === 'critical'
      )
      expect(serviceAlert).toBeDefined()

      // Restore original method
      ;(monitoringService as any).checkServiceHealth = originalCheckServiceHealth
    })
  })

  describe('Threshold Monitoring', () => {
    it('should create warning alert when warning threshold is exceeded', async () => {
      // Record a metric that exceeds warning threshold
      await monitoringService.recordMetric('api_response_time', 1500, 'ms') // Warning threshold is 1000ms

      const activeAlerts = monitoringService.getActiveAlerts()
      const warningAlert = activeAlerts.find(alert => 
        alert.severity === 'medium' && alert.title.includes('Warning threshold exceeded')
      )
      expect(warningAlert).toBeDefined()
    })

    it('should create critical alert when critical threshold is exceeded', async () => {
      // Record a metric that exceeds critical threshold
      await monitoringService.recordMetric('api_response_time', 4000, 'ms') // Critical threshold is 3000ms

      const activeAlerts = monitoringService.getActiveAlerts()
      const criticalAlert = activeAlerts.find(alert => 
        alert.severity === 'critical' && alert.title.includes('Critical threshold exceeded')
      )
      expect(criticalAlert).toBeDefined()
    })
  })

  describe('Metrics Filtering', () => {
    beforeEach(async () => {
      // Set up test data
      const now = new Date()
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000)

      // Mock timestamps for testing
      const originalRecordMetric = monitoringService.recordMetric.bind(monitoringService)
      let callCount = 0
      
      monitoringService.recordMetric = jest.fn().mockImplementation(async (name, value, unit, tags) => {
        const result = await originalRecordMetric(name, value, unit, tags)
        
        // Manually set timestamps for testing
        const metrics = monitoringService.getMetrics(name)
        if (metrics.length > 0) {
          const metric = metrics[metrics.length - 1]
          if (callCount === 0) metric.timestamp = twoHoursAgo
          else if (callCount === 1) metric.timestamp = oneHourAgo
          else metric.timestamp = now
        }
        callCount++
        
        return result
      })

      await monitoringService.recordMetric('test_metric', 100, 'ms')
      await monitoringService.recordMetric('test_metric', 200, 'ms')
      await monitoringService.recordMetric('test_metric', 300, 'ms')
    })

    it('should filter metrics by time range', () => {
      const now = new Date()
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)

      const recentMetrics = monitoringService.getMetrics('test_metric', {
        start: oneHourAgo,
        end: now
      })

      expect(recentMetrics.length).toBeLessThanOrEqual(2) // Should exclude metrics older than 1 hour
    })

    it('should return all metrics when no filter is applied', () => {
      const allMetrics = monitoringService.getMetrics()
      expect(allMetrics.length).toBeGreaterThanOrEqual(3)
    })
  })
})
