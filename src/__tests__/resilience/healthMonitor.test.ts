/**
 * Health Monitor Tests
 * Tests for enhanced health monitoring and alerting functionality
 */

import { HealthMonitor } from '@/lib/resilience/healthMonitor'
import { logger } from '@/utils/logger'

// Mock logger to avoid console output during tests
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('HealthMonitor', () => {
  let healthMonitor: HealthMonitor
  let mockHealthCheck: jest.Mock

  beforeEach(() => {
    healthMonitor = new HealthMonitor({
      interval: 50, // Very fast interval for testing
      timeout: 25,
      retries: 2,
      alertThreshold: 2,
      recoveryThreshold: 2,
    })

    mockHealthCheck = jest.fn()
  })

  afterEach(() => {
    healthMonitor.stop()
    jest.clearAllMocks()
  })

  describe('Service Registration', () => {
    it('should register a service for monitoring', () => {
      healthMonitor.registerService('test-service', mockHealthCheck)

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service).toBeTruthy()
      expect(service?.serviceName).toBe('test-service')
      expect(service?.status).toBe('unknown')
    })

    it('should register service with metadata', () => {
      const metadata = { version: '1.0.0', type: 'database' }
      healthMonitor.registerService('test-service', mockHealthCheck, metadata)

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.metadata).toEqual(metadata)
    })
  })

  describe('Health Monitoring', () => {
    it('should start and stop monitoring', () => {
      const startSpy = jest.fn()
      const stopSpy = jest.fn()

      healthMonitor.on('monitoringStarted', startSpy)
      healthMonitor.on('monitoringStopped', stopSpy)

      healthMonitor.start()
      expect(startSpy).toHaveBeenCalled()

      healthMonitor.stop()
      expect(stopSpy).toHaveBeenCalled()
    })

    it('should perform health checks on registered services', async () => {
      mockHealthCheck.mockResolvedValue(true)
      healthMonitor.registerService('test-service', mockHealthCheck)

      healthMonitor.start()

      // Wait for health check to run
      await new Promise(resolve => setTimeout(resolve, 200))

      expect(mockHealthCheck).toHaveBeenCalled()

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('healthy')
    })

    it('should handle health check failures', async () => {
      mockHealthCheck.mockRejectedValue(new Error('Health check failed'))
      healthMonitor.registerService('test-service', mockHealthCheck)

      healthMonitor.start()

      // Wait for health check to run
      await new Promise(resolve => setTimeout(resolve, 200))

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('degraded')
      expect(service?.consecutiveFailures).toBe(1)
    })

    it('should retry health checks on failure', async () => {
      mockHealthCheck
        .mockRejectedValueOnce(new Error('First failure'))
        .mockRejectedValueOnce(new Error('Second failure'))
        .mockResolvedValue(true)

      healthMonitor.registerService('test-service', mockHealthCheck)
      healthMonitor.start()

      // Wait for health check to run with retries
      await new Promise(resolve => setTimeout(resolve, 200))

      expect(mockHealthCheck).toHaveBeenCalledTimes(3)

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('healthy')
    })

    it('should timeout health checks', async () => {
      mockHealthCheck.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))

      healthMonitor.registerService('test-service', mockHealthCheck)
      healthMonitor.start()

      // Wait for health check to timeout
      await new Promise(resolve => setTimeout(resolve, 200))

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('degraded')
    })
  })

  describe('Alert Management', () => {
    it('should create alerts for unhealthy services', async () => {
      const alertSpy = jest.fn()
      healthMonitor.on('alertCreated', alertSpy)

      mockHealthCheck.mockRejectedValue(new Error('Service failed'))
      healthMonitor.registerService('test-service', mockHealthCheck)

      healthMonitor.start()

      // Wait for multiple health check failures to trigger alert
      await new Promise(resolve => setTimeout(resolve, 250))

      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('unhealthy')
      expect(alertSpy).toHaveBeenCalled()

      const alerts = healthMonitor.getActiveAlerts()
      expect(alerts.length).toBeGreaterThan(0)
      expect(alerts[0].serviceName).toBe('test-service')
      expect(alerts[0].severity).toBe('critical')
    })

    it('should resolve alerts when service recovers', async () => {
      const alertCreatedSpy = jest.fn()
      const alertResolvedSpy = jest.fn()
      const serviceRecoveredSpy = jest.fn()

      healthMonitor.on('alertCreated', alertCreatedSpy)
      healthMonitor.on('alertResolved', alertResolvedSpy)
      healthMonitor.on('serviceRecovered', serviceRecoveredSpy)

      // Start with failing health check
      mockHealthCheck.mockRejectedValue(new Error('Service failed'))
      healthMonitor.registerService('test-service', mockHealthCheck)
      healthMonitor.start()

      // Wait for alert to be created
      await new Promise(resolve => setTimeout(resolve, 250))
      expect(alertCreatedSpy).toHaveBeenCalled()

      // Service recovers
      mockHealthCheck.mockResolvedValue(true)

      // Wait for recovery
      await new Promise(resolve => setTimeout(resolve, 150))

      expect(serviceRecoveredSpy).toHaveBeenCalled()
      expect(alertResolvedSpy).toHaveBeenCalled()

      const activeAlerts = healthMonitor.getActiveAlerts()
      expect(activeAlerts.length).toBe(0)
    })

    it('should create degraded alerts before critical alerts', async () => {
      const alertSpy = jest.fn()
      healthMonitor.on('alertCreated', alertSpy)

      mockHealthCheck.mockRejectedValue(new Error('Service failed'))
      healthMonitor.registerService('test-service', mockHealthCheck)

      healthMonitor.start()

      // Wait for first failure (should create degraded alert)
      await new Promise(resolve => setTimeout(resolve, 150))

      expect(alertSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          alert: expect.objectContaining({
            severity: 'medium',
            serviceName: 'test-service',
          }),
        })
      )

      // Wait for second failure (should create critical alert)
      await new Promise(resolve => setTimeout(resolve, 150))

      expect(alertSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          alert: expect.objectContaining({
            severity: 'critical',
            serviceName: 'test-service',
          }),
        })
      )
    })
  })

  describe('System Health Evaluation', () => {
    it('should evaluate overall system health', async () => {
      const systemHealthSpy = jest.fn()
      healthMonitor.on('systemHealthEvaluated', systemHealthSpy)

      // Register multiple services
      const healthyService = jest.fn().mockResolvedValue(true)
      const degradedService = jest.fn().mockRejectedValue(new Error('Degraded'))
      const unhealthyService = jest.fn().mockRejectedValue(new Error('Failed'))

      healthMonitor.registerService('healthy-service', healthyService)
      healthMonitor.registerService('degraded-service', degradedService)
      healthMonitor.registerService('unhealthy-service', unhealthyService)

      healthMonitor.start()

      // Wait for health checks to complete
      await new Promise(resolve => setTimeout(resolve, 300))

      expect(systemHealthSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'unhealthy',
          totalServices: 3,
          healthyCount: 1,
          degradedCount: 1,
          unhealthyCount: 1,
        })
      )
    })

    it('should report healthy system when all services are healthy', async () => {
      const systemHealthSpy = jest.fn()
      healthMonitor.on('systemHealthEvaluated', systemHealthSpy)

      const healthyService1 = jest.fn().mockResolvedValue(true)
      const healthyService2 = jest.fn().mockResolvedValue(true)

      healthMonitor.registerService('service-1', healthyService1)
      healthMonitor.registerService('service-2', healthyService2)

      healthMonitor.start()

      // Wait for health checks to complete
      await new Promise(resolve => setTimeout(resolve, 200))

      expect(systemHealthSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'healthy',
          totalServices: 2,
          healthyCount: 2,
          degradedCount: 0,
          unhealthyCount: 0,
        })
      )
    })
  })

  describe('Status Reporting', () => {
    it('should provide comprehensive health status', async () => {
      mockHealthCheck.mockResolvedValue(true)
      healthMonitor.registerService('test-service', mockHealthCheck)

      healthMonitor.start()
      await new Promise(resolve => setTimeout(resolve, 150))

      const status = healthMonitor.getHealthStatus()

      expect(status).toHaveProperty('systemStatus')
      expect(status).toHaveProperty('services')
      expect(status).toHaveProperty('activeAlerts')
      expect(status).toHaveProperty('connectionManagerStatus')

      expect(status.services).toHaveLength(1)
      expect(status.services[0].serviceName).toBe('test-service')
      expect(status.services[0].status).toBe('healthy')
    })

    it('should return all alerts including resolved ones', async () => {
      const alertSpy = jest.fn()
      healthMonitor.on('alertCreated', alertSpy)

      // Create and resolve an alert
      mockHealthCheck.mockRejectedValue(new Error('Failed'))
      healthMonitor.registerService('test-service', mockHealthCheck)
      healthMonitor.start()

      await new Promise(resolve => setTimeout(resolve, 250))

      mockHealthCheck.mockResolvedValue(true)
      await new Promise(resolve => setTimeout(resolve, 150))

      const allAlerts = healthMonitor.getAllAlerts()
      const activeAlerts = healthMonitor.getActiveAlerts()

      expect(allAlerts.length).toBeGreaterThan(0)
      expect(activeAlerts.length).toBe(0)
      expect(allAlerts.some(alert => alert.resolved)).toBe(true)
    })
  })
})
