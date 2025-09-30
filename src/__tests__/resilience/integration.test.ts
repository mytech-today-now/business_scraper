/**
 * Resilience System Integration Tests
 * Tests the complete multi-tiered resilience system
 */

import { connectionManager } from '@/lib/resilience/connectionManager'
import { healthMonitor } from '@/lib/resilience/healthMonitor'
import { autoRecoveryService } from '@/lib/resilience/autoRecovery'
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

describe('Resilience System Integration', () => {
  beforeEach(() => {
    // Reset all services
    healthMonitor.stop()
    autoRecoveryService.setEnabled(true)
  })

  afterEach(async () => {
    healthMonitor.stop()
    await connectionManager.shutdown()
  })

  describe('End-to-End Resilience Flow', () => {
    it('should detect service failure and trigger auto-recovery', async () => {
      let serviceHealthy = true
      let recoveryExecuted = false

      // Mock service that can fail and recover
      const mockService = {
        isHealthy: () => serviceHealthy,
        recover: async () => {
          recoveryExecuted = true
          serviceHealthy = true
          return true
        },
      }

      // Register health check
      healthMonitor.registerService('test-service', async () => {
        return mockService.isHealthy()
      })

      // Register recovery plan
      autoRecoveryService.registerRecoveryPlan('test-service', {
        serviceName: 'test-service',
        maxExecutionTime: 30000,
        cooldownPeriod: 1000,
        actions: [
          {
            name: 'recoverService',
            description: 'Recover the test service',
            execute: mockService.recover,
            timeout: 5000,
            retries: 1,
          },
        ],
      })

      // Start monitoring
      healthMonitor.start()

      // Wait for initial health check
      await new Promise(resolve => setTimeout(resolve, 100))

      // Simulate service failure
      serviceHealthy = false

      // Wait for health monitor to detect failure and trigger recovery
      await new Promise(resolve => setTimeout(resolve, 500))

      // Verify recovery was executed
      expect(recoveryExecuted).toBe(true)
      expect(serviceHealthy).toBe(true)

      // Verify service is healthy again
      const service = healthMonitor.getServiceHealth('test-service')
      expect(service?.status).toBe('healthy')
    }, 10000)

    it('should handle circuit breaker integration with health monitoring', async () => {
      let connectionAttempts = 0
      const maxFailures = 3

      // Mock connection factory that fails initially
      const mockConnectionFactory = jest.fn().mockImplementation(async () => {
        connectionAttempts++
        if (connectionAttempts <= maxFailures) {
          throw new Error(`Connection attempt ${connectionAttempts} failed`)
        }
        return { id: 'test-connection', healthy: true }
      })

      // Register health check that depends on connection
      healthMonitor.registerService('connection-dependent-service', async () => {
        try {
          await connectionManager.getConnection(
            'test-connection',
            mockConnectionFactory,
            async (conn) => conn.healthy
          )
          return true
        } catch (error) {
          return false
        }
      })

      healthMonitor.start()

      // Wait for health checks to run and circuit breaker to open
      await new Promise(resolve => setTimeout(resolve, 300))

      const service = healthMonitor.getServiceHealth('connection-dependent-service')
      expect(service?.status).toBe('unhealthy')

      const connectionStatus = connectionManager.getStatus()
      const hasOpenCircuitBreaker = Object.values(connectionStatus.circuitBreakers).some(
        (breaker: any) => breaker.state === 'OPEN'
      )
      expect(hasOpenCircuitBreaker).toBe(true)
    })

    it('should provide comprehensive system status', async () => {
      // Register multiple services with different health states
      healthMonitor.registerService('healthy-service', async () => true)
      healthMonitor.registerService('degraded-service', async () => {
        throw new Error('Intermittent failure')
      })

      // Create some connections
      const mockFactory = jest.fn().mockResolvedValue({ id: 'test', healthy: true })
      await connectionManager.getConnection('test-connection', mockFactory)

      healthMonitor.start()

      // Wait for health checks
      await new Promise(resolve => setTimeout(resolve, 200))

      const healthStatus = healthMonitor.getHealthStatus()
      const connectionStatus = connectionManager.getStatus()
      const recoveryStatus = autoRecoveryService.getRecoveryStatus()

      // Verify comprehensive status
      expect(healthStatus.systemStatus).toBeDefined()
      expect(healthStatus.services.length).toBe(2)
      expect(connectionStatus.totalConnections).toBe(1)
      expect(recoveryStatus.isEnabled).toBe(true)

      // Verify service states
      const healthyService = healthStatus.services.find(s => s.serviceName === 'healthy-service')
      const degradedService = healthStatus.services.find(s => s.serviceName === 'degraded-service')

      expect(healthyService?.status).toBe('healthy')
      expect(degradedService?.status).toBe('degraded')
    })
  })

  describe('Failure Scenarios', () => {
    it('should handle cascading failures gracefully', async () => {
      let primaryServiceHealthy = true
      let dependentServiceHealthy = true

      // Primary service
      healthMonitor.registerService('primary-service', async () => primaryServiceHealthy)

      // Dependent service that fails when primary fails
      healthMonitor.registerService('dependent-service', async () => {
        if (!primaryServiceHealthy) {
          dependentServiceHealthy = false
        }
        return dependentServiceHealthy
      })

      // Recovery plan for primary service
      autoRecoveryService.registerRecoveryPlan('primary-service', {
        serviceName: 'primary-service',
        maxExecutionTime: 10000,
        cooldownPeriod: 500,
        actions: [
          {
            name: 'restartPrimary',
            description: 'Restart primary service',
            execute: async () => {
              primaryServiceHealthy = true
              return true
            },
            timeout: 2000,
            retries: 1,
          },
        ],
      })

      // Recovery plan for dependent service
      autoRecoveryService.registerRecoveryPlan('dependent-service', {
        serviceName: 'dependent-service',
        maxExecutionTime: 10000,
        cooldownPeriod: 500,
        actions: [
          {
            name: 'restartDependent',
            description: 'Restart dependent service',
            execute: async () => {
              if (primaryServiceHealthy) {
                dependentServiceHealthy = true
                return true
              }
              return false
            },
            timeout: 2000,
            retries: 1,
          },
        ],
      })

      healthMonitor.start()

      // Wait for initial health checks
      await new Promise(resolve => setTimeout(resolve, 100))

      // Simulate primary service failure
      primaryServiceHealthy = false

      // Wait for failure detection and recovery
      await new Promise(resolve => setTimeout(resolve, 800))

      // Both services should be recovered
      expect(primaryServiceHealthy).toBe(true)
      expect(dependentServiceHealthy).toBe(true)

      const primaryService = healthMonitor.getServiceHealth('primary-service')
      const dependentService = healthMonitor.getServiceHealth('dependent-service')

      expect(primaryService?.status).toBe('healthy')
      expect(dependentService?.status).toBe('healthy')
    })

    it('should handle recovery failures and cooldown periods', async () => {
      let serviceHealthy = false
      let recoveryAttempts = 0

      // Service that always fails recovery
      healthMonitor.registerService('failing-service', async () => serviceHealthy)

      autoRecoveryService.registerRecoveryPlan('failing-service', {
        serviceName: 'failing-service',
        maxExecutionTime: 5000,
        cooldownPeriod: 200,
        actions: [
          {
            name: 'failingRecovery',
            description: 'Recovery that always fails',
            execute: async () => {
              recoveryAttempts++
              return false // Always fail
            },
            timeout: 1000,
            retries: 1,
          },
        ],
      })

      healthMonitor.start()

      // Wait for failure detection and recovery attempt
      await new Promise(resolve => setTimeout(resolve, 300))

      expect(recoveryAttempts).toBeGreaterThan(0)

      const recoveryStatus = autoRecoveryService.getRecoveryStatus()
      expect(recoveryStatus.servicesInCooldown).toContain('failing-service')

      // Verify service is still unhealthy
      const service = healthMonitor.getServiceHealth('failing-service')
      expect(service?.status).toBe('unhealthy')
    })
  })

  describe('Performance Under Load', () => {
    it('should handle multiple concurrent health checks efficiently', async () => {
      const serviceCount = 20
      const services: Array<{ name: string; healthy: boolean }> = []

      // Register many services
      for (let i = 0; i < serviceCount; i++) {
        const serviceName = `service-${i}`
        const serviceData = { name: serviceName, healthy: true }
        services.push(serviceData)

        healthMonitor.registerService(serviceName, async () => serviceData.healthy)
      }

      const startTime = Date.now()
      healthMonitor.start()

      // Wait for all health checks to complete
      await new Promise(resolve => setTimeout(resolve, 300))

      const endTime = Date.now()
      const duration = endTime - startTime

      // Should complete within reasonable time (less than 1 second for 20 services)
      expect(duration).toBeLessThan(1000)

      const healthStatus = healthMonitor.getHealthStatus()
      expect(healthStatus.services.length).toBe(serviceCount)
      expect(healthStatus.services.every(s => s.status === 'healthy')).toBe(true)
    })

    it('should handle high connection volume', async () => {
      const connectionCount = 10
      const connections: Promise<any>[] = []

      const mockFactory = jest.fn().mockImplementation(async () => ({
        id: Math.random().toString(36),
        healthy: true,
      }))

      // Create multiple connections concurrently
      for (let i = 0; i < connectionCount; i++) {
        connections.push(
          connectionManager.getConnection(`connection-${i}`, mockFactory)
        )
      }

      const results = await Promise.allSettled(connections)
      const successful = results.filter(r => r.status === 'fulfilled').length

      expect(successful).toBe(connectionCount)

      const status = connectionManager.getStatus()
      expect(status.totalConnections).toBe(connectionCount)
    })
  })
})
