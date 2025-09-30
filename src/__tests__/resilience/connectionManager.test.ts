/**
 * Connection Manager Tests
 * Tests for enhanced connection resilience and circuit breaker functionality
 */

import { ConnectionManager } from '@/lib/resilience/connectionManager'
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

describe('ConnectionManager', () => {
  let connectionManager: ConnectionManager
  let mockFactory: jest.Mock
  let mockHealthCheck: jest.Mock

  beforeEach(() => {
    connectionManager = new ConnectionManager({
      maxConnections: 5,
      connectionTimeout: 1000,
      retryAttempts: 3,
      retryDelay: 100,
      healthCheckInterval: 500,
      circuitBreakerThreshold: 2,
      circuitBreakerTimeout: 1000,
    })

    mockFactory = jest.fn()
    mockHealthCheck = jest.fn()
  })

  afterEach(async () => {
    await connectionManager.shutdown()
    jest.clearAllMocks()
  })

  describe('Connection Creation', () => {
    it('should create a connection successfully', async () => {
      const mockConnection = { id: 'test-connection' }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      const connection = await connectionManager.getConnection(
        'test-connection',
        mockFactory,
        mockHealthCheck
      )

      expect(connection).toBe(mockConnection)
      expect(mockFactory).toHaveBeenCalledTimes(1)
    })

    it('should retry connection creation on failure', async () => {
      const mockConnection = { id: 'test-connection' }
      mockFactory
        .mockRejectedValueOnce(new Error('Connection failed'))
        .mockRejectedValueOnce(new Error('Connection failed'))
        .mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      const connection = await connectionManager.getConnection(
        'test-connection',
        mockFactory,
        mockHealthCheck
      )

      expect(connection).toBe(mockConnection)
      expect(mockFactory).toHaveBeenCalledTimes(3)
    })

    it('should fail after max retry attempts', async () => {
      mockFactory.mockRejectedValue(new Error('Connection failed'))

      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow('Failed to create connection test-connection after 3 attempts')

      expect(mockFactory).toHaveBeenCalledTimes(3)
    })

    it('should timeout connection creation', async () => {
      mockFactory.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 2000)))

      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow('Failed to create connection test-connection after 3 attempts')
    })
  })

  describe('Circuit Breaker', () => {
    it('should open circuit breaker after threshold failures', async () => {
      mockFactory.mockRejectedValue(new Error('Connection failed'))

      // First failure
      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()

      // Second failure should open circuit breaker
      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()

      // Third attempt should be blocked by circuit breaker
      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow('Circuit breaker is open for connection: test-connection')
    })

    it('should transition to half-open after timeout', async () => {
      mockFactory.mockRejectedValue(new Error('Connection failed'))

      // Trigger circuit breaker
      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()
      await expect(
        connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()

      // Wait for circuit breaker timeout
      await new Promise(resolve => setTimeout(resolve, 1100))

      // Should allow one attempt in half-open state
      const mockConnection = { id: 'test-connection' }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      const connection = await connectionManager.getConnection(
        'test-connection',
        mockFactory,
        mockHealthCheck
      )

      expect(connection).toBe(mockConnection)
    })
  })

  describe('Health Monitoring', () => {
    it('should perform periodic health checks', async () => {
      const mockConnection = { id: 'test-connection' }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      await connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)

      // Wait for health check interval
      await new Promise(resolve => setTimeout(resolve, 600))

      expect(mockHealthCheck).toHaveBeenCalledWith(mockConnection)
    })

    it('should remove unhealthy connections', async () => {
      const mockConnection = { id: 'test-connection' }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValueOnce(true).mockResolvedValue(false)

      await connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)

      // Wait for health check to detect unhealthy connection
      await new Promise(resolve => setTimeout(resolve, 600))

      const status = connectionManager.getStatus()
      expect(status.totalConnections).toBe(0)
    })
  })

  describe('Status Reporting', () => {
    it('should report correct status', async () => {
      const mockConnection1 = { id: 'connection-1' }
      const mockConnection2 = { id: 'connection-2' }
      
      mockFactory.mockResolvedValue(mockConnection1)
      mockHealthCheck.mockResolvedValue(true)

      await connectionManager.getConnection('connection-1', mockFactory, mockHealthCheck)

      mockFactory.mockResolvedValue(mockConnection2)
      await connectionManager.getConnection('connection-2', mockFactory, mockHealthCheck)

      const status = connectionManager.getStatus()
      expect(status.totalConnections).toBe(2)
      expect(status.healthyConnections).toBe(2)
    })
  })

  describe('Graceful Shutdown', () => {
    it('should close all connections on shutdown', async () => {
      const mockConnection = { 
        id: 'test-connection',
        close: jest.fn().mockResolvedValue(undefined)
      }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      await connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)

      await connectionManager.shutdown()

      expect(mockConnection.close).toHaveBeenCalled()
      
      const status = connectionManager.getStatus()
      expect(status.totalConnections).toBe(0)
    })

    it('should handle shutdown errors gracefully', async () => {
      const mockConnection = { 
        id: 'test-connection',
        close: jest.fn().mockRejectedValue(new Error('Close failed'))
      }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      await connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)

      // Should not throw
      await expect(connectionManager.shutdown()).resolves.not.toThrow()
    })
  })

  describe('Event Emission', () => {
    it('should emit connection events', async () => {
      const connectionCreatedSpy = jest.fn()
      const circuitBreakerOpenedSpy = jest.fn()

      connectionManager.on('connectionCreated', connectionCreatedSpy)
      connectionManager.on('circuitBreakerOpened', circuitBreakerOpenedSpy)

      const mockConnection = { id: 'test-connection' }
      mockFactory.mockResolvedValue(mockConnection)
      mockHealthCheck.mockResolvedValue(true)

      await connectionManager.getConnection('test-connection', mockFactory, mockHealthCheck)

      expect(connectionCreatedSpy).toHaveBeenCalledWith({
        connectionId: 'test-connection',
        attempt: 1,
      })

      // Trigger circuit breaker
      mockFactory.mockRejectedValue(new Error('Connection failed'))
      await expect(
        connectionManager.getConnection('failing-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()
      await expect(
        connectionManager.getConnection('failing-connection', mockFactory, mockHealthCheck)
      ).rejects.toThrow()

      expect(circuitBreakerOpenedSpy).toHaveBeenCalled()
    })
  })
})
