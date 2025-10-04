/**
 * Comprehensive Health API Route Tests
 * Tests all health endpoints with various scenarios including success, error, and edge cases
 * Enhanced with 95% coverage target and comprehensive monitoring testing
 * Target: 95% coverage for /api/health/* routes with resilience focus
 */

import { jest } from '@jest/globals'

// Mock all dependencies before any imports
jest.mock('@/lib/emailValidationService', () => {
  const mockInstance = {
    validateEmail: jest.fn(),
    isValidEmail: jest.fn(),
  }
  return {
    EmailValidationService: jest.fn().mockImplementation(() => mockInstance),
  }
})

jest.mock('@/lib/contactExtractor', () => ({
  contactExtractor: {
    extractContacts: jest.fn(),
  },
}))

jest.mock('@/lib/enhancedScrapingEngine', () => ({
  enhancedScrapingEngine: {
    scrape: jest.fn(),
  },
}))

jest.mock('@/model/scraperService', () => ({
  scraperService: {
    initialize: jest.fn(),
  },
}))

jest.mock('@/lib/streamingSearchService', () => ({
  streamingSearchService: {
    healthCheck: jest.fn(),
    getActiveStreamCount: jest.fn(),
  },
}))

import { NextRequest, NextResponse } from 'next/server'
import { GET as healthGET } from '@/app/api/health/route'
import { GET as detailedHealthGET, POST as detailedHealthPOST } from '@/app/api/health/detailed/route'
import { GET as streamHealthGET, OPTIONS as streamHealthOPTIONS } from '@/app/api/stream-health/route'
import { GET as pingGET, HEAD as pingHEAD, OPTIONS as pingOPTIONS } from '@/app/api/ping/route'

// Mock dependencies
jest.mock('@/lib/database', () => ({
  checkDatabaseConnection: jest.fn(),
}))

jest.mock('@/lib/config-validator', () => ({
  performConfigHealthCheck: jest.fn(),
}))

jest.mock('@/lib/config', () => ({
  getConfig: jest.fn(),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/model/monitoringService', () => ({
  monitoringService: {
    getSystemHealth: jest.fn(),
    recordMetric: jest.fn(),
    getActiveAlerts: jest.fn(),
    getMetrics: jest.fn(),
  },
}))

jest.mock('@/lib/resilience/healthMonitor', () => ({
  healthMonitor: {
    getHealthStatus: jest.fn(),
  },
}))

jest.mock('@/lib/resilience/connectionManager', () => ({
  connectionManager: {
    getStatus: jest.fn(),
  },
}))

jest.mock('@/lib/resilience/autoRecovery', () => ({
  autoRecoveryService: {
    getRecoveryStatus: jest.fn(),
  },
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(),
}))

jest.mock('@/utils/apiErrorHandling', () => ({
  withStandardErrorHandling: jest.fn((handler) => handler),
  createSuccessResponse: jest.fn(),
  handleAsyncApiOperation: jest.fn(),
}))

// Import mocked modules for type safety
import { checkDatabaseConnection } from '@/lib/database'
import { performConfigHealthCheck } from '@/lib/config-validator'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'
import { monitoringService } from '@/model/monitoringService'
import { streamingSearchService } from '@/lib/streamingSearchService'
import { healthMonitor } from '@/lib/resilience/healthMonitor'
import { connectionManager } from '@/lib/resilience/connectionManager'
import { autoRecoveryService } from '@/lib/resilience/autoRecovery'
import { getClientIP } from '@/lib/security'
import { handleAsyncApiOperation } from '@/utils/apiErrorHandling'

// Type the mocked functions
const mockCheckDatabaseConnection = checkDatabaseConnection as jest.MockedFunction<typeof checkDatabaseConnection>
const mockPerformConfigHealthCheck = performConfigHealthCheck as jest.MockedFunction<typeof performConfigHealthCheck>
const mockGetConfig = getConfig as jest.MockedFunction<typeof getConfig>
const mockMonitoringService = monitoringService as jest.Mocked<typeof monitoringService>
const mockStreamingSearchService = streamingSearchService as jest.Mocked<typeof streamingSearchService>
const mockHealthMonitor = healthMonitor as jest.Mocked<typeof healthMonitor>
const mockConnectionManager = connectionManager as jest.Mocked<typeof connectionManager>
const mockAutoRecoveryService = autoRecoveryService as jest.Mocked<typeof autoRecoveryService>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
const mockHandleAsyncApiOperation = handleAsyncApiOperation as jest.MockedFunction<typeof handleAsyncApiOperation>

describe('Health API Routes - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mocks
    mockGetClientIP.mockReturnValue('127.0.0.1')
    mockGetConfig.mockReturnValue({
      app: {
        environment: 'test',
        version: '1.0.0',
      },
    })
    
    // Mock handleAsyncApiOperation to call the operation directly
    mockHandleAsyncApiOperation.mockImplementation(async (operation) => {
      try {
        const result = await operation()
        return { success: true, data: result }
      } catch (error) {
        return { success: false, error: new NextResponse('Error', { status: 500 }) }
      }
    })
  })

  describe('GET /api/health', () => {
    test('should return healthy status when all services are operational', async () => {
      // Setup mocks for healthy state
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockHealthMonitor.getHealthStatus.mockReturnValue({
        services: [{ status: 'healthy' }],
        activeAlerts: [],
      })
      mockConnectionManager.getStatus.mockReturnValue({
        totalConnections: 10,
        healthyConnections: 10,
      })
      mockAutoRecoveryService.getRecoveryStatus.mockReturnValue({
        isEnabled: true,
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'healthy')
      expect(data).toHaveProperty('timestamp')
      expect(data).toHaveProperty('uptime')
      expect(data).toHaveProperty('environment', 'test')
      expect(data).toHaveProperty('version', '1.0.0')
      expect(data).toHaveProperty('checks')
      expect(data.checks).toHaveProperty('database', 'healthy')
      expect(data.checks).toHaveProperty('configuration', 'healthy')
      expect(data.checks).toHaveProperty('streamingService', 'healthy')
      expect(data).toHaveProperty('resilience')
      expect(data.resilience).toHaveProperty('score')
      expect(data.resilience.score).toBeGreaterThanOrEqual(0)
      expect(data.resilience.score).toBeLessThanOrEqual(100)
    })

    test('should return degraded status when some services have warnings', async () => {
      // Setup mocks for degraded state
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'warning' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'degraded',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockHealthMonitor.getHealthStatus.mockReturnValue({
        services: [{ status: 'healthy' }],
        activeAlerts: [],
      })
      mockConnectionManager.getStatus.mockReturnValue({
        totalConnections: 10,
        healthyConnections: 8,
      })
      mockAutoRecoveryService.getRecoveryStatus.mockReturnValue({
        isEnabled: true,
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'degraded')
      expect(data.checks).toHaveProperty('configuration', 'warning')
    })

    test('should return unhealthy status when critical services fail', async () => {
      // Setup mocks for unhealthy state
      mockCheckDatabaseConnection.mockRejectedValue(new Error('Database connection failed'))
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: false })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'unhealthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockHealthMonitor.getHealthStatus.mockReturnValue({
        services: [{ status: 'unhealthy' }],
        activeAlerts: [{ id: '1', message: 'Service down' }],
      })
      mockConnectionManager.getStatus.mockReturnValue({
        totalConnections: 10,
        healthyConnections: 2,
      })
      mockAutoRecoveryService.getRecoveryStatus.mockReturnValue({
        isEnabled: false,
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(503)
      expect(data).toHaveProperty('status', 'unhealthy')
      expect(data.checks).toHaveProperty('database', 'unhealthy')
      expect(data.checks).toHaveProperty('streamingService', 'unhealthy')
    })

    test('should handle streaming service errors gracefully', async () => {
      // Setup mocks where streaming service throws error
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockRejectedValue(new Error('Streaming service error'))
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      // Since streaming service error should cause the health check to fail
      mockHandleAsyncApiOperation.mockImplementation(async (operation) => {
        try {
          await operation()
          return { success: true, data: {} }
        } catch (error) {
          return { success: false, error: new NextResponse('Error', { status: 500 }) }
        }
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data).toHaveProperty('status', 'error')
      expect(data).toHaveProperty('error', 'Health check failed')
    })

    test('should include memory usage information', async () => {
      // Setup mocks for healthy state
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockHealthMonitor.getHealthStatus.mockReturnValue({
        services: [{ status: 'healthy' }],
        activeAlerts: [],
      })
      mockConnectionManager.getStatus.mockReturnValue({
        totalConnections: 10,
        healthyConnections: 10,
      })
      mockAutoRecoveryService.getRecoveryStatus.mockReturnValue({
        isEnabled: true,
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('memory')
      expect(data.memory).toHaveProperty('rss')
      expect(data.memory).toHaveProperty('heapTotal')
      expect(data.memory).toHaveProperty('heapUsed')
      expect(data.memory).toHaveProperty('external')
      expect(data.memory).toHaveProperty('arrayBuffers')
    })
  })

  describe('GET /api/health/detailed', () => {
    test('should return detailed health information', async () => {
      // Setup mocks for detailed health check
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [
          { name: 'database', status: 'healthy', lastCheck: new Date().toISOString() },
          { name: 'cache', status: 'healthy', lastCheck: new Date().toISOString() },
        ],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health/detailed', {
        method: 'GET',
      })

      const response = await detailedHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'healthy')
      expect(data).toHaveProperty('timestamp')
      expect(data).toHaveProperty('responseTime')
      expect(data).toHaveProperty('services')
      expect(Array.isArray(data.services)).toBe(true)
      expect(data.services).toHaveLength(2)
    })

    test('should return 503 when system is unhealthy', async () => {
      // Setup mocks for unhealthy state
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'unhealthy',
        services: [
          { name: 'database', status: 'unhealthy', lastCheck: new Date().toISOString() },
        ],
        activeAlerts: [{ id: '1', message: 'Database connection failed' }],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health/detailed', {
        method: 'GET',
      })

      const response = await detailedHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(503)
      expect(data).toHaveProperty('status', 'unhealthy')
    })

    test('should include metrics when requested', async () => {
      // Setup mocks with metrics
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockMonitoringService.getMetrics.mockReturnValue([
        { name: 'response_time', value: 150, unit: 'ms', timestamp: new Date().toISOString() },
        { name: 'memory_usage', value: 75, unit: '%', timestamp: new Date().toISOString() },
      ])

      const request = new NextRequest('http://localhost:3000/api/health/detailed?includeMetrics=true', {
        method: 'GET',
      })

      const response = await detailedHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('metrics')
      expect(Array.isArray(data.metrics)).toBe(true)
      expect(data.metrics).toHaveLength(2)
    })

    test('should include alerts when requested', async () => {
      // Setup mocks with alerts
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'degraded',
        services: [],
        activeAlerts: [
          { id: '1', message: 'High memory usage', severity: 'warning' },
          { id: '2', message: 'Slow response time', severity: 'info' },
        ],
        lastUpdated: new Date().toISOString(),
      })
      mockMonitoringService.getActiveAlerts.mockReturnValue([
        { id: '1', message: 'High memory usage', severity: 'warning' },
        { id: '2', message: 'Slow response time', severity: 'info' },
      ])

      const request = new NextRequest('http://localhost:3000/api/health/detailed?includeAlerts=true', {
        method: 'GET',
      })

      const response = await detailedHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('alerts')
      expect(Array.isArray(data.alerts)).toBe(true)
      expect(data.alerts).toHaveLength(2)
    })
  })

  describe('POST /api/health/detailed', () => {
    test('should accept custom health check parameters', async () => {
      // Setup mocks
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockMonitoringService.getMetrics.mockReturnValue([])
      mockMonitoringService.getActiveAlerts.mockReturnValue([])

      const requestBody = {
        includeMetrics: true,
        includeAlerts: true,
        timeWindow: 12,
        services: ['database', 'cache'],
        metricNames: ['response_time', 'memory_usage'],
      }

      const request = new NextRequest('http://localhost:3000/api/health/detailed', {
        method: 'POST',
        body: JSON.stringify(requestBody),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await detailedHealthPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('requestedParameters')
      expect(data.requestedParameters).toEqual(requestBody)
    })

    test('should handle invalid JSON in request body', async () => {
      const request = new NextRequest('http://localhost:3000/api/health/detailed', {
        method: 'POST',
        body: 'invalid json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      // Mock handleAsyncApiOperation to simulate JSON parse error
      mockHandleAsyncApiOperation.mockImplementation(async (operation) => {
        try {
          await operation()
          return { success: true, data: {} }
        } catch (error) {
          return { success: false, error: new NextResponse('Error', { status: 500 }) }
        }
      })

      const response = await detailedHealthPOST(request)

      expect(response.status).toBe(500)
    })
  })

  describe('GET /api/stream-health', () => {
    test('should return healthy streaming service status', async () => {
      // Setup mocks for healthy streaming service
      mockStreamingSearchService.healthCheck.mockResolvedValue({
        healthy: true,
        details: {
          activeConnections: 5,
          totalRequests: 100,
          errorRate: 0.01,
        },
      })
      mockStreamingSearchService.getActiveStreamCount.mockReturnValue(5)

      const request = new NextRequest('http://localhost:3000/api/stream-health', {
        method: 'GET',
      })

      const response = await streamHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'healthy')
      expect(data).toHaveProperty('diagnostics')
      expect(data.diagnostics).toHaveProperty('activeStreams', 5)
      expect(data.diagnostics).toHaveProperty('serverInfo')
      expect(data.diagnostics.serverInfo).toHaveProperty('nodeVersion')
      expect(data.diagnostics.serverInfo).toHaveProperty('platform')
      expect(data.diagnostics.serverInfo).toHaveProperty('uptime')
      expect(data.diagnostics.serverInfo).toHaveProperty('memoryUsage')
    })

    test('should return unhealthy status when streaming service fails', async () => {
      // Setup mocks for unhealthy streaming service
      mockStreamingSearchService.healthCheck.mockResolvedValue({
        healthy: false,
        details: {
          activeConnections: 0,
          totalRequests: 50,
          errorRate: 0.8,
          lastError: 'Connection timeout',
        },
      })
      mockStreamingSearchService.getActiveStreamCount.mockReturnValue(0)

      const request = new NextRequest('http://localhost:3000/api/stream-health', {
        method: 'GET',
      })

      const response = await streamHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(503)
      expect(data).toHaveProperty('status', 'unhealthy')
      expect(data.diagnostics).toHaveProperty('activeStreams', 0)
    })

    test('should handle streaming service errors', async () => {
      // Setup mocks for streaming service error
      mockStreamingSearchService.healthCheck.mockRejectedValue(new Error('Service unavailable'))

      const request = new NextRequest('http://localhost:3000/api/stream-health', {
        method: 'GET',
      })

      const response = await streamHealthGET(request)
      const data = await response.json()

      expect(response.status).toBe(503)
      expect(data).toHaveProperty('status', 'unhealthy')
      expect(data).toHaveProperty('error', 'Service unavailable')
    })

    test('should include proper CORS headers', async () => {
      const request = new NextRequest('http://localhost:3000/api/stream-health', {
        method: 'GET',
      })

      mockStreamingSearchService.healthCheck.mockResolvedValue({
        healthy: true,
        details: {},
      })

      const response = await streamHealthGET(request)

      expect(response.headers.get('Cache-Control')).toBe('no-cache, no-store, must-revalidate')
      expect(response.headers.get('Content-Type')).toBe('application/json')
    })
  })

  describe('OPTIONS /api/stream-health', () => {
    test('should handle CORS preflight requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/stream-health', {
        method: 'OPTIONS',
      })

      const response = await streamHealthOPTIONS(request)

      expect(response.status).toBe(200)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('GET, OPTIONS')
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Content-Type')
    })
  })

  describe('GET /api/ping', () => {
    test('should return basic ping response', async () => {
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await pingGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('status', 'ok')
      expect(data).toHaveProperty('timestamp')
      expect(data).toHaveProperty('message', 'pong')
      expect(response.headers.get('Cache-Control')).toBe('no-cache, no-store, must-revalidate')
    })

    test('should include server information in ping response', async () => {
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await pingGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('server')
      expect(data.server).toHaveProperty('uptime')
      expect(data.server).toHaveProperty('environment')
      expect(typeof data.server.uptime).toBe('number')
    })

    test('should handle errors gracefully', async () => {
      // Mock getClientIP to throw an error
      mockGetClientIP.mockImplementation(() => {
        throw new Error('IP extraction failed')
      })

      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'GET',
      })

      const response = await pingGET(request)

      expect(response.status).toBe(500)
    })
  })

  describe('HEAD /api/ping', () => {
    test('should return 200 with no body for HEAD request', async () => {
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'HEAD',
      })

      const response = await pingHEAD(request)

      expect(response.status).toBe(200)
      expect(response.headers.get('Cache-Control')).toBe('no-cache, no-store, must-revalidate')

      // HEAD requests should not have a body
      const text = await response.text()
      expect(text).toBe('')
    })

    test('should handle errors in HEAD request', async () => {
      // Mock getClientIP to throw an error
      mockGetClientIP.mockImplementation(() => {
        throw new Error('IP extraction failed')
      })

      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'HEAD',
      })

      const response = await pingHEAD(request)

      expect(response.status).toBe(500)
    })
  })

  describe('OPTIONS /api/ping', () => {
    test('should handle CORS preflight requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/ping', {
        method: 'OPTIONS',
      })

      const response = await pingOPTIONS()

      expect(response.status).toBe(200)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
      expect(response.headers.get('Access-Control-Allow-Methods')).toBe('GET, HEAD, OPTIONS')
      expect(response.headers.get('Access-Control-Allow-Headers')).toBe('Content-Type')
      expect(response.headers.get('Access-Control-Max-Age')).toBe('86400')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle database connection timeout', async () => {
      // Setup mocks for database timeout
      mockCheckDatabaseConnection.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Connection timeout')), 100)
        })
      })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.checks).toHaveProperty('database', 'unhealthy')
    })

    test('should handle high memory usage warning', async () => {
      // Mock process.memoryUsage to return high memory usage
      const originalMemoryUsage = process.memoryUsage
      process.memoryUsage = jest.fn().mockReturnValue({
        rss: 1000000000,
        heapTotal: 1000000000,
        heapUsed: 950000000, // 95% usage
        external: 50000000,
        arrayBuffers: 10000000,
      })

      // Setup other mocks
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.checks).toHaveProperty('memory', 'warning')

      // Restore original function
      process.memoryUsage = originalMemoryUsage
    })

    test('should handle IndexedDB not supported error gracefully', async () => {
      // Setup mocks for IndexedDB error
      mockCheckDatabaseConnection.mockRejectedValue(new Error('IndexedDB not supported'))
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.checks).toHaveProperty('database', 'healthy') // Should be marked as healthy for IndexedDB
    })

    test('should calculate resilience score correctly', async () => {
      // Setup mocks for resilience score calculation
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockHealthMonitor.getHealthStatus.mockReturnValue({
        services: [
          { status: 'healthy' },
          { status: 'healthy' },
          { status: 'degraded' },
        ],
        activeAlerts: [{ id: '1', message: 'Minor alert' }],
      })
      mockConnectionManager.getStatus.mockReturnValue({
        totalConnections: 10,
        healthyConnections: 9,
      })
      mockAutoRecoveryService.getRecoveryStatus.mockReturnValue({
        isEnabled: true,
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const response = await healthGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('resilience')
      expect(data.resilience).toHaveProperty('score')
      expect(data.resilience.score).toBeGreaterThanOrEqual(0)
      expect(data.resilience.score).toBeLessThanOrEqual(100)
      expect(data.resilience).toHaveProperty('status')
      expect(['excellent', 'good', 'degraded', 'poor']).toContain(data.resilience.status)
    })

    test('should record health check metrics', async () => {
      // Setup mocks
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })
      mockMonitoringService.recordMetric.mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      await healthGET(request)

      expect(mockMonitoringService.recordMetric).toHaveBeenCalledWith(
        'health_check_response_time',
        expect.any(Number),
        'ms',
        expect.objectContaining({
          status: expect.any(String),
        })
      )
    })
  })

  describe('Performance and Load Testing', () => {
    test('should respond within acceptable time limits', async () => {
      // Setup mocks for fast response
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const request = new NextRequest('http://localhost:3000/api/health', {
        method: 'GET',
      })

      const startTime = Date.now()
      const response = await healthGET(request)
      const endTime = Date.now()
      const responseTime = endTime - startTime

      expect(response.status).toBe(200)
      expect(responseTime).toBeLessThan(5000) // Should respond within 5 seconds

      const data = await response.json()
      expect(data).toHaveProperty('responseTime')
      expect(typeof data.responseTime).toBe('number')
    })

    test('should handle concurrent health check requests', async () => {
      // Setup mocks
      mockCheckDatabaseConnection.mockResolvedValue({ connected: true })
      mockPerformConfigHealthCheck.mockResolvedValue({ status: 'healthy' })
      mockStreamingSearchService.healthCheck.mockResolvedValue({ healthy: true })
      mockMonitoringService.getSystemHealth.mockReturnValue({
        overall: 'healthy',
        services: [],
        activeAlerts: [],
        lastUpdated: new Date().toISOString(),
      })

      const requests = Array.from({ length: 5 }, () =>
        new NextRequest('http://localhost:3000/api/health', { method: 'GET' })
      )

      const responses = await Promise.all(
        requests.map(request => healthGET(request))
      )

      responses.forEach(response => {
        expect(response.status).toBe(200)
      })

      const dataPromises = responses.map(response => response.json())
      const dataResults = await Promise.all(dataPromises)

      dataResults.forEach(data => {
        expect(data).toHaveProperty('status', 'healthy')
        expect(data).toHaveProperty('timestamp')
      })
    })
  })
})
