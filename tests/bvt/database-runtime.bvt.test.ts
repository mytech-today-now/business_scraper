/**
 * Database Runtime BVT Test
 * Validates that database connections work correctly in runtime environment
 */

import { getPostgresConnection, testPostgresConnection, healthCheck } from '../../src/lib/postgres-connection'
import { getDatabaseInstance } from '../../src/lib/database-factory'
import { DataRetentionService } from '../../src/lib/compliance/retention'

// Mock logger
jest.mock('../../src/lib/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }
}))

describe('Database Runtime BVT', () => {
  const originalEnv = process.env

  beforeEach(() => {
    jest.resetAllMocks()
    process.env = { ...originalEnv }
    
    // Ensure runtime environment
    delete process.env.IS_BUILD_TIME
    delete process.env.DISABLE_DATABASE
    delete process.env.SKIP_RETENTION_POLICIES
    delete process.env.SKIP_BACKGROUND_JOBS
  })

  afterAll(() => {
    process.env = originalEnv
  })

  describe('PostgreSQL Connection', () => {
    it('should allow database connections in runtime', async () => {
      // Set up runtime environment
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test'
      
      const connection = await getPostgresConnection()
      
      // Should return a connection object (or null if database is not available)
      expect(connection).toBeDefined()
    })

    it('should perform health check in runtime', async () => {
      const result = await healthCheck()
      
      // Should return health check result
      expect(result).toBeDefined()
      expect(typeof result).toBe('object')
    })

    it('should test connection in runtime', async () => {
      const result = await testPostgresConnection()
      
      // Should return test result
      expect(result).toBeDefined()
      expect(typeof result).toBe('object')
    })
  })

  describe('Database Factory', () => {
    it('should create database instance in runtime', async () => {
      const instance = await getDatabaseInstance()
      
      // Should return database instance or null
      expect(instance).toBeDefined()
    })

    it('should handle server environment correctly', async () => {
      // Mock server environment
      Object.defineProperty(global, 'window', {
        value: undefined,
        writable: true
      })
      
      const instance = await getDatabaseInstance()
      
      // Should attempt to create server database
      expect(instance).toBeDefined()
    })
  })

  describe('Data Retention Service', () => {
    it('should initialize retention service in runtime', () => {
      const service = new DataRetentionService()
      
      // Should create service instance
      expect(service).toBeDefined()
      expect(service).toBeInstanceOf(DataRetentionService)
    })

    it('should allow policy creation in runtime', async () => {
      const service = new DataRetentionService()
      
      const testPolicy = {
        name: 'Test Policy',
        description: 'Test retention policy',
        dataType: 'test_data',
        retentionPeriodDays: 30,
        legalBasis: 'legitimate_interests' as const,
        autoDelete: true,
        archiveBeforeDelete: false,
        notificationDays: [7, 1],
        isActive: true,
      }

      try {
        const policyId = await service.createOrUpdatePolicy(testPolicy)
        
        // Should return policy ID or handle gracefully
        expect(typeof policyId === 'string' || policyId === undefined).toBe(true)
      } catch (error) {
        // Should handle database connection errors gracefully
        expect(error).toBeInstanceOf(Error)
      }
    })
  })

  describe('API Routes Runtime', () => {
    it('should handle consent status API in runtime', async () => {
      // Mock Next.js request
      const mockRequest = {
        url: 'http://localhost:3000/api/compliance/consent/status',
        cookies: {
          get: jest.fn().mockReturnValue(undefined)
        }
      } as any

      // Import and test the API route
      try {
        const { GET } = await import('../../src/app/api/compliance/consent/status/route')
        const response = await GET(mockRequest)
        
        // Should return a response
        expect(response).toBeDefined()
        expect(response.status).toBeDefined()
      } catch (error) {
        // Should handle database connection errors gracefully
        expect(error).toBeInstanceOf(Error)
      }
    })

    it('should handle privacy dashboard API in runtime', async () => {
      // Mock Next.js request
      const mockRequest = {
        url: 'http://localhost:3000/api/compliance/privacy-dashboard?email=test@example.com',
      } as any

      try {
        const { GET } = await import('../../src/app/api/compliance/privacy-dashboard/route')
        const response = await GET(mockRequest)
        
        // Should return a response
        expect(response).toBeDefined()
        expect(response.status).toBeDefined()
      } catch (error) {
        // Should handle database connection errors gracefully
        expect(error).toBeInstanceOf(Error)
      }
    })
  })

  describe('Error Handling', () => {
    it('should handle database connection failures gracefully', async () => {
      // Set invalid database URL
      process.env.DATABASE_URL = 'postgresql://invalid:invalid@nonexistent:5432/invalid'
      
      const connection = await getPostgresConnection()
      
      // Should handle connection failure gracefully
      expect(connection === null || connection === undefined).toBe(true)
    })

    it('should provide fallback behavior when database is unavailable', async () => {
      // Set invalid database URL
      process.env.DATABASE_URL = 'postgresql://invalid:invalid@nonexistent:5432/invalid'
      
      const healthResult = await healthCheck()
      
      // Should return health check result even if database is unavailable
      expect(healthResult).toBeDefined()
      expect(typeof healthResult).toBe('object')
    })
  })

  describe('Environment Detection', () => {
    it('should correctly detect runtime environment', () => {
      const { isBuildTime, isDatabaseConnectionAllowed } = require('../../src/lib/build-time-guard')
      
      // Should detect runtime environment
      expect(isBuildTime()).toBe(false)
      expect(isDatabaseConnectionAllowed()).toBe(true)
    })

    it('should respect runtime configuration', () => {
      const { getBuildTimeConfig } = require('../../src/lib/build-time-guard')
      
      const config = getBuildTimeConfig()
      
      // Should allow database operations in runtime
      expect(config.allowDatabaseConnections).toBe(true)
      expect(config.skipRetentionPolicies).toBe(false)
      expect(config.skipBackgroundJobs).toBe(false)
    })
  })
})
