/**
 * Comprehensive tests for PostgreSQL connection functionality
 * Tests hostname resolution, retry logic, and connection handling
 */

import { jest } from '@jest/globals'
import { logger } from '@/utils/logger'
import {
  createPostgresConnection,
  testPostgresConnection,
  getPostgresConnection,
  closePostgresConnection,
  type PostgresConnectionConfig,
} from '../postgres-connection'

// Mock postgres.js
const mockPostgres = jest.fn()
const mockSql = {
  end: jest.fn(),
  query: jest.fn(),
}

jest.mock('postgres', () => ({
  __esModule: true,
  default: mockPostgres,
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('PostgreSQL Connection', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockPostgres.mockReturnValue(mockSql)
    
    // Reset environment variables
    process.env.DB_HOST = 'postgres'
    process.env.DB_PORT = '5432'
    process.env.DB_NAME = 'business_scraper'
    process.env.DB_USER = 'postgres'
    process.env.DB_PASSWORD = 'password'
    process.env.NODE_ENV = 'production'
  })

  describe('createPostgresConnection', () => {
    it('should resolve hostname correctly from config', () => {
      const config: PostgresConnectionConfig = {
        host: 'custom-host',
        port: 5432,
        database: 'test_db',
        username: 'test_user',
        password: 'test_pass',
      }

      createPostgresConnection(config)

      expect(mockPostgres).toHaveBeenCalledWith(
        expect.stringContaining('custom-host'),
        expect.any(Object)
      )
      expect(logger.info).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Hostname resolved',
        expect.objectContaining({
          resolvedHost: 'custom-host',
          source: 'config',
        })
      )
    })

    it('should force localhost to postgres in production', () => {
      const config: PostgresConnectionConfig = {
        host: 'localhost',
        port: 5432,
        database: 'test_db',
        username: 'test_user',
        password: 'test_pass',
      }

      createPostgresConnection(config)

      expect(mockPostgres).toHaveBeenCalledWith(
        expect.stringContaining('postgres'),
        expect.any(Object)
      )
      expect(logger.warn).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Localhost detected in production, forcing to postgres',
        expect.any(Object)
      )
    })

    it('should parse hostname from connection string', () => {
      const config: PostgresConnectionConfig = {
        connectionString: 'postgresql://user:pass@custom-host:5432/db',
      }

      createPostgresConnection(config)

      expect(logger.debug).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Parsed hostname from connection string',
        expect.objectContaining({
          parsedHost: 'custom-host',
        })
      )
    })

    it('should fallback to environment variables', () => {
      process.env.DB_HOST = 'env-host'
      const config: PostgresConnectionConfig = {}

      createPostgresConnection(config)

      expect(mockPostgres).toHaveBeenCalledWith(
        expect.stringContaining('env-host'),
        expect.any(Object)
      )
    })

    it('should use default postgres hostname', () => {
      delete process.env.DB_HOST
      const config: PostgresConnectionConfig = {}

      createPostgresConnection(config)

      expect(mockPostgres).toHaveBeenCalledWith(
        expect.stringContaining('postgres'),
        expect.any(Object)
      )
    })
  })

  describe('testPostgresConnection', () => {
    it('should succeed on first attempt', async () => {
      const mockResult = [{ test: 1, timestamp: new Date() }]
      mockSql.query = jest.fn().mockImplementation(() => mockResult)
      
      // Mock the template literal query
      Object.assign(mockSql, mockResult)

      const config: PostgresConnectionConfig = {
        host: 'test-host',
        port: 5432,
        database: 'test_db',
      }

      const result = await testPostgresConnection(config)

      expect(result).toBe(true)
      expect(logger.info).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Connection test successful',
        expect.objectContaining({
          attempt: 1,
          host: 'test-host',
        })
      )
    })

    it('should retry on connection failure', async () => {
      const error = new Error('Connection failed')
      mockSql.query = jest.fn().mockRejectedValue(error)
      
      // Mock the template literal to throw error
      Object.assign(mockSql, {
        [Symbol.iterator]: () => {
          throw error
        }
      })

      const config: PostgresConnectionConfig = {
        host: 'test-host',
        port: 5432,
        database: 'test_db',
      }

      const retryConfig = {
        maxRetries: 2,
        baseDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
      }

      const result = await testPostgresConnection(config, retryConfig)

      expect(result).toBe(false)
      expect(logger.warn).toHaveBeenCalledTimes(2) // Two failed attempts
      expect(logger.error).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'All connection attempts failed',
        expect.objectContaining({
          totalAttempts: 2,
        })
      )
    })

    it('should close test connection after use', async () => {
      const mockResult = [{ test: 1, timestamp: new Date() }]
      Object.assign(mockSql, mockResult)

      const config: PostgresConnectionConfig = {
        host: 'test-host',
        port: 5432,
        database: 'test_db',
      }

      await testPostgresConnection(config)

      expect(mockSql.end).toHaveBeenCalled()
    })
  })

  describe('getPostgresConnection', () => {
    it('should create global connection from environment variables', () => {
      process.env.DB_HOST = 'env-postgres'
      process.env.DB_PORT = '5433'
      process.env.DB_NAME = 'env_db'

      getPostgresConnection()

      expect(logger.info).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Creating global connection with environment config',
        expect.objectContaining({
          host: 'env-postgres',
          port: 5433,
          database: 'env_db',
          source: 'environment_variables',
        })
      )
    })

    it('should reuse existing global connection', () => {
      // First call creates connection
      getPostgresConnection()
      expect(mockPostgres).toHaveBeenCalledTimes(1)

      // Second call reuses connection
      getPostgresConnection()
      expect(mockPostgres).toHaveBeenCalledTimes(1)
    })
  })

  describe('closePostgresConnection', () => {
    it('should close global connection', async () => {
      // Create global connection first
      getPostgresConnection()
      
      await closePostgresConnection()

      expect(mockSql.end).toHaveBeenCalled()
      expect(logger.info).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Global connection closed successfully'
      )
    })

    it('should handle close errors gracefully', async () => {
      const error = new Error('Close failed')
      mockSql.end.mockRejectedValue(error)

      // Create global connection first
      getPostgresConnection()
      
      await closePostgresConnection()

      expect(logger.error).toHaveBeenCalledWith(
        'PostgreSQL Connection',
        'Failed to close global connection',
        expect.objectContaining({
          error: 'Close failed',
        })
      )
    })
  })
})
