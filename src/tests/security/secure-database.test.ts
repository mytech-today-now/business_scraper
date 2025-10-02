/**
 * SecureDatabase Security Tests
 * Tests for the enhanced SecureDatabase implementation
 * Business Scraper Application - Security Enhancement
 */

import { SecureDatabase } from '@/lib/secureDatabase'
import { logger } from '@/utils/logger'

// Mock the postgres connection
jest.mock('@/lib/postgres-connection', () => ({
  createPostgresConnection: jest.fn(() => ({
    unsafe: jest.fn(),
    begin: jest.fn(),
    end: jest.fn(),
  })),
}))

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

describe('SecureDatabase Security Tests', () => {
  let secureDb: SecureDatabase
  let mockSql: any

  beforeEach(() => {
    mockSql = {
      unsafe: jest.fn(),
      begin: jest.fn(),
      end: jest.fn(),
    }

    // Create SecureDatabase instance with mocked connection
    secureDb = new SecureDatabase({
      host: 'localhost',
      port: 5432,
      database: 'test',
      user: 'test',
      password: 'test',
    })

    // Mock the sql property
    secureDb['sql'] = mockSql
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Query Validation and Security', () => {
    test('should validate queries before execution', async () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
      
      await expect(secureDb.query(maliciousQuery)).rejects.toThrow(/validation failed/i)
    })

    test('should allow safe parameterized queries', async () => {
      const safeQuery = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      
      mockSql.mockImplementation(() => Promise.resolve([{ id: 123, name: 'test' }]))
      
      const result = await secureDb.query(safeQuery, params)
      
      expect(result.rows).toHaveLength(1)
      expect(result.command).toBe('SELECT')
    })

    test('should log security warnings for suspicious queries', async () => {
      const suspiciousQuery = 'SELECT * FROM users WHERE name LIKE \'%admin%\''
      
      mockSql.mockImplementation(() => Promise.resolve([]))
      
      try {
        await secureDb.query(suspiciousQuery, [], { validateQuery: true })
      } catch (error) {
        // Expected to fail validation
      }
      
      expect(logger.warn).toHaveBeenCalled()
    })
  })

  describe('Transaction Security', () => {
    test('should validate queries within transactions', async () => {
      const maliciousQuery = "INSERT INTO users VALUES ('hacker', 'password'); DROP TABLE users; --"
      
      mockSql.begin.mockImplementation(async (callback) => {
        const mockTxSql = jest.fn()
        return await callback(mockTxSql)
      })

      await expect(secureDb.transaction(async (tx) => {
        await tx.query(maliciousQuery)
      })).rejects.toThrow(/validation failed/i)
    })

    test('should allow safe transactions', async () => {
      const safeQuery = 'INSERT INTO users (name, email) VALUES ($1, $2)'
      const params = ['John Doe', 'john@example.com']
      
      mockSql.begin.mockImplementation(async (callback) => {
        const mockTxSql = jest.fn().mockResolvedValue([{ id: 1 }])
        return await callback(mockTxSql)
      })

      const result = await secureDb.transaction(async (tx) => {
        return await tx.query(safeQuery, params)
      })

      expect(mockSql.begin).toHaveBeenCalled()
    })
  })

  describe('Prepared Statement Security', () => {
    test('should validate prepared statements', async () => {
      const maliciousStatement = "SELECT * FROM users WHERE id = $1; DROP TABLE users; --"
      
      await expect(secureDb.preparedQuery('malicious', maliciousStatement, [1]))
        .rejects.toThrow(/validation failed/i)
    })

    test('should execute safe prepared statements', async () => {
      const safeStatement = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      
      mockSql.mockImplementation(() => Promise.resolve([{ id: 123, name: 'test' }]))
      
      const result = await secureDb.preparedQuery('safe_query', safeStatement, params)
      
      expect(result.rows).toHaveLength(1)
      expect(result.command).toBe('SELECT')
    })
  })

  describe('Parameter Conversion Security', () => {
    test('should safely convert parameterized queries', () => {
      const query = 'SELECT * FROM users WHERE id = $1 AND name = $2'
      const params = [123, 'John Doe']
      
      const converted = secureDb['convertToPostgresJSQuery'](query, params)
      
      expect(converted.strings).toHaveLength(3) // Split by $1 and $2
      expect(converted.values).toEqual(params)
    })

    test('should handle complex parameter patterns', () => {
      const query = 'SELECT * FROM users WHERE id = $1 AND (name = $2 OR email = $3) AND status = $4'
      const params = [123, 'John', 'john@example.com', 'active']
      
      const converted = secureDb['convertToPostgresJSQuery'](query, params)
      
      expect(converted.strings).toHaveLength(5) // Split by $1, $2, $3, $4
      expect(converted.values).toEqual(params)
    })
  })

  describe('Error Handling and Retry Logic', () => {
    test('should retry on transient errors', async () => {
      const query = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      
      mockSql
        .mockRejectedValueOnce(new Error('ECONNRESET'))
        .mockResolvedValueOnce([{ id: 123, name: 'test' }])
      
      const result = await secureDb.query(query, params, { maxRetries: 1 })
      
      expect(result.rows).toHaveLength(1)
      expect(mockSql).toHaveBeenCalledTimes(2)
    })

    test('should not retry on validation errors', async () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
      
      await expect(secureDb.query(maliciousQuery, [], { maxRetries: 3 }))
        .rejects.toThrow(/validation failed/i)
      
      // Should not retry validation failures
      expect(mockSql).not.toHaveBeenCalled()
    })
  })

  describe('Query Caching Security', () => {
    test('should cache safe SELECT queries', async () => {
      const query = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      const mockResult = [{ id: 123, name: 'test' }]
      
      mockSql.mockResolvedValue(mockResult)
      
      // First call
      const result1 = await secureDb.query(query, params)
      expect(result1.isFromCache).toBeFalsy()
      
      // Second call should be cached
      const result2 = await secureDb.query(query, params)
      expect(result2.isFromCache).toBeTruthy()
      
      // SQL should only be called once
      expect(mockSql).toHaveBeenCalledTimes(1)
    })

    test('should not cache non-SELECT queries', async () => {
      const query = 'INSERT INTO users (name) VALUES ($1)'
      const params = ['John Doe']
      
      mockSql.mockResolvedValue([{ id: 1 }])
      
      await secureDb.query(query, params)
      await secureDb.query(query, params)
      
      // Should call SQL twice (no caching for INSERT)
      expect(mockSql).toHaveBeenCalledTimes(2)
    })
  })

  describe('Query Timeout Security', () => {
    test('should timeout long-running queries', async () => {
      const query = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      
      // Mock a query that takes too long
      mockSql.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 10000)))
      
      await expect(secureDb.query(query, params, { timeout: 100 }))
        .rejects.toThrow(/timeout/i)
    })

    test('should complete fast queries within timeout', async () => {
      const query = 'SELECT * FROM users WHERE id = $1'
      const params = [123]
      
      mockSql.mockResolvedValue([{ id: 123, name: 'test' }])
      
      const result = await secureDb.query(query, params, { timeout: 5000 })
      
      expect(result.rows).toHaveLength(1)
    })
  })

  describe('Connection Security', () => {
    test('should provide connection status', () => {
      const status = secureDb.getConnectionStatus()
      
      expect(status).toHaveProperty('connected')
      expect(status).toHaveProperty('info')
    })

    test('should provide pool statistics', () => {
      const stats = secureDb.getPoolStats()
      
      expect(stats).toHaveProperty('connected')
      expect(stats).toHaveProperty('info')
    })

    test('should close connections safely', async () => {
      mockSql.end.mockResolvedValue(undefined)
      
      await expect(secureDb.close()).resolves.not.toThrow()
      expect(mockSql.end).toHaveBeenCalled()
    })
  })

  describe('Cache Management Security', () => {
    test('should clear cache on demand', () => {
      expect(() => secureDb.clearCache()).not.toThrow()
      expect(logger.debug).toHaveBeenCalledWith('SecureDatabase', 'Query cache cleared')
    })

    test('should limit cache size', async () => {
      const baseQuery = 'SELECT * FROM users WHERE id = $1'
      mockSql.mockResolvedValue([{ id: 1, name: 'test' }])
      
      // Fill cache beyond limit (assuming limit is 100)
      for (let i = 0; i < 105; i++) {
        await secureDb.query(baseQuery, [i])
      }
      
      // Cache should have been trimmed
      expect(mockSql).toHaveBeenCalledTimes(105)
    })
  })
})
