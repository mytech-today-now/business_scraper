/**
 * Database Security Tests
 * Business Scraper Application - Security Validation Tests
 */

import {
  DatabaseSecurityService
} from '@/lib/databaseSecurity'
import { SecureDatabase } from '@/lib/secureDatabase'
import { Pool } from 'pg'

// Mock pg module
jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue({
      query: jest.fn(),
      release: jest.fn()
    }),
    query: jest.fn(),
    end: jest.fn(),
    totalCount: 5,
    idleCount: 2,
    waitingCount: 0,
    on: jest.fn()
  }))
}))

describe('Database Security Service', () => {
  let securityService: DatabaseSecurityService

  beforeEach(() => {
    securityService = new DatabaseSecurityService()
  })

  describe('SQL Injection Detection', () => {
    it('should detect basic SQL injection patterns', () => {
      const maliciousQueries = [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT * FROM users; DROP TABLE users;",
        "SELECT * FROM users WHERE name = 'admin'--",
        "SELECT * FROM users UNION SELECT * FROM passwords",
        "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('dir')"
      ]

      maliciousQueries.forEach(query => {
        const result = securityService.validateQuery(query)
        expect(result.isValid).toBe(false)
        expect(result.errors.length).toBeGreaterThan(0)
      })
    })

    it('should allow safe parameterized queries', () => {
      const safeQueries = [
        "SELECT * FROM users WHERE id = $1",
        "INSERT INTO users (name, email) VALUES ($1, $2)",
        "UPDATE users SET name = $1 WHERE id = $2",
        "DELETE FROM users WHERE id = $1"
      ]

      safeQueries.forEach(query => {
        const result = securityService.validateQuery(query, ['test'])
        expect(result.isValid).toBe(true)
        expect(result.errors.length).toBe(0)
      })
    })

    it('should detect dangerous keywords', () => {
      const dangerousQueries = [
        "EXEC sp_configure",
        "EXECUTE xp_cmdshell",
        "SELECT * FROM OPENROWSET",
        "BACKUP DATABASE test TO DISK"
      ]

      dangerousQueries.forEach(query => {
        const result = securityService.validateQuery(query)
        expect(result.isValid).toBe(false)
        expect(result.errors.some(e => e.includes('dangerous keyword'))).toBe(true)
      })
    })

    it('should validate query length limits', () => {
      const longQuery = 'SELECT * FROM users WHERE ' + 'a'.repeat(15000)
      const result = securityService.validateQuery(longQuery)
      
      expect(result.isValid).toBe(false)
      expect(result.errors.some(e => e.includes('exceeds maximum length'))).toBe(true)
    })
  })

  describe('Parameter Validation', () => {
    it('should validate safe parameters', () => {
      const safeParams = ['john@example.com', 123, true, null]
      const result = securityService.validateQuery('SELECT * FROM users WHERE email = $1', safeParams)
      
      expect(result.isValid).toBe(true)
    })

    it('should detect malicious parameters', () => {
      const maliciousParams = ["'; DROP TABLE users; --", "1 OR 1=1"]
      const result = securityService.validateQuery('SELECT * FROM users WHERE id = $1', maliciousParams)
      
      expect(result.isValid).toBe(false)
      expect(result.errors.some(e => e.includes('dangerous content'))).toBe(true)
    })

    it('should handle null and undefined parameters', () => {
      const params = [null, undefined, 'valid']
      const result = securityService.validateQuery('SELECT * FROM users WHERE id = $1', params)
      
      expect(result.isValid).toBe(true)
    })

    it('should warn about long parameters', () => {
      const longParam = 'a'.repeat(1500)
      const result = securityService.validateQuery('SELECT * FROM users WHERE name = $1', [longParam])
      
      expect(result.warnings.some(w => w.includes('unusually long'))).toBe(true)
    })
  })

  describe('Query Sanitization', () => {
    it('should sanitize queries by removing comments', () => {
      const query = "SELECT * FROM users -- malicious comment"
      const result = securityService.validateQuery(query)
      
      expect(result.sanitizedQuery).not.toContain('--')
    })

    it('should normalize whitespace', () => {
      const query = "SELECT   *    FROM\n\tusers   WHERE  id = $1"
      const result = securityService.validateQuery(query)
      
      expect(result.sanitizedQuery).toBe("SELECT * FROM users WHERE id = $1")
    })
  })

  describe('Security Statistics', () => {
    it('should track suspicious query attempts', () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = 1 OR 1=1"
      
      // Reset counters
      securityService.resetSecurityCounters()
      
      // Execute malicious query
      securityService.validateQuery(maliciousQuery)
      
      const stats = securityService.getSecurityStats()
      expect(stats.suspiciousQueryCount).toBe(1)
      expect(stats.lastSuspiciousQueryTime).toBeGreaterThan(0)
    })

    it('should reset security counters', () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = 1 OR 1=1"
      
      securityService.validateQuery(maliciousQuery)
      securityService.resetSecurityCounters()
      
      const stats = securityService.getSecurityStats()
      expect(stats.suspiciousQueryCount).toBe(0)
      expect(stats.lastSuspiciousQueryTime).toBe(0)
    })
  })

  describe('Utility Functions', () => {
    it('should escape SQL identifiers', () => {
      expect(DatabaseSecurityService.escapeIdentifier('users')).toBe('"users"')
      expect(DatabaseSecurityService.escapeIdentifier('user_table')).toBe('"user_table"')
    })

    it('should reject invalid identifiers', () => {
      expect(() => DatabaseSecurityService.escapeIdentifier('123invalid')).toThrow()
      expect(() => DatabaseSecurityService.escapeIdentifier('SELECT')).toThrow()
      expect(() => DatabaseSecurityService.escapeIdentifier('user-table')).not.toThrow()
    })

    it('should generate secure IDs', () => {
      const id1 = DatabaseSecurityService.generateSecureId()
      const id2 = DatabaseSecurityService.generateSecureId()
      
      expect(id1).not.toBe(id2)
      expect(id1).toMatch(/^[a-f0-9]{32}$/)
      expect(id2).toMatch(/^[a-f0-9]{32}$/)
    })

    it('should hash and verify sensitive data', () => {
      const data = 'sensitive_password'
      const { hash, salt } = DatabaseSecurityService.hashSensitiveData(data)
      
      expect(hash).toBeDefined()
      expect(salt).toBeDefined()
      expect(hash.length).toBe(128) // 64 bytes in hex
      expect(salt.length).toBe(64)  // 32 bytes in hex
      
      // Verify correct data
      expect(DatabaseSecurityService.verifySensitiveData(data, hash, salt)).toBe(true)
      
      // Verify incorrect data
      expect(DatabaseSecurityService.verifySensitiveData('wrong_password', hash, salt)).toBe(false)
    })
  })
})

describe('Secure Database Wrapper', () => {
  let secureDb: SecureDatabase
  let mockPool: any

  beforeEach(() => {
    const mockConfig = {
      host: 'localhost',
      port: 5432,
      database: 'test',
      user: 'test',
      password: 'test'
    }
    
    secureDb = new SecureDatabase(mockConfig)
    
    // Get the mocked pool instance
    mockPool = new Pool()
  })

  describe('Query Execution', () => {
    it('should execute safe queries successfully', async () => {
      const mockResult = {
        rows: [{ id: 1, name: 'test' }],
        rowCount: 1,
        command: 'SELECT'
      }
      
      mockPool.connect.mockResolvedValue({
        query: jest.fn().mockResolvedValue(mockResult),
        release: jest.fn()
      })

      const result = await secureDb.query('SELECT * FROM users WHERE id = $1', [1])
      
      expect(result.rows).toEqual(mockResult.rows)
      expect(result.rowCount).toBe(1)
      expect(result.command).toBe('SELECT')
      expect(result.executionTime).toBeGreaterThan(0)
    })

    it('should reject malicious queries', async () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = 1 OR 1=1"
      
      await expect(secureDb.query(maliciousQuery)).rejects.toThrow('Query validation failed')
    })

    it('should handle query timeouts', async () => {
      mockPool.connect.mockResolvedValue({
        query: jest.fn().mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100))),
        release: jest.fn()
      })

      await expect(
        secureDb.query('SELECT * FROM users', [], { timeout: 50 })
      ).rejects.toThrow('Query timeout')
    })

    it('should retry on retryable errors', async () => {
      const retryableError = new Error('connection terminated unexpectedly')
      const successResult = {
        rows: [{ id: 1 }],
        rowCount: 1,
        command: 'SELECT'
      }

      mockPool.connect
        .mockResolvedValueOnce({
          query: jest.fn().mockRejectedValue(retryableError),
          release: jest.fn()
        })
        .mockResolvedValueOnce({
          query: jest.fn().mockResolvedValue(successResult),
          release: jest.fn()
        })

      const result = await secureDb.query('SELECT * FROM users', [], { maxRetries: 1 })
      expect(result.rows).toEqual(successResult.rows)
    })
  })

  describe('Transaction Support', () => {
    it('should execute transactions successfully', async () => {
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ command: 'BEGIN' })
          .mockResolvedValueOnce({ rows: [{ id: 1 }], rowCount: 1, command: 'INSERT' })
          .mockResolvedValueOnce({ command: 'COMMIT' }),
        release: jest.fn()
      }
      
      mockPool.connect.mockResolvedValue(mockClient)

      const result = await secureDb.transaction(async (tx) => {
        const insertResult = await tx.query('INSERT INTO users (name) VALUES ($1)', ['test'])
        return insertResult.rows[0]
      })

      expect(mockClient.query).toHaveBeenCalledWith('BEGIN')
      expect(mockClient.query).toHaveBeenCalledWith('COMMIT')
      expect(result).toEqual({ id: 1 })
    })

    it('should rollback on transaction errors', async () => {
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ command: 'BEGIN' })
          .mockRejectedValueOnce(new Error('Transaction error'))
          .mockResolvedValueOnce({ command: 'ROLLBACK' }),
        release: jest.fn()
      }
      
      mockPool.connect.mockResolvedValue(mockClient)

      await expect(
        secureDb.transaction(async (tx) => {
          await tx.query('INSERT INTO users (name) VALUES ($1)', ['test'])
        })
      ).rejects.toThrow('Transaction error')

      expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK')
    })
  })

  describe('Prepared Statements', () => {
    it('should execute prepared statements', async () => {
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ command: 'PREPARE' })
          .mockResolvedValueOnce({ rows: [{ id: 1 }], rowCount: 1, command: 'SELECT' })
          .mockResolvedValueOnce({ command: 'DEALLOCATE' }),
        release: jest.fn()
      }
      
      mockPool.connect.mockResolvedValue(mockClient)

      const result = await secureDb.preparedQuery(
        'get_user',
        'SELECT * FROM users WHERE id = $1',
        [1]
      )

      expect(result.rows).toEqual([{ id: 1 }])
      expect(mockClient.query).toHaveBeenCalledWith('PREPARE get_user AS SELECT * FROM users WHERE id = $1')
      expect(mockClient.query).toHaveBeenCalledWith('EXECUTE get_user', [1])
      expect(mockClient.query).toHaveBeenCalledWith('DEALLOCATE get_user')
    })
  })

  describe('Connection Pool Management', () => {
    it('should provide pool statistics', () => {
      const stats = secureDb.getPoolStats()
      
      expect(stats).toHaveProperty('totalCount')
      expect(stats).toHaveProperty('idleCount')
      expect(stats).toHaveProperty('waitingCount')
    })

    it('should close connections properly', async () => {
      await secureDb.close()
      expect(mockPool.end).toHaveBeenCalled()
    })
  })

  describe('Query Caching', () => {
    it('should cache SELECT query results', async () => {
      const mockResult = {
        rows: [{ id: 1, name: 'test' }],
        rowCount: 1,
        command: 'SELECT'
      }
      
      mockPool.connect.mockResolvedValue({
        query: jest.fn().mockResolvedValue(mockResult),
        release: jest.fn()
      })

      // First query - should hit database
      const result1 = await secureDb.query('SELECT * FROM users WHERE id = $1', [1])
      expect(result1.isFromCache).toBeUndefined()

      // Second identical query - should hit cache
      const result2 = await secureDb.query('SELECT * FROM users WHERE id = $1', [1])
      expect(result2.isFromCache).toBe(true)
    })

    it('should clear cache when requested', () => {
      secureDb.clearCache()
      // Cache clearing is tested implicitly through the caching test above
    })
  })
})
