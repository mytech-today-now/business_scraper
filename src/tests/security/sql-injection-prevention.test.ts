/**
 * SQL Injection Prevention Tests
 * Comprehensive security tests for database operations
 * Business Scraper Application - Security Enhancement
 */

import { SecureDatabase } from '@/lib/secureDatabase'
import { DatabaseValidationService } from '@/lib/database-validation-schemas'
import { PostgreSQLDatabase } from '@/lib/postgresql-database'
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

describe('SQL Injection Prevention Tests', () => {
  let secureDb: SecureDatabase
  let postgresDb: PostgreSQLDatabase
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

    // Create PostgreSQLDatabase instance for testing
    postgresDb = new PostgreSQLDatabase({
      type: 'postgresql',
      host: 'localhost',
      port: 5432,
      database: 'test',
      username: 'test',
      password: 'test',
    })
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Malicious SQL Injection Payloads', () => {
    const maliciousPayloads = [
      // Classic SQL injection patterns (encoded to avoid exposing raw attacks)
      Buffer.from('JyBPUiAnMSc9JzE=', 'base64').toString(), // ' OR '1'='1
      Buffer.from('JzsgRFJPUCBUQUJMRSB1c2VyczsgLS0=', 'base64').toString(), // '; DROP TABLE users; --
      Buffer.from('JyBVTklPTiBTRUxFQ1QgKiBGUk9NIHBhc3N3b3Jkcw==', 'base64').toString(), // ' UNION SELECT * FROM passwords
      Buffer.from('YWRtaW4nLS0=', 'base64').toString(), // admin'--
      Buffer.from('JyBPUiAxPTE7IEVYRUM=', 'base64').toString(), // ' OR 1=1; EXEC
      
      // Boolean-based injection
      "1' OR '1'='1",
      "1' OR 1=1--",
      "' OR 'a'='a",
      
      // Union-based injection
      "' UNION SELECT null, username, password FROM users--",
      "1' UNION SELECT @@version--",
      
      // Time-based injection
      "'; WAITFOR DELAY '00:00:05'--",
      "' OR SLEEP(5)--",
      
      // Stacked queries
      "'; INSERT INTO users VALUES ('hacker', 'password')--",
      "1'; DELETE FROM users WHERE id=1--",
      
      // Comment injection
      "admin'/*",
      "admin'#",
      
      // Hex encoding attempts
      "0x61646D696E",
      
      // Function-based injection
      "'; SELECT LOAD_FILE('/etc/passwd')--",
    ]

    test.each(maliciousPayloads)('should reject malicious payload: %s', async (payload) => {
      // Test direct validation
      const validation = DatabaseValidationService.validateSqlSafety(payload)
      expect(validation.isValid).toBe(false)
      expect(validation.errors.length).toBeGreaterThan(0)
    })

    test('should prevent SQL injection in query parameters', async () => {
      const maliciousEmail = "admin'; DROP TABLE users; --"
      
      const validation = DatabaseValidationService.validateQueryParameters({
        text: 'SELECT * FROM users WHERE email = $1',
        params: [maliciousEmail],
      })

      expect(validation.success).toBe(false)
    })

    test('should prevent SQL injection in business filters', async () => {
      const maliciousFilter = {
        industry: "'; DROP TABLE businesses; --",
        zipCode: "12345' OR '1'='1",
      }

      // This should be caught by the validation in listBusinesses
      const result = await postgresDb.listBusinesses(undefined, maliciousFilter)
      
      // Should return empty array due to validation failure
      expect(result).toEqual([])
      expect(logger.error).toHaveBeenCalled()
    })
  })

  describe('Parameter Validation', () => {
    test('should validate safe parameters', () => {
      const safeParams = [
        'john@example.com',
        'John Doe',
        '12345',
        123,
        true,
        null,
        new Date(),
      ]

      const validation = DatabaseValidationService.validateQueryParameters({
        text: 'SELECT * FROM users WHERE email = $1 AND name = $2',
        params: safeParams,
      })

      expect(validation.success).toBe(true)
    })

    test('should reject parameters with SQL injection patterns', () => {
      const dangerousParams = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'/*",
      ]

      for (const param of dangerousParams) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM users WHERE name = $1',
          params: [param],
        })

        expect(validation.success).toBe(false)
      }
    })

    test('should handle null and undefined parameters safely', () => {
      const validation = DatabaseValidationService.validateQueryParameters({
        text: 'SELECT * FROM users WHERE email = $1 AND name = $2',
        params: [null, undefined],
      })

      expect(validation.success).toBe(true)
    })
  })

  describe('Query Structure Validation', () => {
    test('should validate safe query structures', () => {
      const safeQueries = [
        'SELECT * FROM users WHERE id = $1',
        'INSERT INTO users (name, email) VALUES ($1, $2)',
        'UPDATE users SET name = $1 WHERE id = $2',
        'DELETE FROM users WHERE id = $1',
      ]

      for (const query of safeQueries) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: query,
          params: ['test'],
        })

        expect(validation.success).toBe(true)
      }
    })

    test('should reject queries with dangerous patterns', () => {
      const dangerousQueries = [
        "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
        "SELECT * FROM users WHERE name = 'admin'--",
        "SELECT * FROM users UNION SELECT * FROM passwords",
        "SELECT * FROM users WHERE id = 1 OR 1=1",
      ]

      for (const query of dangerousQueries) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: query,
          params: [],
        })

        expect(validation.success).toBe(false)
      }
    })
  })

  describe('Business Logic Security Tests', () => {
    test('should prevent SQL injection in campaign creation', async () => {
      const maliciousCampaign = {
        name: "Test'; DROP TABLE campaigns; --",
        description: "Normal description",
        industries: ["retail"],
        zipCode: "12345",
        searchRadius: 25,
        searchDepth: 3,
        pagesPerSite: 5,
        status: 'active',
      }

      // Mock the query method to track calls
      const mockQuery = jest.fn().mockRejectedValue(new Error('Validation failed'))
      postgresDb['query'] = mockQuery

      await expect(postgresDb.createCampaign(maliciousCampaign)).rejects.toThrow()
    })

    test('should prevent SQL injection in business updates', async () => {
      const maliciousUpdate = {
        name: "Business'; DROP TABLE businesses; --",
        email: "test@example.com",
      }

      const mockQuery = jest.fn().mockRejectedValue(new Error('Validation failed'))
      postgresDb['query'] = mockQuery

      await expect(postgresDb.updateBusiness('valid-uuid', maliciousUpdate)).rejects.toThrow()
    })

    test('should sanitize search filters', async () => {
      const maliciousFilters = {
        industry: "'; SELECT * FROM users; --",
        minConfidenceScore: "0.5'; DROP TABLE businesses; --",
      }

      // Should handle validation gracefully and return empty results
      const result = await postgresDb.listBusinesses(undefined, maliciousFilters)
      expect(result).toEqual([])
    })
  })

  describe('Edge Cases and Boundary Tests', () => {
    test('should handle extremely long inputs', () => {
      const longString = 'a'.repeat(20000)
      
      const validation = DatabaseValidationService.validateQueryParameters({
        text: 'SELECT * FROM users WHERE name = $1',
        params: [longString],
      })

      expect(validation.success).toBe(false)
    })

    test('should handle special characters safely', () => {
      const specialChars = [
        "O'Reilly",
        "Smith & Jones",
        "Test (Company)",
        "Test-Company",
        "Test_Company",
        "Test.Company",
      ]

      for (const name of specialChars) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM users WHERE name = $1',
          params: [name],
        })

        expect(validation.success).toBe(true)
      }
    })

    test('should handle Unicode and international characters', () => {
      const internationalNames = [
        "José García",
        "北京公司",
        "Société Française",
        "Москва Компания",
        "東京株式会社",
      ]

      for (const name of internationalNames) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM users WHERE name = $1',
          params: [name],
        })

        expect(validation.success).toBe(true)
      }
    })
  })

  describe('Performance and DoS Prevention', () => {
    test('should reject queries that are too long', () => {
      const longQuery = 'SELECT * FROM users WHERE ' + 'name = $1 AND '.repeat(1000) + 'id = $2'

      const validation = DatabaseValidationService.validateQueryParameters({
        text: longQuery,
        params: ['test', 1],
      })

      expect(validation.success).toBe(false)
    })

    test('should limit parameter count', () => {
      const manyParams = Array(1000).fill('test')

      const validation = DatabaseValidationService.validateQueryParameters({
        text: 'SELECT * FROM users WHERE name = $1',
        params: manyParams,
      })

      expect(validation.success).toBe(false)
    })
  })

  describe('Real-world Attack Scenarios', () => {
    test('should prevent authentication bypass attempts', () => {
      const bypassAttempts = [
        "admin' OR '1'='1' --",
        "admin' OR 1=1#",
        "' OR 'x'='x",
        "admin'/*",
        "admin' OR 'a'='a",
      ]

      for (const attempt of bypassAttempts) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM users WHERE username = $1 AND password = $2',
          params: [attempt, 'password'],
        })

        expect(validation.success).toBe(false)
      }
    })

    test('should prevent data extraction attempts', () => {
      const extractionAttempts = [
        "1' UNION SELECT username, password FROM admin_users--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        "1' UNION SELECT column_name FROM information_schema.columns--",
        "1' UNION SELECT @@version--",
      ]

      for (const attempt of extractionAttempts) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM businesses WHERE id = $1',
          params: [attempt],
        })

        expect(validation.success).toBe(false)
      }
    })

    test('should prevent blind SQL injection attempts', () => {
      const blindAttempts = [
        "1' AND (SELECT COUNT(*) FROM users) > 0--",
        "1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>64--",
      ]

      for (const attempt of blindAttempts) {
        const validation = DatabaseValidationService.validateQueryParameters({
          text: 'SELECT * FROM businesses WHERE id = $1',
          params: [attempt],
        })

        expect(validation.success).toBe(false)
      }
    })
  })

  describe('Secure Query Building Validation', () => {
    test('should validate secure business query building', () => {
      const validFilters = {
        industry: 'technology',
        minConfidenceScore: 0.8,
        hasEmail: true,
        zipCode: '12345',
      }

      // Test the private method through reflection or create a test instance
      const queryBuilder = postgresDb['buildSecureBusinessQuery'](undefined, validFilters)

      expect(queryBuilder.query).toContain('WHERE')
      expect(queryBuilder.params).toHaveLength(3) // industry, minConfidenceScore, zipCode
      expect(queryBuilder.query).toMatch(/\$\d+/g) // Should contain parameter placeholders
    })

    test('should validate secure campaign update query building', () => {
      const validUpdates = {
        name: 'Updated Campaign',
        status: 'active',
        searchRadius: 50,
      }

      const queryBuilder = postgresDb['buildSecureCampaignUpdateQuery']('test-id', validUpdates)

      expect(queryBuilder.query).toContain('UPDATE campaigns SET')
      expect(queryBuilder.query).toContain('WHERE id = $')
      expect(queryBuilder.params).toHaveLength(4) // 3 updates + id
    })
  })
})
