/**
 * Comprehensive Business Rule Validation Tests for Database Validation Schemas
 * Tests all validation rules, constraints, and business logic for data integrity
 */

import {
  BusinessInputSchema,
  CampaignInputSchema,
  SessionInputSchema,
  SettingInputSchema,
  CampaignFiltersSchema,
  BusinessFiltersSchema,
  SessionFiltersSchema,
  DatabaseOperationSchema,
  DatabaseValidationService,
  safeString,
  safeText,
  safeEmail,
  safeUrl,
  safePhone,
  safeUuid,
  safeInteger,
  safeFloat,
  sqlInjectionSafe,
} from '@/lib/database-validation-schemas'

describe('Database Validation Schemas - Business Rules', () => {
  let validationService: DatabaseValidationService

  beforeEach(() => {
    validationService = new DatabaseValidationService()
  })

  describe('SQL Injection Protection', () => {
    const maliciousInputs = [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "admin'--",
      "' OR 1=1 --",
      "'; INSERT INTO users VALUES ('hacker', 'password'); --",
      "1' UNION SELECT * FROM users --",
      "'; EXEC xp_cmdshell('dir'); --",
      "1'; WAITFOR DELAY '00:00:05'; --",
      "' OR SLEEP(5) --",
      "1' AND (SELECT COUNT(*) FROM users) > 0 --",
      "'; LOAD_FILE('/etc/passwd'); --",
      "1' OR '1'='1' /*",
      "admin' # comment",
      "0x48656c6c6f", // Hexadecimal
      "' OR 'a'='a",
      "1' OR '1'='1' --",
    ]

    test('should reject all SQL injection patterns', () => {
      maliciousInputs.forEach(input => {
        const result = sqlInjectionSafe.safeParse(input)
        expect(result.success).toBe(false)
        expect(result.error?.issues[0]?.message).toContain('dangerous SQL patterns')
      })
    })

    test('should validate SQL safety check function', () => {
      maliciousInputs.forEach(input => {
        const result = DatabaseValidationService.validateSqlSafety(input)
        expect(result.isValid).toBe(false)
        expect(result.errors.length).toBeGreaterThan(0)
      })
    })

    test('should allow safe inputs', () => {
      const safeInputs = [
        'John Doe',
        'Acme Corporation',
        'john@example.com',
        'https://example.com',
        '+1-555-123-4567',
        'Valid business description',
        '123 Main Street',
      ]

      safeInputs.forEach(input => {
        const result = sqlInjectionSafe.safeParse(input)
        expect(result.success).toBe(true)
      })
    })
  })

  describe('Business Record Validation', () => {
    const validBusinessRecord = {
      campaignId: '123e4567-e89b-12d3-a456-426614174000',
      name: 'Acme Corporation',
      email: 'contact@acme.com',
      phone: '+1-555-123-4567',
      website: 'https://acme.com',
      address: '123 Main Street, Anytown, ST 12345',
      confidenceScore: 0.85,
      contactPerson: 'John Doe',
      coordinates: {
        lat: 40.7128,
        lng: -74.0060,
      },
      industry: 'Technology',
      businessDescription: 'Leading technology solutions provider',
      socialMedia: {
        facebook: 'https://facebook.com/acme',
        twitter: 'https://twitter.com/acme',
      },
      businessHours: {
        monday: '9:00 AM - 5:00 PM',
        tuesday: '9:00 AM - 5:00 PM',
      },
      employeeCount: 150,
      annualRevenue: 5000000,
    }

    test('should validate complete business record', () => {
      const result = BusinessInputSchema.safeParse(validBusinessRecord)
      expect(result.success).toBe(true)
    })

    test('should require campaignId and name', () => {
      const invalidRecord = { ...validBusinessRecord }
      delete invalidRecord.campaignId
      delete invalidRecord.name

      const result = BusinessInputSchema.safeParse(invalidRecord)
      expect(result.success).toBe(false)
      expect(result.error?.issues).toHaveLength(2)
    })

    test('should validate email format', () => {
      const invalidEmails = [
        'invalid-email',
        'test@',
        '@domain.com',
        'test..test@domain.com',
        'test@domain',
        'a'.repeat(321) + '@domain.com', // Too long
      ]

      invalidEmails.forEach(email => {
        const record = { ...validBusinessRecord, email }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })

    test('should validate phone number format', () => {
      const validPhones = [
        '+1-555-123-4567',
        '(555) 123-4567',
        '555.123.4567',
        '5551234567',
        '+44 20 7946 0958',
      ]

      validPhones.forEach(phone => {
        const record = { ...validBusinessRecord, phone }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(true)
      })

      const invalidPhones = [
        'abc-def-ghij',
        '123',
        'phone number',
        '555-123-456789012345', // Too long
      ]

      invalidPhones.forEach(phone => {
        const record = { ...validBusinessRecord, phone }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })

    test('should validate URL format', () => {
      const validUrls = [
        'https://example.com',
        'http://subdomain.example.com',
        'https://example.com/path?query=value',
        'https://example.com:8080',
      ]

      validUrls.forEach(website => {
        const record = { ...validBusinessRecord, website }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(true)
      })

      const invalidUrls = [
        'not-a-url',
        'ftp://example.com',
        'javascript:alert(1)',
        'http://',
        'a'.repeat(2049), // Too long
      ]

      invalidUrls.forEach(website => {
        const record = { ...validBusinessRecord, website }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })

    test('should validate coordinate boundaries', () => {
      const validCoordinates = [
        { lat: 0, lng: 0 },
        { lat: 90, lng: 180 },
        { lat: -90, lng: -180 },
        { lat: 40.7128, lng: -74.0060 },
      ]

      validCoordinates.forEach(coordinates => {
        const record = { ...validBusinessRecord, coordinates }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(true)
      })

      const invalidCoordinates = [
        { lat: 91, lng: 0 }, // Latitude too high
        { lat: -91, lng: 0 }, // Latitude too low
        { lat: 0, lng: 181 }, // Longitude too high
        { lat: 0, lng: -181 }, // Longitude too low
      ]

      invalidCoordinates.forEach(coordinates => {
        const record = { ...validBusinessRecord, coordinates }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })

    test('should validate confidence score range', () => {
      const validScores = [0, 0.5, 1, 0.85]

      validScores.forEach(confidenceScore => {
        const record = { ...validBusinessRecord, confidenceScore }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(true)
      })

      const invalidScores = [-0.1, 1.1, 2, -1]

      invalidScores.forEach(confidenceScore => {
        const record = { ...validBusinessRecord, confidenceScore }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })

    test('should validate employee count and revenue ranges', () => {
      const validCounts = [0, 1, 100, 1000000]

      validCounts.forEach(employeeCount => {
        const record = { ...validBusinessRecord, employeeCount }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(true)
      })

      const invalidCounts = [-1, 1000001]

      invalidCounts.forEach(employeeCount => {
        const record = { ...validBusinessRecord, employeeCount }
        const result = BusinessInputSchema.safeParse(record)
        expect(result.success).toBe(false)
      })
    })
  })

  describe('Campaign Validation', () => {
    const validCampaign = {
      name: 'Tech Companies Campaign',
      description: 'Targeting technology companies in the area',
      industries: ['Technology', 'Software'],
      zipCode: '12345',
      searchRadius: 25,
      searchDepth: 3,
      pagesPerSite: 10,
      status: 'active' as const,
      settings: { customSetting: 'value' },
    }

    test('should validate complete campaign', () => {
      const result = CampaignInputSchema.safeParse(validCampaign)
      expect(result.success).toBe(true)
    })

    test('should validate ZIP code format', () => {
      const validZipCodes = ['12345', '12345-6789']

      validZipCodes.forEach(zipCode => {
        const campaign = { ...validCampaign, zipCode }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(true)
      })

      const invalidZipCodes = ['1234', '123456', 'ABCDE', '12345-678']

      invalidZipCodes.forEach(zipCode => {
        const campaign = { ...validCampaign, zipCode }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(false)
      })
    })

    test('should validate search parameters ranges', () => {
      const validParams = [
        { searchRadius: 1, searchDepth: 1, pagesPerSite: 1 },
        { searchRadius: 500, searchDepth: 10, pagesPerSite: 100 },
        { searchRadius: 25, searchDepth: 5, pagesPerSite: 50 },
      ]

      validParams.forEach(params => {
        const campaign = { ...validCampaign, ...params }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(true)
      })

      const invalidParams = [
        { searchRadius: 0 }, // Too low
        { searchRadius: 501 }, // Too high
        { searchDepth: 0 }, // Too low
        { searchDepth: 11 }, // Too high
        { pagesPerSite: 0 }, // Too low
        { pagesPerSite: 101 }, // Too high
      ]

      invalidParams.forEach(params => {
        const campaign = { ...validCampaign, ...params }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(false)
      })
    })

    test('should validate status enum', () => {
      const validStatuses = ['active', 'paused', 'completed', 'cancelled']

      validStatuses.forEach(status => {
        const campaign = { ...validCampaign, status }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(true)
      })

      const invalidStatuses = ['running', 'pending', 'invalid']

      invalidStatuses.forEach(status => {
        const campaign = { ...validCampaign, status }
        const result = CampaignInputSchema.safeParse(campaign)
        expect(result.success).toBe(false)
      })
    })

    test('should limit industries array size', () => {
      const tooManyIndustries = Array(51).fill('Industry')
      const campaign = { ...validCampaign, industries: tooManyIndustries }
      const result = CampaignInputSchema.safeParse(campaign)
      expect(result.success).toBe(false)
    })
  })

  describe('Session Validation', () => {
    const validSession = {
      campaignId: '123e4567-e89b-12d3-a456-426614174000',
      status: 'running' as const,
      progress: {
        totalBusinesses: 100,
        processedBusinesses: 50,
        validBusinesses: 45,
        errors: 5,
      },
      settings: {
        industries: ['Technology'],
        zipCode: '12345',
        searchRadius: 25,
        maxResults: 1000,
      },
      results: {
        businesses: [],
        errors: [],
        warnings: [],
      },
      metadata: { startTime: new Date().toISOString() },
    }

    test('should validate complete session', () => {
      const result = SessionInputSchema.safeParse(validSession)
      expect(result.success).toBe(true)
    })

    test('should validate session status enum', () => {
      const validStatuses = ['pending', 'running', 'completed', 'failed', 'cancelled']

      validStatuses.forEach(status => {
        const session = { ...validSession, status }
        const result = SessionInputSchema.safeParse(session)
        expect(result.success).toBe(true)
      })
    })

    test('should validate progress counters are non-negative', () => {
      const invalidProgress = [
        { totalBusinesses: -1 },
        { processedBusinesses: -1 },
        { validBusinesses: -1 },
        { errors: -1 },
      ]

      invalidProgress.forEach(progressUpdate => {
        const session = {
          ...validSession,
          progress: { ...validSession.progress, ...progressUpdate }
        }
        const result = SessionInputSchema.safeParse(session)
        expect(result.success).toBe(false)
      })
    })

    test('should validate maxResults range', () => {
      const validMaxResults = [1, 100, 10000]

      validMaxResults.forEach(maxResults => {
        const session = {
          ...validSession,
          settings: { ...validSession.settings, maxResults }
        }
        const result = SessionInputSchema.safeParse(session)
        expect(result.success).toBe(true)
      })

      const invalidMaxResults = [0, 10001]

      invalidMaxResults.forEach(maxResults => {
        const session = {
          ...validSession,
          settings: { ...validSession.settings, maxResults }
        }
        const result = SessionInputSchema.safeParse(session)
        expect(result.success).toBe(false)
      })
    })
  })

  describe('Filter Validation', () => {
    test('should validate campaign filters', () => {
      const validFilters = {
        status: 'active' as const,
        industry: 'Technology',
        zipCode: '12345',
        createdAfter: new Date('2023-01-01'),
        createdBefore: new Date('2023-12-31'),
      }

      const result = CampaignFiltersSchema.safeParse(validFilters)
      expect(result.success).toBe(true)
    })

    test('should validate business filters', () => {
      const validFilters = {
        industry: 'Technology',
        zipCode: '12345-6789',
        hasEmail: true,
        hasPhone: false,
        validated: true,
        createdAfter: new Date('2023-01-01'),
        createdBefore: new Date('2023-12-31'),
        minConfidenceScore: 0.8,
      }

      const result = BusinessFiltersSchema.safeParse(validFilters)
      expect(result.success).toBe(true)
    })

    test('should validate session filters', () => {
      const validFilters = {
        status: 'completed' as const,
        campaignId: '123e4567-e89b-12d3-a456-426614174000',
        startedAfter: new Date('2023-01-01'),
        startedBefore: new Date('2023-12-31'),
      }

      const result = SessionFiltersSchema.safeParse(validFilters)
      expect(result.success).toBe(true)
    })
  })

  describe('Database Operation Validation', () => {
    test('should validate database operations', () => {
      const validOperations = [
        {
          operation: 'SELECT' as const,
          table: 'businesses',
          conditions: { id: '123' },
        },
        {
          operation: 'INSERT' as const,
          table: 'campaigns',
          data: { name: 'New Campaign' },
        },
        {
          operation: 'UPDATE' as const,
          table: 'sessions',
          conditions: { id: '456' },
          data: { status: 'completed' },
        },
        {
          operation: 'DELETE' as const,
          table: 'temp_data',
          conditions: { expired: true },
        },
      ]

      validOperations.forEach(operation => {
        const result = DatabaseOperationSchema.safeParse(operation)
        expect(result.success).toBe(true)
      })
    })

    test('should reject invalid operations', () => {
      const invalidOperations = [
        {
          operation: 'DROP' as any,
          table: 'businesses',
        },
        {
          operation: 'SELECT' as const,
          table: '', // Empty table name
        },
      ]

      invalidOperations.forEach(operation => {
        const result = DatabaseOperationSchema.safeParse(operation)
        expect(result.success).toBe(false)
      })
    })
  })

  describe('Edge Cases and Boundary Testing', () => {
    test('should handle empty and null values appropriately', () => {
      const testCases = [
        { input: '', schema: safeString(10), shouldPass: true },
        { input: null, schema: safeString(10).optional(), shouldPass: true },
        { input: undefined, schema: safeString(10).optional(), shouldPass: true },
      ]

      testCases.forEach(({ input, schema, shouldPass }) => {
        const result = schema.safeParse(input)
        expect(result.success).toBe(shouldPass)
      })
    })

    test('should handle maximum length boundaries', () => {
      const maxLength = 255
      const exactLength = 'a'.repeat(maxLength)
      const tooLong = 'a'.repeat(maxLength + 1)

      expect(safeString(maxLength).safeParse(exactLength).success).toBe(true)
      expect(safeString(maxLength).safeParse(tooLong).success).toBe(false)
    })

    test('should handle numeric boundaries', () => {
      expect(safeInteger(1, 100).safeParse(1).success).toBe(true)
      expect(safeInteger(1, 100).safeParse(100).success).toBe(true)
      expect(safeInteger(1, 100).safeParse(0).success).toBe(false)
      expect(safeInteger(1, 100).safeParse(101).success).toBe(false)

      expect(safeFloat(0, 1).safeParse(0).success).toBe(true)
      expect(safeFloat(0, 1).safeParse(1).success).toBe(true)
      expect(safeFloat(0, 1).safeParse(-0.1).success).toBe(false)
      expect(safeFloat(0, 1).safeParse(1.1).success).toBe(false)
    })

    test('should handle UUID format validation', () => {
      const validUuids = [
        '123e4567-e89b-12d3-a456-426614174000',
        '00000000-0000-0000-0000-000000000000',
        'ffffffff-ffff-ffff-ffff-ffffffffffff',
      ]

      const invalidUuids = [
        '123e4567-e89b-12d3-a456-42661417400', // Too short
        '123e4567-e89b-12d3-a456-4266141740000', // Too long
        '123e4567-e89b-12d3-a456-42661417400g', // Invalid character
        'not-a-uuid',
        '',
      ]

      validUuids.forEach(uuid => {
        expect(safeUuid.safeParse(uuid).success).toBe(true)
      })

      invalidUuids.forEach(uuid => {
        expect(safeUuid.safeParse(uuid).success).toBe(false)
      })
    })
  })

  describe('Performance and Stress Testing', () => {
    test('should handle large valid inputs efficiently', () => {
      const largeValidInput = 'a'.repeat(1000)
      const startTime = Date.now()

      const result = safeText(2000).safeParse(largeValidInput)
      const endTime = Date.now()

      expect(result.success).toBe(true)
      expect(endTime - startTime).toBeLessThan(100) // Should complete in under 100ms
    })

    test('should handle multiple validation calls efficiently', () => {
      const testData = Array(100).fill(0).map((_, i) => ({
        campaignId: '123e4567-e89b-12d3-a456-426614174000',
        name: `Business ${i}`,
        email: `business${i}@example.com`,
      }))

      const startTime = Date.now()

      testData.forEach(data => {
        BusinessInputSchema.safeParse(data)
      })

      const endTime = Date.now()
      expect(endTime - startTime).toBeLessThan(1000) // Should complete in under 1 second
    })
  })
})
