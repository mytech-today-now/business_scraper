/**
 * Comprehensive Business Rule Validation Tests for General Validation Utilities
 * Tests business logic validation, data processing workflows, and constraint enforcement
 */

import { ValidationService } from '@/utils/validation'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'

describe('Validation Service - Business Rules', () => {
  let validationService: ValidationService

  beforeEach(() => {
    validationService = new ValidationService()
  })

  describe('Business Record Validation Rules', () => {
    const validBusinessRecord: BusinessRecord = {
      id: 'business-123',
      businessName: 'Acme Corporation',
      email: ['contact@acme.com', 'sales@acme.com'],
      phone: '+1-555-123-4567',
      websiteUrl: 'https://acme.com',
      address: {
        street: '123 Main Street',
        suite: 'Suite 100',
        city: 'Anytown',
        state: 'CA',
        zipCode: '12345',
      },
      contactPerson: 'John Doe',
      coordinates: {
        lat: 40.7128,
        lng: -74.0060,
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    }

    test('should validate complete business record', () => {
      const result = validationService.validateBusinessRecord(validBusinessRecord)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    test('should require essential business information', () => {
      const incompleteRecord = {
        ...validBusinessRecord,
        businessName: '',
        email: [],
        websiteUrl: '',
      }

      const result = validationService.validateBusinessRecord(incompleteRecord)
      expect(result.isValid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
      expect(result.errors.some(error => error.includes('Business name'))).toBe(true)
    })

    test('should validate email format and constraints', () => {
      const invalidEmails = [
        'invalid-email',
        'test@',
        '@domain.com',
        'test..test@domain.com',
        'test@domain',
        'a'.repeat(250) + '@domain.com', // Too long
      ]

      invalidEmails.forEach(email => {
        const record = { ...validBusinessRecord, email: [email] }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(false)
        expect(result.errors.some(error => error.toLowerCase().includes('email'))).toBe(true)
      })
    })

    test('should validate phone number business rules', () => {
      const validPhones = [
        '+1-555-123-4567',
        '(555) 123-4567',
        '555.123.4567',
        '5551234567',
        '+44 20 7946 0958',
        '+1 800 555 0123',
      ]

      validPhones.forEach(phone => {
        const record = { ...validBusinessRecord, phone }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(true)
      })

      const invalidPhones = [
        'abc-def-ghij',
        '123',
        'phone number',
        '555-123-456789012345', // Too long
        '555-123-456a', // Contains letters
      ]

      invalidPhones.forEach(phone => {
        const record = { ...validBusinessRecord, phone }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(false)
      })
    })

    test('should validate website URL business rules', () => {
      const validUrls = [
        'https://example.com',
        'http://subdomain.example.com',
        'https://example.com/path?query=value',
        'https://example.com:8080',
        'https://www.example-business.com',
      ]

      validUrls.forEach(websiteUrl => {
        const record = { ...validBusinessRecord, websiteUrl }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(true)
      })

      const invalidUrls = [
        'not-a-url',
        'ftp://example.com',
        'javascript:alert(1)',
        'http://',
        'https://',
        'example.com', // Missing protocol
      ]

      invalidUrls.forEach(websiteUrl => {
        const record = { ...validBusinessRecord, websiteUrl }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(false)
      })
    })

    test('should validate address components', () => {
      const validAddresses = [
        {
          street: '123 Main Street',
          city: 'Anytown',
          state: 'CA',
          zipCode: '12345',
        },
        {
          street: '456 Oak Avenue',
          suite: 'Apt 2B',
          city: 'Another City',
          state: 'NY',
          zipCode: '12345-6789',
        },
      ]

      validAddresses.forEach(address => {
        const record = { ...validBusinessRecord, address }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(true)
      })

      const invalidAddresses = [
        {
          street: '', // Empty street
          city: 'Anytown',
          state: 'CA',
          zipCode: '12345',
        },
        {
          street: '123 Main Street',
          city: '', // Empty city
          state: 'CA',
          zipCode: '12345',
        },
        {
          street: '123 Main Street',
          city: 'Anytown',
          state: 'CAL', // Invalid state (too long)
          zipCode: '12345',
        },
        {
          street: '123 Main Street',
          city: 'Anytown',
          state: 'CA',
          zipCode: '1234', // Invalid ZIP code
        },
      ]

      invalidAddresses.forEach(address => {
        const record = { ...validBusinessRecord, address }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(false)
      })
    })

    test('should validate coordinate boundaries', () => {
      const validCoordinates = [
        { lat: 0, lng: 0 },
        { lat: 90, lng: 180 },
        { lat: -90, lng: -180 },
        { lat: 40.7128, lng: -74.0060 },
        { lat: 37.7749, lng: -122.4194 }, // San Francisco
      ]

      validCoordinates.forEach(coordinates => {
        const record = { ...validBusinessRecord, coordinates }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(true)
      })

      const invalidCoordinates = [
        { lat: 91, lng: 0 }, // Latitude too high
        { lat: -91, lng: 0 }, // Latitude too low
        { lat: 0, lng: 181 }, // Longitude too high
        { lat: 0, lng: -181 }, // Longitude too low
        { lat: NaN, lng: 0 }, // Invalid number
        { lat: 0, lng: Infinity }, // Invalid number
      ]

      invalidCoordinates.forEach(coordinates => {
        const record = { ...validBusinessRecord, coordinates }
        const result = validationService.validateBusinessRecord(record)
        expect(result.isValid).toBe(false)
      })
    })
  })

  describe('Scraping Configuration Validation Rules', () => {
    const validConfig: ScrapingConfig = {
      industries: ['Technology', 'Healthcare'],
      zipCode: '12345',
      searchRadius: 25,
      searchDepth: 3,
      pagesPerSite: 10,
      searchResultPages: 3,
      maxSearchResults: 1000,
      bbbAccreditedOnly: false,
      zipRadius: 25,
    }

    test('should validate complete scraping configuration', () => {
      const result = validationService.validateScrapingConfig(validConfig)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    test('should require at least one industry', () => {
      const configWithoutIndustries = { ...validConfig, industries: [] }
      const result = validationService.validateScrapingConfig(configWithoutIndustries)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('industry'))).toBe(true)
    })

    test('should validate ZIP code format', () => {
      const validZipCodes = ['12345', '12345-6789']

      validZipCodes.forEach(zipCode => {
        const config = { ...validConfig, zipCode }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(true)
      })

      const invalidZipCodes = ['1234', '123456', 'ABCDE', '12345-678', 'invalid']

      invalidZipCodes.forEach(zipCode => {
        const config = { ...validConfig, zipCode }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(false)
      })
    })

    test('should validate search parameter ranges', () => {
      const validRanges = [
        { searchRadius: 1, searchDepth: 1, pagesPerSite: 1 },
        { searchRadius: 100, searchDepth: 5, pagesPerSite: 20 },
        { searchRadius: 50, searchDepth: 3, pagesPerSite: 10 },
      ]

      validRanges.forEach(params => {
        const config = { ...validConfig, ...params }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(true)
      })

      const invalidRanges = [
        { searchRadius: 0 }, // Too low
        { searchRadius: 101 }, // Too high
        { searchDepth: 0 }, // Too low
        { searchDepth: 6 }, // Too high
        { pagesPerSite: 0 }, // Too low
        { pagesPerSite: 21 }, // Too high
      ]

      invalidRanges.forEach(params => {
        const config = { ...validConfig, ...params }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(false)
      })
    })

    test('should validate optional parameters', () => {
      const validOptionalParams = [
        { searchResultPages: 1 },
        { searchResultPages: 5 },
        { maxSearchResults: 50 },
        { maxSearchResults: 10000 },
        { zipRadius: 5 },
        { zipRadius: 50 },
      ]

      validOptionalParams.forEach(params => {
        const config = { ...validConfig, ...params }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(true)
      })

      const invalidOptionalParams = [
        { searchResultPages: 0 },
        { searchResultPages: 6 },
        { maxSearchResults: 49 },
        { maxSearchResults: 10001 },
        { zipRadius: 4 },
        { zipRadius: 51 },
      ]

      invalidOptionalParams.forEach(params => {
        const config = { ...validConfig, ...params }
        const result = validationService.validateScrapingConfig(config)
        expect(result.isValid).toBe(false)
      })
    })
  })

  describe('Industry Category Validation Rules', () => {
    const validIndustryCategory: IndustryCategory = {
      id: 'tech-001',
      name: 'Technology',
      keywords: ['software', 'hardware', 'IT', 'computer'],
      isCustom: false,
    }

    test('should validate complete industry category', () => {
      const result = validationService.validateIndustryCategory(validIndustryCategory)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    test('should require essential fields', () => {
      const incompleteCategory = {
        ...validIndustryCategory,
        id: '',
        name: '',
        keywords: [],
      }

      const result = validationService.validateIndustryCategory(incompleteCategory)
      expect(result.isValid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    test('should validate keywords array', () => {
      const validKeywords = [
        ['software'],
        ['software', 'hardware', 'IT'],
        ['technology', 'innovation', 'digital'],
      ]

      validKeywords.forEach(keywords => {
        const category = { ...validIndustryCategory, keywords }
        const result = validationService.validateIndustryCategory(category)
        expect(result.isValid).toBe(true)
      })

      const invalidKeywords = [
        [], // Empty array
        [''], // Empty keyword
        ['   '], // Whitespace only
      ]

      invalidKeywords.forEach(keywords => {
        const category = { ...validIndustryCategory, keywords }
        const result = validationService.validateIndustryCategory(category)
        expect(result.isValid).toBe(false)
      })
    })
  })

  describe('Batch Validation and Performance', () => {
    test('should validate multiple business records efficiently', () => {
      const businesses = Array(50).fill(0).map((_, i) => ({
        id: `business-${i}`,
        businessName: `Business ${i}`,
        email: [`contact${i}@example.com`],
        phone: `555-123-${String(i).padStart(4, '0')}`,
        websiteUrl: `https://business${i}.com`,
        address: {
          street: `${i} Main Street`,
          city: 'Test City',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Technology',
        scrapedAt: new Date(),
      }))

      const startTime = Date.now()
      const summary = validationService.validateBusinessRecords(businesses)
      const endTime = Date.now()

      expect(summary.totalRecords).toBe(50)
      expect(summary.validRecords).toBe(50)
      expect(summary.invalidRecords).toBe(0)
      expect(endTime - startTime).toBeLessThan(1000) // Should complete in under 1 second
    })

    test('should handle mixed valid and invalid records', () => {
      const mixedBusinesses = [
        {
          id: 'valid-1',
          businessName: 'Valid Business',
          email: ['valid@example.com'],
          websiteUrl: 'https://valid.com',
          address: {
            street: '123 Main Street',
            city: 'Valid City',
            state: 'CA',
            zipCode: '12345',
          },
          industry: 'Technology',
          scrapedAt: new Date(),
        },
        {
          id: '', // Invalid - empty ID
          businessName: '',
          email: ['invalid-email'],
          websiteUrl: 'not-a-url',
          address: {
            street: '',
            city: '',
            state: 'INVALID',
            zipCode: '123',
          },
          industry: '',
          scrapedAt: new Date(),
        },
      ]

      const summary = validationService.validateBusinessRecords(mixedBusinesses)
      expect(summary.totalRecords).toBe(2)
      expect(summary.validRecords).toBe(1)
      expect(summary.invalidRecords).toBe(1)
      expect(summary.errors).toHaveLength(1)
      expect(summary.errors[0].index).toBe(1)
    })
  })

  describe('Edge Cases and Error Handling', () => {
    test('should handle null and undefined values gracefully', () => {
      const recordWithNulls = {
        id: 'test-id',
        businessName: 'Test Business',
        email: null as any,
        phone: undefined as any,
        websiteUrl: 'https://test.com',
        address: {
          street: '123 Test Street',
          city: 'Test City',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Technology',
        scrapedAt: new Date(),
      }

      const result = validationService.validateBusinessRecord(recordWithNulls)
      expect(result.isValid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    test('should handle extremely long inputs', () => {
      const longString = 'a'.repeat(10000)
      const recordWithLongInputs = {
        id: 'test-id',
        businessName: longString,
        email: [`${longString}@example.com`],
        websiteUrl: 'https://test.com',
        address: {
          street: longString,
          city: longString,
          state: 'CA',
          zipCode: '12345',
        },
        industry: longString,
        scrapedAt: new Date(),
      }

      const result = validationService.validateBusinessRecord(recordWithLongInputs)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('length') || error.includes('long'))).toBe(true)
    })

    test('should handle special characters and encoding', () => {
      const recordWithSpecialChars = {
        id: 'test-id',
        businessName: 'Café & Restaurant™',
        email: ['café@example.com'],
        websiteUrl: 'https://café-restaurant.com',
        address: {
          street: '123 Café Street',
          city: 'São Paulo',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Food & Beverage',
        scrapedAt: new Date(),
      }

      const result = validationService.validateBusinessRecord(recordWithSpecialChars)
      // Should handle Unicode characters appropriately
      expect(result.isValid).toBe(true)
    })

    test('should validate date constraints', () => {
      const futureDate = new Date(Date.now() + 86400000) // Tomorrow
      const veryOldDate = new Date('1900-01-01')

      const recordWithFutureDate = {
        id: 'test-id',
        businessName: 'Test Business',
        email: ['test@example.com'],
        websiteUrl: 'https://test.com',
        address: {
          street: '123 Test Street',
          city: 'Test City',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Technology',
        scrapedAt: futureDate,
      }

      const result = validationService.validateBusinessRecord(recordWithFutureDate)
      // Future dates should be flagged as warnings or errors
      expect(result.warnings.length > 0 || result.errors.length > 0).toBe(true)
    })
  })

  describe('Business Logic Constraints', () => {
    test('should enforce business-specific validation rules', () => {
      // Test business logic constraints like:
      // - Email domains should be reasonable
      // - Phone numbers should match location
      // - Website URLs should be accessible format

      const businessWithSuspiciousData = {
        id: 'test-id',
        businessName: 'Test Business',
        email: ['test@localhost'], // Suspicious domain
        phone: '+1-555-123-4567',
        websiteUrl: 'http://localhost:3000', // Development URL
        address: {
          street: '123 Test Street',
          city: 'Test City',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Technology',
        scrapedAt: new Date(),
      }

      const result = validationService.validateBusinessRecord(businessWithSuspiciousData)
      // Should generate warnings for suspicious data
      expect(result.warnings.length).toBeGreaterThan(0)
    })

    test('should validate industry-specific constraints', () => {
      const healthcareBusinessWithoutProperInfo = {
        id: 'healthcare-1',
        businessName: 'Medical Practice',
        email: ['info@practice.com'],
        phone: '+1-555-123-4567',
        websiteUrl: 'https://practice.com',
        address: {
          street: '123 Medical Drive',
          city: 'Health City',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Healthcare',
        scrapedAt: new Date(),
      }

      const result = validationService.validateBusinessRecord(healthcareBusinessWithoutProperInfo)
      // Healthcare businesses might have additional validation requirements
      expect(result.isValid).toBe(true) // Basic validation should pass
    })
  })
})
