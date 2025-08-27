import { validationService } from '@/utils/validation'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'

describe('ValidationService', () => {
  describe('validateBusinessRecord', () => {
    const validBusiness: BusinessRecord = {
      id: 'test-123',
      businessName: 'Test Company',
      email: ['test@example.com'],
      phone: '(555) 123-4567',
      websiteUrl: 'https://example.com',
      address: {
        street: '123 Main St',
        city: 'Anytown',
        state: 'CA',
        zipCode: '12345',
      },
      contactPerson: 'John Doe',
      coordinates: {
        lat: 40.7128,
        lng: -74.006,
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    }

    it('should validate a correct business record', () => {
      const result = validationService.validateBusinessRecord(validBusiness)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject business with invalid email', () => {
      const invalidBusiness = {
        ...validBusiness,
        email: ['invalid-email'],
      }
      const result = validationService.validateBusinessRecord(invalidBusiness)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('email'))).toBe(true)
    })

    it('should reject business with invalid phone', () => {
      const invalidBusiness = {
        ...validBusiness,
        phone: 'invalid-phone',
      }
      const result = validationService.validateBusinessRecord(invalidBusiness)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('phone'))).toBe(true)
    })

    it('should reject business with invalid URL', () => {
      const invalidBusiness = {
        ...validBusiness,
        websiteUrl: 'not-a-url',
      }
      const result = validationService.validateBusinessRecord(invalidBusiness)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('websiteUrl'))).toBe(true)
    })

    it('should reject business with invalid ZIP code', () => {
      const invalidBusiness = {
        ...validBusiness,
        address: {
          ...validBusiness.address,
          zipCode: 'invalid',
        },
      }
      const result = validationService.validateBusinessRecord(invalidBusiness)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('zipCode'))).toBe(true)
    })

    it('should warn about missing contact information', () => {
      const businessWithoutContact = {
        ...validBusiness,
        email: [],
        phone: undefined,
      }
      const result = validationService.validateBusinessRecord(businessWithoutContact)
      expect(result.warnings.some(warning => warning.includes('no email or phone contact'))).toBe(
        true
      )
    })

    it('should warn about suspicious business names', () => {
      const suspiciousBusiness = {
        ...validBusiness,
        businessName: 'Test Company',
      }
      const result = validationService.validateBusinessRecord(suspiciousBusiness)
      expect(result.warnings.some(warning => warning.includes('placeholder or test value'))).toBe(
        true
      )
    })

    it('should warn about duplicate emails', () => {
      const businessWithDuplicates = {
        ...validBusiness,
        email: ['test@example.com', 'test@example.com'],
      }
      const result = validationService.validateBusinessRecord(businessWithDuplicates)
      expect(result.warnings.some(warning => warning.includes('duplicate email'))).toBe(true)
    })

    it('should warn about suspicious coordinates', () => {
      const businessWithBadCoords = {
        ...validBusiness,
        coordinates: { lat: 0, lng: 0 },
      }
      const result = validationService.validateBusinessRecord(businessWithBadCoords)
      expect(result.warnings.some(warning => warning.includes('default values'))).toBe(true)
    })
  })

  describe('validateScrapingConfig', () => {
    const validConfig: ScrapingConfig = {
      industries: ['technology', 'healthcare'],
      zipCode: '12345',
      searchRadius: 25,
      searchDepth: 2,
      pagesPerSite: 5,
    }

    it('should validate a correct configuration', () => {
      const result = validationService.validateScrapingConfig(validConfig)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject config with no industries', () => {
      const invalidConfig = {
        ...validConfig,
        industries: [],
      }
      const result = validationService.validateScrapingConfig(invalidConfig)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('industries'))).toBe(true)
    })

    it('should reject config with invalid ZIP code', () => {
      const invalidConfig = {
        ...validConfig,
        zipCode: 'invalid',
      }
      const result = validationService.validateScrapingConfig(invalidConfig)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('zipCode'))).toBe(true)
    })

    it('should reject config with invalid search radius', () => {
      const invalidConfig = {
        ...validConfig,
        searchRadius: 0,
      }
      const result = validationService.validateScrapingConfig(invalidConfig)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('searchRadius'))).toBe(true)
    })

    it('should warn about large search radius', () => {
      const configWithLargeRadius = {
        ...validConfig,
        searchRadius: 75,
      }
      const result = validationService.validateScrapingConfig(configWithLargeRadius)
      expect(result.warnings.some(warning => warning.includes('Large search radius'))).toBe(true)
    })

    it('should warn about high search depth', () => {
      const configWithHighDepth = {
        ...validConfig,
        searchDepth: 4,
      }
      const result = validationService.validateScrapingConfig(configWithHighDepth)
      expect(result.warnings.some(warning => warning.includes('High search depth'))).toBe(true)
    })

    it('should warn about many pages per site', () => {
      const configWithManyPages = {
        ...validConfig,
        pagesPerSite: 15,
      }
      const result = validationService.validateScrapingConfig(configWithManyPages)
      expect(result.warnings.some(warning => warning.includes('High pages per site'))).toBe(true)
    })

    it('should warn about too many industries', () => {
      const configWithManyIndustries = {
        ...validConfig,
        industries: Array.from({ length: 15 }, (_, i) => `industry-${i}`),
      }
      const result = validationService.validateScrapingConfig(configWithManyIndustries)
      expect(result.warnings.some(warning => warning.includes('many industries'))).toBe(true)
    })
  })

  describe('validateIndustryCategory', () => {
    const validIndustry: IndustryCategory = {
      id: 'technology',
      name: 'Technology',
      keywords: ['tech', 'software', 'IT'],
      isCustom: false,
    }

    it('should validate a correct industry category', () => {
      const result = validationService.validateIndustryCategory(validIndustry)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject industry with empty name', () => {
      const invalidIndustry = {
        ...validIndustry,
        name: '',
      }
      const result = validationService.validateIndustryCategory(invalidIndustry)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('name'))).toBe(true)
    })

    it('should reject industry with no keywords', () => {
      const invalidIndustry = {
        ...validIndustry,
        keywords: [],
      }
      const result = validationService.validateIndustryCategory(invalidIndustry)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('keywords'))).toBe(true)
    })

    it('should reject industry with empty keywords', () => {
      const invalidIndustry = {
        ...validIndustry,
        keywords: ['', 'valid'],
      }
      const result = validationService.validateIndustryCategory(invalidIndustry)
      expect(result.isValid).toBe(false)
      expect(result.errors.some(error => error.includes('Keyword cannot be empty'))).toBe(true)
    })
  })

  describe('individual validation methods', () => {
    it('should validate emails correctly', () => {
      expect(validationService.validateEmail('test@example.com')).toBe(true)
      expect(validationService.validateEmail('user.name+tag@domain.co.uk')).toBe(true)
      expect(validationService.validateEmail('invalid-email')).toBe(false)
      expect(validationService.validateEmail('user@')).toBe(false)
      expect(validationService.validateEmail('@domain.com')).toBe(false)
    })

    it('should validate phone numbers correctly', () => {
      expect(validationService.validatePhoneNumber('(555) 123-4567')).toBe(true)
      expect(validationService.validatePhoneNumber('555-123-4567')).toBe(true)
      expect(validationService.validatePhoneNumber('5551234567')).toBe(true)
      expect(validationService.validatePhoneNumber('1-555-123-4567')).toBe(true)
      expect(validationService.validatePhoneNumber('invalid')).toBe(false)
      expect(validationService.validatePhoneNumber('123')).toBe(false)
    })

    it('should validate URLs correctly', () => {
      expect(validationService.validateUrl('https://example.com')).toBe(true)
      expect(validationService.validateUrl('http://www.example.org')).toBe(true)
      expect(validationService.validateUrl('https://subdomain.example.net/path')).toBe(true)
      expect(validationService.validateUrl('not-a-url')).toBe(false)
      expect(validationService.validateUrl('ftp://example.com')).toBe(false)
    })

    it('should validate ZIP codes correctly', () => {
      expect(validationService.validateZipCode('12345')).toBe(true)
      expect(validationService.validateZipCode('12345-6789')).toBe(true)
      expect(validationService.validateZipCode('invalid')).toBe(false)
      expect(validationService.validateZipCode('123')).toBe(false)
      expect(validationService.validateZipCode('123456')).toBe(false)
    })
  })

  describe('sanitizeInput', () => {
    it('should remove script tags', () => {
      const input = '<script>alert("xss")</script>Hello World'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello World')
    })

    it('should remove HTML tags', () => {
      const input = '<p>Hello <strong>World</strong></p>'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello World')
    })

    it('should remove special characters and escape dangerous ones', () => {
      const input = 'Hello<>{}[]|\\World'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello&lt;&gt;{}[]|\\World')
    })

    it('should preserve allowed characters and escape dangerous ones', () => {
      const input = 'Hello World! user@example.com 123-456-7890'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello World! user@example.com 123-456-7890')
    })

    it('should escape HTML entities', () => {
      const input = 'Hello & "World" <script>'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello &amp; &quot;World&quot; &lt;script&gt;')
    })

    it('should trim whitespace', () => {
      const input = '  Hello World  '
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('Hello World')
    })

    it('should remove javascript: URLs', () => {
      const input = 'javascript:alert("xss")'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe('alert(&quot;xss&quot;)')
    })

    it('should remove event handlers', () => {
      const input = 'onclick="alert(1)" onload="malicious()"'
      const result = validationService.sanitizeInput(input)
      expect(result).toBe(' ')
    })
  })

  describe('validateInputSecurity', () => {
    it('should pass for safe input', () => {
      const input = 'Hello World 123'
      const result = validationService.validateInputSecurity(input)
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should detect SQL injection patterns', () => {
      const input = "'; DROP TABLE users; --"
      const result = validationService.validateInputSecurity(input)
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains potentially dangerous SQL patterns')
    })

    it('should detect XSS patterns', () => {
      const input = '<script>alert("xss")</script>'
      const result = validationService.validateInputSecurity(input)
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains potentially dangerous XSS patterns')
    })

    it('should detect path traversal patterns', () => {
      const input = '../../../etc/passwd'
      const result = validationService.validateInputSecurity(input)
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Input contains path traversal patterns')
    })

    it('should warn about command injection patterns', () => {
      const input = 'file.txt; cat /etc/passwd'
      const result = validationService.validateInputSecurity(input)
      expect(result.warnings).toContain(
        'Input contains characters or commands that could be dangerous'
      )
    })
  })

  describe('validateBusinessArray', () => {
    const validBusiness: BusinessRecord = {
      id: 'test-1',
      businessName: 'Valid Company',
      email: ['valid@example.com'],
      websiteUrl: 'https://example.com',
      address: {
        street: '123 Main St',
        city: 'Anytown',
        state: 'CA',
        zipCode: '12345',
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    }

    const invalidBusiness = {
      ...validBusiness,
      id: 'test-2',
      email: ['invalid-email'],
    }

    it('should validate array of business records', () => {
      const businesses = [validBusiness, invalidBusiness]
      const result = validationService.validateBusinessArray(businesses)

      expect(result.totalRecords).toBe(2)
      expect(result.validRecords).toBe(1)
      expect(result.invalidRecords).toBe(1)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0]?.index).toBe(1)
    })

    it('should handle empty array', () => {
      const result = validationService.validateBusinessArray([])
      expect(result.totalRecords).toBe(0)
      expect(result.validRecords).toBe(0)
      expect(result.invalidRecords).toBe(0)
      expect(result.errors).toHaveLength(0)
    })
  })
})
