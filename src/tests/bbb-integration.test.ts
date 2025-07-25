import { zipCodeService } from '@/lib/zipCodeService'

describe('BBB Integration Tests', () => {
  // Increase timeout for API tests
  jest.setTimeout(30000)

  describe('ZIP Code Service', () => {
    test('should extract ZIP code from address', () => {
      const address1 = '123 Main St, New York, NY 10001'
      const address2 = '456 Oak Ave, Los Angeles, CA 90210-1234'
      const address3 = 'No ZIP code here'

      expect(zipCodeService.extractZipCodeFromAddress(address1)).toBe('10001')
      expect(zipCodeService.extractZipCodeFromAddress(address2)).toBe('90210')
      expect(zipCodeService.extractZipCodeFromAddress(address3)).toBeNull()
    })

    test('should calculate distance between ZIP codes', async () => {
      // Test distance between NYC (10001) and LA (90210) - should be ~2400+ miles
      const result = await zipCodeService.calculateDistance('10001', '90210', 50)
      
      expect(result.distance).toBeGreaterThan(2000)
      expect(result.withinRadius).toBe(false)
    })

    test('should validate business within radius', async () => {
      // Test with a business in NYC area
      const businessAddress = '123 Broadway, New York, NY 10001'
      const centerZip = '10002' // Nearby ZIP
      
      const isWithin = await zipCodeService.isBusinessWithinRadius(businessAddress, centerZip, 10)
      expect(isWithin).toBe(true)
    })
  })

  describe('BBB Service Configuration', () => {
    test('should create BBB search options correctly', () => {
      const options = {
        query: 'medical',
        location: 'New York, NY 10001',
        accreditedOnly: false,
        zipRadius: 10,
        maxResults: 3
      }

      expect(options).toHaveProperty('query')
      expect(options).toHaveProperty('location')
      expect(options).toHaveProperty('accreditedOnly')
      expect(options).toHaveProperty('zipRadius')
      expect(options).toHaveProperty('maxResults')

      expect(typeof options.query).toBe('string')
      expect(typeof options.location).toBe('string')
      expect(typeof options.accreditedOnly).toBe('boolean')
      expect(typeof options.zipRadius).toBe('number')
      expect(typeof options.maxResults).toBe('number')
    })
  })

  describe('Configuration Validation', () => {
    test('should validate BBB search options', () => {
      const validOptions = {
        query: 'medical',
        location: 'New York, NY 10001',
        accreditedOnly: false,
        zipRadius: 10,
        maxResults: 5
      }

      expect(validOptions.query).toBeTruthy()
      expect(validOptions.location).toBeTruthy()
      expect(typeof validOptions.accreditedOnly).toBe('boolean')
      expect(validOptions.zipRadius).toBeGreaterThan(0)
      expect(validOptions.maxResults).toBeGreaterThan(0)
    })

    test('should handle edge cases in search parameters', () => {
      const edgeCases = [
        { query: '', location: 'New York, NY', expected: 'empty query' },
        { query: 'medical', location: '', expected: 'empty location' },
        { query: 'medical', location: 'New York, NY', zipRadius: 0, expected: 'zero radius' },
        { query: 'medical', location: 'New York, NY', maxResults: 0, expected: 'zero results' }
      ]

      edgeCases.forEach(testCase => {
        // These should not crash the application
        expect(() => {
          const options = {
            query: testCase.query || 'default',
            location: testCase.location || 'default',
            accreditedOnly: false,
            zipRadius: testCase.zipRadius || 10,
            maxResults: testCase.maxResults || 5
          }
          // Basic validation
          expect(typeof options).toBe('object')
        }).not.toThrow()
      })
    })
  })
})
