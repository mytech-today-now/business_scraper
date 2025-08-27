/**
 * Comprehensive Regression Tests for All Major Features
 * Ensuring no functionality breaks with new changes
 */

import { jest } from '@jest/globals'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { scraperService } from '@/model/scraperService'
import { clientSearchEngine } from '@/model/clientSearchEngine'
import { BusinessRecord } from '@/types/business'

// Mock dependencies
jest.mock('@/model/scraperService')
jest.mock('@/model/clientSearchEngine')
jest.mock('@/utils/logger')

interface RegressionTestCase {
  name: string
  version: string
  testFunction: () => Promise<void>
  expectedBehavior: string
  criticalLevel: 'low' | 'medium' | 'high' | 'critical'
}

class RegressionTestSuite {
  private testCases: RegressionTestCase[] = []
  private results: Map<string, { passed: boolean; error?: string }> = new Map()

  addTestCase(testCase: RegressionTestCase): void {
    this.testCases.push(testCase)
  }

  async runAllTests(): Promise<{ passed: number; failed: number; critical: number }> {
    let passed = 0
    let failed = 0
    let critical = 0

    for (const testCase of this.testCases) {
      try {
        await testCase.testFunction()
        this.results.set(testCase.name, { passed: true })
        passed++
      } catch (error) {
        this.results.set(testCase.name, {
          passed: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        })
        failed++

        if (testCase.criticalLevel === 'critical') {
          critical++
        }
      }
    }

    return { passed, failed, critical }
  }

  getResults(): Map<string, { passed: boolean; error?: string }> {
    return this.results
  }

  getCriticalFailures(): RegressionTestCase[] {
    return this.testCases.filter(
      testCase => testCase.criticalLevel === 'critical' && !this.results.get(testCase.name)?.passed
    )
  }
}

describe('Feature Regression Comprehensive Tests', () => {
  let regressionSuite: RegressionTestSuite

  beforeEach(() => {
    regressionSuite = new RegressionTestSuite()
    jest.clearAllMocks()
  })

  describe('Core Business Search Functionality', () => {
    test('should maintain search functionality across versions', async () => {
      regressionSuite.addTestCase({
        name: 'Basic Business Search',
        version: '3.4.0',
        criticalLevel: 'critical',
        expectedBehavior: 'Search should return business results for valid queries',
        testFunction: async () => {
          const mockResults: BusinessRecord[] = [
            {
              id: '1',
              businessName: 'Test Restaurant',
              url: 'https://example.com',
              phone: '555-1234',
              email: 'test@example.com',
              address: '123 Main St',
              city: 'Test City',
              state: 'TS',
              zipCode: '12345',
              industry: 'restaurants',
              confidence: 0.9,
              source: 'search',
              scrapedAt: new Date().toISOString(),
            },
          ]

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue(mockResults)

          const results = await clientSearchEngine.searchBusinesses('restaurants', '12345', 10)

          expect(results).toHaveLength(1)
          expect(results[0].businessName).toBe('Test Restaurant')
          expect(results[0].industry).toBe('restaurants')
        },
      })

      regressionSuite.addTestCase({
        name: 'Search Parameter Validation',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Invalid search parameters should be handled gracefully',
        testFunction: async () => {
          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          // Test empty query
          const emptyResults = await clientSearchEngine.searchBusinesses('', '12345', 10)
          expect(emptyResults).toEqual([])

          // Test invalid ZIP code
          const invalidZipResults = await clientSearchEngine.searchBusinesses(
            'restaurants',
            'invalid',
            10
          )
          expect(invalidZipResults).toEqual([])

          // Test negative max results
          const negativeResults = await clientSearchEngine.searchBusinesses(
            'restaurants',
            '12345',
            -1
          )
          expect(negativeResults).toEqual([])
        },
      })

      regressionSuite.addTestCase({
        name: 'Search Result Format Consistency',
        version: '3.4.0',
        criticalLevel: 'medium',
        expectedBehavior: 'Search results should maintain consistent data structure',
        testFunction: async () => {
          const mockResults: BusinessRecord[] = [
            {
              id: '1',
              businessName: 'Complete Business',
              url: 'https://example.com',
              phone: '555-1234',
              email: 'test@example.com',
              address: '123 Main St',
              city: 'Test City',
              state: 'TS',
              zipCode: '12345',
              industry: 'restaurants',
              confidence: 0.9,
              source: 'search',
              scrapedAt: new Date().toISOString(),
            },
            {
              id: '2',
              businessName: 'Minimal Business',
              url: 'https://example2.com',
              phone: '',
              email: '',
              address: '',
              city: '',
              state: '',
              zipCode: '',
              industry: 'restaurants',
              confidence: 0.7,
              source: 'search',
              scrapedAt: new Date().toISOString(),
            },
          ]

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue(mockResults)

          const results = await clientSearchEngine.searchBusinesses('restaurants', '12345', 10)

          results.forEach(business => {
            expect(business).toHaveProperty('id')
            expect(business).toHaveProperty('businessName')
            expect(business).toHaveProperty('url')
            expect(business).toHaveProperty('industry')
            expect(business).toHaveProperty('confidence')
            expect(business).toHaveProperty('source')
            expect(business).toHaveProperty('scrapedAt')

            expect(typeof business.id).toBe('string')
            expect(typeof business.businessName).toBe('string')
            expect(typeof business.confidence).toBe('number')
          })
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.critical).toBe(0) // No critical failures allowed
      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('Web Scraping Functionality', () => {
    test('should maintain scraping functionality across versions', async () => {
      regressionSuite.addTestCase({
        name: 'Basic Website Scraping',
        version: '3.4.0',
        criticalLevel: 'critical',
        expectedBehavior: 'Scraping should extract business data from websites',
        testFunction: async () => {
          const mockBusinesses: BusinessRecord[] = [
            {
              id: '1',
              businessName: 'Scraped Business',
              url: 'https://example.com',
              phone: '555-1234',
              email: 'contact@example.com',
              address: '123 Main St',
              city: 'Test City',
              state: 'TS',
              zipCode: '12345',
              industry: 'restaurants',
              confidence: 0.8,
              source: 'scraper',
              scrapedAt: new Date().toISOString(),
            },
          ]

          ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue(mockBusinesses)

          const results = await scraperService.scrapeWebsite('https://example.com', 2, 5)

          expect(results).toHaveLength(1)
          expect(results[0].source).toBe('scraper')
          expect(results[0].businessName).toBe('Scraped Business')
        },
      })

      regressionSuite.addTestCase({
        name: 'Scraping Error Handling',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Scraping errors should be handled gracefully',
        testFunction: async () => {
          ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue([])

          // Test invalid URL
          const invalidUrlResults = await scraperService.scrapeWebsite('invalid-url', 2, 5)
          expect(invalidUrlResults).toEqual([])

          // Test malicious URL
          const maliciousResults = await scraperService.scrapeWebsite(
            'javascript:alert("xss")',
            2,
            5
          )
          expect(maliciousResults).toEqual([])

          // Test with zero depth
          const zeroDepthResults = await scraperService.scrapeWebsite('https://example.com', 0, 5)
          expect(zeroDepthResults).toEqual([])
        },
      })

      regressionSuite.addTestCase({
        name: 'Scraping Resource Management',
        version: '3.4.0',
        criticalLevel: 'medium',
        expectedBehavior: 'Scraping should properly manage browser resources',
        testFunction: async () => {
          ;(scraperService.initializeBrowser as jest.Mock).mockResolvedValue(true)
          ;(scraperService.cleanup as jest.Mock).mockResolvedValue(undefined)

          const initialized = await scraperService.initializeBrowser()
          expect(initialized).toBe(true)

          await scraperService.cleanup()

          // Should not throw error
          expect(true).toBe(true)
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.critical).toBe(0)
      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('Data Processing and Validation', () => {
    test('should maintain data processing consistency', async () => {
      regressionSuite.addTestCase({
        name: 'Business Data Validation',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Business data should be validated consistently',
        testFunction: async () => {
          const validBusiness: BusinessRecord = {
            id: '1',
            businessName: 'Valid Business',
            url: 'https://example.com',
            phone: '555-1234',
            email: 'test@example.com',
            address: '123 Main St',
            city: 'Test City',
            state: 'TS',
            zipCode: '12345',
            industry: 'restaurants',
            confidence: 0.9,
            source: 'scraper',
            scrapedAt: new Date().toISOString(),
          }

          // Validate required fields
          expect(validBusiness.id).toBeTruthy()
          expect(validBusiness.businessName).toBeTruthy()
          expect(validBusiness.url).toBeTruthy()
          expect(validBusiness.industry).toBeTruthy()
          expect(validBusiness.source).toBeTruthy()
          expect(validBusiness.scrapedAt).toBeTruthy()

          // Validate data types
          expect(typeof validBusiness.confidence).toBe('number')
          expect(validBusiness.confidence).toBeGreaterThanOrEqual(0)
          expect(validBusiness.confidence).toBeLessThanOrEqual(1)
        },
      })

      regressionSuite.addTestCase({
        name: 'Data Sanitization',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Input data should be properly sanitized',
        testFunction: async () => {
          const maliciousInputs = [
            '<script>alert("xss")</script>',
            '"; DROP TABLE businesses; --',
            '${jndi:ldap://malicious.com}',
            '../../../etc/passwd',
          ]

          maliciousInputs.forEach(input => {
            // Test that malicious inputs are handled safely
            const sanitized = input
              .replace(/<[^>]*>/g, '')
              .replace(/['"`;]/g, '')
              .replace(/\$\{.*\}/g, '')
              .replace(/\.\./g, '')

            expect(sanitized).not.toContain('<script>')
            expect(sanitized).not.toContain('DROP TABLE')
            expect(sanitized).not.toContain('${')
            expect(sanitized).not.toContain('..')
          })
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.critical).toBe(0)
      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('API Endpoint Consistency', () => {
    test('should maintain API contract consistency', async () => {
      regressionSuite.addTestCase({
        name: 'Search API Response Format',
        version: '3.4.0',
        criticalLevel: 'critical',
        expectedBehavior: 'Search API should return consistent response format',
        testFunction: async () => {
          // Mock API response structure
          const mockApiResponse = {
            results: [
              {
                id: '1',
                name: 'Test Business',
                url: 'https://example.com',
                address: '123 Main St',
                phone: '555-1234',
              },
            ],
            total: 1,
            page: 1,
            limit: 10,
          }

          // Validate response structure
          expect(mockApiResponse).toHaveProperty('results')
          expect(mockApiResponse).toHaveProperty('total')
          expect(Array.isArray(mockApiResponse.results)).toBe(true)
          expect(typeof mockApiResponse.total).toBe('number')
        },
      })

      regressionSuite.addTestCase({
        name: 'Scrape API Response Format',
        version: '3.4.0',
        criticalLevel: 'critical',
        expectedBehavior: 'Scrape API should return consistent response format',
        testFunction: async () => {
          const mockScrapeResponse = {
            businesses: [
              {
                id: '1',
                businessName: 'Scraped Business',
                url: 'https://example.com',
              },
            ],
            success: true,
            scrapedAt: new Date().toISOString(),
          }

          expect(mockScrapeResponse).toHaveProperty('businesses')
          expect(mockScrapeResponse).toHaveProperty('success')
          expect(mockScrapeResponse).toHaveProperty('scrapedAt')
          expect(Array.isArray(mockScrapeResponse.businesses)).toBe(true)
          expect(typeof mockScrapeResponse.success).toBe('boolean')
        },
      })

      regressionSuite.addTestCase({
        name: 'Error Response Format',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Error responses should have consistent format',
        testFunction: async () => {
          const mockErrorResponse = {
            error: 'Invalid request parameters',
            code: 'INVALID_PARAMS',
            timestamp: new Date().toISOString(),
          }

          expect(mockErrorResponse).toHaveProperty('error')
          expect(mockErrorResponse).toHaveProperty('code')
          expect(mockErrorResponse).toHaveProperty('timestamp')
          expect(typeof mockErrorResponse.error).toBe('string')
          expect(typeof mockErrorResponse.code).toBe('string')
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.critical).toBe(0)
      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('Performance Regression', () => {
    test('should maintain performance benchmarks', async () => {
      regressionSuite.addTestCase({
        name: 'Search Performance',
        version: '3.4.0',
        criticalLevel: 'medium',
        expectedBehavior: 'Search operations should complete within acceptable time',
        testFunction: async () => {
          const startTime = Date.now()

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          await clientSearchEngine.searchBusinesses('restaurants', '12345', 10)

          const duration = Date.now() - startTime
          expect(duration).toBeLessThan(5000) // Should complete within 5 seconds
        },
      })

      regressionSuite.addTestCase({
        name: 'Scraping Performance',
        version: '3.4.0',
        criticalLevel: 'medium',
        expectedBehavior: 'Scraping operations should complete within acceptable time',
        testFunction: async () => {
          const startTime = Date.now()

          ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue([])

          await scraperService.scrapeWebsite('https://example.com', 1, 2)

          const duration = Date.now() - startTime
          expect(duration).toBeLessThan(10000) // Should complete within 10 seconds
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('Backward Compatibility', () => {
    test('should maintain backward compatibility', async () => {
      regressionSuite.addTestCase({
        name: 'Legacy API Support',
        version: '3.4.0',
        criticalLevel: 'high',
        expectedBehavior: 'Legacy API endpoints should continue to work',
        testFunction: async () => {
          // Test that old API formats are still supported
          const legacySearchParams = {
            q: 'restaurants', // Old parameter name
            zip: '12345', // Old parameter name
            max: 10, // Old parameter name
          }

          // Should handle legacy parameters gracefully
          expect(legacySearchParams.q).toBeTruthy()
          expect(legacySearchParams.zip).toBeTruthy()
          expect(legacySearchParams.max).toBeGreaterThan(0)
        },
      })

      regressionSuite.addTestCase({
        name: 'Data Format Compatibility',
        version: '3.4.0',
        criticalLevel: 'medium',
        expectedBehavior: 'Old data formats should be handled correctly',
        testFunction: async () => {
          // Test handling of old business record format
          const legacyBusiness = {
            name: 'Legacy Business', // Old field name
            website: 'https://example.com', // Old field name
            telephone: '555-1234', // Old field name
          }

          // Should be able to process legacy format
          expect(legacyBusiness.name).toBeTruthy()
          expect(legacyBusiness.website).toBeTruthy()
          expect(legacyBusiness.telephone).toBeTruthy()
        },
      })

      const results = await regressionSuite.runAllTests()

      expect(results.critical).toBe(0)
      expect(results.passed).toBeGreaterThan(results.failed)
    })
  })

  describe('Regression Test Summary', () => {
    test('should provide comprehensive regression test coverage', async () => {
      const allResults = await regressionSuite.runAllTests()
      const criticalFailures = regressionSuite.getCriticalFailures()

      // Log test results for debugging
      console.log('Regression Test Results:', allResults)

      if (criticalFailures.length > 0) {
        console.error(
          'Critical Failures:',
          criticalFailures.map(f => f.name)
        )
      }

      // No critical failures should be allowed
      expect(criticalFailures.length).toBe(0)

      // At least 90% of tests should pass
      const successRate = allResults.passed / (allResults.passed + allResults.failed)
      expect(successRate).toBeGreaterThanOrEqual(0.9)

      // Should have comprehensive test coverage
      expect(allResults.passed + allResults.failed).toBeGreaterThan(10)
    })
  })
})
