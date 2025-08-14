/**
 * Integration Tests for API Endpoints
 * Comprehensive test suite for all API endpoints and their interactions
 */

import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals'

// Mock API functions since we don't have the actual implementations yet
const mockApiResponse = (data: unknown, status = 200): { json: jest.Mock; status: number } => ({
  json: jest.fn().mockResolvedValue(data),
  status,
})

// Mock external dependencies
jest.mock('@/lib/postgresql-database', () => ({
  database: {
    query: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn()
  }
}))

jest.mock('@/lib/enhancedScrapingEngine', () => ({
  enhancedScrapingEngine: {
    initialize: jest.fn(),
    addJob: jest.fn(),
    getJobStatus: jest.fn(),
    getStats: jest.fn(),
    cancelJob: jest.fn(),
    shutdown: jest.fn()
  }
}))

describe('API Integration Tests', () => {
  beforeAll(async () => {
    // Setup test environment
    process.env.NODE_ENV = 'test'
  })

  afterAll(async () => {
    // Cleanup test environment
  })

  describe('Enhanced Scraping API (/api/enhanced-scrape)', () => {
    describe('POST requests', () => {
      it('should initialize scraping engine', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({ action: 'initialize' }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.message).toContain('initialized')
      })

      it('should add a scraping job', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'add-job',
            url: 'https://example.com',
            depth: 2,
            priority: 5
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.jobId).toBeDefined()
        expect(data.url).toBe('https://example.com')
        expect(data.depth).toBe(2)
        expect(data.priority).toBe(5)
      })

      it('should validate URL parameter', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'add-job'
            // Missing URL
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toContain('URL parameter is required')
      })

      it('should validate URL format', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'add-job',
            url: 'not-a-valid-url'
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toContain('Invalid URL format')
      })

      it('should add multiple jobs', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'add-multiple-jobs',
            urls: ['https://example1.com', 'https://example2.com'],
            depth: 3,
            priority: 7
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.jobIds).toHaveLength(2)
        expect(data.totalJobs).toBe(2)
      })

      it('should limit batch job size', async () => {
        const urls = Array(51).fill('https://example.com')
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'add-multiple-jobs',
            urls
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toContain('Maximum 50 URLs allowed')
      })

      it('should get job status', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'get-job-status',
            jobId: 'test-job-id'
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.job).toBeDefined()
      })

      it('should cancel a job', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'cancel-job',
            jobId: 'test-job-id'
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBeDefined()
      })

      it('should handle invalid actions', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
          method: 'POST',
          body: JSON.stringify({
            action: 'invalid-action'
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await enhancedScrapePost(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toBe('Invalid action')
      })
    })

    describe('GET requests', () => {
      it('should get scraping statistics', async () => {
        const request = new NextRequest('http://localhost:3000/api/enhanced-scrape')

        const response = await enhancedScrapeGet(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.stats).toBeDefined()
        expect(data.timestamp).toBeDefined()
      })
    })
  })

  describe('Data Management API (/api/data-management)', () => {
    describe('POST requests', () => {
      it('should validate business data', async () => {
        const mockBusiness = {
          id: 'test-1',
          businessName: 'Test Business',
          industry: 'Technology',
          email: ['test@example.com'],
          phone: '(555) 123-4567',
          website: 'https://example.com',
          address: {
            street: '123 Main St',
            city: 'New York',
            state: 'NY',
            zipCode: '10001'
          },
          scrapedAt: new Date(),
          confidence: 0.85
        }

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'validate-business',
            business: mockBusiness
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.validation).toBeDefined()
        expect(data.validation.isValid).toBeDefined()
        expect(data.validation.confidence).toBeDefined()
      })

      it('should validate batch of businesses', async () => {
        const mockBusinesses = [
          {
            id: 'test-1',
            businessName: 'Test Business 1',
            industry: 'Technology',
            email: ['test1@example.com'],
            phone: '(555) 123-4567'
          },
          {
            id: 'test-2',
            businessName: 'Test Business 2',
            industry: 'Healthcare',
            email: ['test2@example.com'],
            phone: '(555) 987-6543'
          }
        ]

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'validate-batch',
            businesses: mockBusinesses
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.results).toHaveLength(2)
        expect(data.totalProcessed).toBe(2)
      })

      it('should limit batch validation size', async () => {
        const businesses = Array(1001).fill({
          id: 'test',
          businessName: 'Test',
          industry: 'Test'
        })

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'validate-batch',
            businesses
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toContain('Maximum 1000 businesses allowed')
      })

      it('should find duplicates', async () => {
        const mockRecords = [
          {
            id: 'test-1',
            businessName: 'Test Restaurant',
            industry: 'Restaurant',
            email: ['info@test.com'],
            phone: '(555) 123-4567'
          },
          {
            id: 'test-2',
            businessName: 'Test Restaurant',
            industry: 'Restaurant',
            email: ['contact@test.com'],
            phone: '(555) 123-4567'
          }
        ]

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'find-duplicates',
            records: mockRecords
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.duplicates).toBeDefined()
        expect(data.duplicates.matches).toBeDefined()
        expect(data.duplicates.clusters).toBeDefined()
      })

      it('should compare two records', async () => {
        const record1 = {
          id: 'test-1',
          businessName: 'Test Business',
          industry: 'Technology'
        }
        const record2 = {
          id: 'test-2',
          businessName: 'Test Business Inc',
          industry: 'Technology'
        }

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'compare-records',
            record1,
            record2
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.comparison).toBeDefined()
        expect(data.comparison.confidence).toBeDefined()
        expect(data.comparison.similarity).toBeDefined()
      })

      it('should get retention policies', async () => {
        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'get-retention-policies'
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.policies).toBeDefined()
        expect(Array.isArray(data.policies)).toBe(true)
      })

      it('should export data with enhanced options', async () => {
        const mockBusinesses = [
          {
            id: 'test-1',
            businessName: 'Test Business',
            industry: 'Technology',
            email: ['test@example.com']
          }
        ]

        const request = new NextRequest('http://localhost:3000/api/data-management', {
          method: 'POST',
          body: JSON.stringify({
            action: 'export-enhanced',
            exportBusinesses: mockBusinesses,
            format: 'csv',
            options: {
              includeHeaders: true
            }
          }),
          headers: { 'Content-Type': 'application/json' }
        })

        const response = await dataManagementPost(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.export).toBeDefined()
        expect(data.export.filename).toBeDefined()
        expect(data.export.data).toBeDefined()
      })
    })

    describe('GET requests', () => {
      it('should get overview statistics', async () => {
        const request = new NextRequest('http://localhost:3000/api/data-management?type=overview')

        const response = await dataManagementGet(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.overview).toBeDefined()
      })

      it('should get validation statistics', async () => {
        const request = new NextRequest('http://localhost:3000/api/data-management?type=validation-stats')

        const response = await dataManagementGet(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.validationStats).toBeDefined()
      })

      it('should handle invalid stats type', async () => {
        const request = new NextRequest('http://localhost:3000/api/data-management?type=invalid')

        const response = await dataManagementGet(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toBe('Invalid stats type')
      })
    })
  })

  describe('Error Handling', () => {
    it('should handle malformed JSON', async () => {
      const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'POST',
        body: 'invalid json',
        headers: { 'Content-Type': 'application/json' }
      })

      const response = await enhancedScrapePost(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Internal server error')
    })

    it('should handle missing request body', async () => {
      const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })

      const response = await enhancedScrapePost(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Internal server error')
    })

    it('should handle database connection errors', async () => {
      // Mock database error
      const { database } = require('@/lib/postgresql-database')
      database.query.mockRejectedValueOnce(new Error('Database connection failed'))

      const request = new NextRequest('http://localhost:3000/api/data-management', {
        method: 'POST',
        body: JSON.stringify({
          action: 'get-data-usage-stats'
        }),
        headers: { 'Content-Type': 'application/json' }
      })

      const response = await dataManagementPost(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Internal server error')
    })
  })

  describe('Security Tests', () => {
    it('should sanitize input data', async () => {
      const maliciousInput = {
        action: 'add-job',
        url: 'https://example.com',
        depth: '<script>alert("xss")</script>',
        priority: 'DROP TABLE users;'
      }

      const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'POST',
        body: JSON.stringify(maliciousInput),
        headers: { 'Content-Type': 'application/json' }
      })

      const response = await enhancedScrapePost(request)

      // Should either sanitize or reject the input
      expect(response.status).toBeLessThan(500)
    })

    it('should validate content type', async () => {
      const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'POST',
        body: JSON.stringify({ action: 'initialize' }),
        headers: { 'Content-Type': 'text/plain' }
      })

      const response = await enhancedScrapePost(request)
      
      // Should handle non-JSON content type appropriately
      expect(response.status).toBeLessThan(500)
    })

    it('should handle large payloads', async () => {
      const largePayload = {
        action: 'add-job',
        url: 'https://example.com',
        data: 'x'.repeat(10000000) // 10MB of data
      }

      const request = new NextRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'POST',
        body: JSON.stringify(largePayload),
        headers: { 'Content-Type': 'application/json' }
      })

      const response = await enhancedScrapePost(request)
      
      // Should handle large payloads gracefully
      expect(response.status).toBeLessThan(500)
    })
  })
})
