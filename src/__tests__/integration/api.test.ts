/**
 * Comprehensive API Integration Tests
 * Tests all API endpoints with realistic scenarios
 */

import { NextRequest, NextResponse } from 'next/server'
import { GET as searchGET, POST as searchPOST } from '@/app/api/search/route'
import { GET as scrapeGET, POST as scrapePOST } from '@/app/api/scrape/route'
import { GET as dataManagementGET, POST as dataManagementPOST } from '@/app/api/data-management/route'
import { createMockApiResponse, createMockSearchResults, createMockFetch } from '../utils/testHelpers'
import { jest } from '@jest/globals'

// Mock external dependencies
jest.mock('@/model/searchEngine', () => ({
  searchEngine: {
    searchForBusinesses: jest.fn(),
    initialize: jest.fn(),
  }
}))

jest.mock('@/model/scraperService', () => ({
  scraperService: {
    initialize: jest.fn(),
    searchForWebsites: jest.fn(),
    scrapeWebsite: jest.fn(),
    cleanup: jest.fn(),
  }
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1'),
  sanitizeInput: jest.fn((input) => input),
  validateInput: jest.fn(() => ({ isValid: true, errors: [] })),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  }
}))

describe('API Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    global.fetch = createMockFetch()
  })

  describe('Search API (/api/search)', () => {
    it('should handle GET request for search status', async () => {
      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'GET'
      })

      const response = await searchGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('success')
      expect(data).toHaveProperty('timestamp')
    })

    it('should handle POST request for business search', async () => {
      const { searchEngine } = require('@/model/searchEngine')
      const mockResults = createMockSearchResults(5)
      searchEngine.searchForBusinesses.mockResolvedValue(mockResults)

      const searchData = {
        query: 'restaurants',
        zipCode: '90210',
        maxResults: 10
      }

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify(searchData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await searchPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toHaveLength(5)
      expect(searchEngine.searchForBusinesses).toHaveBeenCalledWith(
        'restaurants',
        '90210',
        10
      )
    })

    it('should validate required fields in POST request', async () => {
      const invalidData = {
        query: '', // Empty query
        zipCode: '90210'
      }

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify(invalidData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await searchPOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toContain('query')
    })

    it('should handle search engine errors gracefully', async () => {
      const { searchEngine } = require('@/model/searchEngine')
      searchEngine.searchForBusinesses.mockRejectedValue(new Error('Search failed'))

      const searchData = {
        query: 'restaurants',
        zipCode: '90210',
        maxResults: 10
      }

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify(searchData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await searchPOST(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.success).toBe(false)
      expect(data.error).toContain('Search failed')
    })
  })

  describe('Scrape API (/api/scrape)', () => {
    it('should handle scraper initialization', async () => {
      const { scraperService } = require('@/model/scraperService')
      scraperService.initialize.mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({ action: 'initialize' }),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(scraperService.initialize).toHaveBeenCalled()
    })

    it('should handle website scraping', async () => {
      const { scraperService } = require('@/model/scraperService')
      const mockScrapedData = {
        businessName: 'Test Business',
        phone: '(555) 123-4567',
        email: 'test@business.com'
      }
      scraperService.scrapeWebsite.mockResolvedValue(mockScrapedData)

      const scrapeData = {
        action: 'scrape',
        url: 'https://example.com',
        depth: 1
      }

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify(scrapeData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockScrapedData)
      expect(scraperService.scrapeWebsite).toHaveBeenCalledWith(
        'https://example.com',
        { depth: 1 }
      )
    })

    it('should validate scrape parameters', async () => {
      const invalidData = {
        action: 'scrape',
        url: 'invalid-url'
      }

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify(invalidData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toContain('url')
    })

    it('should handle scraper cleanup', async () => {
      const { scraperService } = require('@/model/scraperService')
      scraperService.cleanup.mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({ action: 'cleanup' }),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(scraperService.cleanup).toHaveBeenCalled()
    })
  })

  describe('Data Management API (/api/data-management)', () => {
    it('should handle GET request for statistics', async () => {
      const request = new NextRequest('http://localhost:3000/api/data-management', {
        method: 'GET'
      })

      const response = await dataManagementGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data).toHaveProperty('statistics')
      expect(data.statistics).toHaveProperty('cleanup')
      expect(data.statistics).toHaveProperty('retention')
      expect(data.statistics).toHaveProperty('validation')
      expect(data.statistics).toHaveProperty('duplicates')
    })

    it('should handle data validation requests', async () => {
      const validationData = {
        action: 'validate',
        data: [
          {
            id: 'test-1',
            businessName: 'Valid Business',
            industry: 'Technology',
            email: 'test@business.com'
          }
        ]
      }

      const request = new NextRequest('http://localhost:3000/api/data-management', {
        method: 'POST',
        body: JSON.stringify(validationData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await dataManagementPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data).toHaveProperty('validationResults')
    })

    it('should handle duplicate detection requests', async () => {
      const duplicateData = {
        action: 'detect-duplicates',
        data: [
          {
            id: 'test-1',
            businessName: 'Business One',
            email: 'test@business.com'
          },
          {
            id: 'test-2',
            businessName: 'Business One',
            email: 'test@business.com'
          }
        ]
      }

      const request = new NextRequest('http://localhost:3000/api/data-management', {
        method: 'POST',
        body: JSON.stringify(duplicateData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await dataManagementPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data).toHaveProperty('duplicates')
    })

    it('should handle data cleanup requests', async () => {
      const cleanupData = {
        action: 'cleanup',
        options: {
          removeInvalid: true,
          removeDuplicates: true,
          olderThan: '30d'
        }
      }

      const request = new NextRequest('http://localhost:3000/api/data-management', {
        method: 'POST',
        body: JSON.stringify(cleanupData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await dataManagementPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data).toHaveProperty('cleanupResults')
    })
  })

  describe('Error Handling & Security', () => {
    it('should handle malformed JSON requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: 'invalid json',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await searchPOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toContain('Invalid JSON')
    })

    it('should handle missing Content-Type header', async () => {
      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify({ query: 'test' })
      })

      const response = await searchPOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
    })

    it('should sanitize input data', async () => {
      const { sanitizeInput } = require('@/lib/security')
      sanitizeInput.mockImplementation((input) => input.replace(/<script>/g, ''))

      const maliciousData = {
        query: 'restaurants<script>alert("xss")</script>',
        zipCode: '90210'
      }

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify(maliciousData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      await searchPOST(request)

      expect(sanitizeInput).toHaveBeenCalledWith(maliciousData.query)
    })

    it('should log client IP addresses', async () => {
      const { getClientIP } = require('@/lib/security')
      const { logger } = require('@/utils/logger')

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'GET'
      })

      await searchGET(request)

      expect(getClientIP).toHaveBeenCalledWith(request)
      expect(logger.info).toHaveBeenCalled()
    })
  })

  describe('Performance Tests', () => {
    it('should handle concurrent API requests', async () => {
      const requests = Array.from({ length: 10 }, () => 
        new NextRequest('http://localhost:3000/api/search', { method: 'GET' })
      )

      const start = performance.now()
      const responses = await Promise.all(requests.map(req => searchGET(req)))
      const end = performance.now()

      expect(responses).toHaveLength(10)
      responses.forEach(response => {
        expect(response.status).toBe(200)
      })
      expect(end - start).toBeLessThan(1000) // Should complete in under 1 second
    })

    it('should handle large request payloads', async () => {
      const largeData = {
        query: 'restaurants',
        zipCode: '90210',
        metadata: 'x'.repeat(10000) // 10KB of data
      }

      const request = new NextRequest('http://localhost:3000/api/search', {
        method: 'POST',
        body: JSON.stringify(largeData),
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const response = await searchPOST(request)
      expect(response.status).toBeLessThan(500) // Should not crash
    })
  })
})
