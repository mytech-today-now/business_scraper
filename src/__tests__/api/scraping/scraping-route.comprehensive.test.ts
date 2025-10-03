/**
 * Comprehensive Scraping API Route Tests
 * Tests all scraping endpoints with various scenarios including success, error, and edge cases
 * Target: 98% coverage for /api/scraping and /api/scrape routes
 */

import { NextRequest, NextResponse } from 'next/server'
import { GET as scrapingGET, POST as scrapingPOST } from '@/app/api/scraping/route'
import { GET as scrapeGET, POST as scrapePOST } from '@/app/api/scrape/route'
import { jest } from '@jest/globals'

// Mock dependencies
jest.mock('@/model/scraperService', () => ({
  scraperService: {
    initialize: jest.fn(),
    cleanup: jest.fn(),
    scrapeWebsite: jest.fn(),
    searchBusinesses: jest.fn(),
    setSessionId: jest.fn(),
  },
}))

jest.mock('@/lib/security', () => ({
  sanitizeInput: jest.fn(),
  validateInput: jest.fn(),
  getClientIP: jest.fn(),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/lib/metrics', () => ({
  metrics: {
    recordScrapingOperation: jest.fn(),
    recordApiCall: jest.fn(),
  },
}))

jest.mock('@/lib/compliance/scraper-middleware', () => ({
  ScrapingComplianceMiddleware: {
    validateScrapingOperation: jest.fn(),
    logScrapingOperation: jest.fn(),
  },
  ScrapingComplianceUtils: {
    createComplianceContext: jest.fn(),
  },
}))

jest.mock('@/lib/rbac-middleware', () => ({
  withRBAC: jest.fn((handler) => handler),
}))

// Import mocked modules
import { scraperService } from '@/model/scraperService'
import { sanitizeInput, validateInput, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import { metrics } from '@/lib/metrics'
import { ScrapingComplianceMiddleware, ScrapingComplianceUtils } from '@/lib/compliance/scraper-middleware'

describe('Scraping API Routes - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mocks
    ;(getClientIP as jest.Mock).mockReturnValue('192.168.1.100')
    ;(sanitizeInput as jest.Mock).mockImplementation((input: string) => input?.trim())
    ;(validateInput as jest.Mock).mockReturnValue({ isValid: true, errors: [] })
    ;(ScrapingComplianceMiddleware.validateScrapingOperation as jest.Mock).mockResolvedValue({
      allowed: true,
      complianceFlags: [],
    })
    ;(ScrapingComplianceUtils.createComplianceContext as jest.Mock).mockReturnValue({
      requestId: 'req-123',
      timestamp: new Date(),
      ipAddress: '192.168.1.100',
    })
  })

  describe('POST /api/scraping - Scraping Operations', () => {
    const mockContext = {
      user: { id: 'user-123' },
      workspaceId: 'workspace-123',
      database: {
        query: jest.fn(),
      },
    }

    it('should handle initialize action successfully', async () => {
      ;(scraperService.initialize as jest.Mock).mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'initialize',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        success: true,
        data: { message: 'Scraper initialized successfully' },
      })
      expect(scraperService.initialize).toHaveBeenCalled()
      expect(logger.info).toHaveBeenCalledWith(
        'Scraping API',
        'Scraper initialized successfully',
        { userId: 'user-123' }
      )
    })

    it('should handle search action with valid parameters', async () => {
      const mockSearchResults = [
        {
          id: '1',
          businessName: 'Test Business',
          address: '123 Main St',
          phone: '555-1234',
          email: 'test@business.com',
        },
      ]

      ;(scraperService.searchBusinesses as jest.Mock).mockResolvedValue(mockSearchResults)
      ;(mockContext.database.query as jest.Mock).mockResolvedValue({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: 'restaurants',
          zipCode: '12345',
          maxResults: 50,
          workspaceId: 'workspace-123',
          campaignId: 'campaign-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.businesses).toEqual(mockSearchResults)
      expect(scraperService.searchBusinesses).toHaveBeenCalledWith('restaurants', '12345', 50)
    })

    it('should reject search action with missing required parameters', async () => {
      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          // Missing query and zipCode
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle scrape action with valid URL', async () => {
      const mockBusinesses = [
        {
          id: '1',
          businessName: 'Scraped Business',
          url: 'https://example.com',
          confidence: 0.8,
        },
      ]

      ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue(mockBusinesses)
      ;(mockContext.database.query as jest.Mock).mockResolvedValue({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
          depth: 3,
          maxPages: 10,
          workspaceId: 'workspace-123',
          campaignId: 'campaign-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.businesses).toEqual(mockBusinesses)
      expect(scraperService.scrapeWebsite).toHaveBeenCalledWith('https://example.com', 3, 10)
    })

    it('should reject scrape action with invalid URL', async () => {
      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'invalid-url',
          workspaceId: 'workspace-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle cleanup action successfully', async () => {
      ;(scraperService.cleanup as jest.Mock).mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'cleanup',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual({ message: 'Scraper cleanup completed' })
      expect(scraperService.cleanup).toHaveBeenCalled()
    })

    it('should handle status action with session ID', async () => {
      const mockStatus = {
        sessionId: 'session-123',
        status: 'completed',
        progress: 100,
        results: 25,
      }

      ;(mockContext.database.query as jest.Mock).mockResolvedValue({
        rows: [mockStatus],
      })

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'status',
          sessionId: 'session-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockStatus)
    })

    it('should reject invalid action', async () => {
      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'invalid-action',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data).toEqual({
        error: 'Invalid action',
      })
    })

    it('should reject missing action parameter', async () => {
      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data).toEqual({
        error: 'Action parameter is required',
      })
    })

    it('should require workspace ID for search and scrape actions', async () => {
      const contextWithoutWorkspace = {
        user: { id: 'user-123' },
        database: { query: jest.fn() },
      }

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: 'restaurants',
          zipCode: '12345',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, contextWithoutWorkspace)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data).toEqual({
        error: 'Workspace ID is required for this action',
      })
    })

    it('should handle compliance validation failure', async () => {
      ;(ScrapingComplianceMiddleware.validateScrapingOperation as jest.Mock).mockResolvedValue({
        allowed: false,
        reason: 'Rate limit exceeded',
      })

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
          workspaceId: 'workspace-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(429)
      expect(data.error).toContain('Rate limit exceeded')
    })

    it('should handle scraper service errors gracefully', async () => {
      ;(scraperService.initialize as jest.Mock).mockRejectedValue(new Error('Scraper initialization failed'))

      const request = new NextRequest('http://localhost:3000/api/scraping', {
        method: 'POST',
        body: JSON.stringify({
          action: 'initialize',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapingPOST(request, mockContext)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalledWith(
        'Scraping API',
        'Failed to initialize scraper',
        expect.any(Error)
      )
    })
  })

  describe('GET /api/scraping - Status and Capabilities', () => {
    const mockContext = {
      user: { id: 'user-123' },
      workspaceId: 'workspace-123',
      database: {
        query: jest.fn(),
      },
    }

    it('should return scraping capabilities and status', async () => {
      ;(mockContext.database.query as jest.Mock).mockResolvedValue({
        rows: [
          {
            id: 'session-1',
            status: 'completed',
            created_at: new Date(),
            query: 'restaurants',
            zip_code: '12345',
          },
        ],
      })

      const request = new NextRequest('http://localhost:3000/api/scraping')

      const response = await scrapingGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toHaveProperty('status', 'Scraping API is operational')
      expect(data.data).toHaveProperty('capabilities')
      expect(data.data.capabilities).toHaveProperty('actions')
      expect(data.data.capabilities.actions).toEqual(['initialize', 'search', 'scrape', 'cleanup', 'status'])
    })

    it('should return specific session status when sessionId provided', async () => {
      const mockSession = {
        id: 'session-123',
        status: 'running',
        progress: 50,
        results: 10,
      }

      ;(mockContext.database.query as jest.Mock).mockResolvedValue({
        rows: [mockSession],
      })

      const request = new NextRequest('http://localhost:3000/api/scraping?sessionId=session-123')

      const response = await scrapingGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockSession)
    })

    it('should handle database errors gracefully', async () => {
      ;(mockContext.database.query as jest.Mock).mockRejectedValue(new Error('Database error'))

      const request = new NextRequest('http://localhost:3000/api/scraping')

      const response = await scrapingGET(request, mockContext)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalled()
    })
  })

  describe('POST /api/scrape - Legacy Scrape Endpoint', () => {
    beforeEach(() => {
      ;(scraperService.initialize as jest.Mock).mockResolvedValue(undefined)
      ;(scraperService.cleanup as jest.Mock).mockResolvedValue(undefined)
      ;(scraperService.searchBusinesses as jest.Mock).mockResolvedValue([])
      ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue([])
    })

    it('should handle initialize action', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'initialize',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(scraperService.initialize).toHaveBeenCalled()
    })

    it('should handle search action with valid parameters', async () => {
      const mockResults = [
        { businessName: 'Test Restaurant', address: '123 Main St' },
      ]
      ;(scraperService.searchBusinesses as jest.Mock).mockResolvedValue(mockResults)

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: 'restaurants',
          zipCode: '12345',
          maxResults: 50,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.businesses).toEqual(mockResults)
      expect(scraperService.searchBusinesses).toHaveBeenCalledWith('restaurants', '12345', 50)
    })

    it('should reject search with missing query', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          zipCode: '12345',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Query parameter is required')
    })

    it('should validate zip code format', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: 'restaurants',
          zipCode: 'invalid-zip',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Invalid zip code format')
    })

    it('should handle scrape action with URL validation', async () => {
      const mockBusinesses = [
        { businessName: 'Scraped Business', url: 'https://example.com' },
      ]
      ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue(mockBusinesses)

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
          depth: 2,
          maxPages: 5,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.businesses).toEqual(mockBusinesses)
      expect(scraperService.scrapeWebsite).toHaveBeenCalledWith('https://example.com', 2, 5)
    })

    it('should reject scrape with invalid URL', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'not-a-url',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Invalid URL format')
    })

    it('should handle cleanup action', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'cleanup',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(scraperService.cleanup).toHaveBeenCalled()
    })

    it('should reject invalid actions', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'invalid-action',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Invalid action')
    })

    it('should handle compliance middleware validation', async () => {
      ;(ScrapingComplianceMiddleware.validateScrapingOperation as jest.Mock).mockResolvedValue({
        allowed: false,
        reason: 'Compliance violation',
      })

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)

      expect(response.status).toBe(403)
    })

    it('should handle scraping service errors', async () => {
      ;(scraperService.scrapeWebsite as jest.Mock).mockRejectedValue(new Error('Scraping failed'))

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Scraping failed')
      expect(data.businesses).toEqual([])
    })

    it('should set session ID when provided', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'initialize',
          sessionId: 'test-session-123',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      await scrapePOST(request)

      expect(scraperService.setSessionId).toHaveBeenCalledWith('test-session-123')
    })

    it('should handle malformed JSON requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: 'invalid-json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)

      expect(response.status).toBe(400)
    })

    it('should validate input parameters', async () => {
      ;(validateInput as jest.Mock).mockReturnValue({ isValid: false, errors: ['Invalid input'] })

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: '<script>alert("xss")</script>',
          zipCode: '12345',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Invalid query format')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent scraping requests', async () => {
      ;(scraperService.initialize as jest.Mock).mockResolvedValue(undefined)

      const requests = Array.from({ length: 5 }, () =>
        new NextRequest('http://localhost:3000/api/scrape', {
          method: 'POST',
          body: JSON.stringify({ action: 'initialize' }),
          headers: { 'Content-Type': 'application/json' },
        })
      )

      const responses = await Promise.all(requests.map(req => scrapePOST(req)))

      responses.forEach(response => {
        expect([200, 429, 500]).toContain(response.status)
      })
    })

    it('should handle memory pressure during large scraping operations', async () => {
      const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
        businessName: `Business ${i}`,
        url: `https://business${i}.com`,
      }))

      ;(scraperService.scrapeWebsite as jest.Mock).mockResolvedValue(largeDataset)

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'scrape',
          url: 'https://example.com',
          maxPages: 100,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.businesses).toHaveLength(10000)
    })

    it('should handle network timeouts gracefully', async () => {
      ;(scraperService.searchBusinesses as jest.Mock).mockImplementation(
        () => new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Network timeout')), 100)
        )
      )

      const request = new NextRequest('http://localhost:3000/api/scrape', {
        method: 'POST',
        body: JSON.stringify({
          action: 'search',
          query: 'restaurants',
          zipCode: '12345',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await scrapePOST(request)

      expect(response.status).toBe(500)
    })
  })
})
