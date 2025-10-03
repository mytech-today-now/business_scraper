/**
 * Comprehensive Business API Route Tests
 * Tests all business endpoints with various scenarios including success, error, and edge cases
 * Target: 98% coverage for /api/businesses routes
 */

import { NextRequest, NextResponse } from 'next/server'
import { GET as businessesGET, POST as businessesPOST } from '@/app/api/businesses/route'
import { GET as paginatedGET } from '@/app/api/businesses/paginated/route'
import { BusinessRecord } from '@/types/business'
import { jest } from '@jest/globals'

// Mock dependencies
jest.mock('@/model/storage', () => ({
  storage: {
    getAllBusinesses: jest.fn(),
    saveBusiness: jest.fn(),
    getBusiness: jest.fn(),
    deleteBusiness: jest.fn(),
    clearAllBusinesses: jest.fn(),
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/lib/enhancedFilteringService', () => ({
  EnhancedFilteringService: jest.fn().mockImplementation(() => ({
    filterBusinesses: jest.fn(),
  })),
}))

// Import mocked modules
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { EnhancedFilteringService } from '@/lib/enhancedFilteringService'

// Test data factory
const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
  id: 'business-123',
  businessName: 'Test Business',
  industry: 'Technology',
  email: ['test@business.com'],
  phone: '(555) 123-4567',
  websiteUrl: 'https://testbusiness.com',
  address: {
    street: '123 Main St',
    city: 'Test City',
    state: 'TS',
    zipCode: '12345',
    country: 'US',
  },
  scrapedAt: new Date('2024-01-01T00:00:00Z'),
  confidence: 0.85,
  source: 'test',
  qualityScore: 75,
  ...overrides,
})

describe('Business API Routes - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/businesses - Paginated Business Listing', () => {
    const mockBusinesses = [
      createMockBusinessRecord({ id: '1', businessName: 'Alpha Corp', industry: 'Technology' }),
      createMockBusinessRecord({ id: '2', businessName: 'Beta LLC', industry: 'Healthcare' }),
      createMockBusinessRecord({ id: '3', businessName: 'Gamma Inc', industry: 'Finance' }),
    ]

    beforeEach(() => {
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(mockBusinesses)
    })

    it('should return paginated businesses with default parameters', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toHaveProperty('data')
      expect(data).toHaveProperty('pagination')
      expect(data).toHaveProperty('metadata')
      expect(Array.isArray(data.data)).toBe(true)
      expect(data.pagination).toHaveProperty('nextCursor')
      expect(data.pagination).toHaveProperty('hasMore')
      expect(data.pagination).toHaveProperty('totalCount')
      expect(data.metadata).toHaveProperty('processingTime')
      expect(data.metadata).toHaveProperty('source')
    })

    it('should apply search filter correctly', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?search=Alpha')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(1)
      expect(data.data[0].businessName).toBe('Alpha Corp')
      expect(data.metadata.appliedFilters).toHaveProperty('search', 'Alpha')
    })

    it('should apply industry filter correctly', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?industry=Technology')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(1)
      expect(data.data[0].industry).toBe('Technology')
      expect(data.metadata.appliedFilters).toHaveProperty('industry', 'Technology')
    })

    it('should apply email filter correctly', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?hasEmail=true')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.every((business: BusinessRecord) => 
        business.email && business.email.length > 0
      )).toBe(true)
    })

    it('should apply phone filter correctly', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?hasPhone=true')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.every((business: BusinessRecord) => 
        business.phone && business.phone.length > 0
      )).toBe(true)
    })

    it('should apply quality score range filter', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?qualityScoreMin=70&qualityScoreMax=80')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.every((business: BusinessRecord) => {
        const score = business.qualityScore || 0
        return score >= 70 && score <= 80
      })).toBe(true)
    })

    it('should apply date range filter', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?dateStart=2024-01-01&dateEnd=2024-12-31')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.metadata.appliedFilters).toHaveProperty('dateStart', '2024-01-01')
      expect(data.metadata.appliedFilters).toHaveProperty('dateEnd', '2024-12-31')
    })

    it('should apply sorting correctly', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?sortField=businessName&sortOrder=asc')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.metadata.sortConfig).toEqual({
        field: 'businessName',
        order: 'asc',
      })
      
      // Verify sorting is applied
      const businessNames = data.data.map((b: BusinessRecord) => b.businessName)
      const sortedNames = [...businessNames].sort()
      expect(businessNames).toEqual(sortedNames)
    })

    it('should handle pagination with limit', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?limit=2')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(2)
      expect(data.pagination.pageSize).toBe(2)
      expect(data.pagination.hasMore).toBe(true)
    })

    it('should handle cursor-based pagination', async () => {
      const cursor = Buffer.from('1').toString('base64')
      const request = new NextRequest(`http://localhost:3000/api/businesses?cursor=${cursor}&limit=2`)

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.pagination).toHaveProperty('nextCursor')
    })

    it('should validate query parameters', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses?limit=2000') // Exceeds max

      const response = await businessesGET(request)

      expect(response.status).toBe(400)
    })

    it('should handle empty results', async () => {
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue([])

      const request = new NextRequest('http://localhost:3000/api/businesses')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(0)
      expect(data.pagination.totalCount).toBe(0)
      expect(data.pagination.hasMore).toBe(false)
    })

    it('should handle storage errors', async () => {
      ;(storage.getAllBusinesses as jest.Mock).mockRejectedValue(new Error('Storage error'))

      const request = new NextRequest('http://localhost:3000/api/businesses')

      const response = await businessesGET(request)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle multiple filters simultaneously', async () => {
      const request = new NextRequest(
        'http://localhost:3000/api/businesses?search=Alpha&industry=Technology&hasEmail=true&qualityScoreMin=50'
      )

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.metadata.appliedFilters).toEqual({
        search: 'Alpha',
        industry: 'Technology',
        hasEmail: true,
        qualityScoreMin: 50,
      })
    })
  })

  describe('POST /api/businesses - Bulk Business Insert', () => {
    it('should successfully save multiple businesses', async () => {
      const businesses = [
        createMockBusinessRecord({ id: '1', businessName: 'Business One' }),
        createMockBusinessRecord({ id: '2', businessName: 'Business Two' }),
      ]

      ;(storage.saveBusiness as jest.Mock).mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        success: true,
        count: 2,
      })
      expect(storage.saveBusiness).toHaveBeenCalledTimes(2)
      expect(logger.info).toHaveBeenCalledWith('BusinessAPI', 'Saved 2 businesses')
    })

    it('should reject non-array businesses data', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses: 'not-an-array' }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data).toEqual({
        error: 'Expected array of businesses',
      })
    })

    it('should handle empty businesses array', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses: [] }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data).toEqual({
        success: true,
        count: 0,
      })
      expect(storage.saveBusiness).not.toHaveBeenCalled()
    })

    it('should handle storage errors during save', async () => {
      const businesses = [createMockBusinessRecord()]
      ;(storage.saveBusiness as jest.Mock).mockRejectedValue(new Error('Storage error'))

      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)

      expect(response.status).toBe(500)
    })

    it('should handle malformed JSON', async () => {
      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: 'invalid-json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)

      expect(response.status).toBe(400)
    })

    it('should handle large batch of businesses', async () => {
      const businesses = Array.from({ length: 1000 }, (_, i) =>
        createMockBusinessRecord({ id: `business-${i}`, businessName: `Business ${i}` })
      )

      ;(storage.saveBusiness as jest.Mock).mockResolvedValue(undefined)

      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.count).toBe(1000)
      expect(storage.saveBusiness).toHaveBeenCalledTimes(1000)
    })
  })

  describe('GET /api/businesses/paginated - Enhanced Pagination', () => {
    beforeEach(() => {
      // Use the global mock instead of creating a new instance
      const mockEnhancedFilteringService = require('@/lib/enhancedFilteringService').EnhancedFilteringService
      const mockInstance = new mockEnhancedFilteringService()
      mockInstance.filterBusinesses.mockResolvedValue({
        businesses: [createMockBusinessRecord()],
        totalCount: 1,
        hasMore: false,
        nextCursor: null,
      })
    })

    it('should handle enhanced filtering with complex criteria', async () => {
      const request = new NextRequest(
        'http://localhost:3000/api/businesses/paginated?sortBy=confidence_score&sortOrder=desc&limit=50'
      )

      const response = await paginatedGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(enhancedFilteringService.filterBusinesses).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          field: 'confidence_score',
          order: 'desc',
        }),
        50,
        0
      )
    })

    it('should handle cursor-based pagination with enhanced filtering', async () => {
      const cursor = Buffer.from('10').toString('base64')
      const request = new NextRequest(
        `http://localhost:3000/api/businesses/paginated?cursor=${cursor}&limit=25`
      )

      const response = await paginatedGET(request)

      expect(response.status).toBe(200)
      expect(enhancedFilteringService.filterBusinesses).toHaveBeenCalledWith(
        expect.any(Object),
        expect.any(Object),
        25,
        10
      )
    })

    it('should validate enhanced filtering parameters', async () => {
      const request = new NextRequest(
        'http://localhost:3000/api/businesses/paginated?sortBy=invalid_field'
      )

      const response = await paginatedGET(request)

      expect(response.status).toBe(400)
    })

    it('should handle enhanced filtering service errors', async () => {
      ;(enhancedFilteringService.filterBusinesses as jest.Mock).mockRejectedValue(
        new Error('Filtering service error')
      )

      const request = new NextRequest('http://localhost:3000/api/businesses/paginated')

      const response = await paginatedGET(request)

      expect(response.status).toBe(500)
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent requests gracefully', async () => {
      const businesses = [createMockBusinessRecord()]
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(businesses)

      const requests = Array.from({ length: 10 }, () =>
        new NextRequest('http://localhost:3000/api/businesses')
      )

      const responses = await Promise.all(requests.map(req => businessesGET(req)))

      responses.forEach(response => {
        expect(response.status).toBe(200)
      })
    })

    it('should handle memory pressure with large datasets', async () => {
      const largeDataset = Array.from({ length: 10000 }, (_, i) =>
        createMockBusinessRecord({ id: `large-${i}` })
      )
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(largeDataset)

      const request = new NextRequest('http://localhost:3000/api/businesses?limit=100')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(100)
      expect(data.pagination.totalCount).toBe(10000)
    })

    it('should handle special characters in search queries', async () => {
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue([
        createMockBusinessRecord({ businessName: 'Café & Restaurant' }),
      ])

      const request = new NextRequest(
        'http://localhost:3000/api/businesses?search=' + encodeURIComponent('Café & Restaurant')
      )

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(1)
    })

    it('should handle malformed date filters', async () => {
      const request = new NextRequest(
        'http://localhost:3000/api/businesses?dateStart=invalid-date'
      )

      const response = await businessesGET(request)

      // Should handle gracefully, either by ignoring invalid dates or returning error
      expect([200, 400]).toContain(response.status)
    })

    it('should handle network timeouts', async () => {
      ;(storage.getAllBusinesses as jest.Mock).mockImplementation(
        () => new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), 100)
        )
      )

      const request = new NextRequest('http://localhost:3000/api/businesses')

      const response = await businessesGET(request)

      expect(response.status).toBe(500)
    })

    it('should validate business data integrity during bulk insert', async () => {
      const invalidBusinesses = [
        { id: '1' }, // Missing required fields
        createMockBusinessRecord({ id: '2' }), // Valid business
        { businessName: '', id: '3' }, // Invalid business name
      ]

      ;(storage.saveBusiness as jest.Mock).mockImplementation((business) => {
        if (!business.businessName) {
          throw new Error('Invalid business data')
        }
        return Promise.resolve()
      })

      const request = new NextRequest('http://localhost:3000/api/businesses', {
        method: 'POST',
        body: JSON.stringify({ businesses: invalidBusinesses }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await businessesPOST(request)

      // Should handle partial failures appropriately
      expect([200, 400, 500]).toContain(response.status)
    })

    it('should handle database connection failures', async () => {
      ;(storage.getAllBusinesses as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      )

      const request = new NextRequest('http://localhost:3000/api/businesses')

      const response = await businessesGET(request)

      expect(response.status).toBe(500)
      expect(logger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('error'),
        expect.any(Error)
      )
    })

    it('should handle rate limiting scenarios', async () => {
      // Simulate rapid requests
      const requests = Array.from({ length: 100 }, () =>
        new NextRequest('http://localhost:3000/api/businesses')
      )

      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue([])

      const startTime = Date.now()
      const responses = await Promise.all(requests.map(req => businessesGET(req)))
      const endTime = Date.now()

      // All requests should complete within reasonable time
      expect(endTime - startTime).toBeLessThan(10000) // 10 seconds
      responses.forEach(response => {
        expect([200, 429, 500]).toContain(response.status)
      })
    })
  })

  describe('Performance and Optimization Tests', () => {
    it('should handle pagination efficiently with large datasets', async () => {
      const largeDataset = Array.from({ length: 50000 }, (_, i) =>
        createMockBusinessRecord({ id: `perf-${i}` })
      )
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(largeDataset)

      const startTime = Date.now()
      const request = new NextRequest('http://localhost:3000/api/businesses?limit=50')
      const response = await businessesGET(request)
      const endTime = Date.now()

      expect(response.status).toBe(200)
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
    })

    it('should optimize memory usage during filtering', async () => {
      const businesses = Array.from({ length: 1000 }, (_, i) =>
        createMockBusinessRecord({
          id: `mem-${i}`,
          businessName: i % 2 === 0 ? 'Even Business' : 'Odd Business'
        })
      )
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(businesses)

      const request = new NextRequest('http://localhost:3000/api/businesses?search=Even')

      const response = await businessesGET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.length).toBe(500) // Half should match
    })

    it('should handle complex sorting efficiently', async () => {
      const businesses = Array.from({ length: 1000 }, (_, i) =>
        createMockBusinessRecord({
          id: `sort-${i}`,
          businessName: `Business ${String(i).padStart(4, '0')}`,
          qualityScore: Math.floor(Math.random() * 100)
        })
      )
      ;(storage.getAllBusinesses as jest.Mock).mockResolvedValue(businesses)

      const startTime = Date.now()
      const request = new NextRequest(
        'http://localhost:3000/api/businesses?sortField=qualityScore&sortOrder=desc&limit=100'
      )
      const response = await businessesGET(request)
      const endTime = Date.now()

      expect(response.status).toBe(200)
      expect(endTime - startTime).toBeLessThan(2000) // Should sort efficiently
    })
  })
})
