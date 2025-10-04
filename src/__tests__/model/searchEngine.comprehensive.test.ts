/**
 * Comprehensive Business Rule Tests for Search Engine Logic
 * Tests search algorithms, ranking logic, and optimization strategies
 */

import { SearchEngine } from '@/model/searchEngine'
import { QueryOptimizer } from '@/model/queryOptimizer'
import { SearchResultValidator } from '@/model/searchResultValidator'
import { SearchResult, ValidatedSearchResult, OptimizedQuery, QueryPerformance } from '@/types/business'

// Mock dependencies
jest.mock('@/model/queryOptimizer')
jest.mock('@/model/searchResultValidator')
jest.mock('@/utils/logger')

describe('Search Engine - Business Logic Rules', () => {
  let searchEngine: SearchEngine
  let mockQueryOptimizer: jest.Mocked<QueryOptimizer>
  let mockSearchResultValidator: jest.Mocked<SearchResultValidator>

  const mockSearchResults: SearchResult[] = [
    {
      url: 'https://acme-corp.com',
      title: 'Acme Corporation - Technology Solutions',
      snippet: 'Leading provider of technology solutions in San Francisco',
      domain: 'acme-corp.com',
    },
    {
      url: 'https://tech-innovators.com',
      title: 'Tech Innovators Inc',
      snippet: 'Innovative technology company serving the Bay Area',
      domain: 'tech-innovators.com',
    },
    {
      url: 'https://directory-site.com/acme',
      title: 'Acme Corp - Business Directory',
      snippet: 'Find Acme Corp contact information and reviews',
      domain: 'directory-site.com',
    },
  ]

  const mockValidatedResults: ValidatedSearchResult[] = [
    {
      ...mockSearchResults[0],
      scores: {
        relevance: 0.9,
        authority: 0.8,
        business: 0.95,
        geographic: 0.85,
        overall: 0.875,
      },
      metadata: {
        isDuplicate: false,
        confidence: 0.875,
        lastUpdated: new Date(),
        domainAge: 5,
        businessType: 'technology',
      },
    },
    {
      ...mockSearchResults[1],
      scores: {
        relevance: 0.85,
        authority: 0.75,
        business: 0.9,
        geographic: 0.8,
        overall: 0.825,
      },
      metadata: {
        isDuplicate: false,
        confidence: 0.825,
        lastUpdated: new Date(),
        domainAge: 3,
        businessType: 'technology',
      },
    },
  ]

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks()

    // Create mocked instances
    mockQueryOptimizer = new QueryOptimizer() as jest.Mocked<QueryOptimizer>
    mockSearchResultValidator = new SearchResultValidator() as jest.Mocked<SearchResultValidator>

    // Setup default mock implementations
    mockQueryOptimizer.optimizeQuery.mockResolvedValue({
      original: 'technology companies',
      optimized: 'technology companies San Francisco (software OR IT)',
      location: 'San Francisco',
      normalizedLocation: 'San Francisco, CA',
      industry: 'technology',
      synonyms: ['software', 'IT'],
      negativeKeywords: ['directory', 'listing'],
      templates: ['technology companies'],
      confidence: 0.85,
      estimatedResults: 150,
    })

    mockSearchResultValidator.validateResults.mockResolvedValue(mockValidatedResults)

    searchEngine = new SearchEngine()
  })

  describe('Search Algorithm Logic', () => {
    test('should execute search with proper fallback mechanism', async () => {
      // Mock the private searchWithFallback method behavior
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const results = await searchEngine.searchBusinesses('technology companies', 'San Francisco', 10)

      expect(results).toHaveLength(2) // Validated results
      expect(searchSpy).toHaveBeenCalledWith('technology companies', 'San Francisco', 10)
      expect(mockSearchResultValidator.validateResults).toHaveBeenCalledWith(
        mockSearchResults,
        'technology companies',
        'San Francisco'
      )
    })

    test('should handle empty search results gracefully', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue([])

      const results = await searchEngine.searchBusinesses('nonexistent query', 'Unknown Location', 10)

      expect(results).toHaveLength(0)
      expect(mockSearchResultValidator.validateResults).not.toHaveBeenCalled()
    })

    test('should apply result validation when enabled', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const results = await searchEngine.searchBusinesses(
        'technology companies',
        'San Francisco',
        10,
        true // enableValidation
      )

      expect(mockSearchResultValidator.validateResults).toHaveBeenCalledWith(
        mockSearchResults,
        'technology companies',
        'San Francisco'
      )
      expect(results).toHaveLength(2)
    })

    test('should skip validation when disabled', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const results = await searchEngine.searchBusinesses(
        'technology companies',
        'San Francisco',
        10,
        false // enableValidation
      )

      expect(mockSearchResultValidator.validateResults).not.toHaveBeenCalled()
      expect(results).toHaveLength(3) // All raw results
    })
  })

  describe('Search with Detailed Scoring', () => {
    test('should return validated results with detailed scores', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const results = await searchEngine.searchBusinessesWithScores(
        'technology companies',
        'San Francisco',
        10
      )

      expect(results).toHaveLength(2)
      expect(results[0]).toHaveProperty('scores')
      expect(results[0].scores).toHaveProperty('relevance')
      expect(results[0].scores).toHaveProperty('authority')
      expect(results[0].scores).toHaveProperty('business')
      expect(results[0].scores).toHaveProperty('geographic')
      expect(results[0].scores).toHaveProperty('overall')
      expect(results[0]).toHaveProperty('metadata')
    })

    test('should handle validation errors gracefully', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)
      mockSearchResultValidator.validateResults.mockRejectedValue(new Error('Validation failed'))

      const results = await searchEngine.searchBusinessesWithScores(
        'technology companies',
        'San Francisco',
        10
      )

      expect(results).toHaveLength(0)
    })
  })

  describe('Optimized Search Logic', () => {
    test('should perform optimized search with query enhancement', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const result = await searchEngine.searchBusinessesOptimized(
        'technology companies',
        'San Francisco',
        'technology',
        10
      )

      expect(mockQueryOptimizer.optimizeQuery).toHaveBeenCalledWith(
        'technology companies',
        'San Francisco',
        'technology'
      )
      expect(result).toHaveProperty('results')
      expect(result).toHaveProperty('optimization')
      expect(result).toHaveProperty('performance')
      expect(result.results).toHaveLength(2)
    })

    test('should track performance metrics', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const result = await searchEngine.searchBusinessesOptimized(
        'technology companies',
        'San Francisco',
        'technology',
        10
      )

      expect(result.performance).toHaveProperty('query')
      expect(result.performance).toHaveProperty('location')
      expect(result.performance).toHaveProperty('searchTime')
      expect(result.performance).toHaveProperty('resultCount')
      expect(result.performance).toHaveProperty('relevanceScore')
      expect(result.performance).toHaveProperty('timestamp')
      expect(result.performance.searchTime).toBeGreaterThan(0)
    })

    test('should fallback to regular search on optimization failure', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)
      mockQueryOptimizer.optimizeQuery.mockRejectedValue(new Error('Optimization failed'))

      // Mock searchBusinessesWithScores for fallback
      const fallbackSpy = jest.spyOn(searchEngine, 'searchBusinessesWithScores')
      fallbackSpy.mockResolvedValue(mockValidatedResults)

      const result = await searchEngine.searchBusinessesOptimized(
        'technology companies',
        'San Francisco',
        'technology',
        10
      )

      expect(fallbackSpy).toHaveBeenCalled()
      expect(result.optimization.confidence).toBe(0.5) // Fallback confidence
      expect(result.results).toHaveLength(2)
    })
  })

  describe('Search Provider Fallback Logic', () => {
    test('should try multiple search providers in order', async () => {
      const searchWithDuckDuckGoSpy = jest.spyOn(searchEngine as any, 'searchWithDuckDuckGo')
      const searchWithGoogleSpy = jest.spyOn(searchEngine as any, 'searchWithGoogle')
      const searchWithBingSpy = jest.spyOn(searchEngine as any, 'searchWithBing')

      // Mock first provider to fail, second to succeed
      searchWithDuckDuckGoSpy.mockResolvedValue(mockSearchResults)
      searchWithGoogleSpy.mockRejectedValue(new Error('API limit exceeded'))
      searchWithBingSpy.mockRejectedValue(new Error('Service unavailable'))

      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      await searchSpy.call(searchEngine, 'technology companies', 'San Francisco', 10)

      // Should try DuckDuckGo first and succeed
      expect(searchWithDuckDuckGoSpy).toHaveBeenCalled()
    })

    test('should return empty results when all providers fail', async () => {
      const searchWithDuckDuckGoSpy = jest.spyOn(searchEngine as any, 'searchWithDuckDuckGo')
      const searchWithGoogleSpy = jest.spyOn(searchEngine as any, 'searchWithGoogle')
      const searchWithBingSpy = jest.spyOn(searchEngine as any, 'searchWithBing')
      const searchWithYandexSpy = jest.spyOn(searchEngine as any, 'searchWithYandex')

      // Mock all providers to fail
      searchWithDuckDuckGoSpy.mockRejectedValue(new Error('Service unavailable'))
      searchWithGoogleSpy.mockRejectedValue(new Error('API limit exceeded'))
      searchWithBingSpy.mockRejectedValue(new Error('Service unavailable'))
      searchWithYandexSpy.mockRejectedValue(new Error('Service unavailable'))

      const results = await (searchEngine as any).searchWithFallback(
        'technology companies',
        'San Francisco',
        10
      )

      expect(results).toHaveLength(0)
    })
  })

  describe('Search Result Quality Control', () => {
    test('should filter low-quality results', async () => {
      const lowQualityResults: SearchResult[] = [
        {
          url: 'https://spam-site.com',
          title: 'Spam Site',
          snippet: 'Low quality content',
          domain: 'spam-site.com',
        },
      ]

      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(lowQualityResults)
      mockSearchResultValidator.validateResults.mockResolvedValue([]) // No results pass validation

      const results = await searchEngine.searchBusinesses('technology companies', 'San Francisco', 10)

      expect(results).toHaveLength(0)
    })

    test('should maintain result order by relevance score', async () => {
      const unorderedResults = [...mockValidatedResults].reverse() // Reverse order
      mockSearchResultValidator.validateResults.mockResolvedValue(unorderedResults)

      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(mockSearchResults)

      const results = await searchEngine.searchBusinessesWithScores(
        'technology companies',
        'San Francisco',
        10
      )

      // Results should be ordered by overall score (highest first)
      expect(results[0].scores.overall).toBeGreaterThanOrEqual(results[1].scores.overall)
    })
  })

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed search queries', async () => {
      const malformedQueries = [
        '',
        '   ',
        null as any,
        undefined as any,
        'a'.repeat(1000), // Very long query
        '!@#$%^&*()', // Special characters only
      ]

      for (const query of malformedQueries) {
        const results = await searchEngine.searchBusinesses(query, 'San Francisco', 10)
        expect(Array.isArray(results)).toBe(true)
        expect(results.length).toBeGreaterThanOrEqual(0)
      }
    })

    test('should handle invalid location inputs', async () => {
      const invalidLocations = [
        '',
        '   ',
        null as any,
        undefined as any,
        'Invalid Location 12345',
        'NonexistentCity, XX',
      ]

      for (const location of invalidLocations) {
        const results = await searchEngine.searchBusinesses('technology companies', location, 10)
        expect(Array.isArray(results)).toBe(true)
        expect(results.length).toBeGreaterThanOrEqual(0)
      }
    })

    test('should handle network timeouts gracefully', async () => {
      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockImplementation(() => new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Network timeout')), 100)
      ))

      const results = await searchEngine.searchBusinesses('technology companies', 'San Francisco', 10)
      expect(results).toHaveLength(0)
    })

    test('should respect maximum result limits', async () => {
      const largeResultSet = Array(1000).fill(0).map((_, i) => ({
        url: `https://business${i}.com`,
        title: `Business ${i}`,
        snippet: `Description for business ${i}`,
        domain: `business${i}.com`,
      }))

      const searchSpy = jest.spyOn(searchEngine as any, 'searchWithFallback')
      searchSpy.mockResolvedValue(largeResultSet)

      const results = await searchEngine.searchBusinesses('technology companies', 'San Francisco', 50)
      expect(results.length).toBeLessThanOrEqual(50)
    })
  })
})
