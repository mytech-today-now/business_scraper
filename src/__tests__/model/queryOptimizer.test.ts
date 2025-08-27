import { QueryOptimizer, QueryPerformance } from '@/model/queryOptimizer'

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('QueryOptimizer', () => {
  let optimizer: QueryOptimizer

  beforeEach(() => {
    optimizer = new QueryOptimizer()
    jest.clearAllMocks()
  })

  describe('optimizeQuery', () => {
    it('should optimize a basic query', async () => {
      const result = await optimizer.optimizeQuery('restaurants', 'New York', 'restaurants')

      expect(result).toHaveProperty('original', 'restaurants')
      expect(result).toHaveProperty('optimized')
      expect(result).toHaveProperty('location', 'New York')
      expect(result).toHaveProperty('normalizedLocation')
      expect(result).toHaveProperty('industry', 'restaurants')
      expect(result).toHaveProperty('synonyms')
      expect(result).toHaveProperty('negativeKeywords')
      expect(result).toHaveProperty('templates')
      expect(result).toHaveProperty('confidence')
      expect(result).toHaveProperty('estimatedResults')

      expect(result.confidence).toBeGreaterThan(0)
      expect(result.confidence).toBeLessThanOrEqual(1)
      expect(result.estimatedResults).toBeGreaterThan(0)
    })

    it('should include industry-specific synonyms', async () => {
      const result = await optimizer.optimizeQuery('food', 'Seattle', 'restaurants')

      expect(result.synonyms).toContain('restaurant')
      expect(result.synonyms).toContain('dining')
      expect(result.synonyms).toContain('eatery')
    })

    it('should include negative keywords', async () => {
      const result = await optimizer.optimizeQuery('medical', 'Boston', 'healthcare')

      expect(result.negativeKeywords).toContain('jobs')
      expect(result.negativeKeywords).toContain('careers')
      expect(result.negativeKeywords).toContain('reviews')
    })

    it('should normalize location', async () => {
      const result = await optimizer.optimizeQuery('shops', 'Los Angeles, CA')

      expect(result.normalizedLocation).toBe('Los Angeles, CA')
    })

    it('should handle ZIP codes', async () => {
      const result = await optimizer.optimizeQuery('services', '90210')

      expect(result.normalizedLocation).toBe('90210')
    })

    it('should handle errors gracefully', async () => {
      // Test with empty query
      const result = await optimizer.optimizeQuery('', '')

      expect(result.original).toBe('')
      expect(result.confidence).toBeGreaterThan(0)
      expect(result.confidence).toBeLessThanOrEqual(1)
      expect(result.synonyms).toEqual([])
    })
  })

  describe('generateQueryVariations', () => {
    it('should generate multiple query variations', async () => {
      const variations = await optimizer.generateQueryVariations(
        'coffee shops',
        'Portland',
        'restaurants'
      )

      expect(variations.length).toBeGreaterThan(1)
      expect(variations[0]).toHaveProperty('optimized')

      // Should be sorted by confidence
      for (let i = 1; i < variations.length; i++) {
        expect(variations[i - 1]?.confidence).toBeGreaterThanOrEqual(variations[i]?.confidence ?? 0)
      }
    })

    it('should include template-based variations', async () => {
      const variations = await optimizer.generateQueryVariations('pizza', 'Chicago', 'restaurants')

      const hasTemplateVariation = variations.some(
        v => v.optimized.includes('dining') || v.optimized.includes('food service')
      )
      expect(hasTemplateVariation).toBe(true)
    })
  })

  describe('performance tracking', () => {
    it('should record performance metrics', () => {
      const metrics: QueryPerformance = {
        query: 'test query',
        location: 'test location',
        searchTime: 1000,
        resultCount: 25,
        relevanceScore: 0.8,
        timestamp: new Date(),
        searchProvider: 'google',
      }

      optimizer.recordPerformance(metrics)

      const stats = optimizer.getStats()
      expect(stats.performanceMetricsCount).toBe(1)
    })

    it('should provide performance analytics', () => {
      // Record some test metrics
      const metrics: QueryPerformance[] = [
        {
          query: 'restaurants',
          location: 'NYC',
          searchTime: 500,
          resultCount: 20,
          relevanceScore: 0.9,
          timestamp: new Date(),
          searchProvider: 'google',
        },
        {
          query: 'shops',
          location: 'LA',
          searchTime: 800,
          resultCount: 15,
          relevanceScore: 0.7,
          timestamp: new Date(),
          searchProvider: 'bing',
        },
      ]

      metrics.forEach(m => optimizer.recordPerformance(m))

      const analytics = optimizer.getPerformanceAnalytics(24)

      expect(analytics.totalQueries).toBe(2)
      expect(analytics.averageSearchTime).toBe(650)
      expect(analytics.averageResultCount).toBe(17.5)
      expect(analytics.averageRelevanceScore).toBe(0.8)
      expect(analytics.topPerformingQueries).toHaveLength(2)
      expect(analytics.slowestQueries).toHaveLength(2)
      expect(analytics.providerPerformance).toHaveProperty('google')
      expect(analytics.providerPerformance).toHaveProperty('bing')
    })

    it('should handle empty performance data', () => {
      const analytics = optimizer.getPerformanceAnalytics(24)

      expect(analytics.totalQueries).toBe(0)
      expect(analytics.averageSearchTime).toBe(0)
      expect(analytics.topPerformingQueries).toEqual([])
      expect(analytics.providerPerformance).toEqual({})
    })
  })

  describe('query suggestions', () => {
    it('should provide query suggestions', () => {
      // First record some performance data
      const metrics: QueryPerformance = {
        query: 'italian restaurants',
        location: 'NYC',
        searchTime: 500,
        resultCount: 20,
        relevanceScore: 0.9,
        timestamp: new Date(),
        searchProvider: 'google',
      }
      optimizer.recordPerformance(metrics)

      const suggestions = optimizer.getQuerySuggestions('italian', 'NYC', 'restaurants')

      expect(Array.isArray(suggestions)).toBe(true)
      expect(suggestions.length).toBeGreaterThanOrEqual(0)
    })

    it('should include industry-specific suggestions', () => {
      const suggestions = optimizer.getQuerySuggestions('medical', 'Boston', 'healthcare')

      // Should include healthcare-related business types
      expect(suggestions.length).toBeGreaterThan(0)
      expect(
        suggestions.some(
          s => s.includes('medical') || s.includes('clinic') || s.includes('hospital')
        )
      ).toBe(true)
    })

    it('should limit suggestion count', () => {
      const suggestions = optimizer.getQuerySuggestions('business', 'Seattle')

      expect(suggestions.length).toBeLessThanOrEqual(10)
    })
  })

  describe('location normalization', () => {
    it('should normalize ZIP codes correctly', async () => {
      const result = await optimizer.optimizeQuery('shops', '12345')

      expect(result.normalizedLocation).toBe('12345')
    })

    it('should normalize city, state format', async () => {
      const result = await optimizer.optimizeQuery('services', 'San Francisco, CA')

      expect(result.normalizedLocation).toBe('San Francisco, CA')
    })

    it('should handle malformed locations', async () => {
      const result = await optimizer.optimizeQuery('business', 'invalid location format')

      expect(result.normalizedLocation).toBe('invalid location format')
    })
  })

  describe('industry templates', () => {
    it('should use restaurant templates', async () => {
      const result = await optimizer.optimizeQuery('pizza', 'NYC', 'restaurants')

      expect(result.templates.length).toBeGreaterThan(1)
      expect(result.templates.some(t => t.includes('dining'))).toBe(true)
    })

    it('should use healthcare templates', async () => {
      const result = await optimizer.optimizeQuery('dentist', 'LA', 'healthcare')

      expect(result.templates.some(t => t.includes('medical'))).toBe(true)
    })

    it('should handle unknown industries', async () => {
      const result = await optimizer.optimizeQuery('business', 'NYC', 'unknown')

      expect(result.templates).toEqual(['business'])
    })
  })

  describe('cache management', () => {
    it('should provide statistics', () => {
      const stats = optimizer.getStats()

      expect(stats).toHaveProperty('performanceMetricsCount')
      expect(stats).toHaveProperty('synonymCacheSize')
      expect(stats).toHaveProperty('locationCacheSize')
      expect(stats).toHaveProperty('searchTemplatesCount')
      expect(typeof stats.performanceMetricsCount).toBe('number')
      expect(typeof stats.synonymCacheSize).toBe('number')
      expect(typeof stats.locationCacheSize).toBe('number')
      expect(typeof stats.searchTemplatesCount).toBe('number')
    })

    it('should clear cache', () => {
      // Add some data first
      optimizer.recordPerformance({
        query: 'test',
        location: 'test',
        searchTime: 100,
        resultCount: 10,
        relevanceScore: 0.5,
        timestamp: new Date(),
        searchProvider: 'test',
      })

      optimizer.clearCache()

      const stats = optimizer.getStats()
      expect(stats.performanceMetricsCount).toBe(0)
      expect(stats.synonymCacheSize).toBe(0)
      expect(stats.locationCacheSize).toBe(0)
    })
  })

  describe('configuration', () => {
    it('should respect custom configuration', () => {
      const customOptimizer = new QueryOptimizer({
        enableSynonymExpansion: false,
        enableLocationNormalization: false,
        maxSynonyms: 3,
        maxTemplates: 5,
      })

      expect(customOptimizer).toBeInstanceOf(QueryOptimizer)
    })

    it('should use default configuration when none provided', () => {
      const defaultOptimizer = new QueryOptimizer()

      expect(defaultOptimizer).toBeInstanceOf(QueryOptimizer)
    })
  })
})
