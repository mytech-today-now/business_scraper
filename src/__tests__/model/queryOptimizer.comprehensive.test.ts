/**
 * Comprehensive Business Rule Tests for Query Optimizer
 * Tests query optimization algorithms, synonym generation, and ranking logic
 */

import { QueryOptimizer } from '@/model/queryOptimizer'
import { OptimizedQuery, QueryVariation } from '@/types/business'

// Mock dependencies
jest.mock('@/utils/logger')

describe('Query Optimizer - Business Logic Rules', () => {
  let queryOptimizer: QueryOptimizer

  beforeEach(() => {
    queryOptimizer = new QueryOptimizer()
  })

  describe('Query Optimization Logic', () => {
    test('should optimize basic business queries', async () => {
      const result = await queryOptimizer.optimizeQuery(
        'restaurants',
        'New York',
        'food_service'
      )

      expect(result).toHaveProperty('original', 'restaurants')
      expect(result).toHaveProperty('optimized')
      expect(result).toHaveProperty('location', 'New York')
      expect(result).toHaveProperty('normalizedLocation')
      expect(result).toHaveProperty('industry', 'food_service')
      expect(result).toHaveProperty('synonyms')
      expect(result).toHaveProperty('negativeKeywords')
      expect(result).toHaveProperty('templates')
      expect(result).toHaveProperty('confidence')
      expect(result).toHaveProperty('estimatedResults')
    })

    test('should clean and normalize input queries', async () => {
      const dirtyQueries = [
        '  restaurants  ',
        'RESTAURANTS',
        'restaurants!!!',
        'restaurants & bars',
        'restaurants, cafes, diners',
      ]

      for (const query of dirtyQueries) {
        const result = await queryOptimizer.optimizeQuery(query, 'New York')
        expect(result.optimized).not.toContain('  ') // No double spaces
        expect(result.optimized.length).toBeGreaterThan(0)
      }
    })

    test('should normalize location inputs', async () => {
      const locationVariations = [
        'NYC',
        'New York City',
        'New York, NY',
        'Manhattan',
        '10001', // ZIP code
      ]

      for (const location of locationVariations) {
        const result = await queryOptimizer.optimizeQuery('restaurants', location)
        expect(result.normalizedLocation).toBeDefined()
        expect(result.normalizedLocation.length).toBeGreaterThan(0)
      }
    })

    test('should generate relevant synonyms for business terms', async () => {
      const businessTerms = [
        { query: 'restaurants', expectedSynonyms: ['dining', 'eatery', 'cafe'] },
        { query: 'lawyers', expectedSynonyms: ['attorneys', 'legal', 'law'] },
        { query: 'doctors', expectedSynonyms: ['physicians', 'medical', 'healthcare'] },
        { query: 'plumbers', expectedSynonyms: ['plumbing', 'pipes', 'water'] },
      ]

      for (const { query, expectedSynonyms } of businessTerms) {
        const result = await queryOptimizer.optimizeQuery(query, 'New York')
        expect(result.synonyms).toBeDefined()
        expect(Array.isArray(result.synonyms)).toBe(true)
        
        // Check if at least some expected synonyms are present
        const hasRelevantSynonyms = expectedSynonyms.some(synonym =>
          result.synonyms.some(s => s.toLowerCase().includes(synonym.toLowerCase()))
        )
        expect(hasRelevantSynonyms).toBe(true)
      }
    })

    test('should generate industry-specific templates', async () => {
      const industryTests = [
        { industry: 'technology', query: 'software companies' },
        { industry: 'healthcare', query: 'medical practices' },
        { industry: 'food_service', query: 'restaurants' },
        { industry: 'retail', query: 'stores' },
      ]

      for (const { industry, query } of industryTests) {
        const result = await queryOptimizer.optimizeQuery(query, 'New York', industry)
        expect(result.templates).toBeDefined()
        expect(Array.isArray(result.templates)).toBe(true)
        expect(result.templates.length).toBeGreaterThan(0)
      }
    })

    test('should generate negative keywords to filter irrelevant results', async () => {
      const result = await queryOptimizer.optimizeQuery(
        'restaurants',
        'New York',
        'food_service'
      )

      expect(result.negativeKeywords).toBeDefined()
      expect(Array.isArray(result.negativeKeywords)).toBe(true)
      
      // Should include common negative keywords for business searches
      const commonNegatives = ['directory', 'listing', 'review', 'jobs', 'careers']
      const hasRelevantNegatives = commonNegatives.some(negative =>
        result.negativeKeywords.includes(negative)
      )
      expect(hasRelevantNegatives).toBe(true)
    })

    test('should calculate confidence scores appropriately', async () => {
      const testCases = [
        { query: 'restaurants', location: 'New York', industry: 'food_service', expectedMinConfidence: 0.7 },
        { query: 'xyz123', location: 'Unknown', industry: undefined, expectedMaxConfidence: 0.6 },
        { query: 'technology companies', location: 'San Francisco', industry: 'technology', expectedMinConfidence: 0.8 },
      ]

      for (const { query, location, industry, expectedMinConfidence, expectedMaxConfidence } of testCases) {
        const result = await queryOptimizer.optimizeQuery(query, location, industry)
        expect(result.confidence).toBeGreaterThanOrEqual(0)
        expect(result.confidence).toBeLessThanOrEqual(1)
        
        if (expectedMinConfidence) {
          expect(result.confidence).toBeGreaterThanOrEqual(expectedMinConfidence)
        }
        if (expectedMaxConfidence) {
          expect(result.confidence).toBeLessThanOrEqual(expectedMaxConfidence)
        }
      }
    })

    test('should estimate result counts based on query complexity', async () => {
      const queries = [
        { query: 'restaurants', location: 'New York', expectedMin: 100 },
        { query: 'very specific niche business type', location: 'Small Town', expectedMax: 50 },
        { query: 'technology companies', location: 'San Francisco', expectedMin: 200 },
      ]

      for (const { query, location, expectedMin, expectedMax } of queries) {
        const result = await queryOptimizer.optimizeQuery(query, location)
        expect(result.estimatedResults).toBeGreaterThan(0)
        
        if (expectedMin) {
          expect(result.estimatedResults).toBeGreaterThanOrEqual(expectedMin)
        }
        if (expectedMax) {
          expect(result.estimatedResults).toBeLessThanOrEqual(expectedMax)
        }
      }
    })
  })

  describe('Query Variation Generation', () => {
    test('should generate multiple query variations', async () => {
      const variations = await queryOptimizer.generateQueryVariations(
        'restaurants',
        'New York',
        'food_service',
        3
      )

      expect(Array.isArray(variations)).toBe(true)
      expect(variations.length).toBeGreaterThan(0)
      expect(variations.length).toBeLessThanOrEqual(3)
      
      variations.forEach(variation => {
        expect(variation).toHaveProperty('original')
        expect(variation).toHaveProperty('optimized')
        expect(variation).toHaveProperty('confidence')
      })
    })

    test('should create diverse variations for the same base query', async () => {
      const variations = await queryOptimizer.generateQueryVariations(
        'technology companies',
        'San Francisco',
        'technology',
        5
      )

      // Variations should be different from each other
      const uniqueOptimized = new Set(variations.map(v => v.optimized))
      expect(uniqueOptimized.size).toBeGreaterThan(1)
    })

    test('should maintain relevance across variations', async () => {
      const variations = await queryOptimizer.generateQueryVariations(
        'medical practices',
        'Boston',
        'healthcare',
        3
      )

      variations.forEach(variation => {
        expect(variation.confidence).toBeGreaterThan(0.3) // Minimum relevance threshold
        expect(variation.optimized.toLowerCase()).toContain('boston')
      })
    })
  })

  describe('Industry-Specific Optimization', () => {
    test('should apply technology industry optimizations', async () => {
      const result = await queryOptimizer.optimizeQuery(
        'software companies',
        'Silicon Valley',
        'technology'
      )

      const techKeywords = ['software', 'technology', 'IT', 'development', 'programming']
      const optimizedLower = result.optimized.toLowerCase()
      
      const hasTechKeywords = techKeywords.some(keyword => 
        optimizedLower.includes(keyword.toLowerCase())
      )
      expect(hasTechKeywords).toBe(true)
    })

    test('should apply healthcare industry optimizations', async () => {
      const result = await queryOptimizer.optimizeQuery(
        'medical practices',
        'Boston',
        'healthcare'
      )

      const healthcareKeywords = ['medical', 'healthcare', 'clinic', 'practice', 'physician']
      const optimizedLower = result.optimized.toLowerCase()
      
      const hasHealthcareKeywords = healthcareKeywords.some(keyword => 
        optimizedLower.includes(keyword.toLowerCase())
      )
      expect(hasHealthcareKeywords).toBe(true)
    })

    test('should apply retail industry optimizations', async () => {
      const result = await queryOptimizer.optimizeQuery(
        'clothing stores',
        'Los Angeles',
        'retail'
      )

      const retailKeywords = ['store', 'shop', 'retail', 'boutique', 'outlet']
      const optimizedLower = result.optimized.toLowerCase()
      
      const hasRetailKeywords = retailKeywords.some(keyword => 
        optimizedLower.includes(keyword.toLowerCase())
      )
      expect(hasRetailKeywords).toBe(true)
    })
  })

  describe('Geographic Optimization', () => {
    test('should handle major metropolitan areas', async () => {
      const majorCities = [
        'New York',
        'Los Angeles',
        'Chicago',
        'Houston',
        'Phoenix',
        'Philadelphia',
        'San Antonio',
        'San Diego',
        'Dallas',
        'San Jose',
      ]

      for (const city of majorCities) {
        const result = await queryOptimizer.optimizeQuery('restaurants', city)
        expect(result.normalizedLocation).toBeDefined()
        expect(result.confidence).toBeGreaterThan(0.6) // Higher confidence for major cities
      }
    })

    test('should handle ZIP codes appropriately', async () => {
      const zipCodes = ['10001', '90210', '60601', '77001', '85001']

      for (const zipCode of zipCodes) {
        const result = await queryOptimizer.optimizeQuery('restaurants', zipCode)
        expect(result.normalizedLocation).toBeDefined()
        expect(result.optimized).toContain(zipCode)
      }
    })

    test('should handle state abbreviations and full names', async () => {
      const stateTests = [
        { input: 'CA', expected: 'California' },
        { input: 'NY', expected: 'New York' },
        { input: 'Texas', expected: 'Texas' },
        { input: 'FL', expected: 'Florida' },
      ]

      for (const { input, expected } of stateTests) {
        const result = await queryOptimizer.optimizeQuery('restaurants', input)
        expect(result.normalizedLocation.toLowerCase()).toContain(expected.toLowerCase())
      }
    })
  })

  describe('Performance and Efficiency', () => {
    test('should optimize queries within reasonable time limits', async () => {
      const startTime = Date.now()
      
      await queryOptimizer.optimizeQuery(
        'technology companies',
        'San Francisco',
        'technology'
      )
      
      const endTime = Date.now()
      const processingTime = endTime - startTime
      
      expect(processingTime).toBeLessThan(5000) // Should complete within 5 seconds
    })

    test('should handle batch optimization efficiently', async () => {
      const queries = [
        'restaurants',
        'lawyers',
        'doctors',
        'plumbers',
        'electricians',
        'accountants',
        'dentists',
        'veterinarians',
        'mechanics',
        'contractors',
      ]

      const startTime = Date.now()
      
      const promises = queries.map(query => 
        queryOptimizer.optimizeQuery(query, 'New York')
      )
      
      const results = await Promise.all(promises)
      
      const endTime = Date.now()
      const totalTime = endTime - startTime
      
      expect(results).toHaveLength(queries.length)
      expect(totalTime).toBeLessThan(10000) // Should complete within 10 seconds
      
      results.forEach(result => {
        expect(result.confidence).toBeGreaterThan(0)
        expect(result.optimized).toBeDefined()
      })
    })
  })

  describe('Edge Cases and Error Handling', () => {
    test('should handle empty or invalid inputs gracefully', async () => {
      const invalidInputs = [
        { query: '', location: 'New York' },
        { query: 'restaurants', location: '' },
        { query: '   ', location: '   ' },
        { query: null as any, location: 'New York' },
        { query: 'restaurants', location: null as any },
      ]

      for (const { query, location } of invalidInputs) {
        const result = await queryOptimizer.optimizeQuery(query, location)
        expect(result).toBeDefined()
        expect(result.confidence).toBeGreaterThanOrEqual(0)
        expect(result.confidence).toBeLessThanOrEqual(1)
      }
    })

    test('should handle very long queries', async () => {
      const longQuery = 'a'.repeat(1000)
      const result = await queryOptimizer.optimizeQuery(longQuery, 'New York')
      
      expect(result).toBeDefined()
      expect(result.optimized.length).toBeLessThan(longQuery.length) // Should be truncated/cleaned
    })

    test('should handle special characters and encoding', async () => {
      const specialQueries = [
        'café & restaurant',
        'résumé services',
        'piñata stores',
        'naïve businesses',
        'coöperative stores',
      ]

      for (const query of specialQueries) {
        const result = await queryOptimizer.optimizeQuery(query, 'New York')
        expect(result).toBeDefined()
        expect(result.optimized).toBeDefined()
      }
    })

    test('should provide fallback optimization on errors', async () => {
      // Mock an internal error
      const originalMethod = queryOptimizer.optimizeQuery
      jest.spyOn(queryOptimizer, 'optimizeQuery').mockImplementationOnce(() => {
        throw new Error('Internal optimization error')
      })

      // Restore original method for fallback
      queryOptimizer.optimizeQuery = originalMethod

      const result = await queryOptimizer.optimizeQuery('restaurants', 'New York')
      
      expect(result).toBeDefined()
      expect(result.confidence).toBe(0.5) // Fallback confidence
      expect(result.optimized).toBeDefined()
    })
  })
})
