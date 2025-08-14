import { SearchResultValidator } from '@/model/searchResultValidator'
import axios from 'axios'

// Mock axios
jest.mock('axios')
const mockedAxios = axios as jest.Mocked<typeof axios>

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('SearchResultValidator', () => {
  let validator: SearchResultValidator
  
  beforeEach(() => {
    validator = new SearchResultValidator()
    jest.clearAllMocks()
  })

  describe('validateResults', () => {
    const mockResults = [
      {
        url: 'https://restaurant.com',
        title: 'Best Restaurant in Town',
        snippet: 'Fine dining restaurant serving Italian cuisine',
        domain: 'restaurant.com',
      },
      {
        url: 'https://facebook.com/restaurant',
        title: 'Restaurant Facebook Page',
        snippet: 'Social media page for restaurant',
        domain: 'facebook.com',
      },
      {
        url: 'https://techsolutions.com',
        title: 'Tech Solutions Inc',
        snippet: 'Professional technology consulting services',
        domain: 'techsolutions.com',
      },
    ]

    it('should validate and score search results', async () => {
      // Mock SSL checks
      mockedAxios.head.mockResolvedValue({ status: 200 })

      const results = await validator.validateResults(
        mockResults,
        'restaurant',
        'New York'
      )

      expect(results.length).toBeGreaterThanOrEqual(2) // Some results may be filtered
      expect(results[0]).toHaveProperty('scores')
      expect(results[0]).toHaveProperty('metadata')
      expect(results[0]?.scores).toHaveProperty('relevance')
      expect(results[0]?.scores).toHaveProperty('authority')
      expect(results[0]?.scores).toHaveProperty('business')
      expect(results[0]?.scores).toHaveProperty('geographic')
      expect(results[0]?.scores).toHaveProperty('overall')
    })

    it('should filter out results below minimum thresholds', async () => {
      const validatorWithHighThresholds = new SearchResultValidator({
        minRelevanceScore: 0.8,
        minAuthorityScore: 0.8,
        minBusinessScore: 0.8,
      })

      // Mock SSL checks to fail for some domains
      mockedAxios.head.mockRejectedValue(new Error('SSL check failed'))

      const results = await validatorWithHighThresholds.validateResults(
        mockResults,
        'restaurant',
        'New York'
      )

      // Should filter out results that don't meet high thresholds
      expect(results.length).toBeLessThan(mockResults.length)
    })

    it('should sort results by overall score', async () => {
      mockedAxios.head.mockResolvedValue({ status: 200 })

      const results = await validator.validateResults(
        mockResults,
        'restaurant',
        'New York'
      )

      // Results should be sorted by overall score (highest first)
      for (let i = 1; i < results.length; i++) {
        expect(results[i - 1]?.scores.overall).toBeGreaterThanOrEqual(
          results[i]?.scores.overall ?? 0
        )
      }
    })
  })

  describe('relevance scoring', () => {
    it('should score relevance based on query match', async () => {
      const results = [
        {
          url: 'https://restaurant.com',
          title: 'Best Restaurant in Town',
          snippet: 'Fine dining restaurant serving Italian cuisine',
          domain: 'restaurant.com',
        },
        {
          url: 'https://unrelated.com',
          title: 'Unrelated Business',
          snippet: 'This has nothing to do with restaurants',
          domain: 'unrelated.com',
        },
      ]

      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await validator.validateResults(
        results,
        'restaurant',
        'New York'
      )

      // Restaurant result should have higher relevance score
      const restaurantResult = validatedResults.find(r => r.domain === 'restaurant.com')
      const unrelatedResult = validatedResults.find(r => r.domain === 'unrelated.com')

      expect(restaurantResult?.scores.relevance).toBeGreaterThan(
        unrelatedResult?.scores.relevance || 0
      )
    })
  })

  describe('authority scoring', () => {
    it('should calculate authority scores with SSL consideration', async () => {
      const results = [
        {
          url: 'https://business.com',
          title: 'Business Website',
          snippet: 'A business website',
          domain: 'business.com',
        },
      ]

      // Mock SSL check to succeed
      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await validator.validateResults(
        results,
        'business',
        'New York'
      )

      expect(validatedResults.length).toBeGreaterThan(0)
      const result = validatedResults[0]

      // Should have authority score and SSL metadata
      expect(result?.scores.authority).toBeGreaterThan(0)
      expect(result?.metadata).toHaveProperty('hasSSL')
      expect(typeof result?.metadata.hasSSL).toBe('boolean')
    })
  })

  describe('business scoring', () => {
    it('should score business legitimacy correctly', async () => {
      const results = [
        {
          url: 'https://business-inc.com',
          title: 'Professional Services Inc',
          snippet: 'Professional consulting services company',
          domain: 'business-inc.com',
        },
        {
          url: 'https://directory.com',
          title: 'Business Directory Listing',
          snippet: 'Find businesses in our directory',
          domain: 'directory.com',
        },
      ]

      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await validator.validateResults(
        results,
        'business',
        'New York'
      )

      const businessResult = validatedResults.find(r => r.domain === 'business-inc.com')
      const directoryResult = validatedResults.find(r => r.domain === 'directory.com')

      // Business should score higher than directory
      expect(businessResult?.scores.business).toBeGreaterThan(
        directoryResult?.scores.business || 0
      )
    })
  })

  describe('geographic scoring', () => {
    it('should score geographic relevance correctly', async () => {
      const results = [
        {
          url: 'https://nyrestaurant.com',
          title: 'New York Restaurant',
          snippet: 'Best restaurant in New York City',
          domain: 'nyrestaurant.com',
        },
        {
          url: 'https://larestaurant.com',
          title: 'Los Angeles Restaurant',
          snippet: 'Great food in Los Angeles',
          domain: 'larestaurant.com',
        },
      ]

      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await validator.validateResults(
        results,
        'restaurant',
        'New York'
      )

      const nyResult = validatedResults.find(r => r.domain === 'nyrestaurant.com')
      const laResult = validatedResults.find(r => r.domain === 'larestaurant.com')

      // NY restaurant should have higher geographic score for NY search
      expect(nyResult?.scores.geographic).toBeGreaterThan(
        laResult?.scores.geographic || 0
      )
    })
  })

  describe('duplicate detection', () => {
    it('should detect duplicate domains', async () => {
      const results = [
        {
          url: 'https://restaurant.com',
          title: 'Restaurant Home',
          snippet: 'Main page',
          domain: 'restaurant.com',
        },
        {
          url: 'https://restaurant.com/menu',
          title: 'Restaurant Menu',
          snippet: 'Menu page',
          domain: 'restaurant.com',
        },
        {
          url: 'https://restaurant.com/contact',
          title: 'Restaurant Contact',
          snippet: 'Contact page',
          domain: 'restaurant.com',
        },
      ]

      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await validator.validateResults(
        results,
        'restaurant',
        'New York'
      )

      // Should mark duplicates
      const duplicates = validatedResults.filter(r => r.metadata.isDuplicate)
      expect(duplicates.length).toBeGreaterThan(0)
    })
  })

  describe('business type classification', () => {
    it('should classify business types correctly', async () => {
      // Use a validator with very low thresholds to ensure results pass
      const permissiveValidator = new SearchResultValidator({
        minRelevanceScore: 0.0,
        minAuthorityScore: 0.0,
        minBusinessScore: 0.0,
      })

      const results = [
        {
          url: 'https://medical-clinic.com',
          title: 'Medical Clinic',
          snippet: 'Healthcare services',
          domain: 'medical-clinic.com',
        },
        {
          url: 'https://tech-solutions.com',
          title: 'Tech Solutions',
          snippet: 'Software development',
          domain: 'tech-solutions.com',
        },
      ]

      mockedAxios.head.mockResolvedValue({ status: 200 })

      const validatedResults = await permissiveValidator.validateResults(
        results,
        'business',
        'New York'
      )

      expect(validatedResults.length).toBe(2)

      const medicalResult = validatedResults.find(r => r.domain === 'medical-clinic.com')
      const techResult = validatedResults.find(r => r.domain === 'tech-solutions.com')

      expect(medicalResult).toBeDefined()
      expect(techResult).toBeDefined()
      expect(medicalResult?.metadata.businessType).toBe('medical')
      expect(techResult?.metadata.businessType).toBe('services') // 'solutions' keyword matches services
    })
  })

  describe('cache management', () => {
    it('should provide validation statistics', () => {
      const stats = validator.getStats()
      
      expect(stats).toHaveProperty('cacheSize')
      expect(stats).toHaveProperty('domainsProcessed')
      expect(stats).toHaveProperty('duplicatesFound')
      expect(typeof stats.cacheSize).toBe('number')
      expect(typeof stats.domainsProcessed).toBe('number')
      expect(typeof stats.duplicatesFound).toBe('number')
    })

    it('should clear cache', () => {
      validator.clearCache()
      const stats = validator.getStats()
      
      expect(stats.cacheSize).toBe(0)
      expect(stats.domainsProcessed).toBe(0)
    })
  })

  describe('configuration', () => {
    it('should respect custom configuration', () => {
      const customValidator = new SearchResultValidator({
        minRelevanceScore: 0.8,
        minAuthorityScore: 0.7,
        minBusinessScore: 0.6,
        enableDuplicateDetection: false,
        weights: {
          relevance: 0.5,
          authority: 0.3,
          business: 0.2,
          geographic: 0.0,
        },
      })

      expect(customValidator).toBeInstanceOf(SearchResultValidator)
    })
  })
})
