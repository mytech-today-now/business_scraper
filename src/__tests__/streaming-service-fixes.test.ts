/**
 * @jest-environment jsdom
 */

import { StreamingSearchService } from '@/lib/streamingSearchService'
import { SearchEngineService } from '@/model/searchEngine'
import { ScraperService } from '@/model/scraperService'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/model/searchEngine')
jest.mock('@/model/scraperService')
jest.mock('@/utils/logger')

const mockLogger = logger as jest.Mocked<typeof logger>
const MockSearchEngineService = SearchEngineService as jest.MockedClass<typeof SearchEngineService>
const MockScraperService = ScraperService as jest.MockedClass<typeof ScraperService>

describe('StreamingSearchService Fixes', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    MockSearchEngineService.mockClear()
    MockScraperService.mockClear()
  })

  describe('Graceful Initialization', () => {
    it('should initialize successfully when all dependencies are available', async () => {
      // Mock successful initialization
      MockSearchEngineService.mockImplementation(() => ({} as any))
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      expect(healthCheck.healthy).toBe(true)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StreamingSearchService',
        'All services initialized successfully'
      )
    })

    it('should handle SearchEngineService initialization failure gracefully', async () => {
      // Mock SearchEngineService failure
      MockSearchEngineService.mockImplementation(() => {
        throw new Error('SearchEngine initialization failed')
      })
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      expect(healthCheck.healthy).toBe(true) // Should still be healthy with degraded functionality
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StreamingSearchService',
        'Failed to initialize SearchEngineService, will use fallback',
        expect.any(Error)
      )
    })

    it('should handle ScraperService initialization failure gracefully', async () => {
      // Mock ScraperService failure
      MockSearchEngineService.mockImplementation(() => ({} as any))
      MockScraperService.mockImplementation(() => {
        throw new Error('Scraper initialization failed')
      })

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      expect(healthCheck.healthy).toBe(true) // Should still be healthy with degraded functionality
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StreamingSearchService',
        'Failed to initialize ScraperService, will use fallback',
        expect.any(Error)
      )
    })

    it('should handle complete initialization failure', async () => {
      // Mock both services failing
      MockSearchEngineService.mockImplementation(() => {
        throw new Error('SearchEngine initialization failed')
      })
      MockScraperService.mockImplementation(() => {
        throw new Error('Scraper initialization failed')
      })

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      expect(healthCheck.healthy).toBe(true) // Should still be healthy with limited functionality
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StreamingSearchService',
        expect.stringContaining('Service initialized with limited functionality')
      )
    })
  })

  describe('Search Batch Fallback', () => {
    it('should return empty results when search engine is not available', async () => {
      // Mock no search engine
      MockSearchEngineService.mockImplementation(() => {
        throw new Error('SearchEngine not available')
      })
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      // Access private method for testing
      const searchBatch = (service as any).searchBatch.bind(service)
      const results = await searchBatch('test query', 'test location', 0, 10)

      expect(results).toEqual([])
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StreamingSearchService',
        'Search engine not available, returning empty results'
      )
    })

    it('should handle search errors gracefully', async () => {
      // Mock search engine that throws errors
      const mockSearchEngine = {
        search: jest.fn().mockRejectedValue(new Error('Search failed'))
      }
      MockSearchEngineService.mockImplementation(() => mockSearchEngine as any)
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      // Access private method for testing
      const searchBatch = (service as any).searchBatch.bind(service)
      const results = await searchBatch('test query', 'test location', 0, 10)

      expect(results).toEqual([])
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StreamingSearchService',
        'Failed to search batch at offset 0',
        expect.any(Error)
      )
    })
  })

  describe('Health Check', () => {
    it('should report healthy status when initialized properly', async () => {
      MockSearchEngineService.mockImplementation(() => ({} as any))
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      
      expect(healthCheck.healthy).toBe(true)
      expect(healthCheck.details.servicesInitialized.searchEngine).toBe(true)
      expect(healthCheck.details.servicesInitialized.scraperService).toBe(true)
    })

    it('should report degraded status with partial initialization', async () => {
      MockSearchEngineService.mockImplementation(() => {
        throw new Error('SearchEngine failed')
      })
      MockScraperService.mockImplementation(() => ({} as any))

      const service = new StreamingSearchService()
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 10))

      const healthCheck = await service.healthCheck()
      
      expect(healthCheck.healthy).toBe(true) // Still healthy with degraded functionality
      expect(healthCheck.details.servicesInitialized.searchEngine).toBe(false)
      expect(healthCheck.details.servicesInitialized.scraperService).toBe(true)
    })
  })
})
