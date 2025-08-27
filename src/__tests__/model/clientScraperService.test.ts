import { ClientScraperService } from '@/model/clientScraperService'

// Mock the dependencies
jest.mock('@/model/clientSearchEngine', () => ({
  clientSearchEngine: {
    initialize: jest.fn().mockResolvedValue(undefined),
    hasApiCredentials: jest.fn().mockReturnValue(false),
    searchBusinesses: jest
      .fn()
      .mockResolvedValue([
        { url: 'https://example.com', title: 'Test Business', snippet: 'Test snippet' },
      ]),
  },
}))

jest.mock('@/utils/secureStorage', () => ({
  retrieveApiCredentials: jest.fn().mockResolvedValue(null),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

// Mock fetch globally
global.fetch = jest.fn()

describe('ClientScraperService', () => {
  let scraperService: ClientScraperService

  beforeEach(() => {
    scraperService = new ClientScraperService()
    jest.clearAllMocks()

    // Reset fetch mock
    ;(global.fetch as jest.Mock).mockReset()
  })

  describe('initialization', () => {
    it('should initialize in fallback mode when API server is unavailable', async () => {
      // Mock fetch to simulate API server unavailable
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Connection refused'))

      await scraperService.initialize()

      expect(scraperService.isFallbackMode()).toBe(true)
    })

    it('should initialize normally when API server is available', async () => {
      // Mock successful health check
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ status: 'healthy' }),
        })
        // Mock successful scraper initialization
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ success: true }),
        })

      await scraperService.initialize()

      expect(scraperService.isFallbackMode()).toBe(false)
    })
  })

  describe('searchForWebsites', () => {
    it('should search for websites using client search engine', async () => {
      await scraperService.initialize()

      const results = await scraperService.searchForWebsites('restaurants', '60010', 10)

      expect(results).toEqual(['https://example.com'])
    })

    it('should handle search errors gracefully', async () => {
      const { clientSearchEngine } = require('@/model/clientSearchEngine')
      clientSearchEngine.searchBusinesses.mockRejectedValue(new Error('Search failed'))

      await scraperService.initialize()

      const results = await scraperService.searchForWebsites('restaurants', '60010', 10)

      expect(results).toEqual([])
    })
  })

  describe('scrapeWebsite', () => {
    it('should skip website scraping in fallback mode', async () => {
      // Force fallback mode
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Connection refused'))
      await scraperService.initialize()

      const results = await scraperService.scrapeWebsite('https://example.com')

      expect(results).toEqual([])
    })

    it('should attempt server-side scraping when not in fallback mode', async () => {
      // Mock successful initialization
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ status: 'healthy' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ success: true }),
        })
        // Mock successful scraping
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ businesses: [{ name: 'Test Business' }] }),
        })

      await scraperService.initialize()

      const results = await scraperService.scrapeWebsite('https://example.com')

      expect(results).toEqual([{ name: 'Test Business' }])
    })
  })

  describe('cleanup', () => {
    it('should cleanup gracefully in fallback mode', async () => {
      // Force fallback mode
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Connection refused'))
      await scraperService.initialize()

      await expect(scraperService.cleanup()).resolves.not.toThrow()
    })

    it('should attempt server-side cleanup when not in fallback mode', async () => {
      // Mock successful initialization
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ status: 'healthy' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ success: true }),
        })
        // Mock successful cleanup
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ success: true }),
        })

      await scraperService.initialize()
      await expect(scraperService.cleanup()).resolves.not.toThrow()
    })
  })
})
