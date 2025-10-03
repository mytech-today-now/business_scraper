/**
 * Scraper Service - Comprehensive Test Suite
 * Tests web scraping, data extraction, and business record creation
 */

import { scraperService } from '@/model/scraperService'
import { BusinessRecord, ScrapingConfig } from '@/types/business'
import { enhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'
import { geocoder } from '@/model/geocoder'
import { searchEngine } from '@/model/searchEngine'
import { logger } from '@/utils/logger'
import { webSocketServer } from '@/lib/websocket-server'
import { memoryMonitor } from '@/lib/memory-monitor'

// Mock dependencies
jest.mock('@/lib/enhancedScrapingEngine')
jest.mock('@/model/geocoder')
jest.mock('@/model/searchEngine')
jest.mock('@/utils/logger')
jest.mock('@/lib/websocket-server')
jest.mock('@/lib/memory-monitor')

const mockEnhancedScrapingEngine = enhancedScrapingEngine as jest.Mocked<typeof enhancedScrapingEngine>
const mockGeocoder = geocoder as jest.Mocked<typeof geocoder>
const mockSearchEngine = searchEngine as jest.Mocked<typeof searchEngine>
const mockLogger = logger as jest.Mocked<typeof logger>
const mockWebSocketServer = webSocketServer as jest.Mocked<typeof webSocketServer>
const mockMemoryMonitor = memoryMonitor as jest.Mocked<typeof memoryMonitor>

describe('Scraper Service - Comprehensive Tests', () => {
  const createMockScrapingConfig = (overrides: Partial<ScrapingConfig> = {}): ScrapingConfig => ({
    maxPages: 10,
    delay: 1000,
    timeout: 30000,
    retries: 3,
    userAgent: 'Mozilla/5.0 (compatible; BusinessScraper/1.0)',
    enableJavaScript: true,
    followRedirects: true,
    respectRobotsTxt: true,
    maxConcurrency: 3,
    ...overrides,
  })

  const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
    id: 'scraped-business-1',
    businessName: 'Scraped Business Inc.',
    email: ['contact@scraped.com'],
    phone: ['555-123-4567'],
    website: 'https://www.scraped.com',
    streetName: 'Main Street',
    streetNumber: '123',
    city: 'Los Angeles',
    state: 'CA',
    zipCode: '90210',
    industry: 'Technology',
    description: 'A technology company discovered through web scraping',
    scrapedAt: new Date(),
    source: 'web_scraping',
    ...overrides,
  })

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup enhanced scraping engine mock
    mockEnhancedScrapingEngine.scrapeBusinessData.mockResolvedValue({
      businesses: [createMockBusinessRecord()],
      metadata: {
        totalPages: 1,
        totalResults: 1,
        processingTime: 5000,
        successRate: 1.0,
      },
    })

    // Setup geocoder mock
    mockGeocoder.geocodeAddress.mockResolvedValue({
      latitude: 34.0522,
      longitude: -118.2437,
      formattedAddress: '123 Main Street, Los Angeles, CA 90210',
      confidence: 0.95,
    })

    // Setup search engine mock
    mockSearchEngine.searchBusinesses.mockResolvedValue([
      {
        title: 'Scraped Business Inc.',
        url: 'https://www.scraped.com',
        snippet: 'Technology company providing innovative solutions',
        relevanceScore: 0.9,
      },
    ])

    // Setup memory monitor mock
    mockMemoryMonitor.getMemoryUsage.mockReturnValue({
      used: 100 * 1024 * 1024, // 100MB
      total: 1024 * 1024 * 1024, // 1GB
      percentage: 10,
    })
  })

  describe('Basic Scraping Operations', () => {
    it('should scrape business data from a single URL', async () => {
      const url = 'https://example.com/business-directory'
      const config = createMockScrapingConfig()

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(1)
      expect(result.businesses[0]).toMatchObject({
        businessName: 'Scraped Business Inc.',
        email: ['contact@scraped.com'],
        phone: ['555-123-4567'],
        website: 'https://www.scraped.com',
      })
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledWith(url, config)
    })

    it('should handle scraping configuration options correctly', async () => {
      const url = 'https://example.com/business-directory'
      const config = createMockScrapingConfig({
        maxPages: 5,
        delay: 2000,
        timeout: 60000,
        retries: 5,
        maxConcurrency: 2,
      })

      await scraperService.scrapeUrl(url, config)

      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledWith(url, config)
    })

    it('should scrape multiple URLs in batch', async () => {
      const urls = [
        'https://example.com/directory1',
        'https://example.com/directory2',
        'https://example.com/directory3',
      ]
      const config = createMockScrapingConfig()

      mockEnhancedScrapingEngine.scrapeBusinessData
        .mockResolvedValueOnce({
          businesses: [createMockBusinessRecord({ id: 'business-1' })],
          metadata: { totalPages: 1, totalResults: 1, processingTime: 3000, successRate: 1.0 },
        })
        .mockResolvedValueOnce({
          businesses: [createMockBusinessRecord({ id: 'business-2' })],
          metadata: { totalPages: 1, totalResults: 1, processingTime: 3500, successRate: 1.0 },
        })
        .mockResolvedValueOnce({
          businesses: [createMockBusinessRecord({ id: 'business-3' })],
          metadata: { totalPages: 1, totalResults: 1, processingTime: 4000, successRate: 1.0 },
        })

      const result = await scraperService.scrapeBatch(urls, config)

      expect(result.businesses).toHaveLength(3)
      expect(result.metadata.totalResults).toBe(3)
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledTimes(3)
    })
  })

  describe('Search-Based Scraping', () => {
    it('should scrape businesses based on search query', async () => {
      const query = 'technology companies'
      const location = 'Los Angeles, CA'
      const config = createMockScrapingConfig()

      const result = await scraperService.scrapeBySearch(query, location, config)

      expect(result.businesses).toHaveLength(1)
      expect(mockSearchEngine.searchBusinesses).toHaveBeenCalledWith(query, location, config.maxPages)
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalled()
    })

    it('should handle search results with multiple pages', async () => {
      const query = 'restaurants'
      const location = 'New York, NY'
      const config = createMockScrapingConfig({ maxPages: 3 })

      mockSearchEngine.searchBusinesses.mockResolvedValue([
        { title: 'Restaurant 1', url: 'https://restaurant1.com', snippet: 'Great food', relevanceScore: 0.9 },
        { title: 'Restaurant 2', url: 'https://restaurant2.com', snippet: 'Amazing cuisine', relevanceScore: 0.8 },
        { title: 'Restaurant 3', url: 'https://restaurant3.com', snippet: 'Delicious meals', relevanceScore: 0.7 },
      ])

      const result = await scraperService.scrapeBySearch(query, location, config)

      expect(mockSearchEngine.searchBusinesses).toHaveBeenCalledWith(query, location, 3)
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledTimes(3)
    })

    it('should filter search results by relevance score', async () => {
      const query = 'law firms'
      const location = 'Chicago, IL'
      const config = createMockScrapingConfig({ minRelevanceScore: 0.8 })

      mockSearchEngine.searchBusinesses.mockResolvedValue([
        { title: 'High Relevance Law Firm', url: 'https://highrelevance.com', snippet: 'Top law firm', relevanceScore: 0.9 },
        { title: 'Low Relevance Result', url: 'https://lowrelevance.com', snippet: 'Unrelated content', relevanceScore: 0.5 },
      ])

      const result = await scraperService.scrapeBySearch(query, location, config)

      // Should only scrape the high relevance result
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledTimes(1)
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledWith(
        'https://highrelevance.com',
        expect.any(Object)
      )
    })
  })

  describe('Data Enrichment and Geocoding', () => {
    it('should enrich scraped data with geocoding information', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableGeocoding: true })

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses[0]).toMatchObject({
        latitude: 34.0522,
        longitude: -118.2437,
      })
      expect(mockGeocoder.geocodeAddress).toHaveBeenCalledWith(
        '123 Main Street, Los Angeles, CA 90210'
      )
    })

    it('should handle geocoding failures gracefully', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableGeocoding: true })

      mockGeocoder.geocodeAddress.mockRejectedValue(new Error('Geocoding service unavailable'))

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses[0]).not.toHaveProperty('latitude')
      expect(result.businesses[0]).not.toHaveProperty('longitude')
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'ScraperService',
        'Geocoding failed for business',
        expect.any(Error)
      )
    })

    it('should enrich business data with additional metadata', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableEnrichment: true })

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses[0]).toMatchObject({
        scrapedAt: expect.any(Date),
        source: 'web_scraping',
      })
    })
  })

  describe('Error Handling and Resilience', () => {
    it('should handle scraping failures gracefully', async () => {
      const url = 'https://example.com/invalid'
      const config = createMockScrapingConfig()

      mockEnhancedScrapingEngine.scrapeBusinessData.mockRejectedValue(
        new Error('Failed to scrape URL')
      )

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(0)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0]).toMatchObject({
        url,
        error: 'Failed to scrape URL',
        timestamp: expect.any(Date),
      })
      expect(mockLogger.error).toHaveBeenCalledWith(
        'ScraperService',
        'Scraping failed for URL',
        expect.any(Error)
      )
    })

    it('should retry failed scraping attempts', async () => {
      const url = 'https://example.com/flaky'
      const config = createMockScrapingConfig({ retries: 3 })

      mockEnhancedScrapingEngine.scrapeBusinessData
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockRejectedValueOnce(new Error('Another failure'))
        .mockResolvedValueOnce({
          businesses: [createMockBusinessRecord()],
          metadata: { totalPages: 1, totalResults: 1, processingTime: 5000, successRate: 1.0 },
        })

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(1)
      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledTimes(3)
    })

    it('should handle timeout scenarios', async () => {
      const url = 'https://example.com/slow'
      const config = createMockScrapingConfig({ timeout: 1000 })

      mockEnhancedScrapingEngine.scrapeBusinessData.mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 2000))
      )

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(0)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].error).toContain('timeout')
    })
  })

  describe('Memory Management and Performance', () => {
    it('should monitor memory usage during scraping', async () => {
      const url = 'https://example.com/large-directory'
      const config = createMockScrapingConfig()

      await scraperService.scrapeUrl(url, config)

      expect(mockMemoryMonitor.getMemoryUsage).toHaveBeenCalled()
    })

    it('should handle memory pressure gracefully', async () => {
      const urls = Array.from({ length: 10 }, (_, i) => `https://example.com/page${i}`)
      const config = createMockScrapingConfig()

      // Simulate high memory usage
      mockMemoryMonitor.getMemoryUsage.mockReturnValue({
        used: 900 * 1024 * 1024, // 900MB
        total: 1024 * 1024 * 1024, // 1GB
        percentage: 90,
      })

      const result = await scraperService.scrapeBatch(urls, config)

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'ScraperService',
        'High memory usage detected',
        expect.any(Object)
      )
    })

    it('should respect rate limiting and delays', async () => {
      const urls = ['https://example.com/page1', 'https://example.com/page2']
      const config = createMockScrapingConfig({ delay: 1000 })

      const startTime = Date.now()
      await scraperService.scrapeBatch(urls, config)
      const endTime = Date.now()

      // Should take at least 1 second due to delay between requests
      expect(endTime - startTime).toBeGreaterThanOrEqual(1000)
    })
  })

  describe('Real-time Updates and WebSocket Integration', () => {
    it('should send real-time updates via WebSocket', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableRealTimeUpdates: true })

      await scraperService.scrapeUrl(url, config)

      expect(mockWebSocketServer.broadcast).toHaveBeenCalledWith(
        'scraping_progress',
        expect.objectContaining({
          status: 'completed',
          businessesFound: 1,
        })
      )
    })

    it('should send progress updates during batch scraping', async () => {
      const urls = Array.from({ length: 5 }, (_, i) => `https://example.com/page${i}`)
      const config = createMockScrapingConfig({ enableRealTimeUpdates: true })

      await scraperService.scrapeBatch(urls, config)

      expect(mockWebSocketServer.broadcast).toHaveBeenCalledWith(
        'scraping_progress',
        expect.objectContaining({
          status: 'in_progress',
          completed: expect.any(Number),
          total: 5,
        })
      )
    })
  })

  describe('Data Quality and Validation', () => {
    it('should validate scraped business data', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableValidation: true })

      mockEnhancedScrapingEngine.scrapeBusinessData.mockResolvedValue({
        businesses: [
          createMockBusinessRecord({ businessName: 'Valid Business' }),
          createMockBusinessRecord({ businessName: '', email: [] }), // Invalid
        ],
        metadata: { totalPages: 1, totalResults: 2, processingTime: 5000, successRate: 1.0 },
      })

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(1) // Only valid business should be included
      expect(result.businesses[0].businessName).toBe('Valid Business')
    })

    it('should deduplicate scraped businesses', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ enableDeduplication: true })

      mockEnhancedScrapingEngine.scrapeBusinessData.mockResolvedValue({
        businesses: [
          createMockBusinessRecord({ id: 'business-1', businessName: 'Duplicate Business' }),
          createMockBusinessRecord({ id: 'business-2', businessName: 'Duplicate Business' }),
          createMockBusinessRecord({ id: 'business-3', businessName: 'Unique Business' }),
        ],
        metadata: { totalPages: 1, totalResults: 3, processingTime: 5000, successRate: 1.0 },
      })

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.businesses).toHaveLength(2) // Duplicates should be removed
      expect(result.metadata.duplicatesRemoved).toBe(1)
    })

    it('should provide data quality metrics', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig()

      const result = await scraperService.scrapeUrl(url, config)

      expect(result.metadata).toMatchObject({
        totalPages: expect.any(Number),
        totalResults: expect.any(Number),
        processingTime: expect.any(Number),
        successRate: expect.any(Number),
      })
    })
  })

  describe('Compliance and Ethics', () => {
    it('should respect robots.txt when enabled', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({ respectRobotsTxt: true })

      await scraperService.scrapeUrl(url, config)

      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledWith(
        url,
        expect.objectContaining({ respectRobotsTxt: true })
      )
    })

    it('should use appropriate user agent strings', async () => {
      const url = 'https://example.com/business'
      const config = createMockScrapingConfig({
        userAgent: 'BusinessScraper/1.0 (+https://example.com/bot)',
      })

      await scraperService.scrapeUrl(url, config)

      expect(mockEnhancedScrapingEngine.scrapeBusinessData).toHaveBeenCalledWith(
        url,
        expect.objectContaining({
          userAgent: 'BusinessScraper/1.0 (+https://example.com/bot)',
        })
      )
    })

    it('should implement rate limiting to avoid overwhelming servers', async () => {
      const urls = Array.from({ length: 10 }, (_, i) => `https://example.com/page${i}`)
      const config = createMockScrapingConfig({ maxConcurrency: 2, delay: 500 })

      const startTime = Date.now()
      await scraperService.scrapeBatch(urls, config)
      const endTime = Date.now()

      // With 10 URLs, 2 concurrent, and 500ms delay, should take at least 2 seconds
      expect(endTime - startTime).toBeGreaterThanOrEqual(2000)
    })
  })
})
