/**
 * Test suite for concurrent search functionality in SearchOrchestrator
 */

import { SearchOrchestrator, SearchProvider, BusinessDiscoveryProvider, SearchOptions, BusinessResult } from '../searchProviderAbstraction'
import { logger } from '@/utils/logger'

// Mock logger to avoid console output during tests
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}))

// Mock search providers
class MockSearchProvider implements SearchProvider {
  constructor(public name: string, private delay: number = 100, private shouldFail: boolean = false) {}

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    await new Promise(resolve => setTimeout(resolve, this.delay))
    
    if (this.shouldFail) {
      throw new Error(`${this.name} search failed`)
    }

    return [
      {
        title: `${this.name} Business 1`,
        url: `https://${this.name.toLowerCase()}.example.com/business1`,
        snippet: `Business found via ${this.name}`,
        domain: `${this.name.toLowerCase()}.example.com`,
        location: options.location || 'Unknown',
        phone: '555-0001',
        rating: 4.5,
        reviewCount: 100,
        category: 'Test Business',
        source: this.name
      }
    ]
  }
}

class MockBusinessProvider implements BusinessDiscoveryProvider {
  constructor(public name: string, private delay: number = 150, private shouldFail: boolean = false) {}

  async searchBusinesses(options: SearchOptions): Promise<BusinessResult[]> {
    await new Promise(resolve => setTimeout(resolve, this.delay))
    
    if (this.shouldFail) {
      throw new Error(`${this.name} business search failed`)
    }

    return [
      {
        title: `${this.name} Business Directory`,
        url: `https://${this.name.toLowerCase()}.example.com/directory`,
        snippet: `Business directory from ${this.name}`,
        domain: `${this.name.toLowerCase()}.example.com`,
        location: options.location || 'Unknown',
        phone: '555-0002',
        rating: 4.0,
        reviewCount: 50,
        category: 'Directory',
        source: this.name
      }
    ]
  }
}

describe('SearchOrchestrator Concurrent Searches', () => {
  let orchestrator: SearchOrchestrator
  let mockSearchProvider1: MockSearchProvider
  let mockSearchProvider2: MockSearchProvider
  let mockBusinessProvider1: MockBusinessProvider

  beforeEach(() => {
    // Create orchestrator with concurrent searches enabled (no business providers by default)
    orchestrator = new SearchOrchestrator({
      enableConcurrentSearches: true,
      maxConcurrentProviders: 4,
      searchTimeout: 5000
    })

    // Clear the default business providers for testing
    ;(orchestrator as any).businessDiscoveryProviders = []

    // Create mock providers
    mockSearchProvider1 = new MockSearchProvider('MockGoogle', 100)
    mockSearchProvider2 = new MockSearchProvider('MockBing', 150)
    mockBusinessProvider1 = new MockBusinessProvider('MockBBB', 200)

    // Register providers
    orchestrator.registerSearchProvider(mockSearchProvider1)
    orchestrator.registerSearchProvider(mockSearchProvider2)
    ;(orchestrator as any).businessDiscoveryProviders.push(mockBusinessProvider1)

    // Clear mock calls
    jest.clearAllMocks()
  })

  afterEach(() => {
    // Clean up any pending timers
    jest.clearAllTimers()
  })

  describe('Concurrent Search Execution', () => {
    it('should execute searches concurrently and return combined results', async () => {
      const searchOptions: SearchOptions = {
        query: 'restaurants',
        location: 'New York, NY',
        maxResults: 10
      }

      const startTime = Date.now()
      const results = await orchestrator.searchBusinesses(searchOptions)
      const duration = Date.now() - startTime

      // Should have results from both providers
      expect(results).toHaveLength(3) // 2 SERP + 1 Business provider
      expect(results.some(r => r.source === 'MockGoogle')).toBe(true)
      expect(results.some(r => r.source === 'MockBing')).toBe(true)
      expect(results.some(r => r.source === 'MockBBB')).toBe(true)

      // Should complete faster than sequential execution
      // Sequential would be: 100 + 150 + 200 = 450ms minimum
      // Concurrent should be: max(100, 150, 200) = 200ms + overhead
      expect(duration).toBeLessThan(400) // Allow some overhead
    })

    it('should handle provider failures gracefully in concurrent mode', async () => {
      // Add a failing provider
      const failingProvider = new MockSearchProvider('FailingProvider', 50, true)
      orchestrator.registerSearchProvider(failingProvider)

      const searchOptions: SearchOptions = {
        query: 'restaurants',
        location: 'New York, NY',
        maxResults: 10
      }

      const results = await orchestrator.searchBusinesses(searchOptions)

      // Should still get results from working providers
      expect(results.length).toBeGreaterThan(0)
      expect(results.some(r => r.source === 'MockGoogle')).toBe(true)
      expect(results.some(r => r.source === 'MockBing')).toBe(true)
      
      // Should not have results from failing provider
      expect(results.some(r => r.source === 'FailingProvider')).toBe(false)

      // Should log the failure
      expect(logger.warn).toHaveBeenCalledWith(
        'SearchOrchestrator',
        expect.stringContaining('FailingProvider'),
        expect.any(Error)
      )
    })

    it('should respect timeout configuration', async () => {
      // Create orchestrator with very short timeout
      const shortTimeoutOrchestrator = new SearchOrchestrator({
        enableConcurrentSearches: true,
        searchTimeout: 50 // Very short timeout
      })

      // Add slow provider
      const slowProvider = new MockSearchProvider('SlowProvider', 200) // Slower than timeout
      shortTimeoutOrchestrator.registerSearchProvider(slowProvider)

      const searchOptions: SearchOptions = {
        query: 'restaurants',
        location: 'New York, NY',
        maxResults: 10
      }

      const startTime = Date.now()
      const results = await shortTimeoutOrchestrator.searchBusinesses(searchOptions)
      const duration = Date.now() - startTime

      // Should complete quickly due to timeout
      expect(duration).toBeLessThan(150) // Should timeout before 200ms delay

      // Should log timeout warning
      expect(logger.warn).toHaveBeenCalledWith(
        'SearchOrchestrator',
        expect.stringContaining('timed out'),
        expect.any(Error)
      )
    })
  })

  describe('Sequential vs Concurrent Mode', () => {
    it('should support switching between concurrent and sequential modes', async () => {
      const searchOptions: SearchOptions = {
        query: 'restaurants',
        location: 'New York, NY',
        maxResults: 10
      }

      // Test concurrent mode
      orchestrator.updateConfig({ enableConcurrentSearches: true })
      const concurrentResults = await orchestrator.searchBusinesses(searchOptions)

      // Test sequential mode
      orchestrator.updateConfig({ enableConcurrentSearches: false })
      const sequentialResults = await orchestrator.searchBusinesses(searchOptions)

      // Both should return same number of results
      expect(concurrentResults).toHaveLength(sequentialResults.length)
      expect(concurrentResults).toHaveLength(3) // 2 SERP + 1 Business provider

      // Should log different modes
      expect(logger.info).toHaveBeenCalledWith(
        'SearchOrchestrator',
        expect.stringContaining('concurrent search')
      )
      expect(logger.info).toHaveBeenCalledWith(
        'SearchOrchestrator',
        expect.stringContaining('sequential search')
      )
    })
  })

  describe('Configuration Management', () => {
    it('should allow configuration updates', () => {
      const newConfig = {
        enableConcurrentSearches: false,
        maxConcurrentProviders: 8,
        searchTimeout: 10000
      }

      orchestrator.updateConfig(newConfig)
      const currentConfig = orchestrator.getConfig()

      expect(currentConfig.enableConcurrentSearches).toBe(false)
      expect(currentConfig.maxConcurrentProviders).toBe(8)
      expect(currentConfig.searchTimeout).toBe(10000)
    })

    it('should use default configuration values', () => {
      const defaultOrchestrator = new SearchOrchestrator()
      const config = defaultOrchestrator.getConfig()

      expect(config.enableConcurrentSearches).toBe(true)
      expect(config.maxConcurrentProviders).toBe(6)
      expect(config.searchTimeout).toBe(120000)
    })
  })
})
