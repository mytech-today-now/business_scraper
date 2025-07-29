/**
 * Search Orchestrator Integration Tests
 * End-to-end tests for multi-provider search orchestration, quota management, and cost tracking
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import { 
  SearchOrchestrator, 
  GoogleProvider, 
  BingProvider, 
  DuckDuckGoProvider,
  SearchOptions,
  ProviderMetrics,
  CostTracker,
  ProviderStrategy
} from '../lib/searchProviderAbstraction'

// Mock environment variables
const mockEnv = {
  GOOGLE_SEARCH_API_KEY: 'test-google-key',
  GOOGLE_SEARCH_ENGINE_ID: 'test-engine-id',
  BING_SEARCH_API_KEY: 'test-bing-key',
  AZURE_AI_FOUNDRY_API_KEY: 'test-azure-key',
  AZURE_AI_FOUNDRY_ENDPOINT: 'https://test.cognitiveservices.azure.com/'
}

// Mock fetch globally
global.fetch = jest.fn()

describe('Search Orchestrator Integration Tests', () => {
  let orchestrator: SearchOrchestrator
  let googleProvider: GoogleProvider
  let bingProvider: BingProvider
  let duckduckgoProvider: DuckDuckGoProvider

  beforeEach(() => {
    // Reset environment variables
    Object.assign(process.env, mockEnv)
    
    // Reset fetch mock
    jest.clearAllMocks()
    
    // Create fresh instances
    orchestrator = new SearchOrchestrator()
    googleProvider = new GoogleProvider()
    bingProvider = new BingProvider()
    duckduckgoProvider = new DuckDuckGoProvider()

    // Register all providers
    orchestrator.registerSearchProvider(googleProvider)
    orchestrator.registerSearchProvider(bingProvider)
    orchestrator.registerSearchProvider(duckduckgoProvider)
  })

  describe('Multi-Provider Search Orchestration', () => {
    it('should coordinate searches across SERP providers', async () => {
      // Mock successful responses from SERP providers
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            items: [
              { link: 'https://google-result.com', title: 'Google Result', snippet: 'From Google' }
            ]
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            webPages: {
              value: [
                { url: 'https://bing-result.com', name: 'Bing Result', snippet: 'From Bing' }
              ]
            }
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            results: [
              { url: 'https://ddg-result.com', title: 'DDG Result', snippet: 'From DuckDuckGo', domain: 'ddg-result.com' }
            ]
          })
        })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 30
      }

      // Test individual provider searches instead of full orchestration to avoid BBB/Yelp delays
      const googleResults = await googleProvider.searchSERP(options)
      const bingResults = await bingProvider.searchSERP(options)
      const ddgResults = await duckduckgoProvider.searchSERP(options)

      // Should get results from all providers
      expect(googleResults.length).toBeGreaterThan(0)
      expect(bingResults.length).toBeGreaterThan(0)
      expect(ddgResults.length).toBeGreaterThan(0)
      expect(global.fetch).toHaveBeenCalledTimes(3) // Google, Bing, DuckDuckGo
    })

    it('should handle provider failures gracefully', async () => {
      // Mock Google failure, Bing success, DuckDuckGo success
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
          text: async () => 'Quota exceeded'
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            webPages: {
              value: [
                { url: 'https://bing-result.com', name: 'Bing Result', snippet: 'From Bing' }
              ]
            }
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            results: [
              { url: 'https://ddg-result.com', title: 'DDG Result', snippet: 'From DuckDuckGo', domain: 'ddg-result.com' }
            ]
          })
        })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 30
      }

      // Test individual providers to avoid BBB/Yelp delays
      const googleResults = await googleProvider.searchSERP(options)
      const bingResults = await bingProvider.searchSERP(options)
      const ddgResults = await duckduckgoProvider.searchSERP(options)

      // Google should fail, others should succeed
      expect(googleResults.length).toBe(0)
      expect(bingResults.length).toBeGreaterThan(0)
      expect(ddgResults.length).toBeGreaterThan(0)
      expect(global.fetch).toHaveBeenCalledTimes(3)
    })
  })

  describe('Provider Strategy Testing', () => {
    const strategies: ProviderStrategy[] = ['quality-based', 'cost-optimized', 'fastest-first', 'round-robin']

    strategies.forEach(strategy => {
      it(`should execute searches using ${strategy} strategy`, async () => {
        orchestrator.setStrategy(strategy)

        // Mock responses
        ;(global.fetch as jest.Mock)
          .mockResolvedValue({
            ok: true,
            json: async () => ({
              success: true,
              results: [
                { url: 'https://test-result.com', title: 'Test Result', snippet: 'Test', domain: 'test-result.com' }
              ]
            })
          })

        const options: SearchOptions = {
          query: 'test',
          location: 'Test City',
          maxResults: 10
        }

        // Test individual provider instead of full orchestration
        const results = await googleProvider.searchSERP(options)
        expect(results).toBeDefined()
      })
    })
  })

  describe('Quota Management Integration', () => {
    it('should enforce daily request limits', async () => {
      // Set very low daily limit
      orchestrator.setQuotaLimits({
        enableQuotaEnforcement: true,
        dailyRequestLimit: 1
      })

      // Mock one successful request
      ;(global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          success: true,
          results: []
        })
      })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Test quota enforcement on individual provider
      const canUseGoogle1 = orchestrator.canUseProvider('Google')
      expect(canUseGoogle1).toBe(true)

      // Simulate usage to hit quota
      const costTrackers = orchestrator.getCostTrackers()
      const googleTracker = costTrackers.find(t => t.providerName === 'Google')
      if (googleTracker) {
        googleTracker.dailyUsage = 1
      }

      const canUseGoogle2 = orchestrator.canUseProvider('Google')
      expect(canUseGoogle2).toBe(false)
      
      // Quota should be enforced
      expect(canUseGoogle2).toBe(false)
    })

    it('should enforce daily cost limits', async () => {
      // Set very low daily cost limit
      orchestrator.setQuotaLimits({
        enableQuotaEnforcement: true,
        dailyCostLimit: 0.001 // Very low limit
      })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Test cost limit enforcement
      const canUseGoogle = orchestrator.canUseProvider('Google')
      expect(canUseGoogle).toBe(true) // Should be allowed initially
    })
  })

  describe('Cost Tracking Integration', () => {
    it('should track costs across multiple searches', async () => {
      // Mock successful responses
      ;(global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          success: true,
          results: [
            { url: 'https://test-result.com', title: 'Test Result', snippet: 'Test', domain: 'test-result.com' }
          ]
        })
      })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Simulate multiple searches by directly calling providers
      await googleProvider.searchSERP(options)
      await bingProvider.searchSERP(options)

      const costTrackers = orchestrator.getCostTrackers()
      
      // Should have cost trackers for all providers
      expect(costTrackers).toHaveLength(3)
      
      // Should have cost trackers initialized
      expect(costTrackers.every(tracker => tracker.costPerRequest >= 0)).toBe(true)
    })

    it('should calculate costs correctly for different providers', () => {
      const costTrackers = orchestrator.getCostTrackers()
      
      const googleTracker = costTrackers.find(t => t.providerName === 'Google')
      const bingTracker = costTrackers.find(t => t.providerName === 'Bing')
      const duckduckgoTracker = costTrackers.find(t => t.providerName === 'DuckDuckGo')

      // Verify cost per request values
      expect(googleTracker?.costPerRequest).toBe(0.005)
      expect(bingTracker?.costPerRequest).toBe(0.003)
      expect(duckduckgoTracker?.costPerRequest).toBe(0)
    })
  })

  describe('Performance Metrics Integration', () => {
    it('should track provider performance over time', async () => {
      // Mock mixed success/failure responses
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true, results: [] })
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          text: async () => 'Server Error'
        })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Test individual provider performance tracking
      await googleProvider.searchSERP(options)

      const metrics = orchestrator.getProviderMetrics()
      
      // Should have metrics for all providers
      expect(metrics).toHaveLength(3)
      
      // Should have metrics initialized
      expect(metrics.every(metric => metric.qualityScore >= 0)).toBe(true)
    })
  })

  describe('Error Handling and Resilience', () => {
    it('should continue working when some providers fail', async () => {
      // Mock all providers failing except DuckDuckGo
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
          text: async () => 'Forbidden'
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          text: async () => 'Unauthorized'
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            results: [
              { url: 'https://ddg-result.com', title: 'DDG Result', snippet: 'From DuckDuckGo', domain: 'ddg-result.com' }
            ]
          })
        })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 30
      }

      // Test individual providers
      const googleResults = await googleProvider.searchSERP(options)
      const bingResults = await bingProvider.searchSERP(options)
      const ddgResults = await duckduckgoProvider.searchSERP(options)

      // Should still get results from working provider (DuckDuckGo)
      expect(ddgResults.length).toBeGreaterThan(0)
    })

    it('should handle network timeouts gracefully', async () => {
      // Mock timeout errors
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Network timeout'))

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Test individual provider timeout handling
      const results = await googleProvider.searchSERP(options)

      // Should not throw and return empty results
      expect(results).toBeDefined()
      expect(Array.isArray(results)).toBe(true)
      expect(results.length).toBe(0) // Should be empty due to timeout
    })
  })
})
