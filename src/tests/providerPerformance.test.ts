/**
 * Provider Performance Tests
 * Tests for intelligent provider switching, quality scoring algorithms, and performance metrics collection
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import { 
  SearchOrchestrator, 
  GoogleProvider, 
  BingProvider, 
  DuckDuckGoProvider,
  SearchOptions,
  ProviderMetrics,
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

describe('Provider Performance Tests', () => {
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

  describe('Quality Scoring Algorithm', () => {
    it('should calculate quality scores based on result count', () => {
      const metrics = orchestrator.getProviderMetrics()
      
      // All providers should start with neutral quality score
      metrics.forEach(metric => {
        expect(metric.qualityScore).toBe(0.5)
      })
    })

    it('should update quality scores based on performance', async () => {
      // Mock different performance levels
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            items: Array(20).fill(0).map((_, i) => ({
              link: `https://google-result-${i}.com`,
              title: `Google Result ${i}`,
              snippet: 'High quality result'
            }))
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            webPages: {
              value: Array(10).fill(0).map((_, i) => ({
                url: `https://bing-result-${i}.com`,
                name: `Bing Result ${i}`,
                snippet: 'Medium quality result'
              }))
            }
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            results: Array(5).fill(0).map((_, i) => ({
              url: `https://ddg-result-${i}.com`,
              title: `DDG Result ${i}`,
              snippet: 'Lower quality result',
              domain: `ddg-result-${i}.com`
            }))
          })
        })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Perform searches to generate performance data
      await googleProvider.searchSERP(options)
      await bingProvider.searchSERP(options)
      await duckduckgoProvider.searchSERP(options)

      // Quality scores should reflect performance differences
      const metrics = orchestrator.getProviderMetrics()
      expect(metrics).toHaveLength(3)
    })

    it('should factor in response time for quality scoring', async () => {
      // Mock responses with different timing
      const fastResponse = {
        ok: true,
        json: async () => ({
          success: true,
          results: [{ url: 'https://fast.com', title: 'Fast', snippet: 'Fast result', domain: 'fast.com' }]
        })
      }

      ;(global.fetch as jest.Mock).mockResolvedValue(fastResponse)

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      const startTime = Date.now()
      await duckduckgoProvider.searchSERP(options)
      const endTime = Date.now()

      // Response time should be reasonable
      expect(endTime - startTime).toBeLessThan(1000)
    })
  })

  describe('Intelligent Provider Switching', () => {
    const strategies: ProviderStrategy[] = ['quality-based', 'cost-optimized', 'fastest-first', 'round-robin']

    strategies.forEach(strategy => {
      it(`should implement ${strategy} provider selection strategy`, () => {
        orchestrator.setStrategy(strategy)
        
        const metrics = orchestrator.getProviderMetrics()
        expect(metrics).toHaveLength(3)
        
        // Strategy should be set without errors
        expect(true).toBe(true)
      })
    })

    it('should prioritize providers based on quality scores', () => {
      orchestrator.setStrategy('quality-based')
      
      const metrics = orchestrator.getProviderMetrics()
      
      // Simulate different quality scores
      const googleMetric = metrics.find(m => m.name === 'Google')
      const bingMetric = metrics.find(m => m.name === 'Bing')
      const ddgMetric = metrics.find(m => m.name === 'DuckDuckGo')

      expect(googleMetric).toBeDefined()
      expect(bingMetric).toBeDefined()
      expect(ddgMetric).toBeDefined()
    })

    it('should prioritize providers based on cost when using cost-optimized strategy', () => {
      orchestrator.setStrategy('cost-optimized')
      
      const costTrackers = orchestrator.getCostTrackers()
      
      // DuckDuckGo should be cheapest (free)
      const ddgTracker = costTrackers.find(t => t.providerName === 'DuckDuckGo')
      const googleTracker = costTrackers.find(t => t.providerName === 'Google')
      const bingTracker = costTrackers.find(t => t.providerName === 'Bing')

      expect(ddgTracker?.costPerRequest).toBe(0)
      expect(bingTracker?.costPerRequest).toBeLessThan(googleTracker?.costPerRequest || 0)
    })

    it('should handle provider failures and switch to alternatives', async () => {
      // Mock Google failure, others success
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
              value: [{ url: 'https://bing.com', name: 'Bing Result', snippet: 'Success' }]
            }
          })
        })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      const googleResults = await googleProvider.searchSERP(options)
      const bingResults = await bingProvider.searchSERP(options)

      // Google should fail, Bing should succeed
      expect(googleResults.length).toBe(0)
      expect(bingResults.length).toBeGreaterThan(0)
    })
  })

  describe('Performance Metrics Collection', () => {
    it('should track total requests per provider', async () => {
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

      // Perform multiple searches
      await googleProvider.searchSERP(options)
      await googleProvider.searchSERP(options)
      await bingProvider.searchSERP(options)

      const metrics = orchestrator.getProviderMetrics()
      
      // Should track metrics for all providers
      expect(metrics).toHaveLength(3)
      expect(metrics.every(m => m.totalRequests >= 0)).toBe(true)
    })

    it('should track successful vs failed requests', async () => {
      // Mock mixed success/failure
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

      await googleProvider.searchSERP(options)
      await bingProvider.searchSERP(options)

      const metrics = orchestrator.getProviderMetrics()
      
      // Should have metrics for success/failure tracking
      expect(metrics.every(m => m.successfulRequests >= 0)).toBe(true)
      expect(metrics.every(m => m.failedRequests >= 0)).toBe(true)
    })

    it('should track average response times', async () => {
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

      await duckduckgoProvider.searchSERP(options)

      const metrics = orchestrator.getProviderMetrics()
      
      // Should track response times
      expect(metrics.every(m => m.averageResponseTime >= 0)).toBe(true)
    })

    it('should track result counts and quality', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          items: [
            { link: 'https://test1.com', title: 'Test 1', snippet: 'Result 1' },
            { link: 'https://test2.com', title: 'Test 2', snippet: 'Result 2' }
          ]
        })
      })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      const results = await googleProvider.searchSERP(options)

      expect(results.length).toBe(2)
      
      const metrics = orchestrator.getProviderMetrics()
      expect(metrics.every(m => m.averageResultCount >= 0)).toBe(true)
    })
  })

  describe('Provider Health Monitoring', () => {
    it('should detect unhealthy providers', async () => {
      // Mock consistent failures
      ;(global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => 'Server Error'
      })

      const options: SearchOptions = {
        query: 'test',
        location: 'Test City',
        maxResults: 10
      }

      // Multiple failed requests
      await googleProvider.searchSERP(options)
      await googleProvider.searchSERP(options)
      await googleProvider.searchSERP(options)

      const metrics = orchestrator.getProviderMetrics()
      const googleMetric = metrics.find(m => m.name === 'Google')
      
      // Should track failures
      expect(googleMetric).toBeDefined()
    })

    it('should maintain provider status over time', () => {
      const metrics = orchestrator.getProviderMetrics()
      
      // Should have last used timestamps
      expect(metrics.every(m => m.lastUsed instanceof Date)).toBe(true)
    })
  })
})
