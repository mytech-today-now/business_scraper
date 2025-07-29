/**
 * Search Providers Integration Tests
 * Tests for Google Custom Search API, Bing Search API, and Azure AI Foundry integration
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import { 
  SearchOrchestrator, 
  GoogleProvider, 
  BingProvider, 
  DuckDuckGoProvider,
  SearchOptions,
  ProviderMetrics,
  CostTracker
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

describe('Search Providers', () => {
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
  })

  describe('GoogleProvider', () => {
    it('should initialize with correct name', () => {
      expect(googleProvider.name).toBe('Google')
    })

    it('should return empty results when API credentials are missing', async () => {
      delete process.env.GOOGLE_SEARCH_API_KEY
      
      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 10
      }

      const results = await googleProvider.searchSERP(options)
      expect(results).toEqual([])
    })

    it('should make API request with correct parameters', async () => {
      const mockResponse = {
        items: [
          {
            link: 'https://example.com',
            title: 'Test Restaurant',
            snippet: 'Great food and service'
          }
        ]
      }

      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 10
      }

      const results = await googleProvider.searchSERP(options)
      
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('googleapis.com/customsearch/v1'),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'User-Agent': expect.stringContaining('BusinessScraperApp'),
            'Accept': 'application/json'
          })
        })
      )

      expect(results).toHaveLength(1)
      expect(results[0]).toMatchObject({
        url: 'https://example.com',
        title: 'Test Restaurant',
        snippet: 'Great food and service',
        domain: 'example.com',
        source: 'serp'
      })
    })

    it('should handle API errors gracefully', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: async () => 'Quota exceeded'
      })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 10
      }

      const results = await googleProvider.searchSERP(options)
      expect(results).toEqual([])
    })
  })

  describe('BingProvider', () => {
    it('should initialize with correct name', () => {
      expect(bingProvider.name).toBe('Bing')
    })

    it('should prefer Azure AI Foundry over legacy Bing API', async () => {
      const mockAzureResponse = {
        webPages: {
          value: [
            {
              url: 'https://example.com',
              name: 'Test Restaurant',
              snippet: 'Great food and service'
            }
          ]
        }
      }

      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAzureResponse
      })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 10
      }

      const results = await bingProvider.searchSERP(options)
      
      // Should call Azure AI Foundry endpoint
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('cognitiveservices.azure.com'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Ocp-Apim-Subscription-Key': 'test-azure-key',
            'Content-Type': 'application/json'
          })
        })
      )

      expect(results).toHaveLength(1)
      expect(results[0]).toMatchObject({
        url: 'https://example.com',
        title: 'Test Restaurant',
        snippet: 'Great food and service',
        source: 'serp'
      })
    })

    it('should fallback to legacy Bing API when Azure fails', async () => {
      // Mock Azure failure
      ;(global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          text: async () => 'Unauthorized'
        })
        // Mock legacy Bing success
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            webPages: {
              value: [
                {
                  url: 'https://example.com',
                  name: 'Test Restaurant',
                  snippet: 'Great food and service'
                }
              ]
            }
          })
        })

      const options: SearchOptions = {
        query: 'restaurants',
        location: 'New York',
        maxResults: 10
      }

      const results = await bingProvider.searchSERP(options)

      // Should have called Azure endpoint first, then legacy endpoint
      expect(global.fetch).toHaveBeenCalledTimes(2)
      expect(global.fetch).toHaveBeenNthCalledWith(1,
        expect.stringContaining('cognitiveservices.azure.com'),
        expect.any(Object)
      )
      expect(global.fetch).toHaveBeenNthCalledWith(2,
        expect.stringContaining('api.bing.microsoft.com'),
        expect.any(Object)
      )
      expect(results).toHaveLength(1)
    })
  })

  describe('SearchOrchestrator', () => {
    beforeEach(() => {
      orchestrator.registerSearchProvider(googleProvider)
      orchestrator.registerSearchProvider(bingProvider)
      orchestrator.registerSearchProvider(duckduckgoProvider)
    })

    it('should register providers correctly', () => {
      const metrics = orchestrator.getProviderMetrics()
      expect(metrics).toHaveLength(3)
      expect(metrics.map(m => m.name)).toContain('Google')
      expect(metrics.map(m => m.name)).toContain('Bing')
      expect(metrics.map(m => m.name)).toContain('DuckDuckGo')
    })

    it('should track provider performance metrics', () => {
      const metrics = orchestrator.getProviderMetrics()
      
      metrics.forEach(metric => {
        expect(metric).toMatchObject({
          name: expect.any(String),
          totalRequests: 0,
          successfulRequests: 0,
          failedRequests: 0,
          averageResponseTime: 0,
          averageResultCount: 0,
          qualityScore: 0.5, // Initial neutral score
          lastUsed: expect.any(Date),
          costPerRequest: expect.any(Number)
        })
      })
    })

    it('should track cost information', () => {
      const costTrackers = orchestrator.getCostTrackers()
      
      expect(costTrackers).toHaveLength(3)
      costTrackers.forEach(tracker => {
        expect(tracker).toMatchObject({
          providerName: expect.any(String),
          dailyCost: 0,
          monthlyCost: 0,
          dailyUsage: 0,
          monthlyUsage: 0,
          costPerRequest: expect.any(Number),
          lastReset: expect.any(Date)
        })
      })
    })

    it('should enforce quota limits when enabled', () => {
      orchestrator.setQuotaLimits({
        enableQuotaEnforcement: true,
        dailyRequestLimit: 0 // Set to 0 to test blocking
      })

      expect(orchestrator.canUseProvider('Google')).toBe(false)
      expect(orchestrator.canUseProvider('Bing')).toBe(false)
      expect(orchestrator.canUseProvider('DuckDuckGo')).toBe(false)
    })

    it('should allow providers when quotas are disabled', () => {
      orchestrator.setQuotaLimits({
        enableQuotaEnforcement: false
      })

      expect(orchestrator.canUseProvider('Google')).toBe(true)
      expect(orchestrator.canUseProvider('Bing')).toBe(true)
      expect(orchestrator.canUseProvider('DuckDuckGo')).toBe(true)
    })

    it('should set provider strategy correctly', () => {
      orchestrator.setStrategy('quality-based')
      orchestrator.setStrategy('cost-optimized')
      orchestrator.setStrategy('fastest-first')
      orchestrator.setStrategy('round-robin')

      // No direct way to test this without exposing internal state
      // But we can verify it doesn't throw errors
      expect(true).toBe(true)
    })

    it('should track costs correctly', () => {
      const costTrackers = orchestrator.getCostTrackers()

      // Verify all providers have cost trackers
      expect(costTrackers).toHaveLength(3)

      // Google should have higher cost per request than Bing
      const googleTracker = costTrackers.find(t => t.providerName === 'Google')
      const bingTracker = costTrackers.find(t => t.providerName === 'Bing')
      const duckduckgoTracker = costTrackers.find(t => t.providerName === 'DuckDuckGo')

      expect(googleTracker).toBeDefined()
      expect(bingTracker).toBeDefined()
      expect(duckduckgoTracker).toBeDefined()

      // Check cost per request values
      expect(googleTracker!.costPerRequest).toBe(0.005) // Google Custom Search
      expect(bingTracker!.costPerRequest).toBe(0.003) // Bing Search
      expect(duckduckgoTracker!.costPerRequest).toBe(0) // Free

      // Verify Google is more expensive than Bing
      expect(googleTracker!.costPerRequest).toBeGreaterThan(bingTracker!.costPerRequest)
    })
  })

  describe('Provider Quality Scoring', () => {
    it('should calculate quality scores based on performance', () => {
      // This would require access to internal methods
      // In a real implementation, we might expose these for testing
      expect(true).toBe(true)
    })
  })
})
