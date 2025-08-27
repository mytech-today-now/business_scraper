/**
 * Tests for Azure AI Foundry "Grounding with Bing Custom Search" integration
 */

import { ClientSearchEngine } from '@/model/clientSearchEngine'
import { ApiCredentials } from '@/utils/secureStorage'

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

// Mock the secure storage
jest.mock('@/utils/secureStorage', () => ({
  retrieveApiCredentials: jest.fn(),
  ApiCredentials: {},
}))

// Mock fetch for API calls
global.fetch = jest.fn()

describe('Azure AI Foundry Integration', () => {
  let searchEngine: ClientSearchEngine
  let mockCredentials: ApiCredentials

  beforeEach(() => {
    mockCredentials = {
      azureSearchApiKey: 'test-azure-key',
      azureSearchEndpoint: 'https://businessscraper.cognitiveservices.azure.com/',
      azureSearchRegion: 'eastus',
    }

    // Mock the retrieveApiCredentials to return our test credentials
    const { retrieveApiCredentials } = require('@/utils/secureStorage')
    retrieveApiCredentials.mockResolvedValue(mockCredentials)

    searchEngine = new ClientSearchEngine()

    // Clear all mocks
    jest.clearAllMocks()
  })

  describe('Azure AI Foundry API Integration', () => {
    it('should construct correct API endpoint for Grounding with Bing Custom Search', async () => {
      const mockResponse = {
        webPages: {
          value: [
            {
              url: 'https://example-business.com',
              name: 'Example Business',
              snippet: 'A great business in the area',
            },
          ],
        },
      }

      ;(fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      })

      await searchEngine.initialize()

      // Access the private method for testing
      const results = await (searchEngine as any).searchWithAzure('restaurants', 'New York', 10)

      // Verify the fetch was called with correct endpoint
      expect(fetch).toHaveBeenCalledWith(
        'https://businessscraper.cognitiveservices.azure.com/bing/v7.0/custom/search',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Ocp-Apim-Subscription-Key': 'test-azure-key',
            'Content-Type': 'application/json',
          }),
          body: expect.stringContaining('"q":"restaurants New York"'),
        })
      )

      expect(results).toHaveLength(1)
      expect(results[0]).toEqual({
        url: 'https://example-business.com',
        title: 'Example Business',
        snippet: 'A great business in the area',
        domain: 'example-business.com',
      })
    })

    it('should handle API errors gracefully', async () => {
      ;(fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () => 'Unauthorized',
      })

      await searchEngine.initialize()

      await expect(
        (searchEngine as any).searchWithAzure('restaurants', 'New York', 10)
      ).rejects.toThrow('Azure AI Foundry API error: 401')
    })

    it('should handle missing credentials', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({})

      const searchEngineNoCredentials = new ClientSearchEngine()
      await searchEngineNoCredentials.initialize()

      await expect(
        (searchEngineNoCredentials as any).searchWithAzure('restaurants', 'New York', 10)
      ).rejects.toThrow('Azure AI Foundry credentials not configured')
    })

    it('should parse Azure AI Foundry response correctly', () => {
      const mockData = {
        webPages: {
          value: [
            {
              url: 'https://restaurant1.com',
              name: 'Restaurant One',
              snippet: 'Great food and service',
            },
            {
              url: 'https://restaurant2.com',
              name: 'Restaurant Two',
              snippet: 'Amazing atmosphere',
            },
          ],
        },
      }

      const results = (searchEngine as any).parseAzureGroundingResults(mockData, 10)

      expect(results).toHaveLength(2)
      expect(results[0]).toEqual({
        url: 'https://restaurant1.com',
        title: 'Restaurant One',
        snippet: 'Great food and service',
        domain: 'restaurant1.com',
      })
      expect(results[1]).toEqual({
        url: 'https://restaurant2.com',
        title: 'Restaurant Two',
        snippet: 'Amazing atmosphere',
        domain: 'restaurant2.com',
      })
    })

    it('should handle empty response gracefully', () => {
      const mockData = {}

      const results = (searchEngine as any).parseAzureGroundingResults(mockData, 10)

      expect(results).toHaveLength(0)
    })

    it('should filter out invalid URLs', () => {
      const mockData = {
        webPages: {
          value: [
            {
              url: 'https://valid-business.com',
              name: 'Valid Business',
              snippet: 'A valid business',
            },
            {
              url: 'invalid-url',
              name: 'Invalid URL',
              snippet: 'This should be filtered out',
            },
            {
              url: '',
              name: 'Empty URL',
              snippet: 'This should also be filtered out',
            },
          ],
        },
      }

      const results = (searchEngine as any).parseAzureGroundingResults(mockData, 10)

      expect(results).toHaveLength(1)
      expect(results[0].url).toBe('https://valid-business.com')
    })

    it('should respect maxResults parameter', () => {
      const mockData = {
        webPages: {
          value: Array.from({ length: 20 }, (_, i) => ({
            url: `https://business${i}.com`,
            name: `Business ${i}`,
            snippet: `Description for business ${i}`,
          })),
        },
      }

      const results = (searchEngine as any).parseAzureGroundingResults(mockData, 5)

      expect(results).toHaveLength(5)
    })
  })

  describe('Backward Compatibility', () => {
    it('should maintain backward compatibility with legacy parseAzureResults method', () => {
      const mockData = {
        webPages: {
          value: [
            {
              url: 'https://legacy-test.com',
              name: 'Legacy Test',
              snippet: 'Testing backward compatibility',
            },
          ],
        },
      }

      const results = (searchEngine as any).parseAzureResults(mockData, 10)

      expect(results).toHaveLength(1)
      expect(results[0]).toEqual({
        url: 'https://legacy-test.com',
        title: 'Legacy Test',
        snippet: 'Testing backward compatibility',
        domain: 'legacy-test.com',
      })
    })
  })
})
