/**
 * Tests for ClientSearchEngine domain blacklist functionality
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
  ApiCredentials: {}
}))

// Mock search result type
interface SearchResult {
  title: string
  url: string
  snippet: string
}

describe('ClientSearchEngine Domain Blacklist', () => {
  let searchEngine: ClientSearchEngine
  let mockCredentials: ApiCredentials

  beforeEach(async () => {
    mockCredentials = {
      googleSearchApiKey: 'test-key',
      googleSearchEngineId: 'test-engine',
      domainBlacklist: [
        'spam.com',
        'unwanted-site.net',
        'bad-domain.org'
      ]
    }

    // Mock the retrieveApiCredentials to return our test credentials
    const { retrieveApiCredentials } = require('@/utils/secureStorage')
    retrieveApiCredentials.mockResolvedValue(mockCredentials)

    searchEngine = new ClientSearchEngine()
    await searchEngine.initialize()
  })

  describe('applyDomainBlacklist', () => {
    it('should filter out blacklisted domains', () => {
      const mockResults: SearchResult[] = [
        {
          title: 'Good Business',
          url: 'https://goodbusiness.com/contact',
          snippet: 'A legitimate business'
        },
        {
          title: 'Spam Site',
          url: 'https://spam.com/fake-business',
          snippet: 'This should be filtered'
        },
        {
          title: 'Another Good Business',
          url: 'https://anothergood.com/about',
          snippet: 'Another legitimate business'
        },
        {
          title: 'Unwanted Site',
          url: 'https://unwanted-site.net/business',
          snippet: 'This should also be filtered'
        }
      ]

      // Access the private method using bracket notation for testing
      const filteredResults = (searchEngine as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(2)
      expect(filteredResults[0].url).toBe('https://goodbusiness.com/contact')
      expect(filteredResults[1].url).toBe('https://anothergood.com/about')
    })

    it('should handle case-insensitive domain matching', () => {
      const mockResults: SearchResult[] = [
        {
          title: 'Mixed Case Domain',
          url: 'https://SPAM.COM/business',
          snippet: 'Should be filtered despite case'
        },
        {
          title: 'Good Business',
          url: 'https://goodbusiness.com/contact',
          snippet: 'Should not be filtered'
        }
      ]

      const filteredResults = (searchEngine as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
      expect(filteredResults[0].url).toBe('https://goodbusiness.com/contact')
    })

    it('should handle subdomains correctly', () => {
      const mockResults: SearchResult[] = [
        {
          title: 'Subdomain of blacklisted',
          url: 'https://www.spam.com/business',
          snippet: 'Should be filtered'
        },
        {
          title: 'Different domain',
          url: 'https://notspam.com/business',
          snippet: 'Should not be filtered'
        }
      ]

      const filteredResults = (searchEngine as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
      expect(filteredResults[0].url).toBe('https://notspam.com/business')
    })

    it('should return all results when no blacklist is configured', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({
        googleSearchApiKey: 'test-key',
        googleSearchEngineId: 'test-engine'
        // No domainBlacklist
      })

      const searchEngineNoBlacklist = new ClientSearchEngine()
      await searchEngineNoBlacklist.initialize()

      const mockResults: SearchResult[] = [
        {
          title: 'Business 1',
          url: 'https://business1.com/contact',
          snippet: 'Business 1'
        },
        {
          title: 'Business 2',
          url: 'https://business2.com/contact',
          snippet: 'Business 2'
        }
      ]

      const filteredResults = (searchEngineNoBlacklist as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(2)
    })

    it('should return all results when blacklist is empty', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({
        googleSearchApiKey: 'test-key',
        googleSearchEngineId: 'test-engine',
        domainBlacklist: []
      })

      const searchEngineEmptyBlacklist = new ClientSearchEngine()
      await searchEngineEmptyBlacklist.initialize()

      const mockResults: SearchResult[] = [
        {
          title: 'Business 1',
          url: 'https://business1.com/contact',
          snippet: 'Business 1'
        }
      ]

      const filteredResults = (searchEngineEmptyBlacklist as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
    })

    it('should support wildcard subdomain patterns', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({
        googleSearchApiKey: 'test-key',
        googleSearchEngineId: 'test-engine',
        domainBlacklist: ['*.statefarm.com']
      })

      const searchEngineWildcard = new ClientSearchEngine()
      await searchEngineWildcard.initialize()

      const mockResults: SearchResult[] = [
        {
          title: 'State Farm Main',
          url: 'https://statefarm.com/insurance',
          snippet: 'Main site'
        },
        {
          title: 'State Farm Agent',
          url: 'https://agent.statefarm.com/profile',
          snippet: 'Agent site'
        },
        {
          title: 'State Farm WWW',
          url: 'https://www.statefarm.com/auto',
          snippet: 'WWW site'
        },
        {
          title: 'Good Business',
          url: 'https://goodbusiness.com/contact',
          snippet: 'Should not be filtered'
        }
      ]

      const filteredResults = (searchEngineWildcard as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
      expect(filteredResults[0].url).toBe('https://goodbusiness.com/contact')
    })

    it('should support TLD wildcard patterns', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({
        googleSearchApiKey: 'test-key',
        googleSearchEngineId: 'test-engine',
        domainBlacklist: ['statefarm.*']
      })

      const searchEngineTldWildcard = new ClientSearchEngine()
      await searchEngineTldWildcard.initialize()

      const mockResults: SearchResult[] = [
        {
          title: 'State Farm COM',
          url: 'https://statefarm.com/insurance',
          snippet: 'COM site'
        },
        {
          title: 'State Farm NET',
          url: 'https://statefarm.net/info',
          snippet: 'NET site'
        },
        {
          title: 'State Farm ORG',
          url: 'https://statefarm.org/about',
          snippet: 'ORG site'
        },
        {
          title: 'Good Business',
          url: 'https://goodbusiness.com/contact',
          snippet: 'Should not be filtered'
        }
      ]

      const filteredResults = (searchEngineTldWildcard as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
      expect(filteredResults[0].url).toBe('https://goodbusiness.com/contact')
    })

    it('should support middle wildcard patterns', async () => {
      const { retrieveApiCredentials } = require('@/utils/secureStorage')
      retrieveApiCredentials.mockResolvedValue({
        googleSearchApiKey: 'test-key',
        googleSearchEngineId: 'test-engine',
        domainBlacklist: ['*insurance*']
      })

      const searchEngineMiddleWildcard = new ClientSearchEngine()
      await searchEngineMiddleWildcard.initialize()

      const mockResults: SearchResult[] = [
        {
          title: 'My Insurance',
          url: 'https://myinsurance.com/quotes',
          snippet: 'Insurance site'
        },
        {
          title: 'Best Insurance',
          url: 'https://bestinsurance.net/auto',
          snippet: 'Insurance site'
        },
        {
          title: 'Insurance Quotes',
          url: 'https://insurance-quotes.org/home',
          snippet: 'Insurance site'
        },
        {
          title: 'Good Business',
          url: 'https://goodbusiness.com/contact',
          snippet: 'Should not be filtered'
        }
      ]

      const filteredResults = (searchEngineMiddleWildcard as any).applyDomainBlacklist(mockResults)

      expect(filteredResults).toHaveLength(1)
      expect(filteredResults[0].url).toBe('https://goodbusiness.com/contact')
    })

    it('should handle invalid URLs gracefully', () => {
      const mockResults: SearchResult[] = [
        {
          title: 'Invalid URL',
          url: 'not-a-valid-url',
          snippet: 'This has an invalid URL'
        },
        {
          title: 'Valid Business',
          url: 'https://validbusiness.com/contact',
          snippet: 'This should remain'
        }
      ]

      const filteredResults = (searchEngine as any).applyDomainBlacklist(mockResults)

      // Should keep the valid URL and handle the invalid one gracefully
      expect(filteredResults).toHaveLength(2) // Both should remain as invalid URL can't be parsed
    })
  })
})
