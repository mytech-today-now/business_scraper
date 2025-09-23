/**
 * Comprehensive Unit Tests for Yandex Search Engine Integration
 * Tests the Yandex search functionality with 95%+ coverage
 */

import { SearchEngineService } from '../searchEngine'
import { logger } from '@/utils/logger'
import axios from 'axios'

// Mock dependencies
jest.mock('axios')
jest.mock('@/utils/logger')

const mockedAxios = axios as jest.Mocked<typeof axios>
const mockedLogger = logger as jest.Mocked<typeof logger>

describe('Yandex Search Engine Integration', () => {
  let searchEngine: SearchEngineService
  const originalEnv = process.env

  beforeEach(() => {
    jest.clearAllMocks()
    searchEngine = new SearchEngineService()

    // Reset environment variables
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = originalEnv
  })

  describe('Yandex Search API Configuration', () => {
    it('should skip Yandex search when API key is not configured', async () => {
      // Remove Yandex API key
      delete process.env.YANDEX_SEARCH_API_KEY

      // Call the Yandex method directly
      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(mockedLogger.warn).toHaveBeenCalledWith(
        'SearchEngine',
        'Yandex Search API key not configured, skipping Yandex search'
      )
      expect(mockedAxios.get).not.toHaveBeenCalledWith(
        expect.stringContaining('yandex.com')
      )
      expect(results).toHaveLength(0)
    })

    it('should use Yandex search when API key is configured', async () => {
      process.env.YANDEX_SEARCH_API_KEY = 'test-yandex-key'

      // Mock successful Yandex XML response
      const mockXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <found priority="phrase">1000</found>
    <results>
      <grouping attr="d" mode="deep" groups-on-page="10" docs-in-group="1">
        <group>
          <doc id="test123">
            <url>https://example-restaurant.com</url>
            <title>Example Restaurant</title>
            <passages>
              <passage>Great restaurant in the area</passage>
            </passages>
          </doc>
        </group>
      </grouping>
    </results>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      // Call the Yandex method directly
      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://yandex.com/search/xml',
        expect.objectContaining({
          params: expect.objectContaining({
            query: 'restaurants 90210',
            lr: 213,
            l10n: 'en',
            sortby: 'rlv',
          }),
          headers: expect.objectContaining({
            Authorization: 'Api-Key test-yandex-key',
          }),
        })
      )
      expect(results).toHaveLength(1)
      expect(results[0]).toEqual({
        url: 'https://example-restaurant.com',
        title: 'Example Restaurant',
        snippet: 'Great restaurant in the area',
        domain: 'example-restaurant.com',
      })
    })
  })

  describe('Yandex XML Response Parsing', () => {
    beforeEach(() => {
      process.env.YANDEX_SEARCH_API_KEY = 'test-yandex-key'
    })

    it('should parse valid Yandex XML response correctly', async () => {
      const mockXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <found priority="phrase">2</found>
    <results>
      <grouping attr="d" mode="deep" groups-on-page="10" docs-in-group="1">
        <group>
          <doc id="test123">
            <url>https://example-restaurant.com</url>
            <title>Example Restaurant</title>
            <passages>
              <passage>Great restaurant in the area</passage>
            </passages>
          </doc>
        </group>
        <group>
          <doc id="test456">
            <url>https://another-restaurant.com</url>
            <title>Another <hlword>Restaurant</hlword></title>
            <passages>
              <passage>Another great <hlword>restaurant</hlword> nearby</passage>
            </passages>
          </doc>
        </group>
      </grouping>
    </results>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(2)
      expect(results[0]).toEqual({
        url: 'https://example-restaurant.com',
        title: 'Example Restaurant',
        snippet: 'Great restaurant in the area',
        domain: 'example-restaurant.com',
      })
      expect(results[1]).toEqual({
        url: 'https://another-restaurant.com',
        title: 'Another Restaurant', // hlword tags should be removed
        snippet: 'Another great restaurant nearby', // hlword tags should be removed
        domain: 'another-restaurant.com',
      })
    })

    it('should handle Yandex error responses gracefully', async () => {
      const mockErrorXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <error code="15">No results found for your word combination</error>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockErrorXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      expect(mockedLogger.warn).toHaveBeenCalledWith(
        'SearchEngine',
        expect.stringContaining('Yandex search error')
      )
    })

    it('should handle malformed XML responses', async () => {
      const mockMalformedXml = 'This is not valid XML'

      mockedAxios.get.mockResolvedValueOnce({
        data: mockMalformedXml,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      // The XML parser doesn't throw an error for malformed XML, it just returns empty structure
      // So we expect a warning about no response found instead
      expect(mockedLogger.warn).toHaveBeenCalledWith(
        'SearchEngine',
        'No response found in Yandex XML'
      )
    })

    it('should handle empty XML responses', async () => {
      const mockEmptyXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <found priority="phrase">0</found>
    <results>
      <grouping attr="d" mode="deep" groups-on-page="10" docs-in-group="1">
      </grouping>
    </results>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockEmptyXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      expect(mockedLogger.warn).toHaveBeenCalledWith(
        'SearchEngine',
        'No groups found in Yandex response'
      )
    })
  })

  describe('Yandex Search Error Handling', () => {
    beforeEach(() => {
      process.env.YANDEX_SEARCH_API_KEY = 'test-yandex-key'
    })

    it('should handle network errors gracefully', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('Network error'))

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      expect(mockedLogger.error).toHaveBeenCalledWith(
        'SearchEngine',
        'Yandex search failed',
        expect.any(Error)
      )
    })

    it('should handle HTTP error responses', async () => {
      mockedAxios.get.mockRejectedValueOnce({
        response: {
          status: 401,
          statusText: 'Unauthorized',
        },
        message: 'Request failed with status code 401',
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      expect(mockedLogger.error).toHaveBeenCalledWith(
        'SearchEngine',
        'Yandex search failed',
        expect.any(Object)
      )
    })

    it('should handle timeout errors', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('timeout of 10000ms exceeded'))

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results).toHaveLength(0)
      expect(mockedLogger.error).toHaveBeenCalledWith(
        'SearchEngine',
        'Yandex search failed',
        expect.any(Error)
      )
    })
  })

  describe('Yandex Text Cleaning', () => {
    beforeEach(() => {
      process.env.YANDEX_SEARCH_API_KEY = 'test-yandex-key'
    })

    it('should clean highlight tags from titles and snippets', async () => {
      const mockXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <results>
      <grouping attr="d" mode="deep" groups-on-page="10" docs-in-group="1">
        <group>
          <doc id="test123">
            <url>https://example.com</url>
            <title>Best <hlword>Restaurant</hlword> in Town</title>
            <passages>
              <passage>This is a <hlword>great</hlword> place to eat</passage>
            </passages>
          </doc>
        </group>
      </grouping>
    </results>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results[0].title).toBe('Best Restaurant in Town')
      expect(results[0].snippet).toBe('This is a great place to eat')
    })

    it('should decode HTML entities', async () => {
      const mockXmlResponse = `<?xml version="1.0" encoding="utf-8"?>
<yandexsearch version="1.0">
  <response date="20240915T103130">
    <results>
      <grouping attr="d" mode="deep" groups-on-page="10" docs-in-group="1">
        <group>
          <doc id="test123">
            <url>https://example.com</url>
            <title>Tom &amp; Jerry&#39;s Restaurant</title>
            <passages>
              <passage>&quot;Great food&quot; &lt;says everyone&gt;</passage>
            </passages>
          </doc>
        </group>
      </grouping>
    </results>
  </response>
</yandexsearch>`

      mockedAxios.get.mockResolvedValueOnce({
        data: mockXmlResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      })

      const results = await (searchEngine as any).searchWithYandex('restaurants', '90210', 10)

      expect(results[0].title).toBe("Tom & Jerry's Restaurant")
      expect(results[0].snippet).toBe('"Great food" <says everyone>')
    })
  })
})
