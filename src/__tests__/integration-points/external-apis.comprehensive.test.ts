/**
 * External APIs - Comprehensive Integration Points Tests
 *
 * Tests all external API integration points including:
 * - Search engine APIs (Google, Bing, DuckDuckGo)
 * - Geocoding services
 * - Email validation services
 * - Payment processing APIs
 * - Analytics and monitoring APIs
 * - Third-party data enrichment services
 * - Rate limiting and retry logic
 *
 * Updated to use standardized mock utilities for improved reliability.
 */

import { clientSearchEngine } from '@/model/clientSearchEngine'
import { geocoder } from '@/model/geocoder'
import { paymentController } from '@/controller/paymentController'
import { ExportService } from '@/utils/exportService'
import { enhancedErrorLogger } from '@/utils/enhancedErrorLogger'
import {
  setupMockEnvironment,
  createStandardizedHttpMock,
  createStripeMock,
  createGeocodingMock,
  cleanupUtils
} from '@/__tests__/utils/mockSetup'

// Setup standardized mock environment
setupMockEnvironment()

// Create standardized mocks
const httpMock = createStandardizedHttpMock()
const stripeMock = createStripeMock()
const geocodingMock = createGeocodingMock()

describe('External APIs - Comprehensive Integration Points Tests', () => {
  beforeEach(() => {
    // Reset all standardized mocks
    httpMock.reset()
    stripeMock.reset()
    geocodingMock.reset()
  })

  describe('Search Engine APIs', () => {
    describe('Google Custom Search API', () => {
      it('should search businesses using Google API', async () => {
        const mockResponse = {
          items: [
            {
              title: 'Test Restaurant - Best Food in Town',
              link: 'https://testrestaurant.com',
              snippet: 'Great restaurant with amazing food...',
              pagemap: {
                metatags: [{
                  'og:title': 'Test Restaurant',
                  'og:description': 'Best food in town'
                }]
              }
            }
          ],
          searchInformation: {
            totalResults: '1',
            searchTime: 0.45
          }
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        const results = await clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
        
        expect(results).toHaveLength(1)
        expect(results[0].name).toBe('Test Restaurant - Best Food in Town')
        expect(results[0].url).toBe('https://testrestaurant.com')
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('googleapis.com/customsearch'),
          expect.objectContaining({
            method: 'GET'
          })
        )
      })

      it('should handle Google API rate limiting', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: async () => ({
            error: {
              code: 429,
              message: 'Quota exceeded'
            }
          })
        } as Response)

        await expect(
          clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
        ).rejects.toThrow('Quota exceeded')
      })

      it('should handle Google API authentication errors', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({
            error: {
              code: 401,
              message: 'Invalid API key'
            }
          })
        } as Response)

        await expect(
          clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
        ).rejects.toThrow('Invalid API key')
      })
    })

    describe('Bing Custom Search API', () => {
      it('should search businesses using Bing API', async () => {
        const mockResponse = {
          webPages: {
            value: [
              {
                name: 'Test Restaurant',
                url: 'https://testrestaurant.com',
                snippet: 'Great restaurant with amazing food...',
                displayUrl: 'testrestaurant.com'
              }
            ],
            totalEstimatedMatches: 1
          }
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        const results = await clientSearchEngine.searchWithBingAPI('restaurants', '90210', 10)
        
        expect(results).toHaveLength(1)
        expect(results[0].name).toBe('Test Restaurant')
        expect(results[0].url).toBe('https://testrestaurant.com')
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('api.bing.microsoft.com'),
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Ocp-Apim-Subscription-Key': expect.any(String)
            })
          })
        )
      })

      it('should handle Bing API errors', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          json: async () => ({
            error: {
              code: 'InvalidAuthorization',
              message: 'Access denied due to invalid subscription key'
            }
          })
        } as Response)

        await expect(
          clientSearchEngine.searchWithBingAPI('restaurants', '90210', 10)
        ).rejects.toThrow('Access denied')
      })
    })

    describe('DuckDuckGo SERP Scraping', () => {
      it('should scrape DuckDuckGo search results', async () => {
        const mockHTML = `
          <div class="result">
            <h2><a href="https://testrestaurant.com">Test Restaurant</a></h2>
            <p>Great restaurant with amazing food...</p>
          </div>
        `

        mockFetch.mockResolvedValueOnce({
          ok: true,
          text: async () => mockHTML
        } as Response)

        const results = await clientSearchEngine.searchDuckDuckGo('restaurants 90210', 10)
        
        expect(results).toHaveLength(1)
        expect(results[0].url).toBe('https://testrestaurant.com')
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('duckduckgo.com'),
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'User-Agent': expect.any(String)
            })
          })
        )
      })

      it('should handle DuckDuckGo blocking', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          text: async () => 'Access denied'
        } as Response)

        const results = await clientSearchEngine.searchDuckDuckGo('restaurants 90210', 10)
        expect(results).toHaveLength(0)
      })
    })
  })

  describe('Geocoding Services', () => {
    describe('Google Geocoding API', () => {
      it('should geocode address using Google API', async () => {
        const mockResponse = {
          results: [
            {
              geometry: {
                location: {
                  lat: 34.0522,
                  lng: -118.2437
                }
              },
              formatted_address: '123 Main St, Test City, CA 90210, USA',
              place_id: 'ChIJTest123'
            }
          ],
          status: 'OK'
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        const result = await geocoder.geocodeAddress('123 Main St, Test City, CA 90210')
        
        expect(result.lat).toBe(34.0522)
        expect(result.lng).toBe(-118.2437)
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('maps.googleapis.com/maps/api/geocode'),
          expect.objectContaining({
            method: 'GET'
          })
        )
      })

      it('should handle geocoding API errors', async () => {
        const mockResponse = {
          results: [],
          status: 'ZERO_RESULTS'
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        await expect(
          geocoder.geocodeAddress('Invalid Address')
        ).rejects.toThrow('No results found')
      })

      it('should handle geocoding rate limits', async () => {
        const mockResponse = {
          status: 'OVER_QUERY_LIMIT',
          error_message: 'You have exceeded your daily request quota'
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        await expect(
          geocoder.geocodeAddress('123 Main St')
        ).rejects.toThrow('exceeded your daily request quota')
      })
    })

    describe('Alternative Geocoding Services', () => {
      it('should fallback to OpenStreetMap Nominatim', async () => {
        const mockResponse = [
          {
            lat: '34.0522',
            lon: '-118.2437',
            display_name: '123 Main St, Test City, CA 90210, USA'
          }
        ]

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        const result = await geocoder.geocodeWithNominatim('123 Main St, Test City, CA')
        
        expect(result.lat).toBe(34.0522)
        expect(result.lng).toBe(-118.2437)
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('nominatim.openstreetmap.org'),
          expect.objectContaining({
            method: 'GET'
          })
        )
      })
    })
  })

  describe('Payment Processing APIs', () => {
    describe('Stripe Integration', () => {
      it('should create payment intent', async () => {
        const mockResponse = {
          id: 'pi_test123',
          client_secret: 'pi_test123_secret',
          amount: 2999,
          currency: 'usd',
          status: 'requires_payment_method'
        }

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse
        } as Response)

        const paymentIntent = await paymentController.createPaymentIntent({
          amount: 2999,
          currency: 'usd',
          customerId: 'cus_test123'
        })
        
        expect(paymentIntent.id).toBe('pi_test123')
        expect(paymentIntent.amount).toBe(2999)
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('api.stripe.com/v1/payment_intents'),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': expect.stringContaining('Bearer sk_')
            })
          })
        )
      })

      it('should handle Stripe API errors', async () => {
        const mockResponse = {
          error: {
            type: 'card_error',
            code: 'card_declined',
            message: 'Your card was declined.'
          }
        }

        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 402,
          json: async () => mockResponse
        } as Response)

        await expect(
          paymentController.createPaymentIntent({
            amount: 2999,
            currency: 'usd'
          })
        ).rejects.toThrow('Your card was declined')
      })

      it('should handle webhook verification', async () => {
        const mockEvent = {
          id: 'evt_test123',
          type: 'payment_intent.succeeded',
          data: {
            object: {
              id: 'pi_test123',
              status: 'succeeded'
            }
          }
        }

        const webhookPayload = JSON.stringify(mockEvent)
        const signature = 'test-signature'

        const result = await paymentController.handleWebhook(webhookPayload, signature)
        
        expect(result.processed).toBe(true)
        expect(result.eventType).toBe('payment_intent.succeeded')
      })
    })
  })

  describe('Email Validation Services', () => {
    it('should validate email using external service', async () => {
      const mockResponse = {
        email: 'test@example.com',
        valid: true,
        deliverable: true,
        disposable: false,
        role: false,
        reason: 'valid_mailbox'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      } as Response)

      const result = await ExportService.validateEmail('test@example.com')
      
      expect(result.valid).toBe(true)
      expect(result.deliverable).toBe(true)
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('email-validation-api'),
        expect.objectContaining({
          method: 'GET'
        })
      )
    })

    it('should handle email validation API errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: async () => ({
          error: 'Rate limit exceeded'
        })
      } as Response)

      await expect(
        ExportService.validateEmail('test@example.com')
      ).rejects.toThrow('Rate limit exceeded')
    })
  })

  describe('Analytics and Monitoring APIs', () => {
    it('should send analytics events', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true })
      } as Response)

      await enhancedErrorLogger.sendAnalyticsEvent({
        event: 'business_scraped',
        properties: {
          businessName: 'Test Restaurant',
          industry: 'Restaurant',
          source: 'google_search'
        }
      })
      
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('analytics-api'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      )
    })

    it('should handle analytics API failures gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      // Should not throw error - analytics failures should be silent
      await expect(
        enhancedErrorLogger.sendAnalyticsEvent({
          event: 'test_event',
          properties: {}
        })
      ).resolves.not.toThrow()
    })
  })

  describe('Rate Limiting and Retry Logic', () => {
    it('should implement exponential backoff for retries', async () => {
      // First call fails with rate limit
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({
          'Retry-After': '2'
        }),
        json: async () => ({ error: 'Rate limit exceeded' })
      } as Response)

      // Second call succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ results: [] })
      } as Response)

      const startTime = Date.now()
      await clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
      const endTime = Date.now()
      
      // Should have waited at least 2 seconds for retry
      expect(endTime - startTime).toBeGreaterThanOrEqual(2000)
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })

    it('should respect rate limit headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 60)
        }),
        json: async () => ({ error: 'Rate limit exceeded' })
      } as Response)

      await expect(
        clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
      ).rejects.toThrow('Rate limit exceeded')
    })

    it('should implement circuit breaker pattern', async () => {
      // Simulate multiple failures
      for (let i = 0; i < 5; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 500,
          json: async () => ({ error: 'Internal server error' })
        } as Response)
      }

      // After 5 failures, circuit should be open
      for (let i = 0; i < 5; i++) {
        await expect(
          clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
        ).rejects.toThrow()
      }

      // Next call should fail immediately without making HTTP request
      const callsBefore = mockFetch.mock.calls.length
      await expect(
        clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
      ).rejects.toThrow('Circuit breaker is open')
      
      expect(mockFetch.mock.calls.length).toBe(callsBefore) // No new HTTP call
    })
  })

  describe('API Health Monitoring', () => {
    it('should monitor API response times', async () => {
      mockFetch.mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => {
            resolve({
              ok: true,
              json: async () => ({ results: [] })
            } as Response)
          }, 500) // 500ms delay
        })
      })

      const startTime = Date.now()
      await clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
      const endTime = Date.now()
      
      expect(endTime - startTime).toBeGreaterThanOrEqual(500)
    })

    it('should track API success rates', async () => {
      // Mock 3 successful calls and 1 failure
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ results: [] }) } as Response)
        .mockResolvedValueOnce({ ok: true, json: async () => ({ results: [] }) } as Response)
        .mockResolvedValueOnce({ ok: true, json: async () => ({ results: [] }) } as Response)
        .mockResolvedValueOnce({ ok: false, status: 500 } as Response)

      const results = await Promise.allSettled([
        clientSearchEngine.searchBusinesses('test1', '90210', 10),
        clientSearchEngine.searchBusinesses('test2', '90210', 10),
        clientSearchEngine.searchBusinesses('test3', '90210', 10),
        clientSearchEngine.searchBusinesses('test4', '90210', 10),
      ])

      const successCount = results.filter(r => r.status === 'fulfilled').length
      const successRate = successCount / results.length
      
      expect(successRate).toBe(0.75) // 75% success rate
    })

    it('should detect API outages', async () => {
      // Mock network error (API down)
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'))

      await expect(
        clientSearchEngine.searchBusinesses('restaurants', '90210', 10)
      ).rejects.toThrow('ECONNREFUSED')
    })
  })
})
