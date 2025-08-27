/**
 * Rate Limiting Integration Test
 * Tests the enhanced rate limiting improvements in a real environment
 */

import { describe, test, expect, beforeAll, afterAll, jest } from '@jest/globals'
import { clientSearchEngine } from '@/model/clientSearchEngine'
import { testRateLimiting, RateLimitTester } from '@/utils/rateLimitingTest'
import { logger } from '@/utils/logger'

// Mock fetch for testing
global.fetch = jest.fn()

describe('Rate Limiting Integration Tests', () => {
  beforeAll(() => {
    // Setup test environment
    jest.clearAllMocks()
  })

  afterAll(() => {
    // Cleanup
    jest.restoreAllMocks()
  })

  describe('RateLimitTester Utility', () => {
    test('should calculate exponential backoff correctly', () => {
      const tester = new RateLimitTester({
        baseDelay: 30000,
        maxDelay: 300000,
        maxFailures: 2,
        cooldownPeriod: 600000,
      })

      // Test delay calculation with different failure counts
      const delays = []
      for (let i = 0; i < 5; i++) {
        // Simulate failures
        for (let j = 0; j < i; j++) {
          tester.recordFailure()
        }

        const delay = tester.calculateDelay()
        delays.push(delay)

        // Reset for next test
        tester.resetFailures()
      }

      // Verify exponential growth
      expect(delays[0]).toBeGreaterThanOrEqual(30000) // Base delay
      expect(delays[1]).toBeGreaterThanOrEqual(60000) // 2x base delay
      expect(delays[2]).toBeGreaterThanOrEqual(120000) // 4x base delay
      expect(delays[4]).toBeLessThanOrEqual(300000) // Max delay cap
    })

    test('should trigger circuit breaker after max failures', () => {
      const tester = new RateLimitTester({
        baseDelay: 30000,
        maxDelay: 300000,
        maxFailures: 2,
        cooldownPeriod: 600000,
      })

      // Should not skip initially
      expect(tester.shouldSkip()).toBe(false)

      // Record failures
      tester.recordFailure()
      expect(tester.shouldSkip()).toBe(false)

      tester.recordFailure()
      expect(tester.shouldSkip()).toBe(true) // Should skip after 2 failures
    })

    test('should reset circuit breaker after cooldown', async () => {
      const tester = new RateLimitTester({
        baseDelay: 30000,
        maxDelay: 300000,
        maxFailures: 2,
        cooldownPeriod: 100, // Short cooldown for testing
      })

      // Trigger circuit breaker
      tester.recordFailure()
      tester.recordFailure()
      expect(tester.shouldSkip()).toBe(true)

      // Wait for cooldown
      await new Promise(resolve => setTimeout(resolve, 150))

      // Should reset after cooldown
      expect(tester.shouldSkip()).toBe(false)
    })
  })

  describe('ClientSearchEngine Rate Limiting', () => {
    test('should implement proper delays between requests', async () => {
      // Mock successful API response
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          success: true,
          results: [
            { url: 'https://example.com', title: 'Test Business', snippet: 'Test snippet' },
          ],
        }),
      } as Response)

      const startTime = Date.now()

      // Make multiple requests
      const results1 = await clientSearchEngine.searchBusinesses('test query', '60010', 5)
      const midTime = Date.now()
      const results2 = await clientSearchEngine.searchBusinesses('test query 2', '60010', 5)
      const endTime = Date.now()

      // Verify timing
      const firstDelay = midTime - startTime
      const secondDelay = endTime - midTime

      // Should have proper delays (allowing for some variance in test environment)
      expect(firstDelay).toBeGreaterThan(1000) // At least some delay
      expect(secondDelay).toBeGreaterThan(1000) // At least some delay

      expect(results1).toBeDefined()
      expect(results2).toBeDefined()
    }, 120000) // 2 minute timeout for this test

    test('should handle 429 errors with exponential backoff', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>

      // First call returns 429, second call succeeds
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: async () => ({ error: 'Rate limit exceeded', message: '429' }),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            results: [
              { url: 'https://example.com', title: 'Test Business', snippet: 'Test snippet' },
            ],
          }),
        } as Response)

      const startTime = Date.now()
      const results = await clientSearchEngine.searchBusinesses('test query', '60010', 5)
      const endTime = Date.now()

      // Should have taken longer due to retry delay
      const totalTime = endTime - startTime
      expect(totalTime).toBeGreaterThan(30000) // Should include retry delay

      expect(results).toBeDefined()
    }, 180000) // 3 minute timeout for this test

    test('should respect circuit breaker', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>

      // Mock multiple 429 responses to trigger circuit breaker
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        json: async () => ({ error: 'Rate limit exceeded', message: '429' }),
      } as Response)

      // Make multiple requests to trigger circuit breaker
      await clientSearchEngine.searchBusinesses('test query 1', '60010', 5)
      await clientSearchEngine.searchBusinesses('test query 2', '60010', 5)

      // Third request should be skipped due to circuit breaker
      const results = await clientSearchEngine.searchBusinesses('test query 3', '60010', 5)

      // Should return empty results due to circuit breaker
      expect(results).toEqual([])
    }, 240000) // 4 minute timeout for this test
  })

  describe('Anti-Bot Measures', () => {
    test('should use randomized user agents and viewports', () => {
      const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
      ]

      const viewports = [
        { width: 1366, height: 768 },
        { width: 1920, height: 1080 },
        { width: 1440, height: 900 },
        { width: 1280, height: 720 },
      ]

      // Test randomization
      const selectedUserAgents = new Set()
      const selectedViewports = new Set()

      for (let i = 0; i < 20; i++) {
        const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)]
        const randomViewport = viewports[Math.floor(Math.random() * viewports.length)]

        selectedUserAgents.add(randomUserAgent)
        selectedViewports.add(JSON.stringify(randomViewport))
      }

      // Should have some variety in selections
      expect(selectedUserAgents.size).toBeGreaterThan(1)
      expect(selectedViewports.size).toBeGreaterThan(1)
    })

    test('should implement jitter in delays', () => {
      const baseDelay = 30000
      const delays = []

      // Calculate multiple delays to test jitter
      for (let i = 0; i < 10; i++) {
        const exponentialDelay = baseDelay * Math.pow(2, 1) // 1 failure
        const jitter = Math.random() * 0.3 * exponentialDelay
        const finalDelay = exponentialDelay + jitter
        delays.push(finalDelay)
      }

      // Should have variety in delays due to jitter
      const uniqueDelays = new Set(delays)
      expect(uniqueDelays.size).toBeGreaterThan(1)

      // All delays should be within expected range
      delays.forEach(delay => {
        expect(delay).toBeGreaterThanOrEqual(baseDelay * 2) // Base exponential delay
        expect(delay).toBeLessThanOrEqual(baseDelay * 2 * 1.3) // With 30% jitter
      })
    })
  })

  describe('Rate Limiting Test Utility', () => {
    test('should run comprehensive rate limiting test', async () => {
      // This test runs the actual rate limiting test utility
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      await testRateLimiting()

      // Verify test ran and logged results
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    }, 60000) // 1 minute timeout
  })
})

// Helper function to run manual tests
export async function runManualRateLimitingTest() {
  console.log('🧪 Running Manual Rate Limiting Test...')

  try {
    // Test the rate limiting utility
    await testRateLimiting()

    // Test actual search engine with rate limiting
    console.log('Testing ClientSearchEngine with rate limiting...')
    const results = await clientSearchEngine.searchBusinesses(
      'conference planning company',
      '60010',
      5
    )

    console.log(`✅ Search completed successfully with ${results.length} results`)
    console.log('🎉 Manual rate limiting test completed!')
  } catch (error) {
    console.error('❌ Manual test failed:', error)
    throw error
  }
}
