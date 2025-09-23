/**
 * Integration Tests for Streaming Connection Fallback
 * Tests the enhanced streaming connection error handling and fallback mechanisms
 */

import { renderHook, act } from '@testing-library/react'
import { useSearchStreaming } from '@/hooks/useSearchStreaming'

// Mock logger to prevent console output during tests
jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock fetch for fallback API calls
global.fetch = jest.fn()

// Mock EventSource
class MockEventSource {
  static instances: MockEventSource[] = []
  
  url: string
  readyState: number = 0
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
    
    // Simulate immediate connection failure for server unavailable scenarios
    setTimeout(() => {
      this.readyState = 2 // CLOSED
      if (this.onerror) {
        this.onerror(new Event('error'))
      }
    }, 10)
  }

  close() {
    this.readyState = 2 // CLOSED
  }

  simulateServerUnavailable() {
    this.readyState = 2 // CLOSED
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }

  static reset() {
    MockEventSource.instances = []
  }
}

// Replace global EventSource
;(global as any).EventSource = MockEventSource

describe('Streaming Connection Fallback', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    MockEventSource.reset()
    ;(fetch as jest.Mock).mockClear()
  })

  describe('Server Unavailable Scenarios', () => {
    it('should fallback to batch search when server is unavailable', async () => {
      // Mock successful fallback API response
      ;(fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: {
            results: [
              {
                businessName: 'Test Business',
                email: ['test@example.com'],
                phone: ['555-1234'],
                website: 'https://test.com',
              },
            ],
            totalFound: 1,
          },
        }),
      })

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: true,
          maxRetries: 1,
        })
      })

      // Wait for the connection to fail and fallback to trigger
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      // Should have attempted fallback API call
      expect(fetch).toHaveBeenCalledWith('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'comprehensive',
          query: 'restaurants',
          location: 'New York',
          maxResults: 1000,
        }),
      })

      // Should have results from fallback
      expect(result.current.results).toHaveLength(1)
      expect(result.current.progress.status).toBe('completed')
    })

    it('should show user-friendly error message when fallback is disabled', async () => {
      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: false,
          maxRetries: 1,
        })
      })

      // Wait for the connection to fail
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      // Should show user-friendly error message
      expect(result.current.error).toContain('service may be temporarily unavailable')
      expect(result.current.error).toContain('contact support')
      expect(result.current.progress.status).toBe('error')
    })
  })

  describe('Health Check Integration', () => {
    it('should perform health check before retrying', async () => {
      // Mock health check to fail
      ;(fetch as jest.Mock)
        .mockRejectedValueOnce(new Error('Health check failed'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true, data: { results: [] } }),
        })

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: true,
          maxRetries: 2,
        })
      })

      // Wait for health check and fallback
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 200))
      })

      // Should have attempted health check and then fallback
      expect(fetch).toHaveBeenCalledTimes(2)
      expect(result.current.progress.status).toBe('completed')
    })
  })

  describe('Circuit Breaker Integration', () => {
    it('should respect circuit breaker state', async () => {
      const { result } = renderHook(() => useSearchStreaming())

      // Trigger multiple failures to open circuit breaker
      for (let i = 0; i < 5; i++) {
        await act(async () => {
          await result.current.startStreaming('restaurants', 'New York', {
            enableFallback: false,
            maxRetries: 1,
            circuitBreakerThreshold: 3,
          })
        })

        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 50))
        })

        result.current.stopStreaming()
      }

      // Circuit breaker should be open, next attempt should fail immediately
      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: false,
          maxRetries: 1,
          circuitBreakerThreshold: 3,
        })
      })

      expect(result.current.error).toContain('circuit breaker')
    })
  })

  describe('Connection Pool Management', () => {
    it('should handle connection pool exhaustion gracefully', async () => {
      const { result } = renderHook(() => useSearchStreaming())

      // Mock connection pool to return null (exhausted)
      const originalCreateConnection = MockEventSource.prototype.constructor
      MockEventSource.prototype.constructor = function() {
        return null as any
      }

      try {
        await act(async () => {
          await result.current.startStreaming('restaurants', 'New York', {
            enableFallback: true,
            maxRetries: 1,
          })
        })

        expect(result.current.error).toContain('Unable to create streaming connection')
      } finally {
        MockEventSource.prototype.constructor = originalCreateConnection
      }
    })
  })

  describe('Error Message Quality', () => {
    it('should provide actionable error messages', async () => {
      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: false,
          maxRetries: 1,
        })
      })

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      const errorMessage = result.current.error
      expect(errorMessage).toBeTruthy()
      expect(errorMessage).toContain('temporarily unavailable')
      expect(errorMessage).toContain('try again later')
      expect(errorMessage).toContain('contact support')
    })

    it('should provide different messages for different error scenarios', async () => {
      const { result: result1 } = renderHook(() => useSearchStreaming())
      const { result: result2 } = renderHook(() => useSearchStreaming())

      // Test health check failure
      ;(fetch as jest.Mock).mockRejectedValueOnce(new Error('Health check failed'))

      await act(async () => {
        await result1.current.startStreaming('restaurants', 'New York', {
          enableFallback: false,
          maxRetries: 1,
        })
      })

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      // Test max retries exceeded
      await act(async () => {
        await result2.current.startStreaming('restaurants', 'New York', {
          enableFallback: false,
          maxRetries: 0,
        })
      })

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      // Both should have user-friendly error messages
      expect(result1.current.error).toContain('unavailable')
      expect(result2.current.error).toContain('unable to establish')
    })
  })

  describe('Fallback Performance', () => {
    it('should fallback quickly when server is clearly unavailable', async () => {
      const startTime = Date.now()

      ;(fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: { results: [] } }),
      })

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: true,
          maxRetries: 1,
        })
      })

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      const endTime = Date.now()
      const duration = endTime - startTime

      // Should fallback quickly (within reasonable time)
      expect(duration).toBeLessThan(1000)
      expect(result.current.progress.status).toBe('completed')
    })
  })

  describe('Network Connectivity', () => {
    it('should handle offline scenarios', async () => {
      // Mock navigator.onLine
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false,
      })

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('restaurants', 'New York', {
          enableFallback: true,
          maxRetries: 1,
        })
      })

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      expect(result.current.error).toContain('Network connection lost')

      // Restore online status
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true,
      })
    })
  })
})
