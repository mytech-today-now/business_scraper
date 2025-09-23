/**
 * @jest-environment jsdom
 * 
 * Comprehensive tests for streaming connection errors
 * Tests for GitHub Issue #192: EventSource immediately closes with readyState 2
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useSearchStreaming } from '../useSearchStreaming'

// Enhanced MockEventSource to simulate connection errors
class MockEventSourceWithErrors {
  public onopen: ((event: Event) => void) | null = null
  public onmessage: ((event: MessageEvent) => void) | null = null
  public onerror: ((event: Event) => void) | null = null
  public readyState: number = 0
  public url: string
  static instances: MockEventSourceWithErrors[] = []
  static shouldFailImmediately = false
  static shouldFailAfterOpen = false
  static failureCount = 0

  constructor(url: string) {
    this.url = url
    MockEventSourceWithErrors.instances.push(this)
    
    if (MockEventSourceWithErrors.shouldFailImmediately) {
      // Simulate immediate connection failure (readyState 2)
      setTimeout(() => {
        this.readyState = 2 // CLOSED
        MockEventSourceWithErrors.failureCount++
        if (this.onerror) {
          this.onerror(new Event('error'))
        }
      }, 5)
    } else if (MockEventSourceWithErrors.shouldFailAfterOpen) {
      // Simulate connection opening then failing
      setTimeout(() => {
        this.readyState = 1 // OPEN
        if (this.onopen) {
          this.onopen(new Event('open'))
        }
        // Then fail
        setTimeout(() => {
          this.readyState = 2 // CLOSED
          MockEventSourceWithErrors.failureCount++
          if (this.onerror) {
            this.onerror(new Event('error'))
          }
        }, 10)
      }, 10)
    } else {
      // Normal connection
      setTimeout(() => {
        this.readyState = 1 // OPEN
        if (this.onopen) {
          this.onopen(new Event('open'))
        }
      }, 10)
    }
  }

  close() {
    this.readyState = 2
  }

  simulateMessage(data: any) {
    if (this.onmessage && this.readyState === 1) {
      const event = new MessageEvent('message', {
        data: JSON.stringify(data),
      })
      this.onmessage(event)
    }
  }

  simulateError() {
    this.readyState = 2
    MockEventSourceWithErrors.failureCount++
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }

  static reset() {
    MockEventSourceWithErrors.instances = []
    MockEventSourceWithErrors.shouldFailImmediately = false
    MockEventSourceWithErrors.shouldFailAfterOpen = false
    MockEventSourceWithErrors.failureCount = 0
  }
}

// Mock fetch for health checks
const mockFetch = jest.fn()
global.fetch = mockFetch

// Mock navigator.onLine
Object.defineProperty(navigator, 'onLine', {
  writable: true,
  value: true,
})

describe('useSearchStreaming - Connection Error Tests', () => {
  beforeEach(() => {
    MockEventSourceWithErrors.reset()
    mockFetch.mockClear()
    
    // Mock successful health check by default
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ status: 'healthy' }),
    })
    
    // Replace global EventSource with our mock
    global.EventSource = MockEventSourceWithErrors as any
  })

  afterEach(() => {
    jest.clearAllTimers()
  })

  describe('Immediate Connection Failure (readyState 2)', () => {
    test('should handle immediate connection closure', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      // Wait for error to be processed
      await waitFor(() => {
        expect(result.current.error).toBeTruthy()
      }, { timeout: 1000 })

      expect(result.current.isStreaming).toBe(false)
      expect(result.current.progress.connectionStatus).toBe('disconnected')
      expect(MockEventSourceWithErrors.failureCount).toBeGreaterThan(0)
    })

    test('should retry on immediate connection failure', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 3,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      // Wait for retries to complete
      await waitFor(() => {
        expect(MockEventSourceWithErrors.failureCount).toBeGreaterThanOrEqual(2)
      }, { timeout: 2000 })

      expect(result.current.error).toBeTruthy()
      expect(result.current.isStreaming).toBe(false)
    })

    test('should fallback to batch search when enabled', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 50,
          enableFallback: true,
        })
      })

      // Wait for fallback to be triggered
      await waitFor(() => {
        expect(result.current.progress.status).toBe('completed')
      }, { timeout: 1000 })

      expect(result.current.error).toBeNull()
    })
  })

  describe('Connection Failure After Opening', () => {
    test('should handle connection failure after opening', async () => {
      MockEventSourceWithErrors.shouldFailAfterOpen = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      // Wait for connection to open and then fail
      await waitFor(() => {
        expect(result.current.error).toBeTruthy()
      }, { timeout: 1000 })

      expect(MockEventSourceWithErrors.failureCount).toBeGreaterThan(0)
    })
  })

  describe('Health Check Integration', () => {
    test('should perform health check before retrying', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 2,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      // Wait for health checks to be called
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith('/api/health', expect.any(Object))
      }, { timeout: 1000 })
    })

    test('should fallback when health check fails', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
      })

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 50,
          enableFallback: true,
        })
      })

      // Wait for fallback due to health check failure
      await waitFor(() => {
        expect(result.current.progress.status).toBe('completed')
      }, { timeout: 1000 })
    })
  })

  describe('Circuit Breaker', () => {
    test('should open circuit breaker after multiple failures', async () => {
      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      // Trigger multiple failures to open circuit breaker
      for (let i = 0; i < 6; i++) {
        await act(async () => {
          await result.current.startStreaming('test query', 'test location', {
            maxRetries: 1,
            retryDelay: 10,
            enableFallback: false,
            circuitBreakerThreshold: 5,
          })
        })
        
        await waitFor(() => {
          expect(result.current.error).toBeTruthy()
        }, { timeout: 500 })

        result.current.clearResults()
      }

      // Circuit breaker should now be open
      expect(MockEventSourceWithErrors.failureCount).toBeGreaterThanOrEqual(5)
    })
  })

  describe('Network Connectivity', () => {
    test('should handle offline scenarios', async () => {
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false,
      })

      MockEventSourceWithErrors.shouldFailImmediately = true

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      await waitFor(() => {
        expect(result.current.error).toContain('Network connection lost')
      }, { timeout: 1000 })

      // Restore online status
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true,
      })
    })
  })

  describe('Error Recovery', () => {
    test('should recover from temporary connection issues', async () => {
      let failureCount = 0
      const originalConstructor = MockEventSourceWithErrors

      // Mock EventSource that fails first time, succeeds second time
      global.EventSource = class extends originalConstructor {
        constructor(url: string) {
          super(url)
          if (failureCount === 0) {
            failureCount++
            setTimeout(() => {
              this.readyState = 2
              if (this.onerror) {
                this.onerror(new Event('error'))
              }
            }, 5)
          } else {
            setTimeout(() => {
              this.readyState = 1
              if (this.onopen) {
                this.onopen(new Event('open'))
              }
            }, 10)
          }
        }
      } as any

      const { result } = renderHook(() => useSearchStreaming())

      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 2,
          retryDelay: 50,
          enableFallback: false,
        })
      })

      // Should eventually succeed
      await waitFor(() => {
        expect(result.current.isStreaming).toBe(true)
        expect(result.current.progress.connectionStatus).toBe('connected')
      }, { timeout: 1000 })
    })
  })
})
