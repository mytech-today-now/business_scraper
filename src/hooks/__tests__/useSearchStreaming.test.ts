/**
 * @jest-environment jsdom
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useSearchStreaming } from '../useSearchStreaming'

// Mock EventSource
class MockEventSource {
  public onopen: ((event: Event) => void) | null = null
  public onmessage: ((event: MessageEvent) => void) | null = null
  public onerror: ((event: Event) => void) | null = null
  public readyState: number = 0
  public url: string
  static instances: MockEventSource[] = []

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = 1
      if (this.onopen) {
        this.onopen(new Event('open'))
      }
    }, 10)
  }

  close() {
    this.readyState = 2
  }

  // Helper method to simulate receiving messages
  simulateMessage(data: any) {
    if (this.onmessage) {
      const event = new MessageEvent('message', {
        data: JSON.stringify(data),
      })
      this.onmessage(event)
    }
  }

  // Helper method to simulate errors
  simulateError() {
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }

  // Helper method to manually trigger open event
  simulateOpen() {
    this.readyState = 1
    if (this.onopen) {
      this.onopen(new Event('open'))
    }
  }
}

// Mock global EventSource
global.EventSource = MockEventSource as any

// Mock fetch for fallback
global.fetch = jest.fn()

describe('useSearchStreaming', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    MockEventSource.instances = [] // Clear instances array
    ;(global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          success: true,
          data: {
            businesses: [
              {
                id: 'fallback-1',
                name: 'Fallback Business',
                url: 'https://fallback.com',
                industry: 'Test',
              },
            ],
          },
        }),
    })
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('should initialize with default state', () => {
    const { result } = renderHook(() => useSearchStreaming())

    expect(result.current.results).toEqual([])
    expect(result.current.isStreaming).toBe(false)
    expect(result.current.isPaused).toBe(false)
    expect(result.current.error).toBeNull()
    expect(result.current.progress.status).toBe('idle')
  })

  it('should start streaming successfully', async () => {
    const { result } = renderHook(() => useSearchStreaming())

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York', {
        maxResults: 100,
      })
    })

    await waitFor(() => {
      expect(result.current.progress.status).toBe('streaming')
      expect(result.current.isStreaming).toBe(true)
    })
  })

  it('should handle streaming results', async () => {
    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    // Get the created EventSource instance
    eventSource = MockEventSource.instances[0]

    await act(async () => {
      // Simulate receiving a result
      eventSource.simulateMessage({
        type: 'result',
        data: {
          id: 'test-1',
          name: 'Test Restaurant',
          url: 'https://test.com',
          industry: 'Restaurant',
        },
      })
    })

    expect(result.current.results).toHaveLength(1)
    expect(result.current.results[0].name).toBe('Test Restaurant')
  })

  it('should handle progress updates', async () => {
    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    eventSource = MockEventSource.instances[0]

    await act(async () => {
      eventSource.simulateMessage({
        type: 'progress',
        data: {
          totalFound: 500,
          processed: 100,
          currentBatch: 2,
          estimatedTimeRemaining: 30,
        },
      })
    })

    expect(result.current.progress.totalFound).toBe(500)
    expect(result.current.progress.processed).toBe(100)
    expect(result.current.progress.currentBatch).toBe(2)
  })

  it('should pause and resume streaming', async () => {
    const { result } = renderHook(() => useSearchStreaming())

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    await act(async () => {
      result.current.pauseStreaming()
    })

    expect(result.current.isPaused).toBe(true)
    expect(result.current.progress.status).toBe('paused')

    await act(async () => {
      result.current.resumeStreaming()
    })

    expect(result.current.isPaused).toBe(false)
    expect(result.current.progress.status).toBe('streaming')
  })

  it('should stop streaming', async () => {
    const { result } = renderHook(() => useSearchStreaming())

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    await act(async () => {
      result.current.stopStreaming()
    })

    expect(result.current.isStreaming).toBe(false)
    expect(result.current.progress.status).toBe('idle')
  })

  it('should handle connection errors and retry', async () => {
    // Mock fetch for health check
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
    })

    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York', {
        maxRetries: 2,
        retryDelay: 100, // Shorter delay for testing
        circuitBreakerThreshold: 10, // High threshold to prevent circuit breaker from opening
      })
    })

    eventSource = MockEventSource.instances[0]

    // Simulate connection error
    await act(async () => {
      eventSource.simulateError()
    })

    expect(result.current.progress.connectionStatus).toBe('reconnecting')

    // Wait for retry to happen
    await waitFor(() => {
      expect(MockEventSource.instances.length).toBeGreaterThan(1)
    }, { timeout: 1000 })
  })

  it('should fallback to batch search after max retries', async () => {
    // Mock health check to fail, triggering immediate fallback
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: false }) // Health check fails
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          data: { businesses: [{ id: 'fallback-1', name: 'Fallback Business' }] }
        })
      }) // Fallback search succeeds

    const { result } = renderHook(() => useSearchStreaming())

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York', {
        maxRetries: 1,
        retryDelay: 50, // Very short delay for testing
        enableFallback: true,
        circuitBreakerThreshold: 10, // High threshold to prevent circuit breaker from opening
        healthCheckTimeout: 100, // Short timeout for testing
      })
    })

    const eventSource = MockEventSource.instances[0]

    // Simulate connection error - should trigger health check and fallback
    await act(async () => {
      eventSource.simulateError()
    })

    await waitFor(() => {
      expect(result.current.progress.status).toBe('completed')
      expect(result.current.results).toHaveLength(1)
      expect(result.current.results[0].name).toBe('Fallback Business')
    }, { timeout: 5000 })

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/search',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: expect.stringContaining('restaurants'),
      })
    )
  }, 10000)

  it('should handle completion message', async () => {
    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    eventSource = MockEventSource.instances[0]

    await act(async () => {
      eventSource.simulateMessage({
        type: 'completed',
      })
    })

    expect(result.current.progress.status).toBe('completed')
    expect(result.current.isStreaming).toBe(false)
  })

  it('should clear results', async () => {
    const { result } = renderHook(() => useSearchStreaming())

    // Add some results first
    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    const eventSource = MockEventSource.instances[0]

    await act(async () => {
      eventSource.simulateMessage({
        type: 'result',
        data: { id: 'test-1', name: 'Test' },
      })
    })

    expect(result.current.results).toHaveLength(1)

    await act(async () => {
      result.current.clearResults()
    })

    expect(result.current.results).toHaveLength(0)
    expect(result.current.progress.status).toBe('idle')
  })

  it('should not add results when paused', async () => {
    // Mock fetch for health check
    global.fetch = jest.fn().mockResolvedValue({ ok: true })

    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    eventSource = MockEventSource.instances[0]

    // Trigger onopen to set streaming status
    await act(async () => {
      eventSource.simulateOpen()
    })

    await act(async () => {
      result.current.pauseStreaming()
    })

    expect(result.current.isPaused).toBe(true)

    await act(async () => {
      eventSource.simulateMessage({
        type: 'result',
        data: { id: 'test-1', name: 'Test' },
      })
    })

    // Results should not be added when paused
    expect(result.current.results).toHaveLength(0)
  })

  it('should handle error messages from stream', async () => {
    const { result } = renderHook(() => useSearchStreaming())
    let eventSource: MockEventSource

    await act(async () => {
      await result.current.startStreaming('restaurants', 'New York')
    })

    eventSource = MockEventSource.instances[0]

    await act(async () => {
      eventSource.simulateMessage({
        type: 'error',
        message: 'Stream error occurred',
      })
    })

    expect(result.current.error).toBe('Stream error occurred')
    expect(result.current.progress.status).toBe('error')
  })
})
