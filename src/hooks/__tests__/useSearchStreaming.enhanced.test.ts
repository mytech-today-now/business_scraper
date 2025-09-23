/**
 * Enhanced tests for useSearchStreaming hook
 * Tests the improvements made for Issue #190
 */

import { renderHook, act } from '@testing-library/react'
import { useSearchStreaming } from '../useSearchStreaming'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/batchSearchService', () => ({
  batchSearchService: {
    search: jest.fn().mockResolvedValue([]),
  },
}))

// Mock EventSource
class MockEventSource {
  static instances: MockEventSource[] = []
  static CONNECTING = 0
  static OPEN = 1
  static CLOSED = 2

  url: string
  readyState: number = MockEventSource.CONNECTING
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
    
    // Simulate connection opening after a short delay
    setTimeout(() => {
      this.readyState = MockEventSource.OPEN
      if (this.onopen) {
        this.onopen(new Event('open'))
      }
    }, 10)
  }

  close() {
    this.readyState = MockEventSource.CLOSED
  }

  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', {
        data: JSON.stringify(data)
      }))
    }
  }

  simulateError() {
    this.readyState = MockEventSource.CLOSED
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }

  simulateClosingState() {
    this.readyState = 2 // CLOSING state
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }

  addEventListener(type: string, listener: EventListener) {
    if (type === 'open') this.onopen = listener as any
    if (type === 'message') this.onmessage = listener as any
    if (type === 'error') this.onerror = listener as any
  }
}

// Mock fetch for health checks
global.fetch = jest.fn()

// Mock navigator.onLine
Object.defineProperty(navigator, 'onLine', {
  writable: true,
  value: true,
})

// Replace global EventSource with mock
;(global as any).EventSource = MockEventSource

describe('useSearchStreaming Enhanced Tests', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    jest.clearAllMocks()
    navigator.onLine = true
    
    // Mock successful health check
    ;(global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
    })
  })

  describe('Enhanced Connection Management', () => {
    it('should handle readyState CLOSING (2) without excessive logging', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 1,
          retryDelay: 100,
        })
      })

      const eventSource = MockEventSource.instances[0]
      expect(eventSource).toBeDefined()

      // Simulate CLOSING state error (readyState: 2)
      await act(async () => {
        eventSource.simulateClosingState()
      })

      // Should log at debug level, not warn level for CLOSING state
      expect(logger.debug).toHaveBeenCalledWith(
        'useSearchStreaming',
        'Streaming connection closing (normal during reconnect)',
        expect.objectContaining({
          readyState: 2,
        })
      )

      // Should not immediately retry for CLOSING state
      expect(MockEventSource.instances.length).toBe(1)
    })

    it('should handle CONNECTING state gracefully', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      await act(async () => {
        await result.current.startStreaming('test query', 'test location')
      })

      const eventSource = MockEventSource.instances[0]
      
      // Simulate error while in CONNECTING state
      eventSource.readyState = MockEventSource.CONNECTING
      await act(async () => {
        eventSource.simulateError()
      })

      // Should log debug message and return early
      expect(logger.debug).toHaveBeenCalledWith(
        'useSearchStreaming',
        'Connection establishing...',
        expect.any(Object)
      )
    })

    it('should handle CLOSED state gracefully', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      await act(async () => {
        await result.current.startStreaming('test query', 'test location')
      })

      const eventSource = MockEventSource.instances[0]
      
      // Simulate error while in CLOSED state
      eventSource.readyState = MockEventSource.CLOSED
      await act(async () => {
        eventSource.simulateError()
      })

      // Should log debug message and return early
      expect(logger.debug).toHaveBeenCalledWith(
        'useSearchStreaming',
        'Connection closed',
        expect.any(Object)
      )
    })

    it('should not retry when network is offline', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          maxRetries: 3,
        })
      })

      const eventSource = MockEventSource.instances[0]
      
      // Simulate going offline
      navigator.onLine = false
      
      await act(async () => {
        eventSource.simulateError()
      })

      // Should detect offline state and not retry
      expect(logger.warn).toHaveBeenCalledWith(
        'useSearchStreaming',
        'Network connectivity lost, will retry when online'
      )

      expect(result.current.error).toBe('Network connection lost. Retrying when connection is restored...')
    })
  })

  describe('Enhanced Connection Pool', () => {
    it('should clean up stale connections', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      // Start first connection
      await act(async () => {
        await result.current.startStreaming('test query 1', 'test location')
      })

      const firstEventSource = MockEventSource.instances[0]
      
      // Close first connection
      firstEventSource.close()
      
      // Start second connection - should clean up the first one
      await act(async () => {
        await result.current.startStreaming('test query 2', 'test location')
      })

      expect(MockEventSource.instances.length).toBe(2)
      expect(firstEventSource.readyState).toBe(MockEventSource.CLOSED)
    })

    it('should reuse existing open connections', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      // Start first connection
      await act(async () => {
        await result.current.startStreaming('test query', 'test location')
      })

      const initialCount = MockEventSource.instances.length
      
      // Try to start another connection with same session
      await act(async () => {
        await result.current.startStreaming('test query', 'test location')
      })

      // Should reuse existing connection, not create new one
      expect(MockEventSource.instances.length).toBe(initialCount)
    })
  })

  describe('Circuit Breaker Improvements', () => {
    it('should open circuit breaker after threshold failures', async () => {
      const { result } = renderHook(() => useSearchStreaming())
      
      await act(async () => {
        await result.current.startStreaming('test query', 'test location', {
          circuitBreakerThreshold: 2,
          maxRetries: 5,
          retryDelay: 50,
        })
      })

      // Simulate multiple failures
      for (let i = 0; i < 3; i++) {
        const eventSource = MockEventSource.instances[i]
        await act(async () => {
          eventSource.simulateError()
        })
        
        // Wait for retry
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 100))
        })
      }

      // Circuit breaker should be open and fallback to batch search
      expect(logger.warn).toHaveBeenCalledWith(
        'useSearchStreaming',
        expect.stringContaining('Circuit breaker opened')
      )
    })
  })
})
