/**
 * Enhanced tests for useOfflineSupport hook
 * Tests the improvements made for Issue #190
 */

import { renderHook, act } from '@testing-library/react'
import { useOfflineSupport } from '../useOfflineSupport'

// Mock fetch
global.fetch = jest.fn()

describe('useOfflineSupport Enhanced Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Reset navigator.onLine
    Object.defineProperty(navigator, 'onLine', {
      writable: true,
      value: true,
    })
    
    // Mock successful fetch by default
    ;(global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
    })
  })

  describe('Enhanced Offline Detection', () => {
    it('should be conservative about offline detection when ignoreStreamingErrors is true', async () => {
      const mockOnOffline = jest.fn()
      
      const { result } = renderHook(() => 
        useOfflineSupport({
          onOffline: mockOnOffline,
          ignoreStreamingErrors: true,
          pingInterval: 0, // Disable periodic checks
        })
      )
      
      // Simulate fetch failure (like streaming connection error)
      ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Connection failed'))
      
      let connectivityResult: boolean
      await act(async () => {
        connectivityResult = await result.current.checkConnectivity()
      })
      
      // Should return navigator.onLine status instead of false
      expect(connectivityResult!).toBe(true)
      expect(mockOnOffline).not.toHaveBeenCalled()
    })

    it('should detect offline when both fetch fails and navigator.onLine is false', async () => {
      const mockOnOffline = jest.fn()
      
      const { result } = renderHook(() => 
        useOfflineSupport({
          onOffline: mockOnOffline,
          ignoreStreamingErrors: true,
          pingInterval: 0,
        })
      )
      
      // Simulate both fetch failure and navigator offline
      ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Connection failed'))
      navigator.onLine = false
      
      let connectivityResult: boolean
      await act(async () => {
        connectivityResult = await result.current.checkConnectivity()
      })
      
      expect(connectivityResult!).toBe(false)
    })

    it('should detect offline normally when ignoreStreamingErrors is false', async () => {
      const mockOnOffline = jest.fn()
      
      const { result } = renderHook(() => 
        useOfflineSupport({
          onOffline: mockOnOffline,
          ignoreStreamingErrors: false,
          pingInterval: 0,
        })
      )
      
      // Simulate fetch failure
      ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Connection failed'))
      
      let connectivityResult: boolean
      await act(async () => {
        connectivityResult = await result.current.checkConnectivity()
      })
      
      expect(connectivityResult!).toBe(false)
    })
  })

  describe('Enhanced Ping Server', () => {
    it('should use enhanced headers for cache busting', async () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingUrl: '/api/ping',
          pingInterval: 0,
        })
      )
      
      await act(async () => {
        await result.current.checkConnectivity()
      })
      
      expect(global.fetch).toHaveBeenCalledWith('/api/ping', {
        method: 'HEAD',
        cache: 'no-cache',
        signal: expect.any(AbortSignal),
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      })
    })

    it('should handle fetch timeout correctly', async () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingInterval: 0,
        })
      )
      
      // Mock fetch that never resolves
      ;(global.fetch as jest.Mock).mockImplementation(() => 
        new Promise(() => {}) // Never resolves
      )
      
      let connectivityResult: boolean
      await act(async () => {
        connectivityResult = await result.current.checkConnectivity()
      })
      
      // Should timeout and return false
      expect(connectivityResult!).toBe(false)
    })

    it('should handle AbortController correctly', async () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingInterval: 0,
        })
      )
      
      const mockAbort = jest.fn()
      const mockAbortController = {
        abort: mockAbort,
        signal: { aborted: false } as AbortSignal,
      }
      
      jest.spyOn(global, 'AbortController').mockImplementation(() => mockAbortController as any)
      
      await act(async () => {
        await result.current.checkConnectivity()
      })
      
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          signal: mockAbortController.signal,
        })
      )
    })
  })

  describe('Browser Online/Offline Events', () => {
    it('should handle browser online event', () => {
      const mockOnOnline = jest.fn()
      
      renderHook(() => 
        useOfflineSupport({
          onOnline: mockOnOnline,
          pingInterval: 0,
        })
      )
      
      // Simulate browser online event
      act(() => {
        navigator.onLine = true
        window.dispatchEvent(new Event('online'))
      })
      
      expect(mockOnOnline).toHaveBeenCalled()
    })

    it('should handle browser offline event', () => {
      const mockOnOffline = jest.fn()
      
      renderHook(() => 
        useOfflineSupport({
          onOffline: mockOnOffline,
          pingInterval: 0,
        })
      )
      
      // Simulate browser offline event
      act(() => {
        navigator.onLine = false
        window.dispatchEvent(new Event('offline'))
      })
      
      expect(mockOnOffline).toHaveBeenCalled()
    })
  })

  describe('Retry Connection', () => {
    it('should retry connection with exponential backoff', async () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          retryAttempts: 3,
          retryDelay: 100,
          pingInterval: 0,
        })
      )
      
      // Mock fetch to fail first two times, succeed on third
      ;(global.fetch as jest.Mock)
        .mockRejectedValueOnce(new Error('Fail 1'))
        .mockRejectedValueOnce(new Error('Fail 2'))
        .mockResolvedValueOnce({ ok: true })
      
      let retryResult: boolean
      await act(async () => {
        retryResult = await result.current.retryConnection()
      })
      
      expect(retryResult!).toBe(true)
      expect(global.fetch).toHaveBeenCalledTimes(3)
    })

    it('should return false after max retry attempts', async () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          retryAttempts: 2,
          retryDelay: 50,
          pingInterval: 0,
        })
      )
      
      // Mock fetch to always fail
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Always fail'))
      
      let retryResult: boolean
      await act(async () => {
        retryResult = await result.current.retryConnection()
      })
      
      expect(retryResult!).toBe(false)
      expect(global.fetch).toHaveBeenCalledTimes(2)
    })
  })

  describe('State Management', () => {
    it('should track offline duration correctly', () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingInterval: 0,
        })
      )
      
      // Go offline
      act(() => {
        navigator.onLine = false
        window.dispatchEvent(new Event('offline'))
      })
      
      // Check offline duration
      const duration = result.current.getOfflineDuration()
      expect(duration).toBeGreaterThan(0)
    })

    it('should return 0 duration when online', () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingInterval: 0,
        })
      )
      
      const duration = result.current.getOfflineDuration()
      expect(duration).toBe(0)
    })

    it('should track time since last online correctly', () => {
      const { result } = renderHook(() => 
        useOfflineSupport({
          pingInterval: 0,
        })
      )
      
      // Go offline then back online
      act(() => {
        navigator.onLine = false
        window.dispatchEvent(new Event('offline'))
      })
      
      act(() => {
        navigator.onLine = true
        window.dispatchEvent(new Event('online'))
      })
      
      const timeSinceOnline = result.current.getTimeSinceLastOnline()
      expect(timeSinceOnline).toBeGreaterThanOrEqual(0)
    })
  })
})
