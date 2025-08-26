/**
 * @jest-environment jsdom
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useOfflineSupport, useOfflineSync } from '@/hooks/useOfflineSupport'

// Mock fetch
global.fetch = jest.fn()

// Mock navigator.onLine
Object.defineProperty(navigator, 'onLine', {
  writable: true,
  value: true,
})

describe('useOfflineSupport', () => {
  const mockOnOnline = jest.fn()
  const mockOnOffline = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
    navigator.onLine = true
    ;(fetch as jest.Mock).mockClear()
  })

  afterEach(() => {
    // Clean up event listeners
    window.removeEventListener('online', jest.fn())
    window.removeEventListener('offline', jest.fn())
  })

  it('should initialize with online state', () => {
    const { result } = renderHook(() => useOfflineSupport())
    
    expect(result.current.isOnline).toBe(true)
    expect(result.current.isOffline).toBe(false)
    expect(result.current.wasOffline).toBe(false)
  })

  it('should detect offline state', () => {
    const { result } = renderHook(() => 
      useOfflineSupport({ onOffline: mockOnOffline })
    )
    
    act(() => {
      navigator.onLine = false
      window.dispatchEvent(new Event('offline'))
    })
    
    expect(result.current.isOnline).toBe(false)
    expect(result.current.isOffline).toBe(true)
    expect(result.current.wasOffline).toBe(true)
    expect(mockOnOffline).toHaveBeenCalled()
  })

  it('should detect online state after being offline', () => {
    const { result } = renderHook(() => 
      useOfflineSupport({ onOnline: mockOnOnline, onOffline: mockOnOffline })
    )
    
    // Go offline first
    act(() => {
      navigator.onLine = false
      window.dispatchEvent(new Event('offline'))
    })
    
    expect(mockOnOffline).toHaveBeenCalled()
    
    // Come back online
    act(() => {
      navigator.onLine = true
      window.dispatchEvent(new Event('online'))
    })
    
    expect(result.current.isOnline).toBe(true)
    expect(result.current.isOffline).toBe(false)
    expect(result.current.wasOffline).toBe(true)
    expect(mockOnOnline).toHaveBeenCalled()
  })

  it('should track offline duration', async () => {
    const { result } = renderHook(() => useOfflineSupport())
    
    // Go offline
    act(() => {
      navigator.onLine = false
      window.dispatchEvent(new Event('offline'))
    })
    
    // Wait a bit
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 100))
    })
    
    const duration = result.current.getOfflineDuration()
    expect(duration).toBeGreaterThan(0)
    
    // Come back online
    act(() => {
      navigator.onLine = true
      window.dispatchEvent(new Event('online'))
    })
    
    // Duration should be 0 when online
    expect(result.current.getOfflineDuration()).toBe(0)
  })

  it('should check connectivity with ping', async () => {
    ;(fetch as jest.Mock).mockResolvedValueOnce({ ok: true })
    
    const { result } = renderHook(() => 
      useOfflineSupport({ pingUrl: '/api/test' })
    )
    
    let connectivityResult: boolean
    
    await act(async () => {
      connectivityResult = await result.current.checkConnectivity()
    })
    
    expect(connectivityResult!).toBe(true)
    expect(fetch).toHaveBeenCalledWith('/api/test', {
      method: 'HEAD',
      cache: 'no-cache',
      signal: expect.any(AbortSignal),
    })
  })

  it('should handle ping failure', async () => {
    ;(fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'))
    
    const { result } = renderHook(() => useOfflineSupport())
    
    let connectivityResult: boolean
    
    await act(async () => {
      connectivityResult = await result.current.checkConnectivity()
    })
    
    expect(connectivityResult!).toBe(false)
  })

  it('should retry connection with exponential backoff', async () => {
    ;(fetch as jest.Mock)
      .mockRejectedValueOnce(new Error('Network error'))
      .mockRejectedValueOnce(new Error('Network error'))
      .mockResolvedValueOnce({ ok: true })
    
    const { result } = renderHook(() => 
      useOfflineSupport({ retryAttempts: 3, retryDelay: 10 })
    )
    
    let retryResult: boolean
    
    await act(async () => {
      retryResult = await result.current.retryConnection()
    })
    
    expect(retryResult!).toBe(true)
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('should handle periodic connectivity checks', async () => {
    jest.useFakeTimers()
    ;(fetch as jest.Mock).mockResolvedValue({ ok: true })
    
    const { result } = renderHook(() => 
      useOfflineSupport({ pingInterval: 1000 })
    )
    
    // Fast-forward time
    act(() => {
      jest.advanceTimersByTime(1000)
    })
    
    await waitFor(() => {
      expect(fetch).toHaveBeenCalled()
    })
    
    jest.useRealTimers()
  })

  it('should not ping when interval is disabled', () => {
    jest.useFakeTimers()
    
    renderHook(() => 
      useOfflineSupport({ pingInterval: 0 })
    )
    
    act(() => {
      jest.advanceTimersByTime(5000)
    })
    
    expect(fetch).not.toHaveBeenCalled()
    
    jest.useRealTimers()
  })
})

describe('useOfflineSync', () => {
  it('should queue actions when offline', () => {
    const { result } = renderHook(() => useOfflineSync())
    
    act(() => {
      result.current.queueAction('CREATE_USER', { name: 'John' })
      result.current.queueAction('UPDATE_PROFILE', { age: 30 })
    })
    
    expect(result.current.queue).toHaveLength(2)
    expect(result.current.hasQueuedActions).toBe(true)
    expect(result.current.queue[0].action).toBe('CREATE_USER')
    expect(result.current.queue[1].action).toBe('UPDATE_PROFILE')
  })

  it('should remove actions from queue', () => {
    const { result } = renderHook(() => useOfflineSync())
    
    let actionId: string
    
    act(() => {
      actionId = result.current.queueAction('TEST_ACTION', { data: 'test' })
    })
    
    expect(result.current.queue).toHaveLength(1)
    
    act(() => {
      result.current.removeFromQueue(actionId!)
    })
    
    expect(result.current.queue).toHaveLength(0)
    expect(result.current.hasQueuedActions).toBe(false)
  })

  it('should sync queued actions when online', async () => {
    // Mock online state
    Object.defineProperty(navigator, 'onLine', { value: true })
    
    const mockSyncHandler = jest.fn().mockResolvedValue(true)
    
    const { result } = renderHook(() => useOfflineSync())
    
    // Queue some actions
    act(() => {
      result.current.queueAction('ACTION_1', { data: 'test1' })
      result.current.queueAction('ACTION_2', { data: 'test2' })
    })
    
    expect(result.current.queue).toHaveLength(2)
    
    // Sync the queue
    await act(async () => {
      await result.current.syncQueue(mockSyncHandler)
    })
    
    expect(mockSyncHandler).toHaveBeenCalledTimes(2)
    expect(mockSyncHandler).toHaveBeenCalledWith('ACTION_1', { data: 'test1' })
    expect(mockSyncHandler).toHaveBeenCalledWith('ACTION_2', { data: 'test2' })
    expect(result.current.queue).toHaveLength(0)
  })

  it('should handle sync failures with retry logic', async () => {
    Object.defineProperty(navigator, 'onLine', { value: true })
    
    const mockSyncHandler = jest.fn()
      .mockResolvedValueOnce(false) // First action fails
      .mockResolvedValueOnce(true)  // Second action succeeds
    
    const { result } = renderHook(() => useOfflineSync())
    
    // Queue actions
    act(() => {
      result.current.queueAction('FAIL_ACTION', { data: 'fail' })
      result.current.queueAction('SUCCESS_ACTION', { data: 'success' })
    })
    
    // Sync the queue
    await act(async () => {
      await result.current.syncQueue(mockSyncHandler)
    })
    
    // Failed action should remain in queue with incremented retry count
    expect(result.current.queue).toHaveLength(1)
    expect(result.current.queue[0].action).toBe('FAIL_ACTION')
    expect(result.current.queue[0].retries).toBe(1)
  })

  it('should remove actions after max retries', async () => {
    Object.defineProperty(navigator, 'onLine', { value: true })
    
    const mockSyncHandler = jest.fn().mockResolvedValue(false)
    
    const { result } = renderHook(() => useOfflineSync())
    
    // Queue action and simulate multiple failed syncs
    act(() => {
      result.current.queueAction('PERSISTENT_FAIL', { data: 'fail' })
    })
    
    // Sync multiple times to exceed retry limit
    for (let i = 0; i < 4; i++) {
      await act(async () => {
        await result.current.syncQueue(mockSyncHandler)
      })
    }
    
    // Action should be removed after 3 retries
    expect(result.current.queue).toHaveLength(0)
  })

  it('should not sync when offline', async () => {
    Object.defineProperty(navigator, 'onLine', { value: false })
    
    const mockSyncHandler = jest.fn()
    
    const { result } = renderHook(() => useOfflineSync())
    
    act(() => {
      result.current.queueAction('TEST_ACTION', { data: 'test' })
    })
    
    await act(async () => {
      await result.current.syncQueue(mockSyncHandler)
    })
    
    expect(mockSyncHandler).not.toHaveBeenCalled()
    expect(result.current.queue).toHaveLength(1)
  })
})
