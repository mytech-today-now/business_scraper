'use client'

import { useState, useEffect, useCallback, useRef } from 'react'

export interface OfflineState {
  isOnline: boolean
  isOffline: boolean
  wasOffline: boolean
  lastOnlineTime: Date | null
  lastOfflineTime: Date | null
}

export interface OfflineOptions {
  onOnline?: () => void
  onOffline?: () => void
  pingUrl?: string
  pingInterval?: number
  retryAttempts?: number
  retryDelay?: number
  ignoreStreamingErrors?: boolean // New option to ignore streaming-specific errors
}

/**
 * Custom hook for offline support and network status detection
 * Provides comprehensive offline/online state management
 *
 * @param options Configuration for offline behavior
 * @returns Offline state and utility functions
 */
export function useOfflineSupport(options: OfflineOptions = {}) {
  const {
    onOnline,
    onOffline,
    pingUrl = '/api/ping',
    pingInterval = 30000, // 30 seconds
    retryAttempts = 3,
    retryDelay = 1000,
    ignoreStreamingErrors = true, // Default to true to avoid false offline notifications
  } = options

  const [state, setState] = useState<OfflineState>({
    isOnline: true,
    isOffline: false,
    wasOffline: false,
    lastOnlineTime: new Date(),
    lastOfflineTime: null,
  })

  const [isChecking, setIsChecking] = useState(false)

  // Store callbacks in refs to avoid dependency issues
  const onOnlineRef = useRef(onOnline)
  const onOfflineRef = useRef(onOffline)

  // Update refs when callbacks change
  useEffect(() => {
    onOnlineRef.current = onOnline
  }, [onOnline])

  useEffect(() => {
    onOfflineRef.current = onOffline
  }, [onOffline])

  // Update online/offline state
  const updateOnlineStatus = useCallback(
    (isOnline: boolean) => {
      setState(prevState => {
        const now = new Date()
        const wasOffline = prevState.isOffline

        const newState = {
          isOnline,
          isOffline: !isOnline,
          wasOffline: wasOffline || !isOnline,
          lastOnlineTime: isOnline ? now : prevState.lastOnlineTime,
          lastOfflineTime: !isOnline ? now : prevState.lastOfflineTime,
        }

        // Trigger callbacks using refs to avoid dependency issues
        if (isOnline && onOnlineRef.current) {
          onOnlineRef.current()
        } else if (!isOnline && onOfflineRef.current) {
          onOfflineRef.current()
        }

        return newState
      })
    },
    [] // No dependencies to prevent infinite loops
  )

  // Ping server to verify actual connectivity
  const pingServer = useCallback(async (): Promise<boolean> => {
    if (isChecking) return state.isOnline

    setIsChecking(true)

    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000) // 5 second timeout

      // Use a more reliable endpoint for connectivity check
      const response = await fetch(pingUrl, {
        method: 'HEAD',
        cache: 'no-cache',
        signal: controller.signal,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      })

      clearTimeout(timeoutId)
      setIsChecking(false)

      return response.ok
    } catch (error) {
      setIsChecking(false)

      // If ignoring streaming errors, be more conservative about marking as offline
      if (ignoreStreamingErrors) {
        // Only consider it offline if navigator.onLine is also false
        return navigator.onLine
      }

      return false
    }
  }, [pingUrl, isChecking, state.isOnline, ignoreStreamingErrors])

  // Retry connection with exponential backoff
  const retryConnection = useCallback(async (): Promise<boolean> => {
    for (let attempt = 1; attempt <= retryAttempts; attempt++) {
      const isConnected = await pingServer()

      if (isConnected) {
        return true
      }

      if (attempt < retryAttempts) {
        await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt - 1)))
      }
    }

    return false
  }, [pingServer, retryAttempts, retryDelay])

  // Handle browser online/offline events
  useEffect(() => {
    const handleOnline = () => {
      updateOnlineStatus(true)
    }

    const handleOffline = () => {
      updateOnlineStatus(false)
    }

    // Set initial state
    updateOnlineStatus(navigator.onLine)

    // Add event listeners
    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [updateOnlineStatus])

  // Periodic connectivity check
  useEffect(() => {
    if (pingInterval <= 0) return

    const intervalId = setInterval(async () => {
      const isConnected = await pingServer()
      updateOnlineStatus(isConnected)
    }, pingInterval)

    return () => clearInterval(intervalId)
  }, [pingServer, pingInterval, updateOnlineStatus])

  // Force check connectivity
  const checkConnectivity = useCallback(async (): Promise<boolean> => {
    const isConnected = await pingServer()
    updateOnlineStatus(isConnected)
    return isConnected
  }, [pingServer, updateOnlineStatus])

  // Get offline duration
  const getOfflineDuration = useCallback((): number => {
    if (state.isOnline || !state.lastOfflineTime) return 0
    return Date.now() - state.lastOfflineTime.getTime()
  }, [state.isOnline, state.lastOfflineTime])

  // Get time since last online
  const getTimeSinceLastOnline = useCallback((): number => {
    if (!state.lastOnlineTime) return 0
    return Date.now() - state.lastOnlineTime.getTime()
  }, [state.lastOnlineTime])

  return {
    // State
    ...state,
    isChecking,

    // Actions
    checkConnectivity,
    retryConnection,

    // Utilities
    getOfflineDuration,
    getTimeSinceLastOnline,
  }
}

/**
 * Hook for managing offline data synchronization
 * Queues actions when offline and syncs when back online
 */
export function useOfflineSync<T = any>() {
  const [queue, setQueue] = useState<
    Array<{
      id: string
      action: string
      data: T
      timestamp: Date
      retries: number
    }>
  >([])

  const [isSyncing, setIsSyncing] = useState(false)
  const { isOnline } = useOfflineSupport()

  // Add action to queue
  const queueAction = useCallback((action: string, data: T) => {
    const id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    setQueue(prev => [
      ...prev,
      {
        id,
        action,
        data,
        timestamp: new Date(),
        retries: 0,
      },
    ])

    return id
  }, [])

  // Remove action from queue
  const removeFromQueue = useCallback((id: string) => {
    setQueue(prev => prev.filter(item => item.id !== id))
  }, [])

  // Sync queued actions when online
  const syncQueue = useCallback(
    async (syncHandler: (action: string, data: T) => Promise<boolean>) => {
      if (!isOnline || isSyncing || queue.length === 0) return

      setIsSyncing(true)

      const failedItems = []

      for (const item of queue) {
        try {
          const success = await syncHandler(item.action, item.data)

          if (!success) {
            failedItems.push({
              ...item,
              retries: item.retries + 1,
            })
          }
        } catch (error) {
          console.error('Sync error:', error)
          failedItems.push({
            ...item,
            retries: item.retries + 1,
          })
        }
      }

      // Update queue with failed items (with retry limit)
      setQueue(failedItems.filter(item => item.retries < 3))
      setIsSyncing(false)
    },
    [isOnline, isSyncing, queue]
  )

  // Auto-sync when coming back online
  useEffect(() => {
    if (isOnline && queue.length > 0) {
      // Auto-sync could be triggered here if a default sync handler is provided
    }
  }, [isOnline, queue.length])

  return {
    queue,
    queueAction,
    removeFromQueue,
    syncQueue,
    isSyncing,
    hasQueuedActions: queue.length > 0,
  }
}
