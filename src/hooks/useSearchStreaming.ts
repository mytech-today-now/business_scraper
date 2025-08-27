/**
 * Custom React hook for managing search result streaming
 * Provides real-time search results with pause/resume functionality and fallback mechanisms
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface StreamingProgress {
  totalFound: number
  processed: number
  currentBatch: number
  estimatedTimeRemaining: number
  status: 'idle' | 'connecting' | 'streaming' | 'paused' | 'completed' | 'error' | 'fallback'
  connectionStatus: 'disconnected' | 'connected' | 'reconnecting'
  errorMessage?: string
}

export interface StreamingOptions {
  maxResults?: number
  batchSize?: number
  enableFallback?: boolean
  maxRetries?: number
  retryDelay?: number
}

export interface UseSearchStreamingReturn {
  results: BusinessRecord[]
  progress: StreamingProgress
  isStreaming: boolean
  isPaused: boolean
  error: string | null
  startStreaming: (query: string, location: string, options?: StreamingOptions) => Promise<void>
  pauseStreaming: () => void
  resumeStreaming: () => void
  stopStreaming: () => void
  clearResults: () => void
}

const DEFAULT_OPTIONS: Required<StreamingOptions> = {
  maxResults: 1000,
  batchSize: 50,
  enableFallback: true,
  maxRetries: 3,
  retryDelay: 2000,
}

export function useSearchStreaming(): UseSearchStreamingReturn {
  const [results, setResults] = useState<BusinessRecord[]>([])
  const [progress, setProgress] = useState<StreamingProgress>({
    totalFound: 0,
    processed: 0,
    currentBatch: 0,
    estimatedTimeRemaining: 0,
    status: 'idle',
    connectionStatus: 'disconnected',
  })
  const [error, setError] = useState<string | null>(null)
  const [isPaused, setIsPaused] = useState(false)

  // Refs for managing streaming state
  const eventSourceRef = useRef<EventSource | null>(null)
  const retryCountRef = useRef(0)
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const currentOptionsRef = useRef<Required<StreamingOptions>>(DEFAULT_OPTIONS)
  const currentQueryRef = useRef<{ query: string; location: string } | null>(null)

  // Computed state
  const isStreaming = progress.status === 'streaming' || progress.status === 'connecting'

  // Clean up function
  const cleanup = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
      retryTimeoutRef.current = null
    }
  }, [])

  // Fallback to batch search
  const fallbackToBatchSearch = useCallback(
    async (query: string, location: string, maxResults: number) => {
      try {
        logger.info('useSearchStreaming', 'Falling back to batch search')
        setProgress(prev => ({ ...prev, status: 'fallback', connectionStatus: 'disconnected' }))

        const response = await fetch('/api/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: 'comprehensive',
            query,
            location,
            maxResults,
          }),
        })

        if (!response.ok) {
          throw new Error(`Batch search failed: ${response.status}`)
        }

        const data = await response.json()
        if (data.success && data.data?.businesses) {
          setResults(data.data.businesses)
          setProgress(prev => ({
            ...prev,
            status: 'completed',
            totalFound: data.data.businesses.length,
            processed: data.data.businesses.length,
          }))
          setError(null)
        } else {
          throw new Error(data.error || 'Batch search returned no results')
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Fallback search failed'
        logger.error('useSearchStreaming', 'Fallback search failed', err)
        setError(errorMessage)
        setProgress(prev => ({ ...prev, status: 'error', errorMessage }))
      }
    },
    []
  )

  // Start streaming search
  const startStreaming = useCallback(
    async (query: string, location: string, options: StreamingOptions = {}) => {
      const mergedOptions = { ...DEFAULT_OPTIONS, ...options }
      currentOptionsRef.current = mergedOptions
      currentQueryRef.current = { query, location }

      // Reset state
      setResults([])
      setError(null)
      setIsPaused(false)
      retryCountRef.current = 0
      cleanup()

      setProgress({
        totalFound: 0,
        processed: 0,
        currentBatch: 0,
        estimatedTimeRemaining: 0,
        status: 'connecting',
        connectionStatus: 'connecting',
      })

      try {
        // Create EventSource for streaming
        const url = new URL('/api/stream-search', window.location.origin)
        url.searchParams.set('query', query)
        url.searchParams.set('location', location)
        url.searchParams.set('maxResults', mergedOptions.maxResults.toString())
        url.searchParams.set('batchSize', mergedOptions.batchSize.toString())

        const eventSource = new EventSource(url.toString())
        eventSourceRef.current = eventSource

        eventSource.onopen = () => {
          logger.info('useSearchStreaming', 'Streaming connection opened')
          setProgress(prev => ({ ...prev, status: 'streaming', connectionStatus: 'connected' }))
          retryCountRef.current = 0
        }

        eventSource.onmessage = event => {
          try {
            const data = JSON.parse(event.data)

            switch (data.type) {
              case 'result':
                if (!isPaused) {
                  setResults(prev => [...prev, data.data])
                }
                break

              case 'progress':
                setProgress(prev => ({
                  ...prev,
                  ...data.data,
                  status: isPaused ? 'paused' : 'streaming',
                }))
                break

              case 'completed':
                setProgress(prev => ({
                  ...prev,
                  status: 'completed',
                  connectionStatus: 'disconnected',
                }))
                cleanup()
                break

              case 'error':
                throw new Error(data.message || 'Streaming error occurred')
            }
          } catch (err) {
            logger.error('useSearchStreaming', 'Error processing stream message', err)
          }
        }

        eventSource.onerror = () => {
          logger.warn('useSearchStreaming', 'Streaming connection error')
          setProgress(prev => ({ ...prev, connectionStatus: 'reconnecting' }))

          if (retryCountRef.current < mergedOptions.maxRetries) {
            retryCountRef.current++
            retryTimeoutRef.current = setTimeout(() => {
              if (currentQueryRef.current) {
                startStreaming(
                  currentQueryRef.current.query,
                  currentQueryRef.current.location,
                  options
                )
              }
            }, mergedOptions.retryDelay)
          } else if (mergedOptions.enableFallback) {
            cleanup()
            fallbackToBatchSearch(query, location, mergedOptions.maxResults)
          } else {
            setError('Streaming connection failed after maximum retries')
            setProgress(prev => ({ ...prev, status: 'error', connectionStatus: 'disconnected' }))
            cleanup()
          }
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to start streaming'
        logger.error('useSearchStreaming', 'Failed to start streaming', err)
        setError(errorMessage)
        setProgress(prev => ({
          ...prev,
          status: 'error',
          errorMessage,
          connectionStatus: 'disconnected',
        }))

        if (mergedOptions.enableFallback) {
          fallbackToBatchSearch(query, location, mergedOptions.maxResults)
        }
      }
    },
    [isPaused, cleanup, fallbackToBatchSearch]
  )

  // Pause streaming
  const pauseStreaming = useCallback(() => {
    setIsPaused(true)
    setProgress(prev => ({ ...prev, status: 'paused' }))
    logger.info('useSearchStreaming', 'Streaming paused')
  }, [])

  // Resume streaming
  const resumeStreaming = useCallback(() => {
    setIsPaused(false)
    setProgress(prev => ({ ...prev, status: 'streaming' }))
    logger.info('useSearchStreaming', 'Streaming resumed')
  }, [])

  // Stop streaming
  const stopStreaming = useCallback(() => {
    cleanup()
    setProgress(prev => ({ ...prev, status: 'idle', connectionStatus: 'disconnected' }))
    setIsPaused(false)
    logger.info('useSearchStreaming', 'Streaming stopped')
  }, [cleanup])

  // Clear results
  const clearResults = useCallback(() => {
    setResults([])
    setError(null)
    setProgress({
      totalFound: 0,
      processed: 0,
      currentBatch: 0,
      estimatedTimeRemaining: 0,
      status: 'idle',
      connectionStatus: 'disconnected',
    })
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return cleanup
  }, [cleanup])

  return {
    results,
    progress,
    isStreaming,
    isPaused,
    error,
    startStreaming,
    pauseStreaming,
    resumeStreaming,
    stopStreaming,
    clearResults,
  }
}
