/**
 * Custom React hook for managing search result streaming
 * Provides real-time search results with pause/resume functionality and fallback mechanisms
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

// Enhanced Connection Pool Manager for EventSource connections
class StreamingConnectionPool {
  private static instance: StreamingConnectionPool
  private activeConnections = new Map<string, EventSource>()
  private connectionMetrics = new Map<string, { attempts: number; lastAttempt: number; successCount: number }>()
  private readonly maxConnections = 5 // Increased from 3
  private readonly connectionTimeout = 45000 // Increased from 30 seconds
  private readonly reconnectDelay = 1000 // Base reconnect delay

  static getInstance(): StreamingConnectionPool {
    if (!StreamingConnectionPool.instance) {
      StreamingConnectionPool.instance = new StreamingConnectionPool()
    }
    return StreamingConnectionPool.instance
  }

  createConnection(url: string, sessionId: string): EventSource | null {
    // Clean up any stale connections first
    this.cleanupStaleConnections()

    // Check if we're at max connections
    if (this.activeConnections.size >= this.maxConnections) {
      logger.warn('StreamingConnectionPool', `Max connections (${this.maxConnections}) reached, rejecting new connection`)
      return null
    }

    // Check if connection already exists for this session
    const existingConnection = this.activeConnections.get(sessionId)
    if (existingConnection) {
      if (existingConnection.readyState === EventSource.OPEN) {
        logger.debug('StreamingConnectionPool', `Reusing existing connection for session ${sessionId}`)
        return existingConnection
      } else {
        // Clean up stale connection
        logger.debug('StreamingConnectionPool', `Cleaning up stale connection for session ${sessionId}`)
        existingConnection.close()
        this.activeConnections.delete(sessionId)
      }
    }

    // Create new connection with enhanced error handling
    const eventSource = new EventSource(url)
    this.activeConnections.set(sessionId, eventSource)

    // Track metrics
    const metrics = this.connectionMetrics.get(sessionId) || { attempts: 0, lastAttempt: 0, successCount: 0 }
    metrics.attempts++
    metrics.lastAttempt = Date.now()
    this.connectionMetrics.set(sessionId, metrics)

    // Set up connection cleanup
    const cleanup = () => {
      this.activeConnections.delete(sessionId)
      logger.debug('StreamingConnectionPool', `Connection removed from pool: ${sessionId}`)
    }

    // Enhanced event listeners
    eventSource.addEventListener('open', () => {
      const metrics = this.connectionMetrics.get(sessionId)
      if (metrics) {
        metrics.successCount++
        this.connectionMetrics.set(sessionId, metrics)
      }
      logger.info('StreamingConnectionPool', `Connection opened successfully: ${sessionId}`)
    })

    eventSource.addEventListener('error', (event) => {
      logger.warn('StreamingConnectionPool', `Connection error for session ${sessionId}`, {
        readyState: eventSource.readyState,
        url: eventSource.url
      })

      // Only cleanup if connection is permanently closed
      if (eventSource.readyState === EventSource.CLOSED) {
        cleanup()
      }
    })

    // Auto-cleanup after timeout with better state checking
    setTimeout(() => {
      if (eventSource.readyState !== EventSource.CLOSED && eventSource.readyState !== EventSource.OPEN) {
        logger.debug('StreamingConnectionPool', `Auto-closing stale connection after timeout: ${sessionId}`)
        eventSource.close()
        cleanup()
      }
    }, this.connectionTimeout)

    logger.debug('StreamingConnectionPool', `New connection created: ${sessionId} (${this.activeConnections.size}/${this.maxConnections})`)
    return eventSource
  }

  // Clean up stale connections
  private cleanupStaleConnections(): void {
    for (const [sessionId, connection] of this.activeConnections.entries()) {
      if (connection.readyState === EventSource.CLOSED) {
        this.activeConnections.delete(sessionId)
        logger.debug('StreamingConnectionPool', `Cleaned up stale connection: ${sessionId}`)
      }
    }
  }

  closeConnection(sessionId: string): void {
    const connection = this.activeConnections.get(sessionId)
    if (connection) {
      connection.close()
      this.activeConnections.delete(sessionId)
      logger.debug('StreamingConnectionPool', `Connection closed: ${sessionId}`)
    }
  }

  getConnectionMetrics(sessionId: string) {
    return this.connectionMetrics.get(sessionId) || { attempts: 0, lastAttempt: 0, successCount: 0 }
  }

  getPoolStatus() {
    return {
      activeConnections: this.activeConnections.size,
      maxConnections: this.maxConnections,
      totalSessions: this.connectionMetrics.size,
    }
  }
}

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
  maxRetryDelay?: number
  circuitBreakerThreshold?: number
  healthCheckTimeout?: number
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
  maxRetryDelay: 30000, // 30 seconds max delay
  circuitBreakerThreshold: 5, // Open circuit after 5 consecutive failures
  healthCheckTimeout: 5000, // 5 seconds for health check
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
  const currentQueryRef = useRef<{ query: string; location: string; sessionId?: string } | null>(null)

  // Circuit breaker state
  const circuitBreakerRef = useRef({
    failureCount: 0,
    lastFailureTime: 0,
    isOpen: false,
  })

  // Computed state
  const isStreaming = progress.status === 'streaming' || progress.status === 'connecting'

  // Circuit breaker functions
  const checkCircuitBreaker = useCallback(() => {
    const circuit = circuitBreakerRef.current
    const now = Date.now()

    // Reset circuit breaker after 60 seconds
    if (circuit.isOpen && now - circuit.lastFailureTime > 60000) {
      circuit.isOpen = false
      circuit.failureCount = 0
      logger.info('useSearchStreaming', 'Circuit breaker reset after timeout')
    }

    return !circuit.isOpen
  }, [])

  const recordFailure = useCallback(() => {
    const circuit = circuitBreakerRef.current
    circuit.failureCount++
    circuit.lastFailureTime = Date.now()

    if (circuit.failureCount >= currentOptionsRef.current.circuitBreakerThreshold) {
      circuit.isOpen = true
      logger.warn('useSearchStreaming', `Circuit breaker opened after ${circuit.failureCount} failures`)
    }
  }, [])

  const recordSuccess = useCallback(() => {
    const circuit = circuitBreakerRef.current
    circuit.failureCount = 0
    circuit.isOpen = false
  }, [])

  // Health check function
  const performHealthCheck = useCallback(async (): Promise<boolean> => {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), currentOptionsRef.current.healthCheckTimeout)

      const response = await fetch('/api/health', {
        method: 'GET',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      return response.ok
    } catch (error) {
      logger.debug('useSearchStreaming', 'Health check failed', error)
      return false
    }
  }, [])

  // Clean up function with connection pool management
  const cleanup = useCallback(() => {
    if (eventSourceRef.current) {
      // Use connection pool for proper cleanup
      const connectionPool = StreamingConnectionPool.getInstance()
      if (currentQueryRef.current?.sessionId) {
        connectionPool.closeConnection(currentQueryRef.current.sessionId)
      } else {
        // Fallback to direct close if no session ID
        eventSourceRef.current.close()
      }
      eventSourceRef.current = null
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
      retryTimeoutRef.current = null
    }
    // Reset current query reference
    currentQueryRef.current = null
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

      // Check circuit breaker before attempting connection
      if (!checkCircuitBreaker()) {
        logger.info('useSearchStreaming', 'Circuit breaker is open, using fallback immediately')
        if (mergedOptions.enableFallback) {
          fallbackToBatchSearch(query, location, mergedOptions.maxResults)
        } else {
          const errorMessage = 'Service temporarily unavailable (circuit breaker open)'
          setError(errorMessage)
          setProgress(prev => ({
            ...prev,
            status: 'error',
            connectionStatus: 'disconnected',
            errorMessage,
          }))
        }
        return
      }

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
        // Create EventSource for streaming using connection pool
        const url = new URL('/api/stream-search', window.location.origin)
        url.searchParams.set('q', query)
        url.searchParams.set('location', location)
        url.searchParams.set('maxResults', mergedOptions.maxResults.toString())
        url.searchParams.set('batchSize', mergedOptions.batchSize.toString())

        // Generate session ID for connection pooling
        const sessionId = `search-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
        const connectionPool = StreamingConnectionPool.getInstance()

        const eventSource = connectionPool.createConnection(url.toString(), sessionId)
        if (!eventSource) {
          throw new Error('Unable to create streaming connection - pool exhausted')
        }

        eventSourceRef.current = eventSource
        currentQueryRef.current = { query, location, sessionId }

        eventSource.onopen = () => {
          logger.info('useSearchStreaming', 'Streaming connection opened')
          setProgress(prev => ({ ...prev, status: 'streaming', connectionStatus: 'connected' }))
          retryCountRef.current = 0
          recordSuccess() // Reset circuit breaker on successful connection
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
            const errorMessage = err instanceof Error ? err.message : 'Error processing stream message'
            logger.error('useSearchStreaming', 'Error processing stream message', err)
            setError(errorMessage)
            setProgress(prev => ({
              ...prev,
              status: 'error',
              errorMessage,
            }))
            cleanup()
          }
        }

        eventSource.onerror = async event => {
          const errorDetails = {
            readyState: eventSource.readyState,
            url: eventSource.url,
            retryCount: retryCountRef.current,
            timestamp: new Date().toISOString(),
            connectionStatus: navigator.onLine ? 'online' : 'offline',
            circuitBreakerState: circuitBreakerRef.current.isOpen ? 'open' : 'closed',
            failureCount: circuitBreakerRef.current.failureCount,
          }

          // Handle different readyState scenarios to reduce noise
          if (eventSource.readyState === EventSource.CONNECTING) {
            // Connection is still trying to establish, this is normal
            logger.debug('useSearchStreaming', 'Connection establishing...', errorDetails)
            return
          }

          if (eventSource.readyState === EventSource.CLOSED) {
            // Connection was closed, this might be expected during cleanup
            logger.debug('useSearchStreaming', 'Connection closed', errorDetails)
            return
          }

          // Only record failure for actual connection issues
          recordFailure()

          // Enhanced logging with connection diagnostics - reduce log level for readyState 2 (CLOSING)
          const isClosingState = eventSource.readyState === 2 // EventSource.CLOSING
          const logLevel = isClosingState ? 'debug' :
            (circuitBreakerRef.current.failureCount <= mergedOptions.circuitBreakerThreshold ? 'warn' : 'debug')

          const logMessage = circuitBreakerRef.current.isOpen
            ? 'Streaming connection error (circuit breaker open)'
            : isClosingState
              ? 'Streaming connection closing (normal during reconnect)'
              : 'Streaming connection error'

          logger[logLevel]('useSearchStreaming', logMessage, errorDetails)

          // Check for network connectivity issues
          if (!navigator.onLine) {
            logger.warn('useSearchStreaming', 'Network connectivity lost, will retry when online')
            setError('Network connection lost. Retrying when connection is restored...')
            setProgress(prev => ({ ...prev, connectionStatus: 'reconnecting' }))
            return
          }

          // Don't immediately retry for CLOSING state - let it complete
          if (isClosingState) {
            logger.debug('useSearchStreaming', 'Waiting for connection to close before retry')
            return
          }

          setProgress(prev => ({ ...prev, connectionStatus: 'reconnecting' }))

          // Gracefully close the current connection if not already closed
          if (eventSource.readyState !== EventSource.CLOSED) {
            eventSource.close()
          }

          // Check circuit breaker before retrying
          if (!checkCircuitBreaker()) {
            logger.info('useSearchStreaming', 'Circuit breaker is open, falling back to batch search')
            cleanup()
            if (mergedOptions.enableFallback) {
              fallbackToBatchSearch(query, location, mergedOptions.maxResults)
            } else {
              const errorMessage = 'Service temporarily unavailable (circuit breaker open)'
              setError(errorMessage)
              setProgress(prev => ({
                ...prev,
                status: 'error',
                connectionStatus: 'disconnected',
                errorMessage,
              }))
            }
            return
          }

          if (retryCountRef.current < mergedOptions.maxRetries) {
            // Perform health check before retrying
            const isHealthy = await performHealthCheck()
            if (!isHealthy) {
              logger.info('useSearchStreaming', 'Health check failed, falling back to batch search')
              cleanup()
              if (mergedOptions.enableFallback) {
                fallbackToBatchSearch(query, location, mergedOptions.maxResults)
              } else {
                const errorMessage = 'Streaming service is currently unavailable. Please try again later or contact support if the issue persists.'
                setError(errorMessage)
                setProgress(prev => ({
                  ...prev,
                  status: 'error',
                  connectionStatus: 'disconnected',
                  errorMessage,
                }))
              }
              return
            }

            retryCountRef.current++
            logger.info(
              'useSearchStreaming',
              `Retrying connection (${retryCountRef.current}/${mergedOptions.maxRetries})`
            )

            // Enhanced exponential backoff with jitter and circuit breaker awareness
            const exponentialDelay = mergedOptions.retryDelay * Math.pow(2, retryCountRef.current - 1)

            // Add jitter to prevent thundering herd (±25% randomization)
            const jitterRange = exponentialDelay * 0.25
            const jitter = (Math.random() - 0.5) * 2 * jitterRange
            const jitteredDelay = exponentialDelay + jitter

            // Apply circuit breaker penalty if circuit was recently opened
            const circuit = circuitBreakerRef.current
            const circuitPenalty = circuit.isOpen ? 5000 : 0 // 5s penalty for open circuit

            const delay = Math.min(Math.max(jitteredDelay + circuitPenalty, mergedOptions.retryDelay), mergedOptions.maxRetryDelay)

            logger.debug('useSearchStreaming', `Retry delay calculated: ${delay}ms (base: ${exponentialDelay}ms, jitter: ${jitter.toFixed(0)}ms, penalty: ${circuitPenalty}ms)`)

            retryTimeoutRef.current = setTimeout(() => {
              if (currentQueryRef.current) {
                startStreaming(
                  currentQueryRef.current.query,
                  currentQueryRef.current.location,
                  options
                )
              }
            }, delay)
          } else if (mergedOptions.enableFallback) {
            logger.info('useSearchStreaming', 'Max retries reached, falling back to batch search')
            cleanup()
            fallbackToBatchSearch(query, location, mergedOptions.maxResults)
          } else {
            const errorMessage = 'Unable to establish streaming connection. The service may be temporarily unavailable. Please try again later or contact support if the issue persists.'
            logger.error('useSearchStreaming', errorMessage, errorDetails)
            setError(errorMessage)
            setProgress(prev => ({
              ...prev,
              status: 'error',
              connectionStatus: 'disconnected',
              errorMessage,
            }))
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
