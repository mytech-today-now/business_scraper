'use client'

import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  Play,
  Pause,
  Square,
  Activity,
  Clock,
  Database,
  Zap,
  AlertTriangle,
  CheckCircle,
  XCircle,
  BarChart3,
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { VirtualizedResultsTable } from './VirtualizedResultsTable'
import { BusinessRecord } from '@/types/business'
import {
  streamingService,
  StreamingSearchParams,
  StreamingMessage,
  StreamingSession,
} from '@/lib/streamingService'
import { logger } from '@/utils/logger'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'

export interface StreamingResultsDisplayProps {
  searchParams: StreamingSearchParams
  onResultsUpdate?: (results: BusinessRecord[]) => void
  onStatusChange?: (status: string) => void
  autoStart?: boolean
  className?: string
}

export function StreamingResultsDisplay({
  searchParams,
  onResultsUpdate,
  onStatusChange,
  autoStart = false,
  className,
}: StreamingResultsDisplayProps): JSX.Element {
  // State management
  const [session, setSession] = useState<StreamingSession | null>(null)
  const [results, setResults] = useState<BusinessRecord[]>([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [showProgress, setShowProgress] = useState(true)
  const [showConnectionHealth, setShowConnectionHealth] = useState(false)
  const [showErrorHistory, setShowErrorHistory] = useState(false)
  const [realtimeStats, setRealtimeStats] = useState({
    resultsPerSecond: 0,
    avgResponseTime: 0,
    successRate: 100,
    lastUpdateTime: Date.now(),
  })

  // Refs
  const unsubscribeRef = useRef<(() => void) | null>(null)
  const statsIntervalRef = useRef<number | null>(null)
  const lastResultCountRef = useRef(0)
  const lastStatsUpdateRef = useRef(Date.now())

  /**
   * Start streaming search
   */
  const startStreaming = useCallback(async () => {
    try {
      setIsStreaming(true)
      setResults([])
      lastResultCountRef.current = 0

      const sessionId = await streamingService.startStreaming(searchParams)
      const newSession = streamingService.getSession(sessionId)

      if (newSession) {
        setSession(newSession)
        onStatusChange?.('streaming')

        // Subscribe to streaming events
        unsubscribeRef.current = streamingService.subscribe(sessionId, handleStreamingMessage)

        // Start real-time statistics tracking
        startStatsTracking()

        toast.success('Streaming search started')
        logger.info('Streaming search started', { sessionId, searchParams })
      }
    } catch (error) {
      logger.error('Failed to start streaming', { error })
      toast.error('Failed to start streaming search')
      setIsStreaming(false)
      onStatusChange?.('error')
    }
  }, [searchParams, onStatusChange])

  /**
   * Pause streaming
   */
  const pauseStreaming = useCallback(() => {
    if (session) {
      streamingService.pauseStreaming(session.id)
      setIsPaused(true)
      onStatusChange?.('paused')
      toast.info('Streaming paused')
    }
  }, [session, onStatusChange])

  /**
   * Resume streaming
   */
  const resumeStreaming = useCallback(() => {
    if (session) {
      streamingService.resumeStreaming(session.id)
      setIsPaused(false)
      onStatusChange?.('streaming')
      toast.info('Streaming resumed')
    }
  }, [session, onStatusChange])

  /**
   * Stop streaming
   */
  const stopStreaming = useCallback(() => {
    if (session) {
      streamingService.cancelStreaming(session.id)
      setIsStreaming(false)
      setIsPaused(false)
      setSession(null)
      onStatusChange?.('stopped')

      // Cleanup
      if (unsubscribeRef.current) {
        unsubscribeRef.current()
        unsubscribeRef.current = null
      }

      stopStatsTracking()
      toast.info('Streaming stopped')
    }
  }, [session, onStatusChange])

  /**
   * Handle streaming messages
   */
  const handleStreamingMessage = useCallback(
    (message: StreamingMessage) => {
      switch (message.type) {
        case 'result':
          if (message.result) {
            setResults(prev => {
              const newResults = [...prev, message.result!.business]
              onResultsUpdate?.(newResults)
              return newResults
            })
          }
          break

        case 'progress':
          if (message.progress) {
            setSession(prev => (prev ? { ...prev, progress: message.progress! } : null))
          }
          break

        case 'complete':
          setIsStreaming(false)
          setIsPaused(false)
          onStatusChange?.('completed')
          stopStatsTracking()
          toast.success(`Streaming completed! Found ${results.length} businesses`)
          break

        case 'error':
          setIsStreaming(false)
          setIsPaused(false)
          onStatusChange?.('error')
          stopStatsTracking()
          toast.error('Streaming error occurred')
          break

        case 'paused':
          setIsPaused(true)
          onStatusChange?.('paused')
          break

        case 'resumed':
          setIsPaused(false)
          onStatusChange?.('streaming')
          break
      }
    },
    [results.length, onResultsUpdate, onStatusChange]
  )

  /**
   * Start real-time statistics tracking
   */
  const startStatsTracking = useCallback(() => {
    statsIntervalRef.current = window.setInterval(() => {
      const now = Date.now()
      const timeDelta = (now - lastStatsUpdateRef.current) / 1000 // seconds
      const resultsDelta = results.length - lastResultCountRef.current

      if (timeDelta > 0) {
        const resultsPerSecond = resultsDelta / timeDelta

        setRealtimeStats(prev => ({
          resultsPerSecond: Math.round(resultsPerSecond * 10) / 10,
          avgResponseTime: prev.avgResponseTime, // Would be calculated from actual response times
          successRate: session?.progress
            ? Math.round(
                (1 - session.progress.errors / Math.max(session.progress.processed, 1)) * 100
              )
            : 100,
          lastUpdateTime: now,
        }))
      }

      lastResultCountRef.current = results.length
      lastStatsUpdateRef.current = now
    }, 1000)
  }, [results.length, session])

  /**
   * Stop statistics tracking
   */
  const stopStatsTracking = useCallback(() => {
    if (statsIntervalRef.current) {
      clearInterval(statsIntervalRef.current)
      statsIntervalRef.current = null
    }
  }, [])

  /**
   * Auto-start streaming if enabled
   */
  useEffect(() => {
    if (autoStart && !isStreaming) {
      startStreaming()
    }
  }, [autoStart, isStreaming, startStreaming])

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      if (unsubscribeRef.current) {
        unsubscribeRef.current()
      }
      stopStatsTracking()
    }
  }, [stopStatsTracking])

  /**
   * Get status color
   */
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600'
      case 'paused':
        return 'text-yellow-600'
      case 'completed':
        return 'text-blue-600'
      case 'error':
        return 'text-red-600'
      case 'cancelled':
        return 'text-gray-600'
      default:
        return 'text-gray-600'
    }
  }

  /**
   * Get status icon
   */
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <Activity className="w-4 h-4" />
      case 'paused':
        return <Pause className="w-4 h-4" />
      case 'completed':
        return <CheckCircle className="w-4 h-4" />
      case 'error':
        return <XCircle className="w-4 h-4" />
      case 'cancelled':
        return <Square className="w-4 h-4" />
      default:
        return <Clock className="w-4 h-4" />
    }
  }

  return (
    <div className={clsx('space-y-6', className)}>
      {/* Streaming Controls */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              Real-time Search Streaming
            </CardTitle>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <Button
                  onClick={startStreaming}
                  icon={Play}
                  className="bg-green-600 hover:bg-green-700"
                >
                  Start Streaming
                </Button>
              ) : (
                <>
                  {!isPaused ? (
                    <Button onClick={pauseStreaming} icon={Pause} variant="outline">
                      Pause
                    </Button>
                  ) : (
                    <Button
                      onClick={resumeStreaming}
                      icon={Play}
                      className="bg-blue-600 hover:bg-blue-700"
                    >
                      Resume
                    </Button>
                  )}

                  <Button
                    onClick={stopStreaming}
                    icon={Square}
                    variant="outline"
                    className="text-red-600 hover:text-red-700"
                  >
                    Stop
                  </Button>
                </>
              )}

              <Button
                onClick={() => setShowProgress(!showProgress)}
                icon={BarChart3}
                variant="ghost"
                size="sm"
              >
                {showProgress ? 'Hide' : 'Show'} Progress
              </Button>

              {session && (
                <>
                  <Button
                    onClick={() => setShowConnectionHealth(!showConnectionHealth)}
                    icon={Activity}
                    variant="ghost"
                    size="sm"
                    className={
                      session.connectionHealth.isConnected ? 'text-green-600' : 'text-red-600'
                    }
                  >
                    Connection
                  </Button>

                  {session.errorHistory.length > 0 && (
                    <Button
                      onClick={() => setShowErrorHistory(!showErrorHistory)}
                      icon={AlertTriangle}
                      variant="ghost"
                      size="sm"
                      className="text-yellow-600"
                    >
                      Errors ({session.errorHistory.length})
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
        </CardHeader>

        {showProgress && session && (
          <CardContent>
            {/* Status and Progress */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  {getStatusIcon(session.status)}
                  <span className="text-sm font-medium">Status</span>
                </div>
                <div className={clsx('font-semibold capitalize', getStatusColor(session.status))}>
                  {session.status}
                </div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Database className="w-4 h-4" />
                  <span className="text-sm font-medium">Results Found</span>
                </div>
                <div className="font-semibold text-blue-600">{results.length.toLocaleString()}</div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="w-4 h-4" />
                  <span className="text-sm font-medium">Speed</span>
                </div>
                <div className="font-semibold text-green-600">
                  {realtimeStats.resultsPerSecond}/sec
                </div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm font-medium">ETA</span>
                </div>
                <div className="font-semibold text-purple-600">
                  {session.progress.estimatedTimeRemaining > 0
                    ? `${Math.round(session.progress.estimatedTimeRemaining)}s`
                    : 'Calculating...'}
                </div>
              </div>
            </div>

            {/* Current Source and Progress Bar */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">Current Source:</span>
                <span className="font-medium">{session.progress.currentSource}</span>
              </div>

              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{
                    width: `${Math.min((session.progress.processed / (searchParams.maxResults || 1000)) * 100, 100)}%`,
                  }}
                />
              </div>

              <div className="flex items-center justify-between text-xs text-gray-500">
                <span>Processed: {session.progress.processed.toLocaleString()}</span>
                <span>Target: {(searchParams.maxResults || 1000).toLocaleString()}</span>
              </div>

              {session.progress.errors > 0 && (
                <div className="flex items-center gap-1 text-sm text-red-600">
                  <AlertTriangle className="w-4 h-4" />
                  <span>{session.progress.errors} errors encountered</span>
                </div>
              )}
            </div>
          </CardContent>
        )}
      </Card>

      {/* Connection Health Panel */}
      {showConnectionHealth && session && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="w-5 h-5" />
              Connection Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <div
                    className={clsx(
                      'w-3 h-3 rounded-full',
                      session.connectionHealth.isConnected ? 'bg-green-500' : 'bg-red-500'
                    )}
                  />
                  <span className="text-sm font-medium">Status</span>
                </div>
                <div
                  className={clsx(
                    'font-semibold',
                    session.connectionHealth.isConnected ? 'text-green-600' : 'text-red-600'
                  )}
                >
                  {session.connectionHealth.isConnected ? 'Connected' : 'Disconnected'}
                </div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm font-medium">Last Heartbeat</span>
                </div>
                <div className="font-semibold text-blue-600">
                  {Math.round((Date.now() - session.connectionHealth.lastHeartbeat) / 1000)}s ago
                </div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="w-4 h-4" />
                  <span className="text-sm font-medium">Latency</span>
                </div>
                <div className="font-semibold text-purple-600">
                  {session.connectionHealth.latency}ms
                </div>
              </div>

              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm font-medium">Reconnect Attempts</span>
                </div>
                <div className="font-semibold text-orange-600">
                  {session.connectionHealth.reconnectAttempts}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Error History Panel */}
      {showErrorHistory && session && session.errorHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              Error History ({session.errorHistory.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {session.errorHistory
                .slice(-10)
                .reverse()
                .map((error, index) => (
                  <div
                    key={index}
                    className={clsx(
                      'p-3 rounded-lg border-l-4',
                      error.severity === 'high'
                        ? 'bg-red-50 border-red-500'
                        : error.severity === 'medium'
                          ? 'bg-yellow-50 border-yellow-500'
                          : 'bg-blue-50 border-blue-500'
                    )}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span
                        className={clsx(
                          'text-xs font-medium uppercase',
                          error.severity === 'high'
                            ? 'text-red-600'
                            : error.severity === 'medium'
                              ? 'text-yellow-600'
                              : 'text-blue-600'
                        )}
                      >
                        {error.severity} Severity
                      </span>
                      <span className="text-xs text-gray-500">
                        {new Date(error.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-700">{error.error}</p>
                  </div>
                ))}
            </div>

            {session.errorHistory.length > 10 && (
              <div className="mt-3 text-center">
                <span className="text-sm text-gray-500">
                  Showing last 10 of {session.errorHistory.length} errors
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Results Table */}
      <VirtualizedResultsTable
        onEdit={business => {
          // Handle edit
          console.log('Edit business:', business)
        }}
        onDelete={businessId => {
          // Handle delete
          setResults(prev => prev.filter(b => b.id !== businessId))
        }}
        onExport={businesses => {
          // Handle export
          console.log('Export businesses:', businesses)
        }}
        height={600}
        initialFilters={{}}
        initialSort={{ field: 'scrapedAt', order: 'desc' }}
      />
    </div>
  )
}
