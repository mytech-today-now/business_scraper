/**
 * Progress Indicator Component
 * Displays real-time streaming progress, connection status, and controls
 */

import React from 'react'
import { StreamingProgress } from '@/hooks/useSearchStreaming'
import {
  Play,
  Pause,
  Square,
  Wifi,
  WifiOff,
  RotateCcw,
  AlertCircle,
  CheckCircle,
  Clock,
  Database,
} from 'lucide-react'

interface ProgressIndicatorProps {
  progress: StreamingProgress
  isStreaming: boolean
  isPaused: boolean
  error: string | null
  onPause: () => void
  onResume: () => void
  onStop: () => void
  className?: string
}

export function ProgressIndicator({
  progress,
  isStreaming,
  isPaused,
  error,
  onPause,
  onResume,
  onStop,
  className = '',
}: ProgressIndicatorProps): JSX.Element {
  const getStatusIcon = () => {
    switch (progress.connectionStatus) {
      case 'connected':
        return <Wifi className="h-4 w-4 text-green-500" />
      case 'reconnecting':
        return <RotateCcw className="h-4 w-4 text-yellow-500 animate-spin" />
      case 'disconnected':
      default:
        return <WifiOff className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusText = () => {
    switch (progress.status) {
      case 'idle':
        return 'Ready to search'
      case 'connecting':
        return 'Connecting to search stream...'
      case 'streaming':
        return 'Streaming results in real-time'
      case 'paused':
        return 'Stream paused'
      case 'completed':
        return 'Search completed'
      case 'error':
        return 'Search error occurred'
      case 'fallback':
        return 'Using fallback search method'
      default:
        return 'Unknown status'
    }
  }

  const getProgressPercentage = () => {
    if (progress.totalFound === 0) return 0
    return Math.min((progress.processed / progress.totalFound) * 100, 100)
  }

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${Math.round(seconds)}s`
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = Math.round(seconds % 60)
    return `${minutes}m ${remainingSeconds}s`
  }

  return (
    <div
      className={`bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow-sm ${className}`}
    >
      {/* Header with status and connection */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {getStatusIcon()}
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
            {getStatusText()}
          </span>
        </div>

        {/* Control buttons */}
        <div className="flex items-center gap-1">
          {isStreaming && !isPaused && (
            <button
              onClick={onPause}
              className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Pause streaming"
              aria-label="Pause streaming"
            >
              <Pause className="h-4 w-4 text-gray-600 dark:text-gray-400" />
            </button>
          )}

          {isPaused && (
            <button
              onClick={onResume}
              className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Resume streaming"
              aria-label="Resume streaming"
            >
              <Play className="h-4 w-4 text-green-600 dark:text-green-400" />
            </button>
          )}

          {(isStreaming || isPaused) && (
            <button
              onClick={onStop}
              className="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Stop streaming"
              aria-label="Stop streaming"
            >
              <Square className="h-4 w-4 text-red-600 dark:text-red-400" />
            </button>
          )}
        </div>
      </div>

      {/* Progress bar */}
      {(isStreaming || isPaused || progress.status === 'completed') && (
        <div className="mb-3">
          <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
            <span>Progress</span>
            <span>{Math.round(getProgressPercentage())}%</span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-300 ease-out"
              style={{ width: `${getProgressPercentage()}%` }}
            />
          </div>
        </div>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-blue-500" />
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Results Found</div>
            <div className="font-medium text-gray-900 dark:text-gray-100" aria-live="polite">
              {progress.processed.toLocaleString()}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <CheckCircle className="h-4 w-4 text-green-500" />
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Total Expected</div>
            <div className="font-medium text-gray-900 dark:text-gray-100" aria-live="polite">
              {progress.totalFound > 0 ? progress.totalFound.toLocaleString() : '—'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-orange-500" />
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Time Remaining</div>
            <div className="font-medium text-gray-900 dark:text-gray-100" aria-live="polite">
              {progress.estimatedTimeRemaining > 0
                ? formatTime(progress.estimatedTimeRemaining)
                : '—'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="h-4 w-4 rounded-full bg-blue-500 flex items-center justify-center">
            <span className="text-xs text-white font-bold">#</span>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Current Batch</div>
            <div className="font-medium text-gray-900 dark:text-gray-100" aria-live="polite">
              {progress.currentBatch > 0 ? progress.currentBatch : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
          <div className="flex items-start gap-2">
            <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
            <div>
              <div className="text-sm font-medium text-red-800 dark:text-red-200">Search Error</div>
              <div className="text-sm text-red-700 dark:text-red-300 mt-1" role="alert">
                {error}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Fallback notice */}
      {progress.status === 'fallback' && (
        <div className="mt-3 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
          <div className="flex items-start gap-2">
            <AlertCircle className="h-4 w-4 text-yellow-500 mt-0.5 flex-shrink-0" />
            <div>
              <div className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                Fallback Mode
              </div>
              <div className="text-sm text-yellow-700 dark:text-yellow-300 mt-1" role="alert">
                Streaming connection failed. Using standard search method.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Accessibility announcements */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {isStreaming && `Search in progress. ${progress.processed} results found so far.`}
        {isPaused && 'Search paused. Click resume to continue.'}
        {progress.status === 'completed' &&
          `Search completed. Found ${progress.processed} total results.`}
        {error && `Search error: ${error}`}
      </div>
    </div>
  )
}
