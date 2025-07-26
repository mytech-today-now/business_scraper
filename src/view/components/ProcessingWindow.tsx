'use client'

import React, { useState, useEffect } from 'react'
import { 
  Globe, 
  Search, 
  Database, 
  CheckCircle, 
  XCircle, 
  Clock, 
  AlertTriangle,
  Eye,
  EyeOff,
  Zap,
  Activity,
  Wifi,
  WifiOff
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { logger } from '@/utils/logger'

export interface ProcessingStep {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  url?: string
  startTime?: Date
  endTime?: Date
  duration?: number
  details?: string
  error?: string
  dataSource?: 'demo' | 'real'
  businessesFound?: number
}

export interface ProcessingWindowProps {
  isVisible: boolean
  isActive: boolean
  currentStep?: string
  steps: ProcessingStep[]
  isDemoMode: boolean
  onToggleVisibility: () => void
  onClear: () => void
  progress: {
    current: number
    total: number
    percentage: number
  }
  currentUrl?: string
}

/**
 * Get console log color based on level
 */
function getConsoleLogColor(level: string): string {
  switch (level) {
    case 'error':
      return 'text-red-400'
    case 'warn':
      return 'text-yellow-400'
    case 'info':
      return 'text-blue-400'
    case 'debug':
      return 'text-purple-400'
    default:
      return 'text-gray-300'
  }
}

/**
 * Processing Window Component
 * Shows real-time processing status and clearly indicates demo vs real scraping
 */
export function ProcessingWindow({
  isVisible,
  isActive,
  currentStep,
  steps,
  isDemoMode,
  onToggleVisibility,
  onClear,
  progress,
  currentUrl
}: ProcessingWindowProps) {
  const [autoScroll, setAutoScroll] = useState(true)
  const [consoleLogs, setConsoleLogs] = useState<Array<{
    timestamp: Date
    level: 'log' | 'info' | 'warn' | 'error' | 'debug'
    message: string
    args: any[]
  }>>([])
  const [showConsole, setShowConsole] = useState(false)

  // Auto-scroll to latest step when new steps are added
  useEffect(() => {
    if (autoScroll && isVisible) {
      const container = document.getElementById('processing-steps-container')
      if (container) {
        container.scrollTop = container.scrollHeight
      }
    }
  }, [steps.length, autoScroll, isVisible])

  // Console capture setup
  useEffect(() => {
    const originalConsole = {
      log: console.log,
      info: console.info,
      warn: console.warn,
      error: console.error,
      debug: console.debug
    }

    const captureConsole = (level: 'log' | 'info' | 'warn' | 'error' | 'debug') => {
      return (...args: any[]) => {
        // Call original console method
        originalConsole[level](...args)

        // Capture for our display
        const message = args.map(arg =>
          typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
        ).join(' ')

        setConsoleLogs(prev => [...prev.slice(-999), { // Keep last 1000 logs
          timestamp: new Date(),
          level,
          message,
          args
        }])
      }
    }

    // Override console methods
    console.log = captureConsole('log')
    console.info = captureConsole('info')
    console.warn = captureConsole('warn')
    console.error = captureConsole('error')
    console.debug = captureConsole('debug')

    // Cleanup on unmount
    return () => {
      console.log = originalConsole.log
      console.info = originalConsole.info
      console.warn = originalConsole.warn
      console.error = originalConsole.error
      console.debug = originalConsole.debug
    }
  }, [])

  // Auto-scroll console output when new logs are added
  useEffect(() => {
    if (showConsole && autoScroll) {
      const container = document.getElementById('console-output-container')
      if (container) {
        container.scrollTop = container.scrollHeight
      }
    }
  }, [consoleLogs.length, showConsole, autoScroll])

  const getStepIcon = (step: ProcessingStep) => {
    switch (step.status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'running':
        return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
      case 'skipped':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  const getStepColor = (step: ProcessingStep) => {
    switch (step.status) {
      case 'completed':
        return 'border-l-green-500 bg-green-50'
      case 'failed':
        return 'border-l-red-500 bg-red-50'
      case 'running':
        return 'border-l-blue-500 bg-blue-50'
      case 'skipped':
        return 'border-l-yellow-500 bg-yellow-50'
      default:
        return 'border-l-gray-300 bg-gray-50'
    }
  }

  const getDataSourceBadge = (dataSource?: 'demo' | 'real') => {
    if (!dataSource) return null
    
    return (
      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
        dataSource === 'demo' 
          ? 'bg-orange-100 text-orange-800' 
          : 'bg-green-100 text-green-800'
      }`}>
        {dataSource === 'demo' ? (
          <>
            <Database className="h-3 w-3 mr-1" />
            Demo Data
          </>
        ) : (
          <>
            <Wifi className="h-3 w-3 mr-1" />
            Live Web
          </>
        )}
      </span>
    )
  }

  const formatDuration = (ms?: number) => {
    if (!ms) return ''
    if (ms < 1000) return `${ms}ms`
    return `${(ms / 1000).toFixed(1)}s`
  }

  const completedSteps = steps.filter(s => s.status === 'completed').length
  const failedSteps = steps.filter(s => s.status === 'failed').length
  const totalBusinesses = steps.reduce((sum, step) => sum + (step.businessesFound || 0), 0)

  if (!isVisible) {
    return (
      <div className="fixed bottom-4 right-4 z-50">
        <Button
          onClick={onToggleVisibility}
          className="rounded-full shadow-lg"
          size="sm"
        >
          <Eye className="h-4 w-4 mr-2" />
          Show Processing
          {isActive && (
            <div className="ml-2 h-2 w-2 bg-blue-500 rounded-full animate-pulse" />
          )}
        </Button>
      </div>
    )
  }

  return (
    <Card className="mb-6 shadow-lg">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <CardTitle className="text-lg">Processing Status</CardTitle>
            {isDemoMode ? (
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-orange-100 text-orange-800">
                <Database className="h-4 w-4 mr-1" />
                Demo Mode
              </span>
            ) : (
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                <Wifi className="h-4 w-4 mr-1" />
                Live Scraping
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setAutoScroll(!autoScroll)}
              className={autoScroll ? 'text-blue-600' : 'text-gray-400'}
            >
              <Zap className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={onClear}
              disabled={isActive}
            >
              Clear
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={onToggleVisibility}
            >
              <EyeOff className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {/* Progress Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div className="bg-blue-50 p-3 rounded-lg">
            <div className="text-sm font-medium text-blue-600">Progress</div>
            <div className="text-2xl font-bold text-blue-700">{progress.percentage}%</div>
            <div className="text-xs text-blue-500">{progress.current} of {progress.total}</div>
          </div>
          <div className="bg-green-50 p-3 rounded-lg">
            <div className="text-sm font-medium text-green-600">Completed</div>
            <div className="text-2xl font-bold text-green-700">{completedSteps}</div>
            <div className="text-xs text-green-500">steps finished</div>
          </div>
          <div className="bg-red-50 p-3 rounded-lg">
            <div className="text-sm font-medium text-red-600">Failed</div>
            <div className="text-2xl font-bold text-red-700">{failedSteps}</div>
            <div className="text-xs text-red-500">steps failed</div>
          </div>
          <div className="bg-purple-50 p-3 rounded-lg">
            <div className="text-sm font-medium text-purple-600">Businesses</div>
            <div className="text-2xl font-bold text-purple-700">{totalBusinesses}</div>
            <div className="text-xs text-purple-500">found so far</div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mb-4">
          <div className="flex justify-between text-sm text-gray-600 mb-1">
            <span>Overall Progress</span>
            <span>{progress.percentage}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress.percentage}%` }}
            />
          </div>
        </div>

        {/* Current Activity */}
        {isActive && currentUrl && (
          <div className="mb-4 p-3 bg-blue-50 rounded-lg border-l-4 border-blue-500">
            <div className="flex items-center space-x-2">
              <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
              <span className="text-sm font-medium text-blue-700">Currently Processing:</span>
            </div>
            <div className="text-sm text-blue-600 mt-1 font-mono break-all">{currentUrl}</div>
          </div>
        )}

        {/* Processing Steps */}
        <div 
          id="processing-steps-container"
          className="max-h-64 overflow-y-auto space-y-2 border rounded-lg p-2"
        >
          {steps.length === 0 ? (
            <div className="text-center text-gray-500 py-8">
              <Search className="h-8 w-8 mx-auto mb-2 text-gray-400" />
              <p>No processing steps yet</p>
              <p className="text-xs">Start scraping to see real-time progress</p>
            </div>
          ) : (
            steps.map((step, index) => (
              <div
                key={step.id}
                className={`p-3 border-l-4 rounded-r-lg ${getStepColor(step)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-2 flex-1">
                    {getStepIcon(step)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="text-sm font-medium">{step.name}</span>
                        {getDataSourceBadge(step.dataSource)}
                        {step.businessesFound !== undefined && (
                          <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                            {step.businessesFound} businesses
                          </span>
                        )}
                      </div>
                      {step.url && (
                        <div className="text-xs text-gray-600 font-mono break-all mb-1">
                          {step.url}
                        </div>
                      )}
                      {step.details && (
                        <div className="text-xs text-gray-600 mb-1">
                          {step.details}
                        </div>
                      )}
                      {step.error && (
                        <div className="text-xs text-red-600 bg-red-100 p-2 rounded mt-1">
                          {step.error}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 ml-2">
                    {step.duration && formatDuration(step.duration)}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Console Output Section */}
        <div className="mt-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-700">Console Output</h3>
            <div className="flex items-center space-x-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setConsoleLogs([])}
                className="text-xs"
              >
                Clear Console
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowConsole(!showConsole)}
                className="text-xs"
              >
                {showConsole ? 'Hide' : 'Show'}
              </Button>
            </div>
          </div>

          {showConsole && (
            <div className="border rounded-lg bg-gray-900 text-gray-100 font-mono text-xs">
              <div
                id="console-output-container"
                className="h-48 min-h-48 max-h-96 overflow-auto p-3 space-y-1 resize-vertical"
              >
                {consoleLogs.length === 0 ? (
                  <div className="text-gray-500 italic">No console output yet...</div>
                ) : (
                  consoleLogs.map((log, index) => (
                    <div key={index} className="flex items-start space-x-2">
                      <span className="text-gray-500 text-xs flex-shrink-0">
                        {log.timestamp.toLocaleTimeString()}
                      </span>
                      <span className={`flex-shrink-0 ${getConsoleLogColor(log.level)}`}>
                        [{log.level.toUpperCase()}]
                      </span>
                      <span className="flex-1 break-all whitespace-pre-wrap">
                        {log.message}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
