/**
 * Memory Dashboard Component
 * Displays real-time memory monitoring and cleanup controls
 */

'use client'

import React, { useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Trash2,
  Settings,
  X,
  Play,
  Square,
  Zap,
  HardDrive,
  Clock,
} from 'lucide-react'
import { createCSPSafeStyle } from '@/lib/cspUtils'
import { useMemoryMonitor, useMemoryFormatter } from '@/hooks/useMemoryMonitor'
import { Button } from './ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { CleanupOptions } from '@/lib/memory-cleanup'
import toast from 'react-hot-toast'

interface MemoryDashboardProps {
  className?: string
  compact?: boolean
}

export function MemoryDashboard({
  className = '',
  compact = false,
}: MemoryDashboardProps): JSX.Element {
  const {
    isMonitoring,
    currentStats,
    alerts,
    thresholds,
    isCleanupInProgress,
    lastCleanupResult,
    startMonitoring,
    stopMonitoring,
    clearAlerts,
    performCleanup,
    performEmergencyCleanup,
    dismissAlert,
  } = useMemoryMonitor()

  const {
    formatBytes,
    formatPercentage,
    getMemoryStatusColor,
    getMemoryStatusBgColor,
    getAlertIcon,
    getAlertColor,
  } = useMemoryFormatter()

  const [showSettings, setShowSettings] = useState(false)
  const [cleanupOptions, setCleanupOptions] = useState<CleanupOptions>({
    clearSearchResults: true,
    clearProcessingSteps: false,
    clearErrorLogs: false,
    clearCachedData: true,
    forceGarbageCollection: false,
    retainLastSessions: 3,
  })

  const handleStartMonitoring = () => {
    startMonitoring()
    toast.success('Memory monitoring started')
  }

  const handleStopMonitoring = () => {
    stopMonitoring()
    toast.success('Memory monitoring stopped')
  }

  const handleCleanup = async () => {
    try {
      const result = await performCleanup(cleanupOptions)
      if (result.success) {
        toast.success(
          `Cleanup completed! Cleared ${result.itemsCleared} items, freed ${formatBytes(result.memoryFreed)}`
        )
      } else {
        toast.error(`Cleanup failed: ${result.errors.join(', ')}`)
      }
    } catch (error) {
      toast.error('Cleanup failed')
    }
  }

  const handleEmergencyCleanup = async () => {
    try {
      const result = await performEmergencyCleanup()
      if (result.success) {
        toast.success(`Emergency cleanup completed! Cleared ${result.itemsCleared} items`)
      } else {
        toast.error(`Emergency cleanup failed: ${result.errors.join(', ')}`)
      }
    } catch (error) {
      toast.error('Emergency cleanup failed')
    }
  }

  if (compact) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        {currentStats && (
          <>
            <div className="flex items-center gap-1 text-sm">
              <Activity className="h-4 w-4" />
              <span className={getMemoryStatusColor(currentStats.percentage, thresholds)}>
                {formatPercentage(currentStats.percentage)}
              </span>
            </div>
            <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${getMemoryStatusBgColor(currentStats.percentage, thresholds)}`}
                style={createCSPSafeStyle({ width: `${Math.min(currentStats.percentage, 100)}%` })}
              />
            </div>
          </>
        )}
        {alerts.length > 0 && <AlertTriangle className="h-4 w-4 text-orange-500 animate-pulse" />}
      </div>
    )
  }

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Memory Monitor
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              icon={Settings}
              onClick={() => setShowSettings(!showSettings)}
            >
              Settings
            </Button>
            {isMonitoring ? (
              <Button variant="outline" size="sm" icon={Square} onClick={handleStopMonitoring}>
                Stop
              </Button>
            ) : (
              <Button variant="outline" size="sm" icon={Play} onClick={handleStartMonitoring}>
                Start
              </Button>
            )}
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Memory Statistics */}
        {currentStats && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Memory Usage</span>
              <span
                className={`text-sm font-mono ${getMemoryStatusColor(currentStats.percentage, thresholds)}`}
              >
                {formatBytes(currentStats.used)} / {formatBytes(currentStats.total)}
              </span>
            </div>

            <div className="w-full h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${getMemoryStatusBgColor(currentStats.percentage, thresholds)}`}
                style={createCSPSafeStyle({ width: `${Math.min(currentStats.percentage, 100)}%` })}
              />
            </div>

            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>0%</span>
              <span className={getMemoryStatusColor(currentStats.percentage, thresholds)}>
                {formatPercentage(currentStats.percentage)}
              </span>
              <span>100%</span>
            </div>
          </div>
        )}

        {/* Memory Alerts */}
        {alerts.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Alerts</span>
              <Button variant="ghost" size="sm" onClick={clearAlerts} className="text-xs">
                Clear All
              </Button>
            </div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {alerts.slice(-5).map((alert, index) => (
                <div
                  key={index}
                  className={`p-2 rounded-md text-xs flex items-center justify-between ${getAlertColor(alert.level)}`}
                >
                  <div className="flex items-center gap-2">
                    <span>{getAlertIcon(alert.level)}</span>
                    <span>{alert.message}</span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => dismissAlert(index)}
                    className="h-4 w-4 p-0"
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Cleanup Controls */}
        <div className="space-y-3">
          <span className="text-sm font-medium">Memory Cleanup</span>

          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              icon={Trash2}
              onClick={handleCleanup}
              disabled={isCleanupInProgress}
              className="flex-1"
            >
              {isCleanupInProgress ? 'Cleaning...' : 'Clean Memory'}
            </Button>

            <Button
              variant="destructive"
              size="sm"
              icon={Zap}
              onClick={handleEmergencyCleanup}
              disabled={isCleanupInProgress}
            >
              Emergency
            </Button>
          </div>

          {lastCleanupResult && (
            <div className="text-xs text-muted-foreground p-2 bg-muted rounded">
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                Last cleanup: {lastCleanupResult.itemsCleared} items cleared,
                {formatBytes(lastCleanupResult.memoryFreed)} freed
              </div>
            </div>
          )}
        </div>

        {/* Settings Panel */}
        {showSettings && (
          <div className="space-y-3 p-3 border rounded-md bg-muted/50">
            <span className="text-sm font-medium">Cleanup Options</span>

            <div className="space-y-2 text-xs">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.clearSearchResults}
                  onChange={e =>
                    setCleanupOptions(prev => ({
                      ...prev,
                      clearSearchResults: e.target.checked,
                    }))
                  }
                />
                Clear search results
              </label>

              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.clearCachedData}
                  onChange={e =>
                    setCleanupOptions(prev => ({
                      ...prev,
                      clearCachedData: e.target.checked,
                    }))
                  }
                />
                Clear cached data
              </label>

              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.forceGarbageCollection}
                  onChange={e =>
                    setCleanupOptions(prev => ({
                      ...prev,
                      forceGarbageCollection: e.target.checked,
                    }))
                  }
                />
                Force garbage collection
              </label>

              <div className="flex items-center gap-2">
                <label>Retain last</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={cleanupOptions.retainLastSessions || 3}
                  onChange={e =>
                    setCleanupOptions(prev => ({
                      ...prev,
                      retainLastSessions: parseInt(e.target.value) || 3,
                    }))
                  }
                  className="w-12 px-1 py-0.5 text-xs border rounded"
                />
                <label>sessions</label>
              </div>
            </div>
          </div>
        )}

        {!isMonitoring && (
          <div className="text-center text-sm text-muted-foreground py-4">
            <HardDrive className="h-8 w-8 mx-auto mb-2 opacity-50" />
            Memory monitoring is stopped. Click Start to begin monitoring.
          </div>
        )}
      </CardContent>
    </Card>
  )
}
