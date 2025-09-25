/**
 * Memory Usage Dashboard Component
 * Real-time memory monitoring with alerts and historical tracking
 */

'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { useMemoryLeakDetection } from '@/hooks/useMemoryLeakDetection'
import { logger } from '@/utils/logger'

interface MemoryStats {
  heapUsed: number
  heapTotal: number
  external: number
  rss: number
  arrayBuffers: number
  timestamp: Date
}

interface MemoryAlert {
  id: string
  type: 'warning' | 'critical' | 'emergency'
  message: string
  timestamp: Date
  resolved: boolean
}

export function MemoryUsageDashboard() {
  const [memoryStats, setMemoryStats] = useState<MemoryStats | null>(null)
  const [memoryHistory, setMemoryHistory] = useState<MemoryStats[]>([])
  const [alerts, setAlerts] = useState<MemoryAlert[]>([])
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [autoCleanupEnabled, setAutoCleanupEnabled] = useState(true)

  const { isTracking, alerts: leakAlerts, clearAlerts } = useMemoryLeakDetection({
    componentName: 'MemoryUsageDashboard',
    onMemoryLeak: (alert) => {
      addAlert('critical', `Memory leak detected: ${alert.description}`)
    },
  })

  /**
   * Fetch current memory stats
   */
  const fetchMemoryStats = useCallback(async () => {
    try {
      const response = await fetch('/api/memory')
      if (response.ok) {
        const data = await response.json()
        const stats: MemoryStats = {
          heapUsed: data.heapUsed,
          heapTotal: data.heapTotal,
          external: data.external,
          rss: data.rss,
          arrayBuffers: data.arrayBuffers,
          timestamp: new Date(),
        }
        
        setMemoryStats(stats)
        
        // Add to history (keep last 50 readings)
        setMemoryHistory(prev => {
          const newHistory = [...prev, stats]
          return newHistory.slice(-50)
        })

        // Check for alerts
        checkMemoryThresholds(stats)
        
      } else {
        logger.error('MemoryDashboard', 'Failed to fetch memory stats')
      }
    } catch (error) {
      logger.error('MemoryDashboard', 'Error fetching memory stats', error)
    }
  }, [])

  /**
   * Check memory thresholds and create alerts
   */
  const checkMemoryThresholds = useCallback((stats: MemoryStats) => {
    const heapUsagePercent = (stats.heapUsed / stats.heapTotal) * 100
    const heapUsedMB = stats.heapUsed / (1024 * 1024)

    // Clear resolved alerts
    setAlerts(prev => prev.filter(alert => !alert.resolved))

    // Check thresholds
    if (heapUsedMB > 500) {
      addAlert('emergency', `Critical memory usage: ${heapUsedMB.toFixed(1)}MB (Emergency threshold exceeded)`)
    } else if (heapUsedMB > 400) {
      addAlert('critical', `High memory usage: ${heapUsedMB.toFixed(1)}MB (Critical threshold exceeded)`)
    } else if (heapUsagePercent > 70) {
      addAlert('warning', `Memory usage at ${heapUsagePercent.toFixed(1)}% of heap`)
    }
  }, [])

  /**
   * Add alert
   */
  const addAlert = useCallback((type: 'warning' | 'critical' | 'emergency', message: string) => {
    const alert: MemoryAlert = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      message,
      timestamp: new Date(),
      resolved: false,
    }

    setAlerts(prev => {
      // Check if similar alert already exists
      const existingAlert = prev.find(a => a.message === message && !a.resolved)
      if (existingAlert) {
        return prev
      }
      return [alert, ...prev].slice(0, 10) // Keep last 10 alerts
    })
  }, [])

  /**
   * Resolve alert
   */
  const resolveAlert = useCallback((alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, resolved: true } : alert
    ))
  }, [])

  /**
   * Trigger memory cleanup
   */
  const triggerCleanup = useCallback(async () => {
    try {
      const response = await fetch('/api/memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'cleanup' }),
      })

      if (response.ok) {
        addAlert('warning', 'Memory cleanup triggered successfully')
        // Refresh stats after cleanup
        setTimeout(fetchMemoryStats, 1000)
      } else {
        addAlert('critical', 'Failed to trigger memory cleanup')
      }
    } catch (error) {
      logger.error('MemoryDashboard', 'Error triggering cleanup', error)
      addAlert('critical', 'Error triggering memory cleanup')
    }
  }, [fetchMemoryStats])

  /**
   * Force garbage collection
   */
  const forceGarbageCollection = useCallback(async () => {
    try {
      const response = await fetch('/api/memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'gc' }),
      })

      if (response.ok) {
        addAlert('warning', 'Garbage collection triggered')
        setTimeout(fetchMemoryStats, 500)
      } else {
        addAlert('critical', 'Failed to trigger garbage collection')
      }
    } catch (error) {
      logger.error('MemoryDashboard', 'Error triggering GC', error)
    }
  }, [fetchMemoryStats])

  /**
   * Format bytes to human readable
   */
  const formatBytes = useCallback((bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }, [])

  /**
   * Get memory usage color
   */
  const getMemoryUsageColor = useCallback((usedMB: number): string => {
    if (usedMB > 500) return 'bg-red-500'
    if (usedMB > 400) return 'bg-orange-500'
    if (usedMB > 300) return 'bg-yellow-500'
    return 'bg-green-500'
  }, [])

  /**
   * Get alert variant
   */
  const getAlertVariant = useCallback((type: string) => {
    switch (type) {
      case 'emergency': return 'destructive'
      case 'critical': return 'destructive'
      case 'warning': return 'default'
      default: return 'default'
    }
  }, [])

  // Start/stop monitoring
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null

    if (isMonitoring) {
      fetchMemoryStats() // Initial fetch
      interval = setInterval(fetchMemoryStats, 3000) // Update every 3 seconds
    }

    return () => {
      if (interval) {
        clearInterval(interval)
      }
    }
  }, [isMonitoring, fetchMemoryStats])

  // Auto-start monitoring
  useEffect(() => {
    setIsMonitoring(true)
  }, [])

  const currentHeapUsageMB = memoryStats ? memoryStats.heapUsed / (1024 * 1024) : 0
  const heapUsagePercent = memoryStats ? (memoryStats.heapUsed / memoryStats.heapTotal) * 100 : 0
  const activeAlerts = alerts.filter(alert => !alert.resolved)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Memory Usage Dashboard</h2>
        <div className="flex items-center space-x-2">
          <Badge variant={isTracking ? 'default' : 'secondary'}>
            {isTracking ? 'Tracking Active' : 'Tracking Inactive'}
          </Badge>
          <Button
            variant={isMonitoring ? 'destructive' : 'default'}
            onClick={() => setIsMonitoring(!isMonitoring)}
          >
            {isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
          </Button>
        </div>
      </div>

      {/* Active Alerts */}
      {activeAlerts.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-lg font-semibold">Active Alerts</h3>
          {activeAlerts.map(alert => (
            <Alert key={alert.id} variant={getAlertVariant(alert.type)}>
              <AlertDescription className="flex items-center justify-between">
                <span>{alert.message}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => resolveAlert(alert.id)}
                >
                  Resolve
                </Button>
              </AlertDescription>
            </Alert>
          ))}
        </div>
      )}

      {/* Memory Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Heap Used</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatBytes(memoryStats?.heapUsed || 0)}</div>
            <Progress 
              value={heapUsagePercent} 
              className="mt-2"
            />
            <p className="text-xs text-muted-foreground mt-1">
              {heapUsagePercent.toFixed(1)}% of heap
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Heap Total</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatBytes(memoryStats?.heapTotal || 0)}</div>
            <div className={`h-2 rounded-full mt-2 ${getMemoryUsageColor(currentHeapUsageMB)}`} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">RSS</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatBytes(memoryStats?.rss || 0)}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Resident Set Size
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">External</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatBytes(memoryStats?.external || 0)}</div>
            <p className="text-xs text-muted-foreground mt-1">
              External memory
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Memory Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Memory Management Actions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center space-x-4">
            <Button onClick={triggerCleanup} variant="outline">
              Trigger Cleanup
            </Button>
            <Button onClick={forceGarbageCollection} variant="outline">
              Force GC
            </Button>
            <Button onClick={clearAlerts} variant="outline">
              Clear Leak Alerts
            </Button>
          </div>
          
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="autoCleanup"
              checked={autoCleanupEnabled}
              onChange={(e) => setAutoCleanupEnabled(e.target.checked)}
            />
            <label htmlFor="autoCleanup" className="text-sm">
              Enable automatic cleanup
            </label>
          </div>
        </CardContent>
      </Card>

      {/* Memory History Chart */}
      {memoryHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Memory Usage History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64 flex items-end space-x-1">
              {memoryHistory.slice(-20).map((stat, index) => {
                const heightPercent = (stat.heapUsed / Math.max(...memoryHistory.map(s => s.heapUsed))) * 100
                return (
                  <div
                    key={index}
                    className={`flex-1 ${getMemoryUsageColor(stat.heapUsed / (1024 * 1024))} rounded-t`}
                    style={{ height: `${heightPercent}%` }}
                    title={`${formatBytes(stat.heapUsed)} at ${stat.timestamp.toLocaleTimeString()}`}
                  />
                )
              })}
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Last 20 readings (hover for details)
            </p>
          </CardContent>
        </Card>
      )}

      {/* Memory Leak Alerts */}
      {leakAlerts.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Memory Leak Detection</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {leakAlerts.slice(0, 5).map((alert, index) => (
                <Alert key={index} variant="destructive">
                  <AlertDescription>
                    {alert.description} (Severity: {alert.severity})
                  </AlertDescription>
                </Alert>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
