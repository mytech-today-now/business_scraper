'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import {
  Activity,
  Clock,
  Database,
  Zap,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import { clsx } from 'clsx'

interface PerformanceMetrics {
  renderTime: number
  scrollPerformance: {
    avgTime: number
    maxTime: number
    samples: number
  }
  memoryUsage: {
    used: number
    total: number
    limit: number
  }
  apiPerformance: {
    avgResponseTime: number
    successRate: number
    errorRate: number
  }
  cacheHitRate: number
  activeConnections: number
  timestamp: Date
}

interface PerformanceAlert {
  id: string
  type: 'warning' | 'error' | 'info'
  message: string
  metric: string
  value: number
  threshold: number
  timestamp: Date
}

/**
 * Performance Monitoring Dashboard Component
 */
export function PerformanceMonitoringDashboard(): JSX.Element {
  const [metrics, setMetrics] = useState<PerformanceMetrics | null>(null)
  const [alerts, setAlerts] = useState<PerformanceAlert[]>([])
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [historicalData, setHistoricalData] = useState<PerformanceMetrics[]>([])

  /**
   * Collect current performance metrics
   */
  const collectMetrics = useCallback(async (): Promise<PerformanceMetrics> => {
    const startTime = performance.now()

    // Measure render time (simulate)
    await new Promise(resolve => setTimeout(resolve, 1))
    const renderTime = performance.now() - startTime

    // Get memory usage
    const memory = (performance as any).memory || {}
    const memoryUsage = {
      used: memory.usedJSHeapSize || 0,
      total: memory.totalJSHeapSize || 0,
      limit: memory.jsHeapSizeLimit || 0,
    }

    // Simulate API performance metrics
    const apiPerformance = {
      avgResponseTime: Math.random() * 500 + 200, // 200-700ms
      successRate: 0.95 + Math.random() * 0.05, // 95-100%
      errorRate: Math.random() * 0.05, // 0-5%
    }

    // Simulate scroll performance
    const scrollPerformance = {
      avgTime: Math.random() * 50 + 20, // 20-70ms
      maxTime: Math.random() * 100 + 50, // 50-150ms
      samples: Math.floor(Math.random() * 100) + 50,
    }

    return {
      renderTime,
      scrollPerformance,
      memoryUsage,
      apiPerformance,
      cacheHitRate: 0.7 + Math.random() * 0.3, // 70-100%
      activeConnections: Math.floor(Math.random() * 50) + 10,
      timestamp: new Date(),
    }
  }, [])

  /**
   * Check for performance alerts
   */
  const checkAlerts = useCallback((metrics: PerformanceMetrics): PerformanceAlert[] => {
    const newAlerts: PerformanceAlert[] = []

    // Render time alert
    if (metrics.renderTime > 100) {
      newAlerts.push({
        id: `render-${Date.now()}`,
        type: metrics.renderTime > 200 ? 'error' : 'warning',
        message: 'High render time detected',
        metric: 'renderTime',
        value: metrics.renderTime,
        threshold: 100,
        timestamp: new Date(),
      })
    }

    // Memory usage alert
    const memoryUsagePercent = (metrics.memoryUsage.used / metrics.memoryUsage.limit) * 100
    if (memoryUsagePercent > 80) {
      newAlerts.push({
        id: `memory-${Date.now()}`,
        type: memoryUsagePercent > 90 ? 'error' : 'warning',
        message: 'High memory usage detected',
        metric: 'memoryUsage',
        value: memoryUsagePercent,
        threshold: 80,
        timestamp: new Date(),
      })
    }

    // API performance alert
    if (metrics.apiPerformance.avgResponseTime > 1000) {
      newAlerts.push({
        id: `api-${Date.now()}`,
        type: 'warning',
        message: 'Slow API response times',
        metric: 'apiResponseTime',
        value: metrics.apiPerformance.avgResponseTime,
        threshold: 1000,
        timestamp: new Date(),
      })
    }

    // Error rate alert
    if (metrics.apiPerformance.errorRate > 0.05) {
      newAlerts.push({
        id: `error-${Date.now()}`,
        type: 'error',
        message: 'High error rate detected',
        metric: 'errorRate',
        value: metrics.apiPerformance.errorRate * 100,
        threshold: 5,
        timestamp: new Date(),
      })
    }

    return newAlerts
  }, [])

  /**
   * Start monitoring
   */
  const startMonitoring = useCallback(() => {
    setIsMonitoring(true)

    const interval = setInterval(async () => {
      try {
        const newMetrics = await collectMetrics()
        setMetrics(newMetrics)

        // Add to historical data (keep last 50 entries)
        setHistoricalData(prev => {
          const updated = [...prev, newMetrics]
          return updated.slice(-50)
        })

        // Check for alerts
        const newAlerts = checkAlerts(newMetrics)
        if (newAlerts.length > 0) {
          setAlerts(prev => [...prev, ...newAlerts].slice(-20)) // Keep last 20 alerts
        }
      } catch (error) {
        console.error('Failed to collect metrics:', error)
      }
    }, 2000) // Collect every 2 seconds

    return () => clearInterval(interval)
  }, [collectMetrics, checkAlerts])

  /**
   * Stop monitoring
   */
  const stopMonitoring = useCallback(() => {
    setIsMonitoring(false)
  }, [])

  /**
   * Clear alerts
   */
  const clearAlerts = useCallback(() => {
    setAlerts([])
  }, [])

  /**
   * Format bytes to human readable
   */
  const formatBytes = useCallback((bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }, [])

  /**
   * Get performance status
   */
  const getPerformanceStatus = useCallback(
    (metrics: PerformanceMetrics): 'excellent' | 'good' | 'warning' | 'critical' => {
      const issues = checkAlerts(metrics)
      const errorCount = issues.filter(alert => alert.type === 'error').length
      const warningCount = issues.filter(alert => alert.type === 'warning').length

      if (errorCount > 0) return 'critical'
      if (warningCount > 2) return 'warning'
      if (warningCount > 0) return 'good'
      return 'excellent'
    },
    [checkAlerts]
  )

  useEffect(() => {
    const cleanup = startMonitoring()
    return cleanup
  }, [startMonitoring])

  const performanceStatus = metrics ? getPerformanceStatus(metrics) : 'good'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Performance Monitoring</h2>
        <div className="flex items-center gap-2">
          <div
            className={clsx(
              'flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium',
              performanceStatus === 'excellent'
                ? 'bg-green-100 text-green-800'
                : performanceStatus === 'good'
                  ? 'bg-blue-100 text-blue-800'
                  : performanceStatus === 'warning'
                    ? 'bg-yellow-100 text-yellow-800'
                    : 'bg-red-100 text-red-800'
            )}
          >
            {performanceStatus === 'excellent' && <CheckCircle className="h-4 w-4" />}
            {performanceStatus === 'good' && <CheckCircle className="h-4 w-4" />}
            {performanceStatus === 'warning' && <AlertTriangle className="h-4 w-4" />}
            {performanceStatus === 'critical' && <XCircle className="h-4 w-4" />}
            {performanceStatus.charAt(0).toUpperCase() + performanceStatus.slice(1)}
          </div>
          <Button
            variant={isMonitoring ? 'destructive' : 'default'}
            size="sm"
            onClick={isMonitoring ? stopMonitoring : startMonitoring}
            icon={Activity}
          >
            {isMonitoring ? 'Stop' : 'Start'} Monitoring
          </Button>
        </div>
      </div>

      {/* Metrics Grid */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Render Performance */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Zap className="h-4 w-4" />
                Render Time
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.renderTime.toFixed(1)}ms</div>
              <div className="text-xs text-muted-foreground">Target: &lt;100ms</div>
            </CardContent>
          </Card>

          {/* Scroll Performance */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Scroll Performance
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {metrics.scrollPerformance.avgTime.toFixed(1)}ms
              </div>
              <div className="text-xs text-muted-foreground">
                Max: {metrics.scrollPerformance.maxTime.toFixed(1)}ms
              </div>
            </CardContent>
          </Card>

          {/* Memory Usage */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Database className="h-4 w-4" />
                Memory Usage
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatBytes(metrics.memoryUsage.used)}</div>
              <div className="text-xs text-muted-foreground">
                {((metrics.memoryUsage.used / metrics.memoryUsage.limit) * 100).toFixed(1)}% of
                limit
              </div>
            </CardContent>
          </Card>

          {/* API Performance */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4" />
                API Response
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {metrics.apiPerformance.avgResponseTime.toFixed(0)}ms
              </div>
              <div className="text-xs text-muted-foreground">
                {(metrics.apiPerformance.successRate * 100).toFixed(1)}% success rate
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Alerts */}
      {alerts.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Performance Alerts ({alerts.length})
              </CardTitle>
              <Button variant="outline" size="sm" onClick={clearAlerts}>
                Clear All
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {alerts.slice(-5).map(alert => (
                <div
                  key={alert.id}
                  className={clsx(
                    'p-3 rounded-lg border',
                    alert.type === 'error'
                      ? 'bg-red-50 border-red-200'
                      : alert.type === 'warning'
                        ? 'bg-yellow-50 border-yellow-200'
                        : 'bg-blue-50 border-blue-200'
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium text-sm">{alert.message}</div>
                      <div className="text-xs text-muted-foreground">
                        {alert.metric}: {alert.value.toFixed(1)} (threshold: {alert.threshold})
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {alert.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Historical Performance Chart */}
      {historicalData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Performance Trends</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64 flex items-end justify-between gap-1">
              {historicalData.slice(-20).map((data, index) => (
                <div
                  key={index}
                  className="flex-1 bg-blue-200 rounded-t"
                  style={{
                    height: `${Math.min((data.renderTime / 200) * 100, 100)}%`,
                    minHeight: '4px',
                  }}
                  title={`${data.renderTime.toFixed(1)}ms at ${data.timestamp.toLocaleTimeString()}`}
                />
              ))}
            </div>
            <div className="text-xs text-muted-foreground mt-2">
              Render time over last {historicalData.length} samples
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
