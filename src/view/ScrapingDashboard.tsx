/**
 * Real-time Monitoring Interface
 * Live scraping progress indicators, error tracking, and system health monitoring
 */

'use client'

import React, { useState, useEffect, useRef } from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cpu,
  Database,
  Globe,
  HardDrive,
  MemoryStick,
  Monitor,
  Network,
  Server,
  Wifi,
  Zap,
  TrendingUp,
  TrendingDown,
  Pause,
  Play,
  Square,
  RefreshCw,
  Settings,
  Download,
  Filter,
  Search,
  Bell,
  BellOff
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { logger } from '@/utils/logger'

interface ScrapingStats {
  totalJobs: number
  completedJobs: number
  failedJobs: number
  activeJobs: number
  queuedJobs: number
  averageProcessingTime: number
  successRate: number
  pagesPerMinute: number
}

interface SystemHealth {
  status: 'healthy' | 'warning' | 'critical'
  cpu: { usage: number; cores: number }
  memory: { used: number; total: number; percentage: number }
  disk: { used: number; total: number; percentage: number }
  network: { bytesIn: number; bytesOut: number; latency: number }
  database: { connections: number; maxConnections: number; responseTime: number }
  uptime: number
  lastCheck: Date
}

interface ErrorLog {
  id: string
  timestamp: Date
  level: 'error' | 'warning' | 'info'
  source: string
  message: string
  details?: any
  resolved: boolean
}

interface PerformanceMetric {
  timestamp: Date
  metric: string
  value: number
  unit: string
}

interface Alert {
  id: string
  type: 'performance' | 'error' | 'system' | 'capacity'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  timestamp: Date
  acknowledged: boolean
  resolved: boolean
}

interface ScrapingJob {
  id: string
  url: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  depth: number
  priority: number
  retries: number
  maxRetries: number
  createdAt: string
  startedAt?: string
  completedAt?: string
  error?: string
  resultCount?: number
}

export function ScrapingDashboard() {
  const [stats, setStats] = useState<ScrapingStats | null>(null)
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null)
  const [errorLogs, setErrorLogs] = useState<ErrorLog[]>([])
  const [performanceMetrics, setPerformanceMetrics] = useState<PerformanceMetric[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [jobs, setJobs] = useState<ScrapingJob[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [alertsEnabled, setAlertsEnabled] = useState(true)
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h')
  const [activeTab, setActiveTab] = useState<'overview' | 'performance' | 'logs' | 'alerts'>('overview')
  const wsRef = useRef<WebSocket | null>(null)

  // WebSocket connection for real-time updates
  useEffect(() => {
    if (autoRefresh) {
      connectWebSocket()
    } else {
      disconnectWebSocket()
    }

    return () => disconnectWebSocket()
  }, [autoRefresh])

  const connectWebSocket = () => {
    try {
      wsRef.current = new WebSocket('ws://localhost:3001/ws/monitoring')

      wsRef.current.onopen = () => {
        logger.info('ScrapingDashboard', 'WebSocket connected')
      }

      wsRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data)
        handleRealtimeUpdate(data)
      }

      wsRef.current.onclose = () => {
        logger.info('ScrapingDashboard', 'WebSocket disconnected')
        // Attempt to reconnect after 5 seconds
        if (autoRefresh) {
          setTimeout(connectWebSocket, 5000)
        }
      }

      wsRef.current.onerror = (error) => {
        logger.error('ScrapingDashboard', 'WebSocket error', error)
      }
    } catch (error) {
      logger.error('ScrapingDashboard', 'Failed to connect WebSocket', error)
    }
  }

  const disconnectWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
  }

  const handleRealtimeUpdate = (data: any) => {
    switch (data.type) {
      case 'stats':
        setStats(data.payload)
        break
      case 'systemHealth':
        setSystemHealth(data.payload)
        break
      case 'errorLog':
        setErrorLogs(prev => [data.payload, ...prev].slice(0, 100))
        break
      case 'performanceMetric':
        setPerformanceMetrics(prev => [...prev, data.payload].slice(-100))
        break
      case 'alert':
        setAlerts(prev => [data.payload, ...prev])
        if (alertsEnabled && data.payload.severity === 'critical') {
          // Show browser notification for critical alerts
          showNotification(data.payload)
        }
        break
    }
  }

  // Fetch initial data and system health
  const fetchData = async () => {
    try {
      const [statsResponse, healthResponse, logsResponse] = await Promise.all([
        fetch('/api/enhanced-scrape'),
        fetch('/api/system-health'),
        fetch('/api/error-logs?limit=50')
      ])

      const [statsData, healthData, logsData] = await Promise.all([
        statsResponse.json(),
        healthResponse.json(),
        logsResponse.json()
      ])

      if (statsData.success) {
        setStats(statsData.stats)
      }

      if (healthData.success) {
        setSystemHealth(healthData.health)
      }

      if (logsData.success) {
        setErrorLogs(logsData.logs)
      }

      setError(null)
    } catch (error) {
      logger.error('ScrapingDashboard', 'Failed to fetch data', error)
      setError('Failed to connect to monitoring services')
    }
  }

  const showNotification = (alert: Alert) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(`Critical Alert: ${alert.title}`, {
        body: alert.message,
        icon: '/favicon.ico'
      })
    }
  }

  // Initialize engine
  const initializeEngine = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/enhanced-scrape', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'initialize' }),
      })
      
      const data = await response.json()
      if (data.success) {
        await fetchData()
        setError(null)
      } else {
        setError('Failed to initialize scraping engine')
      }
    } catch (error) {
      logger.error('ScrapingDashboard', 'Failed to initialize engine', error)
      setError('Failed to initialize scraping engine')
    } finally {
      setIsLoading(false)
    }
  }

  // Shutdown engine
  const shutdownEngine = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/enhanced-scrape', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'shutdown' }),
      })
      
      const data = await response.json()
      if (data.success) {
        setStats(null)
        setJobs([])
        setError(null)
      } else {
        setError('Failed to shutdown scraping engine')
      }
    } catch (error) {
      logger.error('ScrapingDashboard', 'Failed to shutdown engine', error)
      setError('Failed to shutdown scraping engine')
    } finally {
      setIsLoading(false)
    }
  }

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000) // Refresh every 5 seconds
      return () => clearInterval(interval)
    }
    return undefined
  }, [autoRefresh])

  // Initial data fetch
  useEffect(() => {
    fetchData()
  }, [])

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    return `${(ms / 60000).toFixed(1)}m`
  }

  const formatPercentage = (value: number) => {
    return `${(value * 100).toFixed(1)}%`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Enhanced Scraping Dashboard</h2>
        <div className="flex items-center space-x-4">
          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
            <span className="text-sm">Auto-refresh</span>
          </label>
          <Button onClick={fetchData} disabled={isLoading}>
            Refresh
          </Button>
          <Button onClick={initializeEngine} disabled={isLoading}>
            Initialize
          </Button>
          <Button onClick={shutdownEngine} disabled={isLoading} variant="destructive">
            Shutdown
          </Button>
        </div>
      </div>

      {error && (
        <Card className="p-4 border-red-200 bg-red-50">
          <p className="text-red-600">{error}</p>
        </Card>
      )}

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Total Jobs</h3>
            <p className="text-2xl font-bold">{stats.totalJobs}</p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Active Jobs</h3>
            <p className="text-2xl font-bold text-blue-600">{stats.activeJobs}</p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Queued Jobs</h3>
            <p className="text-2xl font-bold text-yellow-600">{stats.queuedJobs}</p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Success Rate</h3>
            <p className="text-2xl font-bold text-green-600">
              {formatPercentage(stats.successRate)}
            </p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Completed</h3>
            <p className="text-2xl font-bold text-green-600">{stats.completedJobs}</p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Failed</h3>
            <p className="text-2xl font-bold text-red-600">{stats.failedJobs}</p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Avg Processing Time</h3>
            <p className="text-2xl font-bold">
              {formatDuration(stats.averageProcessingTime)}
            </p>
          </Card>

          <Card className="p-4">
            <h3 className="text-sm font-medium text-gray-500">Pages/Minute</h3>
            <p className="text-2xl font-bold text-purple-600">{stats.pagesPerMinute}</p>
          </Card>
        </div>
      )}

      {stats && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Performance Overview</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Job Completion Rate</span>
                <span>{formatPercentage(stats.successRate)}</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-green-600 h-2 rounded-full"
                  style={{ width: `${stats.successRate * 100}%` }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Queue Utilization</span>
                <span>
                  {stats.activeJobs + stats.queuedJobs} / {stats.totalJobs}
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{
                    width: `${
                      stats.totalJobs > 0
                        ? ((stats.activeJobs + stats.queuedJobs) / stats.totalJobs) * 100
                        : 0
                    }%`,
                  }}
                ></div>
              </div>
            </div>
          </div>
        </Card>
      )}

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button
            onClick={() => {
              // Add test job functionality
              const testUrl = 'https://example.com'
              fetch('/api/enhanced-scrape', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  action: 'add-job',
                  url: testUrl,
                  depth: 2,
                  priority: 5,
                }),
              }).then(() => fetchData())
            }}
            disabled={isLoading}
          >
            Add Test Job
          </Button>

          <Button
            onClick={() => {
              // Add multiple test jobs
              const testUrls = [
                'https://example.com',
                'https://test.com',
                'https://demo.com',
              ]
              fetch('/api/enhanced-scrape', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  action: 'add-multiple-jobs',
                  urls: testUrls,
                  depth: 2,
                  priority: 3,
                }),
              }).then(() => fetchData())
            }}
            disabled={isLoading}
          >
            Add Batch Jobs
          </Button>

          <Button
            onClick={() => {
              // Clear completed jobs (if such functionality exists)
              fetchData()
            }}
            disabled={isLoading}
            variant="outline"
          >
            Refresh Data
          </Button>
        </div>
      </Card>

      {!stats && !error && (
        <Card className="p-8 text-center">
          <p className="text-gray-500">
            Enhanced scraping engine not initialized. Click "Initialize" to start.
          </p>
        </Card>
      )}
    </div>
  )
}
