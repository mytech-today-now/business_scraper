import React, { useState, useEffect } from 'react'
import { analyticsService, RevenueMetrics, UserMetrics, FeatureUsageData } from '@/model/analyticsService'
import { Card, CardContent, CardHeader, CardTitle } from '@/view/components/ui/Card'
import { Select } from '@/view/components/ui/Select'
import { LineChart, BarChart, PieChart } from '@/view/components/ui/Charts'
import { Spinner } from '@/view/components/ui/Spinner'
import { Alert } from '@/view/components/ui/Alert'
import { Button } from '@/view/components/ui/Button'
import { Download, RefreshCw, TrendingUp, Users, DollarSign, Activity } from 'lucide-react'
import { logger } from '@/utils/logger'

/**
 * Time range options for analytics
 */
const TIME_RANGE_OPTIONS = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '1y', label: 'Last year' }
]

/**
 * Analytics Dashboard Component
 */
export const AnalyticsDashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState('30d')
  const [revenueMetrics, setRevenueMetrics] = useState<RevenueMetrics | null>(null)
  const [userMetrics, setUserMetrics] = useState<UserMetrics | null>(null)
  const [featureUsage, setFeatureUsage] = useState<FeatureUsageData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  useEffect(() => {
    loadAnalytics()
  }, [timeRange])

  /**
   * Load analytics data for the selected time range
   */
  const loadAnalytics = async () => {
    setLoading(true)
    setError(null)
    
    try {
      const { startDate, endDate } = getDateRange(timeRange)

      // Track analytics dashboard view
      await analyticsService.trackEvent('feature_analytics_dashboard_view', {
        timeRange,
        timestamp: new Date().toISOString()
      })

      const [revenue, users, features] = await Promise.all([
        analyticsService.getRevenueMetrics(startDate, endDate),
        analyticsService.getUserMetrics(startDate, endDate),
        analyticsService.getFeatureUsageAnalytics(startDate, endDate)
      ])

      setRevenueMetrics(revenue)
      setUserMetrics(users)
      setFeatureUsage(features)
      setLastUpdated(new Date())

      logger.info('AnalyticsDashboard', 'Analytics data loaded successfully', {
        timeRange,
        revenueTotal: revenue.totalRevenue,
        userCount: users.totalUsers,
        featureUsageTotal: features.totalFeatureUsage
      })
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load analytics'
      setError(errorMessage)
      logger.error('AnalyticsDashboard', 'Failed to load analytics', error)
    } finally {
      setLoading(false)
    }
  }

  /**
   * Get date range based on selected time range
   */
  const getDateRange = (range: string) => {
    const endDate = new Date()
    const startDate = new Date()

    switch (range) {
      case '7d':
        startDate.setDate(endDate.getDate() - 7)
        break
      case '30d':
        startDate.setDate(endDate.getDate() - 30)
        break
      case '90d':
        startDate.setDate(endDate.getDate() - 90)
        break
      case '1y':
        startDate.setFullYear(endDate.getFullYear() - 1)
        break
      default:
        startDate.setDate(endDate.getDate() - 30)
    }

    return { startDate, endDate }
  }

  /**
   * Format currency values
   */
  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount)
  }

  /**
   * Format percentage values
   */
  const formatPercentage = (value: number) => {
    return `${(value * 100).toFixed(1)}%`
  }

  /**
   * Format number with commas
   */
  const formatNumber = (value: number) => {
    return value.toLocaleString()
  }

  /**
   * Handle data export
   */
  const handleExport = async () => {
    try {
      await analyticsService.trackEvent('feature_analytics_export', {
        timeRange,
        timestamp: new Date().toISOString()
      })

      // Create export data
      const exportData = {
        timeRange,
        lastUpdated: lastUpdated?.toISOString(),
        revenueMetrics,
        userMetrics,
        featureUsage
      }

      // Create and download JSON file
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analytics-report-${timeRange}-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      logger.info('AnalyticsDashboard', 'Analytics data exported successfully')
    } catch (error) {
      logger.error('AnalyticsDashboard', 'Failed to export analytics data', error)
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
        <Spinner size="lg" />
        <p className="text-muted-foreground">Loading analytics...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <p>Failed to load analytics: {error}</p>
        </Alert>
        <Button onClick={loadAnalytics} variant="outline">
          <RefreshCw className="w-4 h-4 mr-2" />
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold">Analytics Dashboard</h1>
          {lastUpdated && (
            <p className="text-sm text-muted-foreground">
              Last updated: {lastUpdated.toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={timeRange}
            onValueChange={setTimeRange}
            options={TIME_RANGE_OPTIONS}
            className="w-40"
            aria-label="Select time range"
          />
          <Button onClick={loadAnalytics} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button onClick={handleExport} variant="outline" size="sm">
            <Download className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Revenue Metrics */}
      {revenueMetrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Revenue</CardTitle>
              <DollarSign className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {formatCurrency(revenueMetrics.totalRevenue)}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Monthly Recurring Revenue</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {formatCurrency(revenueMetrics.monthlyRecurringRevenue)}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Average Revenue Per User</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">
                {formatCurrency(revenueMetrics.averageRevenuePerUser)}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Churn Rate</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {formatPercentage(revenueMetrics.churnRate)}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* User Metrics */}
      {userMetrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatNumber(userMetrics.totalUsers)}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Users</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatNumber(userMetrics.activeUsers)}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">New Users</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatNumber(userMetrics.newUsers)}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Retention Rate</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatPercentage(userMetrics.retentionRate)}</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Feature Usage Chart */}
      {featureUsage && featureUsage.topFeatures.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Feature Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <BarChart
              data={featureUsage.topFeatures.map(([feature, count]) => ({
                name: feature,
                value: count
              }))}
              height={300}
              showValues={true}
            />
          </CardContent>
        </Card>
      )}
    </div>
  )
}
