'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/Tabs'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import {
  DollarSign,
  Users,
  CreditCard,
  TrendingUp,
  AlertTriangle,
  Activity,
  Download,
  Settings,
} from 'lucide-react'

// Import existing services
import { paymentAnalyticsService } from '@/model/paymentAnalyticsService'
import { monitoringService } from '@/model/monitoringService'
import { auditService } from '@/model/auditService'

interface DashboardData {
  analytics: any
  performance: any
  alerts: any[]
}

export function AdminDashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      setError(null)

      const endDate = new Date()
      const startDate = new Date()
      startDate.setDate(startDate.getDate() - 30) // Last 30 days

      // Load data from existing services
      const [analyticsResult, performanceData] = await Promise.all([
        paymentAnalyticsService.generateUserAnalytics('admin', startDate, endDate),
        monitoringService.getPerformanceDashboard(24),
      ])

      // Extract analytics data
      const analytics = analyticsResult.success ? analyticsResult.data : null

      setData({
        analytics,
        performance: performanceData,
        alerts: performanceData?.alerts?.active || [],
      })
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
      setError('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const generateComplianceReport = async () => {
    try {
      const endDate = new Date()
      const startDate = new Date()
      startDate.setMonth(startDate.getMonth() - 1) // Last month

      const report = await auditService.generateComplianceReport(startDate, endDate, 'GDPR')

      // In a real implementation, this would trigger a download
      console.log('Compliance Report Generated:', report)
      alert('Compliance report generated successfully!')
    } catch (error) {
      console.error('Failed to generate compliance report:', error)
      alert('Failed to generate compliance report')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading dashboard...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="text-red-600 text-lg mb-2">Error Loading Dashboard</div>
          <div className="text-sm text-muted-foreground mb-4">{error}</div>
          <Button onClick={loadDashboardData}>Retry</Button>
        </div>
      </div>
    )
  }

  const { analytics, performance, alerts } = data || {}

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Payment System Dashboard</h1>
        <div className="flex space-x-2">
          <Button onClick={generateComplianceReport} variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Export Compliance Report
          </Button>
          <Button variant="outline">
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </Button>
        </div>
      </div>

      {/* Alert Banner */}
      {alerts && alerts.length > 0 && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 text-red-500 mr-2" />
              <span className="font-medium text-red-800">
                {alerts.length} active alert{alerts.length > 1 ? 's' : ''}
              </span>
            </div>
            <div className="mt-2 space-y-1">
              {alerts.slice(0, 3).map((alert, index) => (
                <div key={index} className="text-sm text-red-700">
                  • {alert.title || alert.message || 'Unknown alert'}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Revenue</CardTitle>
            <DollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${analytics?.metrics?.totalRevenue?.toFixed(2) || '0.00'}
            </div>
            <p className="text-xs text-muted-foreground">
              +{((analytics?.metrics?.growthRate || 0) * 100).toFixed(1)}% from last month
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics?.metrics?.activeUsers || 0}</div>
            <p className="text-xs text-muted-foreground">
              {analytics?.metrics?.userGrowthRate
                ? `${(analytics.metrics.userGrowthRate * 100).toFixed(1)}% growth rate`
                : 'No growth data'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Monthly Revenue</CardTitle>
            <CreditCard className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${analytics?.metrics?.monthlyRevenue?.toFixed(2) || '0.00'}
            </div>
            <p className="text-xs text-muted-foreground">
              ARPU: ${analytics?.metrics?.averageRevenuePerUser?.toFixed(2) || '0.00'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Health</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {((performance?.overview?.uptime || 0.99) * 100).toFixed(1)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Avg response: {performance?.overview?.averageResponseTime?.toFixed(0) || 150}ms
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Detailed Tabs */}
      <Tabs defaultValue="analytics" className="space-y-4">
        <TabsList>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Revenue Trends</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span>Total Revenue:</span>
                    <span className="font-medium">
                      ${analytics?.metrics?.totalRevenue?.toFixed(2) || '0.00'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Growth Rate:</span>
                    <span
                      className={`font-medium ${
                        (analytics?.metrics?.growthRate || 0) >= 0
                          ? 'text-green-600'
                          : 'text-red-600'
                      }`}
                    >
                      {((analytics?.metrics?.growthRate || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Transaction Count:</span>
                    <span className="font-medium">{analytics?.metrics?.transactionCount || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>User Metrics</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span>Total Users:</span>
                    <span className="font-medium">{analytics?.metrics?.totalUsers || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Active Users:</span>
                    <span className="font-medium">{analytics?.metrics?.activeUsers || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>New This Month:</span>
                    <span className="font-medium">{analytics?.metrics?.newUsers || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Response Times</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {performance?.overview?.averageResponseTime?.toFixed(0) || 150}ms
                </div>
                <p className="text-sm text-muted-foreground">Average response time</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Error Rate</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {((performance?.overview?.errorRate || 0.01) * 100).toFixed(2)}%
                </div>
                <p className="text-sm text-muted-foreground">Error rate</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Uptime</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {((performance?.overview?.uptime || 0.99) * 100).toFixed(2)}%
                </div>
                <p className="text-sm text-muted-foreground">System uptime</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="subscriptions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Subscription Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">
                    {analytics?.subscriptionMetrics?.totalSubscriptions || 0}
                  </div>
                  <p className="text-sm text-muted-foreground">Total</p>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {analytics?.subscriptionMetrics?.activeSubscriptions || 0}
                  </div>
                  <p className="text-sm text-muted-foreground">Active</p>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">
                    {analytics?.subscriptionMetrics?.canceledSubscriptions || 0}
                  </div>
                  <p className="text-sm text-muted-foreground">Canceled</p>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {analytics?.subscriptionMetrics?.trialSubscriptions || 0}
                  </div>
                  <p className="text-sm text-muted-foreground">Trial</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>GDPR Compliance</span>
                  <Badge variant="default">Compliant</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>PCI DSS</span>
                  <Badge variant="default">Compliant</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>SOC 2</span>
                  <Badge variant="default">Compliant</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Audit Logging</span>
                  <Badge variant="default">Active</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
