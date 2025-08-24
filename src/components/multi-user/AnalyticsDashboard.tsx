/**
 * Analytics Dashboard Component
 * Provides comprehensive analytics and metrics visualization for multi-user collaboration
 */

'use client'

import React, { useState, useEffect } from 'react'
import { User, DashboardMetrics, PerformanceMetrics, DataQualityMetrics } from '@/types/multi-user'

interface AnalyticsDashboardProps {
  currentUser: User
  workspaceId?: string
  teamId?: string
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  currentUser,
  workspaceId,
  teamId
}) => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null)
  const [realtimeMetrics, setRealtimeMetrics] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedPeriod, setSelectedPeriod] = useState<'day' | 'week' | 'month'>('week')
  const [autoRefresh, setAutoRefresh] = useState(true)

  useEffect(() => {
    fetchMetrics()
    
    if (autoRefresh) {
      const interval = setInterval(fetchMetrics, 30000) // Refresh every 30 seconds
      return () => clearInterval(interval)
    }
  }, [selectedPeriod, workspaceId, teamId, autoRefresh])

  useEffect(() => {
    if (autoRefresh) {
      fetchRealtimeMetrics()
      const interval = setInterval(fetchRealtimeMetrics, 5000) // Refresh every 5 seconds
      return () => clearInterval(interval)
    }
  }, [workspaceId, autoRefresh])

  const fetchMetrics = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams({
        period: selectedPeriod,
        ...(workspaceId && { workspaceId }),
        ...(teamId && { teamId })
      })

      const response = await fetch(`/api/analytics?${params}`)
      const data = await response.json()

      if (data.success) {
        setMetrics(data.data)
      } else {
        setError(data.error || 'Failed to fetch metrics')
      }
    } catch (err) {
      setError('Failed to fetch metrics')
    } finally {
      setLoading(false)
    }
  }

  const fetchRealtimeMetrics = async () => {
    try {
      const params = new URLSearchParams({
        ...(workspaceId && { workspaceId })
      })

      const response = await fetch(`/api/analytics/realtime?${params}`)
      const data = await response.json()

      if (data.success) {
        setRealtimeMetrics(data.data)
      }
    } catch (err) {
      console.error('Failed to fetch realtime metrics:', err)
    }
  }

  const canViewAnalytics = currentUser.roles?.some(role => 
    role.role.permissions.includes('analytics.view')
  )

  if (!canViewAnalytics) {
    return (
      <div className="p-6 bg-red-50 border border-red-200 rounded-lg">
        <h3 className="text-lg font-semibold text-red-800 mb-2">Access Denied</h3>
        <p className="text-red-600">You don't have permission to view analytics.</p>
      </div>
    )
  }

  if (loading && !metrics) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-24 bg-gray-200 rounded"></div>
            ))}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="h-64 bg-gray-200 rounded"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Analytics Dashboard</h2>
          <p className="text-gray-600">
            {workspaceId ? 'Workspace Analytics' : teamId ? 'Team Analytics' : 'Global Analytics'}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <label className="text-sm text-gray-600">Auto-refresh:</label>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
          </div>
          <select
            value={selectedPeriod}
            onChange={(e) => setSelectedPeriod(e.target.value as any)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="day">Last 24 Hours</option>
            <option value="week">Last Week</option>
            <option value="month">Last Month</option>
          </select>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-600">{error}</p>
          <button
            onClick={() => setError(null)}
            className="text-red-800 hover:text-red-900 ml-2"
          >
            ×
          </button>
        </div>
      )}

      {/* Real-time Metrics */}
      {realtimeMetrics && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-blue-800 mb-2">Live Status</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {realtimeMetrics.activeUsers}
              </div>
              <div className="text-sm text-blue-700">Active Users</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {realtimeMetrics.activeSessions}
              </div>
              <div className="text-sm text-blue-700">Active Sessions</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {realtimeMetrics.collaboration?.activeCollaborators || 0}
              </div>
              <div className="text-sm text-blue-700">Collaborators</div>
            </div>
          </div>
        </div>
      )}

      {/* Overview Cards */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-600">Total Users</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {metrics.overview.totalUsers}
                </p>
                <p className="text-sm text-green-600">
                  {metrics.overview.activeUsers} active
                </p>
              </div>
              <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                <span className="text-blue-600">👥</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-600">Campaigns</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {metrics.overview.totalCampaigns}
                </p>
                <p className="text-sm text-gray-500">
                  {metrics.overview.totalBusinesses} businesses
                </p>
              </div>
              <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                <span className="text-green-600">📊</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-600">Success Rate</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {metrics.performance.successRate.toFixed(1)}%
                </p>
                <p className="text-sm text-gray-500">
                  {metrics.performance.errorRate.toFixed(1)}% errors
                </p>
              </div>
              <div className="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center">
                <span className="text-yellow-600">⚡</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-600">Data Quality</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {metrics.dataQuality.validationRate.toFixed(1)}%
                </p>
                <p className="text-sm text-gray-500">
                  {metrics.dataQuality.enrichmentRate.toFixed(1)}% enriched
                </p>
              </div>
              <div className="w-8 h-8 bg-purple-100 rounded-full flex items-center justify-center">
                <span className="text-purple-600">✨</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Performance Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance Metrics</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Avg Scraping Time</span>
                <span className="text-sm font-medium">
                  {metrics.performance.avgScrapingTime.toFixed(2)}s
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Request Throughput</span>
                <span className="text-sm font-medium">
                  {metrics.performance.requestThroughput.toFixed(1)}/min
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Total Actions</span>
                <span className="text-sm font-medium">
                  {metrics.performance.totalActions}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Quality</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Valid Records</span>
                <span className="text-sm font-medium">
                  {metrics.dataQuality.validRecords} / {metrics.dataQuality.totalRecords}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">High Confidence</span>
                <span className="text-sm font-medium">
                  {metrics.dataQuality.highConfidence}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Enrichment Rate</span>
                <span className="text-sm font-medium">
                  {metrics.dataQuality.enrichmentRate.toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* User Activity */}
      {metrics && metrics.userActivity.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Contributors</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead>
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Campaigns
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Validated
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Sessions
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Login
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {metrics.userActivity.slice(0, 5).map(user => (
                  <tr key={user.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {user.firstName} {user.lastName}
                      </div>
                      <div className="text-sm text-gray-500">
                        {user.username}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.campaignsCreated}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.businessesValidated}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.scrapingSessionsRun}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {user.lastLoginAt 
                        ? new Date(user.lastLoginAt).toLocaleDateString()
                        : 'Never'
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Team Performance */}
      {metrics && metrics.teamPerformance.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Team Performance</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {metrics.teamPerformance.slice(0, 6).map(team => (
              <div key={team.id} className="border border-gray-200 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-2">{team.name}</h4>
                <div className="space-y-1 text-sm text-gray-600">
                  <div className="flex justify-between">
                    <span>Members:</span>
                    <span>{team.memberCount}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Campaigns:</span>
                    <span>{team.totalCampaigns}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Businesses:</span>
                    <span>{team.totalBusinesses}</span>
                  </div>
                  {team.avgConfidenceScore && (
                    <div className="flex justify-between">
                      <span>Avg Quality:</span>
                      <span>{(team.avgConfidenceScore * 100).toFixed(1)}%</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Activity */}
      {realtimeMetrics && realtimeMetrics.recentActivity && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
          <div className="space-y-2">
            {realtimeMetrics.recentActivity.length === 0 ? (
              <p className="text-sm text-gray-500">No recent activity</p>
            ) : (
              realtimeMetrics.recentActivity.map((activity: any, index: number) => (
                <div key={index} className="flex items-center space-x-3 text-sm">
                  <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                  <span className="text-gray-600">
                    <span className="font-medium">{activity.user}</span>
                    <span className="ml-1">{activity.action}</span>
                  </span>
                  <span className="text-gray-400 ml-auto">
                    {new Date(activity.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
