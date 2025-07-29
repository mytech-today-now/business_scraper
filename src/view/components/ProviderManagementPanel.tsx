'use client'

import React, { useState, useEffect } from 'react'
import {
  Activity,
  TrendingUp,
  Clock,
  DollarSign,
  AlertTriangle,
  CheckCircle,
  Settings,
  BarChart3,
  Zap,
  Shield,
  RefreshCw
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { logger } from '@/utils/logger'

/**
 * Provider performance metrics interface
 */
interface ProviderMetrics {
  name: string
  totalRequests: number
  successfulRequests: number
  failedRequests: number
  averageResponseTime: number
  averageResultCount: number
  qualityScore: number
  lastUsed: Date
  costPerRequest?: number
  quotaRemaining?: number
}

/**
 * Cost tracking interface
 */
interface CostTracker {
  providerName: string
  dailyCost: number
  monthlyCost: number
  dailyQuota: number
  monthlyQuota: number
  dailyUsage: number
  monthlyUsage: number
  costPerRequest: number
  lastReset: Date
}

/**
 * Quota limits configuration
 */
interface QuotaLimits {
  dailyRequestLimit?: number
  monthlyRequestLimit?: number
  dailyCostLimit?: number
  monthlyCostLimit?: number
  enableQuotaEnforcement: boolean
}

interface ProviderManagementPanelProps {
  onClose?: () => void
}

/**
 * Provider Management Panel Component
 * Displays provider performance metrics, cost tracking, and quota management
 */
export function ProviderManagementPanel({ onClose }: ProviderManagementPanelProps) {
  const [metrics, setMetrics] = useState<ProviderMetrics[]>([])
  const [costTrackers, setCostTrackers] = useState<CostTracker[]>([])
  const [quotaLimits, setQuotaLimits] = useState<QuotaLimits>({
    enableQuotaEnforcement: true,
    dailyRequestLimit: 1000,
    monthlyRequestLimit: 10000,
    dailyCostLimit: 50.0,
    monthlyCostLimit: 500.0
  })
  const [isLoading, setIsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'performance' | 'costs' | 'quotas'>('performance')

  useEffect(() => {
    loadProviderData()
  }, [])

  const loadProviderData = async () => {
    setIsLoading(true)
    try {
      // Get real data from the API
      const response = await fetch('/api/provider-management')
      const result = await response.json()

      if (result.success) {
        const { metrics, costTrackers, quotaLimits } = result.data

        logger.info('ProviderManagement', `Loaded ${metrics.length} provider metrics, ${costTrackers.length} cost trackers, and quota limits`)

        setMetrics(metrics)
        setCostTrackers(costTrackers)
        setQuotaLimits(quotaLimits)
      } else {
        throw new Error(result.error || 'Failed to load provider data')
      }
    } catch (error) {
      logger.error('ProviderManagement', 'Failed to load provider data', error)

      // Fallback to empty arrays if real data fails
      setMetrics([])
      setCostTrackers([])
    } finally {
      setIsLoading(false)
    }
  }

  const getSuccessRate = (metric: ProviderMetrics): number => {
    return metric.totalRequests > 0 ? (metric.successfulRequests / metric.totalRequests) * 100 : 0
  }

  const getQuotaUsagePercentage = (tracker: CostTracker, type: 'daily' | 'monthly'): number => {
    if (type === 'daily') {
      return tracker.dailyQuota > 0 ? (tracker.dailyUsage / tracker.dailyQuota) * 100 : 0
    }
    return tracker.monthlyQuota > 0 ? (tracker.monthlyUsage / tracker.monthlyQuota) * 100 : 0
  }

  const saveQuotaSettings = async () => {
    try {
      // Save quota settings via API
      const response = await fetch('/api/provider-management', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quotaLimits })
      })

      const result = await response.json()

      if (result.success) {
        logger.info('ProviderManagement', 'Quota settings saved successfully', quotaLimits)

        // Refresh data to show updated settings
        await loadProviderData()
      } else {
        throw new Error(result.error || 'Failed to save quota settings')
      }
    } catch (error) {
      logger.error('ProviderManagement', 'Failed to save quota settings', error)
    }
  }

  const getStatusColor = (percentage: number): string => {
    if (percentage >= 90) return 'text-red-600'
    if (percentage >= 75) return 'text-yellow-600'
    return 'text-green-600'
  }

  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 4
    }).format(amount)
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Activity className="h-6 w-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-semibold">Provider Management</h2>
              <p className="text-sm text-gray-600">Monitor performance, costs, and quotas</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Button variant="ghost" onClick={loadProviderData} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
            {onClose && (
              <Button variant="ghost" onClick={onClose}>
                ✕
              </Button>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="border-b px-6">
          <nav className="flex space-x-8">
            {[
              { id: 'performance', label: 'Performance', icon: BarChart3 },
              { id: 'costs', label: 'Costs', icon: DollarSign },
              { id: 'quotas', label: 'Quotas', icon: Shield }
            ].map(tab => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="p-6">
          {activeTab === 'performance' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {metrics.map(metric => (
                  <Card key={metric.name}>
                    <CardHeader>
                      <CardTitle className="flex items-center justify-between">
                        <span>{metric.name}</span>
                        <div className="flex items-center space-x-1">
                          <div className={`w-2 h-2 rounded-full ${
                            metric.qualityScore >= 0.8 ? 'bg-green-500' :
                            metric.qualityScore >= 0.6 ? 'bg-yellow-500' : 'bg-red-500'
                          }`} />
                          <span className="text-sm text-gray-500">
                            {(metric.qualityScore * 100).toFixed(0)}%
                          </span>
                        </div>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <div className="text-gray-500">Success Rate</div>
                          <div className="font-medium">{getSuccessRate(metric).toFixed(1)}%</div>
                        </div>
                        <div>
                          <div className="text-gray-500">Avg Response</div>
                          <div className="font-medium">{metric.averageResponseTime}ms</div>
                        </div>
                        <div>
                          <div className="text-gray-500">Total Requests</div>
                          <div className="font-medium">{metric.totalRequests}</div>
                        </div>
                        <div>
                          <div className="text-gray-500">Avg Results</div>
                          <div className="font-medium">{metric.averageResultCount.toFixed(1)}</div>
                        </div>
                      </div>
                      {metric.costPerRequest !== undefined && (
                        <div className="pt-2 border-t">
                          <div className="text-xs text-gray-500">Cost per request</div>
                          <div className="text-sm font-medium">{formatCurrency(metric.costPerRequest)}</div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'costs' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {costTrackers.map(tracker => (
                  <Card key={tracker.providerName}>
                    <CardHeader>
                      <CardTitle className="flex items-center justify-between">
                        <span>{tracker.providerName}</span>
                        <DollarSign className="h-5 w-5 text-green-600" />
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-sm text-gray-500">Daily Cost</div>
                          <div className="text-lg font-semibold">{formatCurrency(tracker.dailyCost)}</div>
                          <div className="text-xs text-gray-500">{tracker.dailyUsage} requests</div>
                        </div>
                        <div>
                          <div className="text-sm text-gray-500">Monthly Cost</div>
                          <div className="text-lg font-semibold">{formatCurrency(tracker.monthlyCost)}</div>
                          <div className="text-xs text-gray-500">{tracker.monthlyUsage} requests</div>
                        </div>
                      </div>
                      <div className="pt-2 border-t">
                        <div className="text-xs text-gray-500">Rate</div>
                        <div className="text-sm font-medium">{formatCurrency(tracker.costPerRequest)} per request</div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'quotas' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Quota Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="enableQuotas"
                      checked={quotaLimits.enableQuotaEnforcement}
                      onChange={(e) => setQuotaLimits(prev => ({
                        ...prev,
                        enableQuotaEnforcement: e.target.checked
                      }))}
                      className="rounded"
                    />
                    <label htmlFor="enableQuotas" className="text-sm font-medium">
                      Enable quota enforcement
                    </label>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Input
                      label="Daily Request Limit"
                      type="number"
                      value={quotaLimits.dailyRequestLimit || ''}
                      onChange={(e) => setQuotaLimits(prev => ({
                        ...prev,
                        dailyRequestLimit: parseInt(e.target.value) || undefined
                      }))}
                    />
                    <Input
                      label="Monthly Request Limit"
                      type="number"
                      value={quotaLimits.monthlyRequestLimit || ''}
                      onChange={(e) => setQuotaLimits(prev => ({
                        ...prev,
                        monthlyRequestLimit: parseInt(e.target.value) || undefined
                      }))}
                    />
                    <Input
                      label="Daily Cost Limit ($)"
                      type="number"
                      step="0.01"
                      value={quotaLimits.dailyCostLimit || ''}
                      onChange={(e) => setQuotaLimits(prev => ({
                        ...prev,
                        dailyCostLimit: parseFloat(e.target.value) || undefined
                      }))}
                    />
                    <Input
                      label="Monthly Cost Limit ($)"
                      type="number"
                      step="0.01"
                      value={quotaLimits.monthlyCostLimit || ''}
                      onChange={(e) => setQuotaLimits(prev => ({
                        ...prev,
                        monthlyCostLimit: parseFloat(e.target.value) || undefined
                      }))}
                    />
                  </div>

                  <div className="pt-4 border-t">
                    <Button onClick={saveQuotaSettings} className="w-full">
                      <Settings className="h-4 w-4 mr-2" />
                      Save Quota Settings
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Current Usage */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {costTrackers.map(tracker => (
                  <Card key={tracker.providerName}>
                    <CardHeader>
                      <CardTitle>{tracker.providerName} Usage</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>Daily Usage</span>
                          <span className={getStatusColor(getQuotaUsagePercentage(tracker, 'daily'))}>
                            {tracker.dailyUsage} / {tracker.dailyQuota}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              getQuotaUsagePercentage(tracker, 'daily') >= 90 ? 'bg-red-500' :
                              getQuotaUsagePercentage(tracker, 'daily') >= 75 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.min(getQuotaUsagePercentage(tracker, 'daily'), 100)}%` }}
                          />
                        </div>
                      </div>
                      
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>Monthly Usage</span>
                          <span className={getStatusColor(getQuotaUsagePercentage(tracker, 'monthly'))}>
                            {tracker.monthlyUsage} / {tracker.monthlyQuota}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              getQuotaUsagePercentage(tracker, 'monthly') >= 90 ? 'bg-red-500' :
                              getQuotaUsagePercentage(tracker, 'monthly') >= 75 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.min(getQuotaUsagePercentage(tracker, 'monthly'), 100)}%` }}
                          />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t px-6 py-4 flex justify-end space-x-3">
          <Button variant="outline" onClick={loadProviderData}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh Data
          </Button>
          {onClose && (
            <Button onClick={onClose}>
              Close
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
