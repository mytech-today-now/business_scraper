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
  RefreshCw,
  Search
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

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
  const [isTesting, setIsTesting] = useState(false)
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

  const handleRefresh = async () => {
    try {
      await loadProviderData()
      toast.success('Provider data refreshed successfully!', {
        duration: 3000,
        icon: '🔄'
      })
    } catch (error) {
      toast.error('Failed to refresh provider data', {
        duration: 4000,
        icon: '❌'
      })
    }
  }

  const runSearchProviderTest = async () => {
    setIsTesting(true)

    try {
      // Show loading toast
      const loadingToast = toast.loading('Testing search providers (Google, Bing, DuckDuckGo)...')

      logger.info('ProviderManagement', 'Starting search provider test with IT services in 60010')

      // Create AbortController for timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => {
        controller.abort()
        logger.warn('ProviderManagement', 'Search provider test timed out after 30 seconds')
      }, 30000) // 30 second timeout for search-only test

      // Test search providers directly (no scraping)
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          provider: 'google', // Start with just Google for faster testing
          query: 'IT consulting services',
          location: '60010',
          maxResults: 5,
          zipRadius: 25,
          accreditedOnly: false
        }),
        signal: controller.signal
      })

      // Clear timeout if request completes
      clearTimeout(timeoutId)

      logger.info('ProviderManagement', 'Search provider test API call completed, parsing response...')

      const result = await response.json()

      // Dismiss loading toast
      toast.dismiss(loadingToast)

      logger.info('ProviderManagement', 'Search provider test response received', {
        success: result.success,
        hasResults: !!result.count
      })

      if (result.success) {
        logger.info('ProviderManagement', `Search provider test completed successfully. Found ${result.count} results.`, {
          query: result.query,
          location: result.location,
          resultCount: result.count,
          provider: 'google'
        })

        // Show success toast
        toast.success(`Search provider test completed! Found ${result.count} results. Check console for details.`, {
          duration: 6000,
          icon: '🔍'
        })

        // Refresh provider data to show updated usage
        await loadProviderData()
      } else {
        throw new Error(result.error || 'Search provider test failed')
      }
    } catch (error) {
      logger.error('ProviderManagement', 'Search provider test failed', error)

      // Show specific error message based on error type
      let errorMessage = 'Search provider test failed. Check console for details.'

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          errorMessage = 'Search provider test timed out after 30 seconds. This may indicate API issues.'
          logger.warn('ProviderManagement', 'Search provider test aborted due to timeout')
        } else if (error.message.includes('fetch')) {
          errorMessage = 'Network error during search provider test. Check your connection.'
        }
      }

      toast.error(errorMessage, {
        duration: 6000,
        icon: '❌'
      })
    } finally {
      setIsTesting(false)
    }
  }

  const runProviderTest = async () => {
    setIsTesting(true)

    try {
      // Show loading toast
      const loadingToast = toast.loading('Running provider test with real search requests...')

      logger.info('ProviderManagement', 'Starting provider test with IT Consulting search in 60010')

      // Create AbortController for timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => {
        controller.abort()
        logger.warn('ProviderManagement', 'Provider test timed out after 60 seconds')
      }, 60000) // 60 second timeout

      // Make comprehensive search request with limited results (3-5 per provider)
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          provider: 'comprehensive',
          query: 'IT help near me',
          location: '60010',
          maxResults: 12, // This will be divided among providers (3-4 each)
          zipRadius: 25,
          accreditedOnly: false
        }),
        signal: controller.signal
      })

      // Clear timeout if request completes
      clearTimeout(timeoutId)

      logger.info('ProviderManagement', 'Provider test API call completed, parsing response...')

      const result = await response.json()

      // Dismiss loading toast
      toast.dismiss(loadingToast)

      logger.info('ProviderManagement', 'Provider test response received', {
        success: result.success,
        hasResults: !!result.count
      })

      if (result.success) {
        logger.info('ProviderManagement', `Provider test completed successfully. Found ${result.count} results.`, {
          query: result.query,
          location: result.location,
          resultCount: result.count,
          providerStats: result.providerStats
        })

        // Show success toast
        toast.success(`Provider test completed! Found ${result.count} results. Check console for details.`, {
          duration: 6000,
          icon: '🧪'
        })

        // Refresh provider data to show updated usage
        await loadProviderData()
      } else {
        throw new Error(result.error || 'Provider test failed')
      }
    } catch (error) {
      logger.error('ProviderManagement', 'Provider test failed', error)

      // Show specific error message based on error type
      let errorMessage = 'Provider test failed. Check console for details.'

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          errorMessage = 'Provider test timed out after 60 seconds. This may indicate API issues.'
          logger.warn('ProviderManagement', 'Provider test aborted due to timeout')
        } else if (error.message.includes('fetch')) {
          errorMessage = 'Network error during provider test. Check your connection.'
        }
      }

      toast.error(errorMessage, {
        duration: 6000,
        icon: '❌'
      })
    } finally {
      setIsTesting(false)
    }
  }

  const saveQuotaSettings = async () => {
    try {
      // Show loading toast
      const loadingToast = toast.loading('Saving quota settings...')

      // Save quota settings via API
      const response = await fetch('/api/provider-management', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ quotaLimits })
      })

      const result = await response.json()

      // Dismiss loading toast
      toast.dismiss(loadingToast)

      if (result.success) {
        logger.info('ProviderManagement', 'Quota settings saved successfully', quotaLimits)

        // Show success toast
        toast.success('Quota settings saved successfully!', {
          duration: 4000,
          icon: '✅'
        })

        // Refresh data to show updated settings
        await loadProviderData()
      } else {
        throw new Error(result.error || 'Failed to save quota settings')
      }
    } catch (error) {
      logger.error('ProviderManagement', 'Failed to save quota settings', error)

      // Show error toast
      toast.error('Failed to save quota settings. Please try again.', {
        duration: 5000,
        icon: '❌'
      })
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
            <Button variant="ghost" onClick={handleRefresh} disabled={isLoading}>
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

              {/* Provider Test Section */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Zap className="h-5 w-5 text-blue-600" />
                    <span>Provider Testing</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <p className="text-sm text-gray-600">
                      Test search providers to verify functionality and update usage metrics.
                    </p>

                    {/* Quick Search Test */}
                    <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg border border-blue-200">
                      <div className="font-medium mb-2 text-blue-800 dark:text-blue-200">Quick Search Test (Recommended)</div>
                      <ul className="space-y-1 text-sm text-blue-700 dark:text-blue-300">
                        <li>• <strong>Query:</strong> "IT consulting services"</li>
                        <li>• <strong>Location:</strong> 60010 (ZIP code)</li>
                        <li>• <strong>Provider:</strong> Google Search API</li>
                        <li>• <strong>Timeout:</strong> 30 seconds</li>
                      </ul>
                      <Button
                        onClick={runSearchProviderTest}
                        disabled={isTesting || isLoading}
                        className="w-full mt-3"
                        variant="default"
                      >
                        {isTesting ? (
                          <>
                            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                            Testing Search Providers...
                          </>
                        ) : (
                          <>
                            <Search className="h-4 w-4 mr-2" />
                            Quick Search Test
                          </>
                        )}
                      </Button>
                    </div>

                    {/* Full Provider Test */}
                    <div className="bg-amber-50 dark:bg-amber-900/20 p-3 rounded-lg border border-amber-200">
                      <div className="font-medium mb-2 text-amber-800 dark:text-amber-200">Full Provider Test (May Take Longer)</div>
                      <ul className="space-y-1 text-sm text-amber-700 dark:text-amber-300">
                        <li>• <strong>Query:</strong> "IT help near me"</li>
                        <li>• <strong>Location:</strong> 60010 (ZIP code)</li>
                        <li>• <strong>Providers:</strong> All (Google, Bing, DuckDuckGo + Scraping)</li>
                        <li>• <strong>Timeout:</strong> 60 seconds</li>
                        <li>• <strong>Note:</strong> May encounter CAPTCHA delays</li>
                      </ul>
                      <Button
                        onClick={runProviderTest}
                        disabled={isTesting || isLoading}
                        className="w-full mt-3"
                        variant="outline"
                      >
                        {isTesting ? (
                          <>
                            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                            Running Full Test...
                          </>
                        ) : (
                          <>
                            <Zap className="h-4 w-4 mr-2" />
                            Full Provider Test
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
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
          <Button variant="outline" onClick={handleRefresh}>
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
