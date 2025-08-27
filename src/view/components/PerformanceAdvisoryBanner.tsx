'use client'

import React from 'react'
import { AlertTriangle, X, Zap, Settings, ChevronRight } from 'lucide-react'
import { usePerformance } from '@/controller/PerformanceContext'
import { Button } from './ui/Button'
import { Card } from './ui/Card'
import { clsx } from 'clsx'

/**
 * Performance Advisory Banner Props
 */
interface PerformanceAdvisoryBannerProps {
  /** Additional CSS classes */
  className?: string
  /** Show settings button */
  showSettings?: boolean
  /** Callback when settings is clicked */
  onSettingsClick?: () => void
}

/**
 * Performance Advisory Banner Component
 * Displays contextual performance recommendations and optimization options
 */
export function PerformanceAdvisoryBanner({
  className,
  showSettings = true,
  onSettingsClick,
}: PerformanceAdvisoryBannerProps) {
  const {
    mode,
    metrics,
    showAdvisoryBanner,
    showPaginationPrompt,
    dismissAdvisoryBanner,
    acceptPagination,
    declinePagination,
    setMode,
  } = usePerformance()

  // Don't render if no advisory needed
  if (!showAdvisoryBanner && !showPaginationPrompt) {
    return null
  }

  /**
   * Get banner configuration based on current state
   */
  const getBannerConfig = () => {
    const { datasetSize, performanceScore } = metrics

    if (showPaginationPrompt) {
      return {
        type: 'warning' as const,
        icon: AlertTriangle,
        title: 'Large Dataset Detected',
        message: `You have ${datasetSize.toLocaleString()} results. For better performance, we recommend enabling pagination mode.`,
        actions: [
          {
            label: 'Enable Pagination',
            onClick: acceptPagination,
            variant: 'primary' as const,
          },
          {
            label: 'Continue in Expanded Mode',
            onClick: declinePagination,
            variant: 'secondary' as const,
          },
        ],
      }
    }

    if (showAdvisoryBanner) {
      const isHighMemory = metrics.memoryUsage > 300 * 1024 * 1024 // 300MB

      return {
        type: isHighMemory ? 'warning' : ('info' as const),
        icon: isHighMemory ? AlertTriangle : Zap,
        title: isHighMemory ? 'Performance Advisory' : 'Optimization Available',
        message: isHighMemory
          ? `High memory usage detected (${Math.round(metrics.memoryUsage / 1024 / 1024)}MB). Consider enabling pagination for better performance.`
          : `You have ${datasetSize.toLocaleString()} results. Enable pagination or continue in expanded mode for optimal browsing.`,
        actions: [
          {
            label: 'Enable Pagination',
            onClick: () => setMode('pagination'),
            variant: 'primary' as const,
          },
          {
            label: 'Dismiss',
            onClick: dismissAdvisoryBanner,
            variant: 'secondary' as const,
          },
        ],
      }
    }

    return null
  }

  const config = getBannerConfig()
  if (!config) return null

  const { type, icon: Icon, title, message, actions } = config

  return (
    <Card
      className={clsx(
        'border-l-4 mb-4 transition-all duration-300 ease-in-out',
        {
          'border-l-blue-500 bg-blue-50 dark:bg-blue-950/20': type === 'info',
          'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-950/20': type === 'warning',
          'border-l-red-500 bg-red-50 dark:bg-red-950/20': type === 'error',
        },
        className
      )}
    >
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div
            className={clsx('flex-shrink-0 p-1 rounded-full', {
              'text-blue-600 bg-blue-100 dark:text-blue-400 dark:bg-blue-900/30': type === 'info',
              'text-yellow-600 bg-yellow-100 dark:text-yellow-400 dark:bg-yellow-900/30':
                type === 'warning',
              'text-red-600 bg-red-100 dark:text-red-400 dark:bg-red-900/30': type === 'error',
            })}
          >
            <Icon className="h-5 w-5" />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-2">
              <h3
                className={clsx('text-sm font-semibold', {
                  'text-blue-800 dark:text-blue-200': type === 'info',
                  'text-yellow-800 dark:text-yellow-200': type === 'warning',
                  'text-red-800 dark:text-red-200': type === 'error',
                })}
              >
                {title}
              </h3>

              {/* Performance Score Badge */}
              {metrics.performanceScore < 80 && (
                <div
                  className={clsx('px-2 py-1 rounded-full text-xs font-medium', {
                    'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300':
                      metrics.performanceScore >= 60,
                    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300':
                      metrics.performanceScore >= 40,
                    'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300':
                      metrics.performanceScore < 40,
                  })}
                >
                  Performance: {metrics.performanceScore}%
                </div>
              )}
            </div>

            <p
              className={clsx('text-sm mb-3', {
                'text-blue-700 dark:text-blue-300': type === 'info',
                'text-yellow-700 dark:text-yellow-300': type === 'warning',
                'text-red-700 dark:text-red-300': type === 'error',
              })}
            >
              {message}
            </p>

            {/* Performance Metrics */}
            <div className="flex items-center gap-4 mb-3 text-xs text-muted-foreground">
              <span>Dataset: {metrics.datasetSize.toLocaleString()} items</span>
              <span>Memory: {Math.round(metrics.memoryUsage / 1024 / 1024)}MB</span>
              <span>Mode: {mode}</span>
              {metrics.averageRenderTime > 0 && <span>Render: {metrics.averageRenderTime}ms</span>}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 flex-wrap">
              {actions.map((action, index) => (
                <Button
                  key={index}
                  size="sm"
                  variant={action.variant}
                  onClick={action.onClick}
                  className="text-xs"
                >
                  {action.label}
                  {action.variant === 'primary' && <ChevronRight className="ml-1 h-3 w-3" />}
                </Button>
              ))}

              {/* Settings Button */}
              {showSettings && onSettingsClick && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={onSettingsClick}
                  className="text-xs ml-auto"
                  title="Performance Settings"
                >
                  <Settings className="h-3 w-3 mr-1" />
                  Settings
                </Button>
              )}
            </div>
          </div>

          {/* Close Button */}
          <Button
            size="sm"
            variant="ghost"
            onClick={dismissAdvisoryBanner}
            className="flex-shrink-0 p-1 h-auto"
            title="Dismiss"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </Card>
  )
}

/**
 * Performance Mode Prompt Component
 * Specialized prompt for pagination mode switching
 */
export function PerformanceModePrompt() {
  const { metrics, showPaginationPrompt, acceptPagination, declinePagination } = usePerformance()

  if (!showPaginationPrompt) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <Card className="max-w-md w-full">
        <div className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-full">
              <Zap className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">Optimize Performance?</h3>
              <p className="text-sm text-muted-foreground">
                Large dataset detected ({metrics.datasetSize.toLocaleString()} results)
              </p>
            </div>
          </div>

          <p className="text-sm mb-6">
            For better browsing experience with large datasets, we recommend enabling pagination
            mode. This will improve page responsiveness and reduce memory usage.
          </p>

          <div className="flex gap-3">
            <Button onClick={acceptPagination} className="flex-1">
              <Zap className="h-4 w-4 mr-2" />
              Enable Pagination
            </Button>
            <Button variant="outline" onClick={declinePagination} className="flex-1">
              Continue Expanded
            </Button>
          </div>

          <p className="text-xs text-muted-foreground mt-3 text-center">
            You can change this setting anytime in Performance Settings
          </p>
        </div>
      </Card>
    </div>
  )
}
