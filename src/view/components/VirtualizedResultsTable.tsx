'use client'

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { FixedSizeList as List } from 'react-window'
import InfiniteLoader from 'react-window-infinite-loader'
import AutoSizer from 'react-virtualized-auto-sizer'
import {
  Download,
  Edit,
  Trash2,
  ExternalLink,
  Search,
  Filter,
  SortAsc,
  SortDesc,
  Eye,
  EyeOff,
  Star,
  Award,
  Shield,
  Globe,
  Activity,
  Monitor,
} from 'lucide-react'
import { BusinessRecord } from '@/types/business'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import {
  formatBusinessName,
  formatAddress,
  formatPhoneNumber,
  formatDate,
  formatUrl,
} from '@/utils/formatters'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'
import {
  useVirtualScrolling,
  VirtualScrollingFilters,
  VirtualScrollingSortConfig,
  calculateAILeadScore,
} from '@/lib/virtualScrollingService'
import { AILeadScore, AIBadge } from '@/lib/aiLeadScoringService'
import { logger } from '@/utils/logger'
import {
  performanceMonitoringService,
  PerformanceMetrics,
  ScrollMetrics,
} from '@/lib/performanceMonitoringService'

interface VirtualizedResultsTableProps {
  onEdit?: (business: BusinessRecord) => void
  onDelete?: (businessId: string) => void
  onExport?: (businesses: BusinessRecord[]) => void
  isLoading?: boolean
  isExporting?: boolean
  height?: number
  initialFilters?: VirtualScrollingFilters
  initialSort?: VirtualScrollingSortConfig
}

interface VirtualTableItem {
  business?: BusinessRecord
  isLoading?: boolean
  aiScore?: AILeadScore
}

const ROW_HEIGHT = 80
const HEADER_HEIGHT = 60
const LOAD_MORE_THRESHOLD = 5

/**
 * VirtualizedResultsTable component for high-performance rendering of large datasets
 */
export function VirtualizedResultsTable({
  onEdit,
  onDelete,
  onExport,
  isLoading = false,
  isExporting = false,
  height = 600,
  initialFilters,
  initialSort,
}: VirtualizedResultsTableProps): JSX.Element {
  // Virtual scrolling service
  const { fetchBusinesses, prefetchNextPage, clearCache } = useVirtualScrolling()

  // State management
  const [items, setItems] = useState<VirtualTableItem[]>([])
  const [hasNextPage, setHasNextPage] = useState(true)
  const [isLoadingMore, setIsLoadingMore] = useState(false)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [totalCount, setTotalCount] = useState(0)
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set())

  // Filtering and sorting
  const [filters, setFilters] = useState<VirtualScrollingFilters>(initialFilters || {})
  const [sortConfig, setSortConfig] = useState<VirtualScrollingSortConfig>(
    initialSort || { field: 'scrapedAt', order: 'desc' }
  )
  const [searchQuery, setSearchQuery] = useState('')

  // Column visibility
  const [visibleColumns, setVisibleColumns] = useState({
    businessName: true,
    industry: true,
    contact: true,
    location: true,
    quality: true,
    aiScore: true,
    actions: true,
  })

  // Performance monitoring state
  const [performanceMetrics, setPerformanceMetrics] = useState<PerformanceMetrics[]>([])
  const [scrollMetrics, setScrollMetrics] = useState<ScrollMetrics>({
    position: 0,
    velocity: 0,
    direction: 'none',
    timestamp: Date.now(),
  })
  const [showPerformancePanel, setShowPerformancePanel] = useState(
    process.env.NODE_ENV === 'development'
  )
  const [scrollPosition, setScrollPosition] = useState(0)

  // Refs
  const listRef = useRef<List>(null)
  const infiniteLoaderRef = useRef<InfiniteLoader>(null)
  const performanceStartTime = useRef<number>(0)
  const lastScrollTime = useRef<number>(0)
  const lastScrollPosition = useRef<number>(0)
  const frameRateCounter = useRef<number>(0)
  const frameRateTimer = useRef<number>(0)

  /**
   * Performance monitoring setup
   */
  useEffect(() => {
    const componentName = 'VirtualizedResultsTable'

    // Start frame rate monitoring using the service
    performanceMonitoringService.startFrameRateMonitoring(componentName)

    return () => {
      // Cleanup frame rate monitoring
      performanceMonitoringService.stopFrameRateMonitoring(componentName)
    }
  }, [])

  /**
   * Record performance metrics using the monitoring service
   */
  const recordPerformanceMetric = useCallback(
    (operation: string = 'render', additionalData: Partial<PerformanceMetrics> = {}) => {
      const renderTime = performance.now() - performanceStartTime.current
      const memoryInfo = (performance as any).memory
      const componentName = 'VirtualizedResultsTable'

      const metric: PerformanceMetrics = {
        renderTime,
        scrollPosition,
        visibleItemsCount: Math.min(items.length, Math.ceil(height / ROW_HEIGHT)),
        totalItemsCount: totalCount,
        memoryUsage: memoryInfo?.usedJSHeapSize,
        timestamp: Date.now(),
        componentName,
        operation,
        ...additionalData,
      }

      // Record metric using the service
      performanceMonitoringService.recordMetric(metric)

      // Update local state for UI display
      setPerformanceMetrics(prev => {
        const newMetrics = [...prev, metric]
        return newMetrics.slice(-100)
      })
    },
    [scrollPosition, items.length, height, totalCount]
  )

  /**
   * Load initial data
   */
  useEffect(() => {
    performanceStartTime.current = performance.now()
    loadInitialData()
  }, [filters, sortConfig])

  /**
   * Load initial data and reset state
   */
  const loadInitialData = useCallback(async () => {
    try {
      setIsLoadingMore(true)
      setItems([])
      setNextCursor(null)
      setHasNextPage(true)

      const result = await fetchBusinesses(undefined, 100, sortConfig, filters)

      const itemsWithAI = result.data.map(business => ({
        business,
        aiScore: calculateAILeadScore(business),
      }))

      setItems(itemsWithAI)
      setNextCursor(result.pagination.nextCursor)
      setHasNextPage(result.pagination.hasMore)
      setTotalCount(result.pagination.totalCount)

      // Record performance metrics
      recordPerformanceMetric('loadInitialData', {
        scrollVelocity: 0,
      })

      // Prefetch next page
      if (result.pagination.nextCursor) {
        prefetchNextPage(result.pagination.nextCursor, 100, sortConfig, filters)
      }
    } catch (error) {
      console.error('Failed to load initial data:', error)
      toast.error('Failed to load business data')
    } finally {
      setIsLoadingMore(false)
    }
  }, [fetchBusinesses, prefetchNextPage, sortConfig, filters, recordPerformanceMetric])

  /**
   * Load more items for infinite scrolling
   */
  const loadMoreItems = useCallback(async () => {
    if (!hasNextPage || isLoadingMore || !nextCursor) return

    try {
      setIsLoadingMore(true)
      performanceStartTime.current = performance.now()

      const result = await fetchBusinesses(nextCursor, 100, sortConfig, filters)

      const newItemsWithAI = result.data.map(business => ({
        business,
        aiScore: calculateAILeadScore(business),
      }))

      setItems(prev => [...prev, ...newItemsWithAI])
      setNextCursor(result.pagination.nextCursor)
      setHasNextPage(result.pagination.hasMore)

      // Record performance metrics for loading more items
      recordPerformanceMetric('loadMoreItems', {
        scrollVelocity: scrollMetrics.velocity,
      })

      // Prefetch next page
      if (result.pagination.nextCursor) {
        prefetchNextPage(result.pagination.nextCursor, 100, sortConfig, filters)
      }
    } catch (error) {
      console.error('Failed to load more items:', error)
      toast.error('Failed to load more data')
    } finally {
      setIsLoadingMore(false)
    }
  }, [
    fetchBusinesses,
    prefetchNextPage,
    hasNextPage,
    isLoadingMore,
    nextCursor,
    sortConfig,
    filters,
    recordPerformanceMetric,
    scrollMetrics.velocity,
  ])

  /**
   * Check if item is loaded
   */
  const isItemLoaded = useCallback(
    (index: number) => {
      return !!items[index]?.business
    },
    [items]
  )

  /**
   * Enhanced scroll handling with performance monitoring
   */
  const handleScroll = useCallback(({ scrollTop }: { scrollTop: number }) => {
    // Increment frame counter using the service
    performanceMonitoringService.incrementFrameCount('VirtualizedResultsTable')

    const now = Date.now()
    const timeDelta = now - lastScrollTime.current
    const positionDelta = scrollTop - lastScrollPosition.current

    if (timeDelta > 0) {
      const velocity = Math.abs(positionDelta) / timeDelta
      const direction = positionDelta > 0 ? 'down' : positionDelta < 0 ? 'up' : 'none'

      setScrollMetrics({
        position: scrollTop,
        velocity,
        direction,
        timestamp: now,
      })

      setScrollPosition(scrollTop)
    }

    lastScrollTime.current = now
    lastScrollPosition.current = scrollTop
  }, [])

  /**
   * Handle search
   */
  const handleSearch = useCallback((query: string) => {
    performanceStartTime.current = performance.now()
    setSearchQuery(query)
    setFilters(prev => ({ ...prev, search: query || undefined }))
  }, [])

  /**
   * Handle sorting
   */
  const handleSort = useCallback((field: VirtualScrollingSortConfig['field']) => {
    setSortConfig(prev => ({
      field,
      order: prev.field === field && prev.order === 'asc' ? 'desc' : 'asc',
    }))
  }, [])

  /**
   * Handle row selection
   */
  const handleRowSelect = useCallback((businessId: string, selected: boolean) => {
    setSelectedRows(prev => {
      const newSet = new Set(prev)
      if (selected) {
        newSet.add(businessId)
      } else {
        newSet.delete(businessId)
      }
      return newSet
    })
  }, [])

  /**
   * Handle select all
   */
  const handleSelectAll = useCallback(
    (selected: boolean) => {
      if (selected) {
        const allIds = items.map(item => item.business?.id).filter(Boolean) as string[]
        setSelectedRows(new Set(allIds))
      } else {
        setSelectedRows(new Set())
      }
    },
    [items]
  )

  /**
   * Export selected or all businesses using virtualized export with performance tracking
   */
  const handleExport = useCallback(async () => {
    try {
      performanceStartTime.current = performance.now()

      // Start virtualized export
      const exportOptions = {
        format: 'csv' as const,
        includeAIScores: true,
        includeHeaders: true,
        filters: filters,
        sorting: sortConfig,
        batchSize: 1000,
      }

      const response = await fetch('/api/export/virtualized', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(exportOptions),
      })

      if (!response.ok) {
        throw new Error('Failed to start export')
      }

      const result = await response.json()

      // Record export performance
      recordPerformanceMetric('export', {
        scrollVelocity: 0,
      })

      if (result.success) {
        toast.success(`Export started! Estimated completion: ${result.estimatedDuration}s`)

        // Start polling for progress
        pollExportProgress(result.exportId)
      } else {
        throw new Error(result.error || 'Export failed')
      }
    } catch (error) {
      console.error('Export failed:', error)
      toast.error('Failed to start export')
    }
  }, [filters, sortConfig])

  /**
   * Poll export progress
   */
  const pollExportProgress = useCallback(async (exportId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/export/virtualized/${exportId}/progress`)

        if (!response.ok) {
          clearInterval(pollInterval)
          return
        }

        const result = await response.json()

        if (result.success) {
          const progress = result.progress

          if (progress.status === 'completed') {
            clearInterval(pollInterval)
            toast.success('Export completed! Download will start automatically.')
            // Here you would trigger the download
          } else if (progress.status === 'error') {
            clearInterval(pollInterval)
            toast.error(`Export failed: ${progress.errorMessage}`)
          } else {
            // Update progress UI if needed
            console.log(`Export progress: ${progress.percentage}%`)
          }
        }
      } catch (error) {
        console.error('Failed to check export progress:', error)
        clearInterval(pollInterval)
      }
    }, 2000) // Poll every 2 seconds

    // Clear interval after 10 minutes to prevent infinite polling
    setTimeout(() => clearInterval(pollInterval), 10 * 60 * 1000)
  }, [])

  /**
   * Render enhanced AI score badges
   */
  const renderAIScoreBadges = useCallback((aiScore: AILeadScore) => {
    return (
      <div className="flex items-center gap-1">
        {/* Overall Score Badge */}
        <div
          className={clsx(
            'px-2 py-1 rounded-full text-xs font-medium',
            aiScore.rank === 'A'
              ? 'bg-green-100 text-green-800'
              : aiScore.rank === 'B'
                ? 'bg-blue-100 text-blue-800'
                : aiScore.rank === 'C'
                  ? 'bg-yellow-100 text-yellow-800'
                  : aiScore.rank === 'D'
                    ? 'bg-orange-100 text-orange-800'
                    : 'bg-red-100 text-red-800'
          )}
        >
          {aiScore.rank} ({aiScore.overallScore})
        </div>

        {/* Dynamic Badges */}
        {aiScore.badges.slice(0, 3).map((badge: AIBadge, index) => {
          const IconComponent =
            badge.type === 'verified-email'
              ? Shield
              : badge.type === 'active-website'
                ? Globe
                : badge.type === 'complete-profile'
                  ? Award
                  : Star

          return (
            <IconComponent
              key={index}
              className={clsx(
                'h-3 w-3',
                badge.color === 'green'
                  ? 'text-green-600'
                  : badge.color === 'blue'
                    ? 'text-blue-600'
                    : badge.color === 'purple'
                      ? 'text-purple-600'
                      : badge.color === 'orange'
                        ? 'text-orange-600'
                        : 'text-gray-600'
              )}
              title={badge.description}
            />
          )
        })}

        {/* Confidence Indicator */}
        <div
          className="h-2 w-8 bg-gray-200 rounded-full overflow-hidden"
          title={`Confidence: ${Math.round(aiScore.confidence * 100)}%`}
        >
          <div
            className={clsx(
              'h-full transition-all duration-300',
              aiScore.confidence > 0.8
                ? 'bg-green-500'
                : aiScore.confidence > 0.6
                  ? 'bg-yellow-500'
                  : 'bg-red-500'
            )}
            style={{ width: `${aiScore.confidence * 100}%` }}
          />
        </div>
      </div>
    )
  }, [])

  /**
   * Row renderer for virtual list
   */
  const Row = useCallback(
    ({ index, style }: { index: number; style: React.CSSProperties }) => {
      const item = items[index]

      if (!item?.business) {
        return (
          <div style={style} className="flex items-center justify-center p-4 border-b">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="ml-2 text-sm text-muted-foreground">Loading...</span>
          </div>
        )
      }

      const { business, aiScore } = item

      return (
        <div
          style={style}
          className={clsx(
            'flex items-center border-b hover:bg-accent/50 transition-colors group px-4',
            selectedRows.has(business.id) && 'bg-accent/30'
          )}
        >
          {/* Selection checkbox */}
          <div className="w-12 flex-shrink-0">
            <input
              type="checkbox"
              checked={selectedRows.has(business.id)}
              onChange={e => handleRowSelect(business.id, e.target.checked)}
              className="rounded"
            />
          </div>

          {/* Business Name */}
          {visibleColumns.businessName && (
            <div className="flex-1 min-w-0 px-2">
              <div className="font-medium text-sm truncate">
                {formatBusinessName(business.businessName)}
              </div>
              <div className="text-xs text-muted-foreground truncate">{business.websiteUrl}</div>
            </div>
          )}

          {/* Industry */}
          {visibleColumns.industry && (
            <div className="w-32 flex-shrink-0 px-2">
              <span className="text-sm">{business.industry}</span>
            </div>
          )}

          {/* Contact */}
          {visibleColumns.contact && (
            <div className="w-48 flex-shrink-0 px-2">
              <div className="text-sm">{business.email[0] || 'No email'}</div>
              <div className="text-xs text-muted-foreground">
                {business.phone ? formatPhoneNumber(business.phone) : 'No phone'}
              </div>
            </div>
          )}

          {/* Location */}
          {visibleColumns.location && (
            <div className="w-40 flex-shrink-0 px-2">
              <div className="text-sm truncate">{formatAddress(business.address)}</div>
            </div>
          )}

          {/* AI Score */}
          {visibleColumns.aiScore && aiScore && (
            <div className="w-32 flex-shrink-0 px-2">{renderAIScoreBadges(aiScore)}</div>
          )}

          {/* Actions */}
          {visibleColumns.actions && (
            <div className="w-24 flex-shrink-0 flex items-center gap-1 px-2">
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={() => onEdit?.(business)}
              >
                <Edit className="h-3 w-3" />
              </Button>
              {onDelete && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 text-destructive hover:text-destructive"
                  onClick={() => onDelete(business.id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              )}
            </div>
          )}
        </div>
      )
    },
    [items, selectedRows, visibleColumns, handleRowSelect, onEdit, onDelete, renderAIScoreBadges]
  )

  const itemCount = hasNextPage ? items.length + 1 : items.length
  const allSelected =
    items.length > 0 && items.every(item => item.business && selectedRows.has(item.business.id))

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Business Results ({totalCount.toLocaleString()})</CardTitle>
          <div className="flex items-center gap-2">
            {process.env.NODE_ENV === 'development' && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowPerformancePanel(!showPerformancePanel)}
                icon={Monitor}
                className={showPerformancePanel ? 'bg-blue-100' : ''}
              >
                Performance
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleExport}
              disabled={isExporting}
              icon={Download}
            >
              Export ({selectedRows.size > 0 ? selectedRows.size : items.length})
            </Button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <Input
              placeholder="Search businesses..."
              value={searchQuery}
              onChange={e => handleSearch(e.target.value)}
              icon={Search}
            />
          </div>
          <Button variant="outline" size="sm" icon={Filter}>
            Filters
          </Button>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {/* Table Header */}
        <div className="border-b bg-muted/50" style={{ height: HEADER_HEIGHT }}>
          <div className="flex items-center h-full px-4">
            <div className="w-12 flex-shrink-0">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={e => handleSelectAll(e.target.checked)}
                className="rounded"
              />
            </div>

            {visibleColumns.businessName && (
              <div className="flex-1 px-2">
                <button
                  className="flex items-center gap-1 font-medium text-sm hover:text-primary"
                  onClick={() => handleSort('businessName')}
                >
                  Business Name
                  {sortConfig.field === 'businessName' &&
                    (sortConfig.order === 'asc' ? (
                      <SortAsc className="h-3 w-3" />
                    ) : (
                      <SortDesc className="h-3 w-3" />
                    ))}
                </button>
              </div>
            )}

            {visibleColumns.industry && (
              <div className="w-32 flex-shrink-0 px-2">
                <button
                  className="flex items-center gap-1 font-medium text-sm hover:text-primary"
                  onClick={() => handleSort('industry')}
                >
                  Industry
                  {sortConfig.field === 'industry' &&
                    (sortConfig.order === 'asc' ? (
                      <SortAsc className="h-3 w-3" />
                    ) : (
                      <SortDesc className="h-3 w-3" />
                    ))}
                </button>
              </div>
            )}

            {visibleColumns.contact && (
              <div className="w-48 flex-shrink-0 px-2">
                <span className="font-medium text-sm">Contact</span>
              </div>
            )}

            {visibleColumns.location && (
              <div className="w-40 flex-shrink-0 px-2">
                <span className="font-medium text-sm">Location</span>
              </div>
            )}

            {visibleColumns.aiScore && (
              <div className="w-32 flex-shrink-0 px-2">
                <span className="font-medium text-sm">AI Score</span>
              </div>
            )}

            {visibleColumns.actions && (
              <div className="w-24 flex-shrink-0 px-2">
                <span className="font-medium text-sm">Actions</span>
              </div>
            )}
          </div>
        </div>

        {/* Virtual List */}
        <div style={{ height: height - HEADER_HEIGHT }}>
          <AutoSizer>
            {({ height: autoHeight, width }) => (
              <InfiniteLoader
                ref={infiniteLoaderRef}
                isItemLoaded={isItemLoaded}
                itemCount={itemCount}
                loadMoreItems={loadMoreItems}
                threshold={LOAD_MORE_THRESHOLD}
              >
                {({ onItemsRendered, ref }) => (
                  <List
                    ref={list => {
                      ref(list)
                      listRef.current = list
                    }}
                    height={autoHeight}
                    width={width}
                    itemCount={itemCount}
                    itemSize={ROW_HEIGHT}
                    onItemsRendered={onItemsRendered}
                    onScroll={handleScroll}
                  >
                    {Row}
                  </List>
                )}
              </InfiniteLoader>
            )}
          </AutoSizer>
        </div>

        {/* Loading indicator */}
        {isLoadingMore && (
          <div className="flex items-center justify-center p-4 border-t">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="ml-2 text-sm text-muted-foreground">Loading more results...</span>
          </div>
        )}

        {/* Performance Monitoring Panel */}
        {showPerformancePanel && performanceMetrics.length > 0 && (
          <div className="border-t bg-gray-50 p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-medium text-sm flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Performance Metrics
              </h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPerformanceMetrics([])}
                className="text-xs"
              >
                Clear
              </Button>
            </div>

            {(() => {
              const latest = performanceMetrics[performanceMetrics.length - 1]
              const avgRenderTime =
                performanceMetrics.reduce((sum, m) => sum + m.renderTime, 0) /
                performanceMetrics.length
              const maxRenderTime = Math.max(...performanceMetrics.map(m => m.renderTime))

              return (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 text-xs">
                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Latest Render</div>
                    <div
                      className={clsx(
                        'font-mono',
                        latest.renderTime > 16.67
                          ? 'text-red-600'
                          : latest.renderTime > 8
                            ? 'text-yellow-600'
                            : 'text-green-600'
                      )}
                    >
                      {latest.renderTime.toFixed(2)}ms
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Avg Render</div>
                    <div
                      className={clsx(
                        'font-mono',
                        avgRenderTime > 16.67
                          ? 'text-red-600'
                          : avgRenderTime > 8
                            ? 'text-yellow-600'
                            : 'text-green-600'
                      )}
                    >
                      {avgRenderTime.toFixed(2)}ms
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Max Render</div>
                    <div
                      className={clsx(
                        'font-mono',
                        maxRenderTime > 16.67
                          ? 'text-red-600'
                          : maxRenderTime > 8
                            ? 'text-yellow-600'
                            : 'text-green-600'
                      )}
                    >
                      {maxRenderTime.toFixed(2)}ms
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Memory Usage</div>
                    <div className="font-mono text-blue-600">
                      {latest.memoryUsage
                        ? `${Math.round(latest.memoryUsage / 1024 / 1024)}MB`
                        : 'N/A'}
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Scroll Velocity</div>
                    <div className="font-mono text-purple-600">
                      {scrollMetrics.velocity.toFixed(1)}px/ms
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Frame Rate</div>
                    <div
                      className={clsx(
                        'font-mono',
                        (latest.frameRate || 0) < 30
                          ? 'text-red-600'
                          : (latest.frameRate || 0) < 50
                            ? 'text-yellow-600'
                            : 'text-green-600'
                      )}
                    >
                      {latest.frameRate || 0} fps
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Total Items</div>
                    <div className="font-mono text-gray-800">
                      {latest.totalItemsCount.toLocaleString()}
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Visible Items</div>
                    <div className="font-mono text-gray-800">{latest.visibleItemsCount}</div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Scroll Position</div>
                    <div className="font-mono text-gray-800">{scrollPosition.toFixed(0)}px</div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Scroll Direction</div>
                    <div
                      className={clsx(
                        'font-mono',
                        scrollMetrics.direction === 'down'
                          ? 'text-blue-600'
                          : scrollMetrics.direction === 'up'
                            ? 'text-green-600'
                            : 'text-gray-600'
                      )}
                    >
                      {scrollMetrics.direction}
                    </div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Metrics Count</div>
                    <div className="font-mono text-gray-800">{performanceMetrics.length}</div>
                  </div>

                  <div className="bg-white p-2 rounded border">
                    <div className="font-medium text-gray-600">Performance Score</div>
                    <div
                      className={clsx(
                        'font-mono font-bold',
                        avgRenderTime < 8 && (latest.frameRate || 0) > 50
                          ? 'text-green-600'
                          : avgRenderTime < 16.67 && (latest.frameRate || 0) > 30
                            ? 'text-yellow-600'
                            : 'text-red-600'
                      )}
                    >
                      {avgRenderTime < 8 && (latest.frameRate || 0) > 50
                        ? 'Excellent'
                        : avgRenderTime < 16.67 && (latest.frameRate || 0) > 30
                          ? 'Good'
                          : 'Poor'}
                    </div>
                  </div>
                </div>
              )
            })()}

            <div className="mt-3 text-xs text-gray-500">
              Performance monitoring is enabled in development mode. Green = Good (&lt;8ms), Yellow
              = Acceptable (&lt;16.67ms), Red = Slow (&gt;16.67ms)
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
