/**
 * Virtual Scrolling Service
 * Handles data fetching, caching, and management for virtual scrolling components
 */

import React from 'react'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface VirtualScrollingFilters {
  search?: string
  industry?: string
  hasEmail?: boolean
  hasPhone?: boolean
  qualityScore?: {
    min?: number
    max?: number
  }
  dateRange?: {
    start?: string
    end?: string
  }
}

export interface VirtualScrollingSortConfig {
  field: 'businessName' | 'industry' | 'scrapedAt' | 'qualityScore'
  order: 'asc' | 'desc'
}

export interface PaginatedResponse {
  data: BusinessRecord[]
  pagination: {
    nextCursor: string | null
    hasMore: boolean
    totalCount: number
    currentPage: number
    pageSize: number
  }
  metadata: {
    processingTime: number
    source: 'postgresql' | 'indexeddb'
    appliedFilters: Record<string, any>
    sortConfig: {
      field: string
      order: string
    }
  }
}

export interface VirtualScrollingCache {
  [key: string]: {
    data: BusinessRecord[]
    timestamp: number
    cursor: string | null
    hasMore: boolean
  }
}

/**
 * Virtual Scrolling Service Class
 */
export class VirtualScrollingService {
  private cache: VirtualScrollingCache = {}
  private readonly cacheTimeout = 5 * 60 * 1000 // 5 minutes
  private readonly defaultPageSize = 100

  /**
   * Fetch paginated business data
   */
  async fetchBusinesses(
    cursor?: string,
    limit: number = this.defaultPageSize,
    sortConfig?: VirtualScrollingSortConfig,
    filters?: VirtualScrollingFilters
  ): Promise<PaginatedResponse> {
    const cacheKey = this.generateCacheKey(cursor, limit, sortConfig, filters)
    
    // Check cache first
    const cachedData = this.getCachedData(cacheKey)
    if (cachedData) {
      logger.info('VirtualScrollingService', `Cache hit for key: ${cacheKey}`)
      return {
        data: cachedData.data,
        pagination: {
          nextCursor: cachedData.cursor,
          hasMore: cachedData.hasMore,
          totalCount: -1, // Not available from cache
          currentPage: -1, // Not applicable for cursor pagination
          pageSize: limit
        },
        metadata: {
          processingTime: 0,
          source: 'postgresql', // Assume PostgreSQL for cached data
          appliedFilters: filters || {},
          sortConfig: {
            field: sortConfig?.field || 'scrapedAt',
            order: sortConfig?.order || 'desc'
          }
        }
      }
    }

    try {
      // Build query parameters
      const queryParams = new URLSearchParams()
      
      if (cursor) queryParams.set('cursor', cursor)
      queryParams.set('limit', limit.toString())
      
      if (sortConfig) {
        queryParams.set('sortField', sortConfig.field)
        queryParams.set('sortOrder', sortConfig.order)
      }
      
      if (filters) {
        if (filters.search) queryParams.set('search', filters.search)
        if (filters.industry) queryParams.set('industry', filters.industry)
        if (filters.hasEmail !== undefined) queryParams.set('hasEmail', filters.hasEmail.toString())
        if (filters.hasPhone !== undefined) queryParams.set('hasPhone', filters.hasPhone.toString())
        if (filters.qualityScore?.min !== undefined) queryParams.set('qualityScoreMin', filters.qualityScore.min.toString())
        if (filters.qualityScore?.max !== undefined) queryParams.set('qualityScoreMax', filters.qualityScore.max.toString())
        if (filters.dateRange?.start) queryParams.set('dateStart', filters.dateRange.start)
        if (filters.dateRange?.end) queryParams.set('dateEnd', filters.dateRange.end)
      }

      const response = await fetch(`/api/businesses?${queryParams.toString()}`)

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const result: PaginatedResponse = await response.json()

      // Cache the result
      this.setCachedData(cacheKey, {
        data: result.data,
        timestamp: Date.now(),
        cursor: result.pagination.nextCursor,
        hasMore: result.pagination.hasMore
      })

      logger.info('VirtualScrollingService', `Fetched ${result.data.length} businesses`)
      return result

    } catch (error) {
      logger.error('VirtualScrollingService', 'Failed to fetch businesses', error)
      throw error
    }
  }

  /**
   * Prefetch next page for smoother scrolling
   */
  async prefetchNextPage(
    cursor: string,
    limit: number = this.defaultPageSize,
    sortConfig?: VirtualScrollingSortConfig,
    filters?: VirtualScrollingFilters
  ): Promise<void> {
    try {
      await this.fetchBusinesses(cursor, limit, sortConfig, filters)
      logger.info('VirtualScrollingService', 'Prefetched next page successfully')
    } catch (error) {
      logger.warn('VirtualScrollingService', 'Failed to prefetch next page', error)
    }
  }

  /**
   * Clear cache (useful when filters or sort changes)
   */
  clearCache(): void {
    this.cache = {}
    logger.info('VirtualScrollingService', 'Cache cleared')
  }

  /**
   * Clear expired cache entries
   */
  clearExpiredCache(): void {
    const now = Date.now()
    const expiredKeys = Object.keys(this.cache).filter(
      key => now - this.cache[key].timestamp > this.cacheTimeout
    )
    
    expiredKeys.forEach(key => delete this.cache[key])
    
    if (expiredKeys.length > 0) {
      logger.info('VirtualScrollingService', `Cleared ${expiredKeys.length} expired cache entries`)
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; oldestEntry: number; newestEntry: number } {
    const entries = Object.values(this.cache)
    const timestamps = entries.map(entry => entry.timestamp)
    
    return {
      size: entries.length,
      oldestEntry: timestamps.length > 0 ? Math.min(...timestamps) : 0,
      newestEntry: timestamps.length > 0 ? Math.max(...timestamps) : 0
    }
  }

  /**
   * Generate cache key from parameters
   */
  private generateCacheKey(
    cursor?: string,
    limit?: number,
    sortConfig?: VirtualScrollingSortConfig,
    filters?: VirtualScrollingFilters
  ): string {
    const keyParts = [
      cursor || 'start',
      limit?.toString() || this.defaultPageSize.toString(),
      sortConfig ? `${sortConfig.field}-${sortConfig.order}` : 'scrapedAt-desc',
      filters ? JSON.stringify(filters) : 'no-filters'
    ]
    
    return keyParts.join('|')
  }

  /**
   * Get cached data if valid
   */
  private getCachedData(key: string): VirtualScrollingCache[string] | null {
    const cached = this.cache[key]
    if (!cached) return null
    
    const isExpired = Date.now() - cached.timestamp > this.cacheTimeout
    if (isExpired) {
      delete this.cache[key]
      return null
    }
    
    return cached
  }

  /**
   * Set cached data
   */
  private setCachedData(key: string, data: VirtualScrollingCache[string]): void {
    this.cache[key] = data
    
    // Clean up expired entries periodically
    if (Object.keys(this.cache).length % 10 === 0) {
      this.clearExpiredCache()
    }
  }
}

// Export singleton instance
export const virtualScrollingService = new VirtualScrollingService()

/**
 * Hook for React components to use virtual scrolling service
 */
export function useVirtualScrolling() {
  return {
    fetchBusinesses: virtualScrollingService.fetchBusinesses.bind(virtualScrollingService),
    prefetchNextPage: virtualScrollingService.prefetchNextPage.bind(virtualScrollingService),
    clearCache: virtualScrollingService.clearCache.bind(virtualScrollingService),
    getCacheStats: virtualScrollingService.getCacheStats.bind(virtualScrollingService)
  }
}

/**
 * Enhanced hook with state management for virtual scrolling components
 */
export function useVirtualScrollingState(
  initialFilters?: VirtualScrollingFilters,
  initialSort?: VirtualScrollingSortConfig
) {
  const [items, setItems] = React.useState<BusinessRecord[]>([])
  const [hasNextPage, setHasNextPage] = React.useState(true)
  const [isLoading, setIsLoading] = React.useState(false)
  const [nextCursor, setNextCursor] = React.useState<string | null>(null)
  const [totalCount, setTotalCount] = React.useState(0)
  const [filters, setFilters] = React.useState<VirtualScrollingFilters>(initialFilters || {})
  const [sortConfig, setSortConfig] = React.useState<VirtualScrollingSortConfig>(
    initialSort || { field: 'scrapedAt', order: 'desc' }
  )

  const { fetchBusinesses, prefetchNextPage, clearCache } = useVirtualScrolling()

  const loadInitialData = React.useCallback(async () => {
    try {
      setIsLoading(true)
      setItems([])
      setNextCursor(null)
      setHasNextPage(true)

      const result = await fetchBusinesses(undefined, 100, sortConfig, filters)

      setItems(result.data)
      setNextCursor(result.pagination.nextCursor)
      setHasNextPage(result.pagination.hasMore)
      setTotalCount(result.pagination.totalCount)

      // Prefetch next page
      if (result.pagination.nextCursor) {
        prefetchNextPage(result.pagination.nextCursor, 100, sortConfig, filters)
      }

    } catch (error) {
      logger.error('useVirtualScrollingState', 'Failed to load initial data', error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }, [fetchBusinesses, prefetchNextPage, sortConfig, filters])

  const loadMoreItems = React.useCallback(async () => {
    if (!hasNextPage || isLoading || !nextCursor) return

    try {
      setIsLoading(true)

      const result = await fetchBusinesses(nextCursor, 100, sortConfig, filters)

      setItems(prev => [...prev, ...result.data])
      setNextCursor(result.pagination.nextCursor)
      setHasNextPage(result.pagination.hasMore)

      // Prefetch next page
      if (result.pagination.nextCursor) {
        prefetchNextPage(result.pagination.nextCursor, 100, sortConfig, filters)
      }

    } catch (error) {
      logger.error('useVirtualScrollingState', 'Failed to load more items', error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }, [fetchBusinesses, prefetchNextPage, hasNextPage, isLoading, nextCursor, sortConfig, filters])

  const updateFilters = React.useCallback((newFilters: VirtualScrollingFilters) => {
    setFilters(newFilters)
    clearCache() // Clear cache when filters change
  }, [clearCache])

  const updateSort = React.useCallback((newSort: VirtualScrollingSortConfig) => {
    setSortConfig(newSort)
    clearCache() // Clear cache when sort changes
  }, [clearCache])

  // Load initial data when filters or sort change
  React.useEffect(() => {
    loadInitialData()
  }, [loadInitialData])

  return {
    items,
    hasNextPage,
    isLoading,
    totalCount,
    filters,
    sortConfig,
    loadInitialData,
    loadMoreItems,
    updateFilters,
    updateSort
  }
}

// Import AI scoring service for internal use
import { aiLeadScoringService } from './aiLeadScoringService'

/**
 * Calculate AI lead score for a business (wrapper for the enhanced service)
 */
export async function calculateAILeadScore(business: BusinessRecord) {
  try {
    return await aiLeadScoringService.calculateLeadScore(business)
  } catch (error) {
    logger.error('VirtualScrollingService', 'Failed to calculate AI lead score', error)
    // Return fallback score
    return {
      overallScore: 50,
      confidence: 0.5,
      rank: 'C' as const,
      factors: {
        contactability: { score: 50, weight: 0.3, details: { emailQuality: 50, phonePresence: 50, websiteAccessibility: 50, multiChannelAvailability: 50 } },
        businessMaturity: { score: 50, weight: 0.25, details: { dataCompleteness: 50, establishedPresence: 50, professionalWebsite: 50, businessInformation: 50 } },
        marketPotential: { score: 50, weight: 0.25, details: { industryGrowth: 50, locationAdvantage: 50, competitivePosition: 50, marketSize: 50 } },
        engagementLikelihood: { score: 50, weight: 0.2, details: { responsiveness: 50, digitalPresence: 50, businessActivity: 50, communicationChannels: 50 } }
      },
      predictions: {
        conversionProbability: 0.5,
        responseTime: 'moderate' as const,
        bestContactMethod: 'email' as const,
        optimalContactTime: { dayOfWeek: ['Tuesday', 'Wednesday'], timeOfDay: ['10:00 AM'] }
      },
      badges: [],
      warnings: [],
      recommendations: [],
      scoringVersion: '2.0.0',
      lastUpdated: new Date(),
      processingTime: 0
    }
  }
}
