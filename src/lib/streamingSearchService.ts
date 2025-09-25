/**
 * Streaming Search Service
 * Provides real-time search results streaming for large datasets
 */

import { logger } from '@/utils/logger'
import { SearchEngineService, SearchResult } from '@/model/searchEngine'
import { BusinessRecord } from '@/types/business'
import { ScraperService } from '@/model/scraperService'
import { EventEmitter } from 'events'

export interface StreamingSearchOptions {
  maxResults?: number
  batchSize?: number
  delayBetweenBatches?: number
  enableRealTimeUpdates?: boolean
}

export interface SearchProgress {
  totalFound: number
  processed: number
  currentBatch: number
  estimatedTimeRemaining: number
  status: 'searching' | 'processing' | 'completed' | 'error'
}

export interface StreamingSearchResult {
  type: 'result' | 'progress' | 'complete' | 'error'
  data?: BusinessRecord
  progress?: SearchProgress
  error?: string
  timestamp: number
}

/**
 * Streaming Search Service for real-time result delivery
 */
export class StreamingSearchService extends EventEmitter {
  private searchEngine: SearchEngineService | null = null
  private scraperService: ScraperService | null = null
  private activeStreams: Map<string, boolean> = new Map()
  private initializationError: string | null = null
  private isInitialized: boolean = false

  constructor() {
    super()
    this.initializeServices()
  }

  /**
   * Initialize services with proper error handling and graceful degradation
   */
  private async initializeServices(): Promise<void> {
    try {
      logger.info('StreamingSearchService', 'Initializing services...')

      // Try to initialize SearchEngineService
      try {
        this.searchEngine = new SearchEngineService()
        logger.info('StreamingSearchService', 'SearchEngineService initialized successfully')
      } catch (searchEngineError) {
        logger.warn('StreamingSearchService', 'Failed to initialize SearchEngineService, will use fallback', searchEngineError)
        this.searchEngine = null
      }

      // Try to initialize ScraperService
      try {
        this.scraperService = new ScraperService()
        logger.info('StreamingSearchService', 'ScraperService initialized successfully')
      } catch (scraperError) {
        logger.warn('StreamingSearchService', 'Failed to initialize ScraperService, will use fallback', scraperError)
        this.scraperService = null
      }

      // Service is considered initialized even if some dependencies failed
      // This allows for graceful degradation
      this.isInitialized = true

      if (this.searchEngine && this.scraperService) {
        logger.info('StreamingSearchService', 'All services initialized successfully')
      } else {
        const missingServices = []
        if (!this.searchEngine) missingServices.push('SearchEngineService')
        if (!this.scraperService) missingServices.push('ScraperService')
        logger.warn('StreamingSearchService', `Service initialized with limited functionality. Missing: ${missingServices.join(', ')}`)
      }
    } catch (error) {
      this.initializationError = error instanceof Error ? error.message : 'Unknown initialization error'
      logger.error('StreamingSearchService', 'Critical initialization failure', error)
      this.isInitialized = false
    }
  }

  /**
   * Stream search results in real-time
   */
  async *streamSearchResults(
    query: string,
    location: string = '',
    options: StreamingSearchOptions = {}
  ): AsyncGenerator<StreamingSearchResult, void, unknown> {
    const streamId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    const {
      maxResults = 1000,
      batchSize = 50,
      delayBetweenBatches = 100,
      enableRealTimeUpdates = true,
    } = options

    this.activeStreams.set(streamId, true)
    logger.info('StreamingSearch', `Starting streaming search for "${query}" (${streamId})`)

    try {
      let offset = 0
      let totalFound = 0
      let processed = 0
      const startTime = Date.now()

      while (offset < maxResults && this.activeStreams.get(streamId)) {
        // Search for batch of results
        const searchResults = await this.searchBatch(query, location, offset, batchSize)

        if (searchResults.length === 0) {
          break // No more results
        }

        totalFound += searchResults.length

        // Emit progress update
        if (enableRealTimeUpdates) {
          const progress: SearchProgress = {
            totalFound,
            processed,
            currentBatch: Math.floor(offset / batchSize) + 1,
            estimatedTimeRemaining: this.estimateTimeRemaining(startTime, processed, totalFound),
            status: 'processing',
          }

          yield {
            type: 'progress',
            progress,
            timestamp: Date.now(),
          }
        }

        // Process each search result
        for (const searchResult of searchResults) {
          if (!this.activeStreams.get(streamId)) break

          try {
            // Scrape business data from the URL
            const businessData = await this.scraperService.scrapeWebsite(searchResult.url, 1, 1)

            if (businessData.length > 0) {
              const business = businessData[0]

              // Enhance with search result data
              const enhancedBusiness: BusinessRecord = {
                ...business,
                name: business.name || searchResult.title,
                website: business.website || searchResult.url,
                description: business.description || searchResult.snippet,
              }

              yield {
                type: 'result',
                data: enhancedBusiness,
                timestamp: Date.now(),
              }

              processed++
              this.emit('result', enhancedBusiness)
            }
          } catch (error) {
            logger.warn('StreamingSearch', `Failed to process ${searchResult.url}`, error)
          }

          // Small delay to prevent overwhelming
          if (delayBetweenBatches > 0) {
            await this.delay(delayBetweenBatches / batchSize)
          }
        }

        offset += batchSize

        // Delay between batches
        if (delayBetweenBatches > 0) {
          await this.delay(delayBetweenBatches)
        }
      }

      // Emit completion
      yield {
        type: 'complete',
        progress: {
          totalFound,
          processed,
          currentBatch: Math.floor(offset / batchSize),
          estimatedTimeRemaining: 0,
          status: 'completed',
        },
        timestamp: Date.now(),
      }

      logger.info(
        'StreamingSearch',
        `Completed streaming search for "${query}": ${processed} results`
      )
    } catch (error) {
      logger.error('StreamingSearch', `Streaming search failed for "${query}"`, error)

      yield {
        type: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now(),
      }
    } finally {
      this.activeStreams.delete(streamId)
    }
  }

  /**
   * Search for a batch of results
   */
  private async searchBatch(
    query: string,
    location: string,
    offset: number,
    batchSize: number
  ): Promise<SearchResult[]> {
    try {
      // Check if search engine is available
      if (!this.searchEngine) {
        logger.warn('StreamingSearchService', 'Search engine not available, returning empty results')
        return []
      }

      const searchQuery = location ? `${query} ${location}` : query
      logger.debug('StreamingSearchService', `Searching batch: query="${searchQuery}", offset=${offset}, batchSize=${batchSize}`)

      const results = await this.searchEngine.search(searchQuery, {
        maxResults: batchSize,
        // Add offset support if available in search engine
      })

      logger.debug('StreamingSearchService', `Search batch returned ${results.length} results`)
      return results.slice(0, batchSize)
    } catch (error) {
      logger.error('StreamingSearchService', `Failed to search batch at offset ${offset}`, error)
      // Return empty array to allow streaming to continue with next batch
      return []
    }
  }

  /**
   * Process streaming search with callback
   */
  async processStreamingSearch(
    query: string,
    location: string,
    onResult: (business: BusinessRecord) => void,
    onProgress?: (progress: SearchProgress) => void,
    onComplete?: (totalResults: number) => void,
    onError?: (error: string) => void,
    options: StreamingSearchOptions = {}
  ): Promise<void> {
    // Validate inputs
    if (!query || typeof query !== 'string' || query.trim().length === 0) {
      const errorMessage = 'Invalid query: Query must be a non-empty string'
      logger.error('StreamingSearchService', errorMessage)
      if (onError) {
        onError(errorMessage)
      }
      return
    }

    // Validate services are initialized
    if (!this.searchEngine || !this.scraperService) {
      const errorMessage = 'Services not properly initialized'
      logger.error('StreamingSearchService', errorMessage)
      if (onError) {
        onError(errorMessage)
      }
      return
    }

    logger.info('StreamingSearchService', `Starting processStreamingSearch for query: "${query}", location: "${location}"`)

    try {
      let totalResults = 0

      for await (const result of this.streamSearchResults(query, location, options)) {
        switch (result.type) {
          case 'result':
            if (result.data) {
              try {
                onResult(result.data)
                totalResults++
              } catch (callbackError) {
                logger.error('StreamingSearchService', 'Error in onResult callback', callbackError)
              }
            }
            break

          case 'progress':
            if (result.progress && onProgress) {
              try {
                onProgress(result.progress)
              } catch (callbackError) {
                logger.error('StreamingSearchService', 'Error in onProgress callback', callbackError)
              }
            }
            break

          case 'complete':
            if (onComplete) {
              try {
                onComplete(totalResults)
              } catch (callbackError) {
                logger.error('StreamingSearchService', 'Error in onComplete callback', callbackError)
              }
            }
            break

          case 'error':
            if (result.error && onError) {
              try {
                onError(result.error)
              } catch (callbackError) {
                logger.error('StreamingSearchService', 'Error in onError callback', callbackError)
              }
            }
            break
        }
      }

      logger.info('StreamingSearchService', `Completed processStreamingSearch with ${totalResults} results`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      logger.error('StreamingSearchService', `processStreamingSearch failed: ${errorMessage}`, error)
      if (onError) {
        try {
          onError(errorMessage)
        } catch (callbackError) {
          logger.error('StreamingSearchService', 'Error in onError callback during exception handling', callbackError)
        }
      }
    }
  }

  /**
   * Stop a streaming search
   */
  stopStream(streamId: string): void {
    this.activeStreams.set(streamId, false)
    logger.info('StreamingSearch', `Stopped streaming search ${streamId}`)
  }

  /**
   * Stop all active streams
   */
  stopAllStreams(): void {
    for (const streamId of this.activeStreams.keys()) {
      this.activeStreams.set(streamId, false)
    }
    logger.info('StreamingSearch', 'Stopped all streaming searches')
  }

  /**
   * Get active stream count
   */
  getActiveStreamCount(): number {
    return Array.from(this.activeStreams.values()).filter(active => active).length
  }

  /**
   * Estimate time remaining based on current progress
   */
  private estimateTimeRemaining(startTime: number, processed: number, total: number): number {
    if (processed === 0) return 0

    const elapsed = Date.now() - startTime
    const rate = processed / elapsed // results per millisecond
    const remaining = total - processed

    return remaining / rate
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Health check for streaming service
   */
  async healthCheck(): Promise<{ healthy: boolean; details: Record<string, any> }> {
    const details: Record<string, any> = {
      timestamp: new Date().toISOString(),
      activeStreams: this.getActiveStreamCount(),
      servicesInitialized: {
        searchEngine: !!this.searchEngine,
        scraperService: !!this.scraperService,
      },
    }

    try {
      // Test search engine
      if (this.searchEngine) {
        try {
          const testResults = await this.searchEngine.search('test', { maxResults: 1 })
          details.searchEngineTest = {
            success: true,
            resultCount: testResults.length,
          }
        } catch (searchError) {
          details.searchEngineTest = {
            success: false,
            error: 'Search engine test failed',
          }
        }
      } else {
        details.searchEngineTest = {
          success: false,
          error: 'Search engine not initialized',
        }
      }

      // Test scraper service
      if (this.scraperService) {
        details.scraperServiceTest = {
          success: true,
          initialized: true,
        }
      } else {
        details.scraperServiceTest = {
          success: false,
          error: 'Scraper service not initialized',
        }
      }

      // Service is considered healthy if it's initialized, even with limited functionality
      const healthy = this.isInitialized && !this.initializationError

      logger.info('StreamingSearchService', `Health check completed: ${healthy ? 'HEALTHY' : 'UNHEALTHY'}`, details)

      return { healthy, details }
    } catch (error) {
      details.error = error instanceof Error ? error.message : 'Unknown error'
      logger.error('StreamingSearchService', 'Health check failed', error)
      return { healthy: false, details }
    }
  }
}

/**
 * Default streaming search service instance
 */
export const streamingSearchService = new StreamingSearchService()


