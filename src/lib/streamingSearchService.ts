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
  private searchEngine: SearchEngineService
  private scraperService: ScraperService
  private activeStreams: Map<string, boolean> = new Map()

  constructor() {
    super()
    this.searchEngine = new SearchEngineService()
    this.scraperService = new ScraperService()
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
      enableRealTimeUpdates = true
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
            status: 'processing'
          }

          yield {
            type: 'progress',
            progress,
            timestamp: Date.now()
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
                description: business.description || searchResult.snippet
              }

              yield {
                type: 'result',
                data: enhancedBusiness,
                timestamp: Date.now()
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
          status: 'completed'
        },
        timestamp: Date.now()
      }

      logger.info('StreamingSearch', `Completed streaming search for "${query}": ${processed} results`)

    } catch (error) {
      logger.error('StreamingSearch', `Streaming search failed for "${query}"`, error)
      
      yield {
        type: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now()
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
      const searchQuery = location ? `${query} ${location}` : query
      const results = await this.searchEngine.search(searchQuery, {
        maxResults: batchSize,
        // Add offset support if available in search engine
      })

      return results.slice(0, batchSize)
    } catch (error) {
      logger.error('StreamingSearch', `Failed to search batch at offset ${offset}`, error)
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
    try {
      let totalResults = 0

      for await (const result of this.streamSearchResults(query, location, options)) {
        switch (result.type) {
          case 'result':
            if (result.data) {
              onResult(result.data)
              totalResults++
            }
            break

          case 'progress':
            if (result.progress && onProgress) {
              onProgress(result.progress)
            }
            break

          case 'complete':
            if (onComplete) {
              onComplete(totalResults)
            }
            break

          case 'error':
            if (result.error && onError) {
              onError(result.error)
            }
            break
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      if (onError) {
        onError(errorMessage)
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
}

/**
 * Default streaming search service instance
 */
export const streamingSearchService = new StreamingSearchService()
