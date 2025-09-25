/**
 * Enhanced Streaming Data Processor for Large Datasets
 * Provides real-time streaming capabilities with memory optimization
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface StreamingConfig {
  batchSize: number
  maxMemoryUsage: number // in MB
  processingDelay: number // in ms
  enableCompression: boolean
  enableCaching: boolean
  maxConcurrentStreams: number
}

export interface StreamingMetrics {
  totalProcessed: number
  currentBatchSize: number
  memoryUsage: number
  processingRate: number // items per second
  averageProcessingTime: number
  errorCount: number
  streamCount: number
}

export interface StreamingBatch<T> {
  id: string
  data: T[]
  timestamp: Date
  size: number
  compressed?: boolean
}

export class StreamingDataProcessor<T = BusinessRecord> extends EventEmitter {
  private config: StreamingConfig
  private activeStreams: Map<string, NodeJS.ReadableStream> = new Map()
  private processingQueue: StreamingBatch<T>[] = []
  private metrics: StreamingMetrics
  private isProcessing = false
  private memoryMonitor?: NodeJS.Timeout
  private performanceMonitor?: NodeJS.Timeout

  constructor(config?: Partial<StreamingConfig>) {
    super()
    
    this.config = {
      batchSize: 100,
      maxMemoryUsage: 512, // 512MB
      processingDelay: 50, // 50ms between batches
      enableCompression: true,
      enableCaching: true,
      maxConcurrentStreams: 5,
      ...config,
    }

    this.metrics = {
      totalProcessed: 0,
      currentBatchSize: 0,
      memoryUsage: 0,
      processingRate: 0,
      averageProcessingTime: 0,
      errorCount: 0,
      streamCount: 0,
    }

    this.startMonitoring()
  }

  /**
   * Create a new streaming processor for large datasets
   */
  async createStream(streamId: string, dataSource: T[]): Promise<void> {
    if (this.activeStreams.size >= this.config.maxConcurrentStreams) {
      throw new Error('Maximum concurrent streams reached')
    }

    try {
      logger.info('StreamingProcessor', `Creating stream ${streamId} with ${dataSource.length} items`)

      // Create batches from data source
      const batches = this.createBatches(dataSource, streamId)
      
      // Add batches to processing queue
      this.processingQueue.push(...batches)
      
      // Start processing if not already running
      if (!this.isProcessing) {
        this.startProcessing()
      }

      this.metrics.streamCount++
      this.emit('streamCreated', { streamId, batchCount: batches.length })

    } catch (error) {
      logger.error('StreamingProcessor', `Failed to create stream ${streamId}`, error)
      this.metrics.errorCount++
      throw error
    }
  }

  /**
   * Process data in streaming batches
   */
  private async startProcessing(): Promise<void> {
    if (this.isProcessing) return

    this.isProcessing = true
    logger.info('StreamingProcessor', 'Starting batch processing')

    while (this.processingQueue.length > 0) {
      const batch = this.processingQueue.shift()
      if (!batch) continue

      try {
        await this.processBatch(batch)
        
        // Memory pressure check
        if (this.metrics.memoryUsage > this.config.maxMemoryUsage) {
          logger.warn('StreamingProcessor', 'Memory pressure detected, triggering cleanup')
          await this.performMemoryCleanup()
        }

        // Delay between batches for performance optimization
        if (this.config.processingDelay > 0) {
          await new Promise(resolve => setTimeout(resolve, this.config.processingDelay))
        }

      } catch (error) {
        logger.error('StreamingProcessor', `Failed to process batch ${batch.id}`, error)
        this.metrics.errorCount++
        this.emit('batchError', { batchId: batch.id, error })
      }
    }

    this.isProcessing = false
    logger.info('StreamingProcessor', 'Batch processing completed')
    this.emit('processingComplete', this.metrics)
  }

  /**
   * Process individual batch
   */
  private async processBatch(batch: StreamingBatch<T>): Promise<void> {
    const startTime = Date.now()
    
    try {
      this.metrics.currentBatchSize = batch.size
      
      // Emit batch start event
      this.emit('batchStart', { 
        batchId: batch.id, 
        size: batch.size,
        timestamp: batch.timestamp 
      })

      // Process batch data (can be overridden by subclasses)
      const processedData = await this.processData(batch.data)
      
      // Update metrics
      this.metrics.totalProcessed += batch.size
      const processingTime = Date.now() - startTime
      this.updatePerformanceMetrics(processingTime, batch.size)

      // Emit batch completion
      this.emit('batchComplete', {
        batchId: batch.id,
        processedCount: processedData.length,
        processingTime,
        totalProcessed: this.metrics.totalProcessed
      })

      // Emit individual items for real-time updates
      processedData.forEach(item => {
        this.emit('itemProcessed', item)
      })

    } catch (error) {
      logger.error('StreamingProcessor', `Batch processing failed for ${batch.id}`, error)
      throw error
    }
  }

  /**
   * Process data items (override in subclasses for custom processing)
   */
  protected async processData(data: T[]): Promise<T[]> {
    // Default implementation - can be overridden
    return data.map(item => {
      // Apply any transformations here
      return item
    })
  }

  /**
   * Create batches from data source
   */
  private createBatches(data: T[], streamId: string): StreamingBatch<T>[] {
    const batches: StreamingBatch<T>[] = []
    
    for (let i = 0; i < data.length; i += this.config.batchSize) {
      const batchData = data.slice(i, i + this.config.batchSize)
      const batch: StreamingBatch<T> = {
        id: `${streamId}-batch-${Math.floor(i / this.config.batchSize)}`,
        data: batchData,
        timestamp: new Date(),
        size: batchData.length,
        compressed: this.config.enableCompression
      }
      
      batches.push(batch)
    }
    
    return batches
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(processingTime: number, itemCount: number): void {
    // Calculate processing rate (items per second)
    this.metrics.processingRate = itemCount / (processingTime / 1000)
    
    // Update average processing time
    this.metrics.averageProcessingTime = 
      (this.metrics.averageProcessingTime + processingTime) / 2
  }

  /**
   * Start monitoring system resources
   */
  private startMonitoring(): void {
    // Memory monitoring
    this.memoryMonitor = setInterval(() => {
      const memUsage = process.memoryUsage()
      this.metrics.memoryUsage = Math.round(memUsage.heapUsed / 1024 / 1024) // MB
    }, 1000)

    // Performance monitoring
    this.performanceMonitor = setInterval(() => {
      this.emit('metricsUpdate', this.metrics)
    }, 5000)
  }

  /**
   * Perform memory cleanup
   */
  private async performMemoryCleanup(): Promise<void> {
    logger.info('StreamingProcessor', 'Performing memory cleanup')

    const beforeCleanup = this.metrics.memoryUsage

    // Clear processed batches from memory
    this.processingQueue = this.processingQueue.slice(-5) // Keep only last 5 batches

    // Clear old streams
    this.activeStreams.clear()

    // Force garbage collection if available
    if (global.gc) {
      global.gc()
    }

    // Update memory metrics
    const memUsage = process.memoryUsage()
    this.metrics.memoryUsage = Math.round(memUsage.heapUsed / 1024 / 1024) // MB

    // Emit cleanup event
    this.emit('memoryCleanup', {
      beforeCleanup,
      afterCleanup: this.metrics.memoryUsage
    })

    logger.info('StreamingProcessor', `Memory cleanup completed. Before: ${beforeCleanup}MB, After: ${this.metrics.memoryUsage}MB`)
  }

  /**
   * Get current metrics
   */
  getMetrics(): StreamingMetrics {
    return { ...this.metrics }
  }

  /**
   * Stop all processing and cleanup
   */
  async stop(): Promise<void> {
    logger.info('StreamingProcessor', 'Stopping streaming processor')
    
    this.isProcessing = false
    this.processingQueue = []
    this.activeStreams.clear()
    
    if (this.memoryMonitor) {
      clearInterval(this.memoryMonitor)
    }
    
    if (this.performanceMonitor) {
      clearInterval(this.performanceMonitor)
    }
    
    this.emit('stopped')
  }
}

// Export singleton instance
export const streamingProcessor = new StreamingDataProcessor()
