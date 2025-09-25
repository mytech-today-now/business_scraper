/**
 * Memory-Efficient Data Processor
 * Optimized for processing large datasets with minimal memory footprint
 */

import { logger } from '@/utils/logger'
import { memoryMonitor } from './memory-monitor'
import { memoryCleanup } from './memory-cleanup'
import { BusinessRecord } from '@/types/business'
import { EventEmitter } from 'events'

export interface ProcessingOptions {
  batchSize?: number
  maxConcurrency?: number
  memoryThreshold?: number
  enableGarbageCollection?: boolean
  progressCallback?: (progress: ProcessingProgress) => void
}

export interface ProcessingProgress {
  processed: number
  total: number
  percentage: number
  memoryUsage: number
  estimatedTimeRemaining: number
  currentBatch: number
  totalBatches: number
}

export interface ProcessingResult<T> {
  success: boolean
  data: T[]
  processed: number
  errors: string[]
  memoryStats: {
    initialMemory: number
    peakMemory: number
    finalMemory: number
    memoryFreed: number
  }
  duration: number
}

export class MemoryEfficientProcessor<T> extends EventEmitter {
  private isProcessing: boolean = false
  private shouldStop: boolean = false
  private currentMemoryUsage: number = 0
  private peakMemoryUsage: number = 0
  private initialMemoryUsage: number = 0

  constructor() {
    super()
  }

  /**
   * Process large dataset with memory optimization
   */
  async processDataset<R>(
    data: T[],
    processor: (batch: T[]) => Promise<R[]>,
    options: ProcessingOptions = {}
  ): Promise<ProcessingResult<R>> {
    const {
      batchSize = 100,
      maxConcurrency = 2,
      memoryThreshold = 400 * 1024 * 1024, // 400MB
      enableGarbageCollection = true,
      progressCallback,
    } = options

    if (this.isProcessing) {
      throw new Error('Processor is already running')
    }

    this.isProcessing = true
    this.shouldStop = false
    this.initialMemoryUsage = this.getCurrentMemoryUsage()
    this.currentMemoryUsage = this.initialMemoryUsage
    this.peakMemoryUsage = this.initialMemoryUsage

    const startTime = Date.now()
    const total = data.length
    const totalBatches = Math.ceil(total / batchSize)
    let processed = 0
    const results: R[] = []
    const errors: string[] = []

    logger.info('MemoryEfficientProcessor', `Starting processing: ${total} items in ${totalBatches} batches`)

    try {
      // Process data in batches
      for (let batchIndex = 0; batchIndex < totalBatches && !this.shouldStop; batchIndex++) {
        const batchStart = batchIndex * batchSize
        const batchEnd = Math.min(batchStart + batchSize, total)
        const batch = data.slice(batchStart, batchEnd)

        // Check memory usage before processing batch
        this.updateMemoryUsage()
        
        if (this.currentMemoryUsage > memoryThreshold) {
          logger.warn('MemoryEfficientProcessor', `Memory threshold exceeded: ${this.formatBytes(this.currentMemoryUsage)}`)
          
          // Perform cleanup
          await this.performMemoryCleanup(enableGarbageCollection)
          
          // Check again after cleanup
          this.updateMemoryUsage()
          if (this.currentMemoryUsage > memoryThreshold) {
            throw new Error(`Memory usage still too high after cleanup: ${this.formatBytes(this.currentMemoryUsage)}`)
          }
        }

        try {
          // Process batch with concurrency control
          const batchResults = await this.processBatchWithConcurrency(batch, processor, maxConcurrency)
          results.push(...batchResults)
          processed += batch.length

          // Update progress
          const progress: ProcessingProgress = {
            processed,
            total,
            percentage: (processed / total) * 100,
            memoryUsage: this.currentMemoryUsage,
            estimatedTimeRemaining: this.calculateETA(startTime, processed, total),
            currentBatch: batchIndex + 1,
            totalBatches,
          }

          if (progressCallback) {
            progressCallback(progress)
          }

          this.emit('progress', progress)

          // Periodic memory cleanup
          if ((batchIndex + 1) % 5 === 0 && enableGarbageCollection) {
            await this.performMemoryCleanup(true)
          }

          // Small delay to allow other operations
          await this.sleep(10)

        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error'
          errors.push(`Batch ${batchIndex + 1}: ${errorMessage}`)
          logger.error('MemoryEfficientProcessor', `Error processing batch ${batchIndex + 1}`, error)
        }
      }

      // Final cleanup
      await this.performMemoryCleanup(enableGarbageCollection)
      this.updateMemoryUsage()

      const duration = Date.now() - startTime
      const result: ProcessingResult<R> = {
        success: errors.length === 0,
        data: results,
        processed,
        errors,
        memoryStats: {
          initialMemory: this.initialMemoryUsage,
          peakMemory: this.peakMemoryUsage,
          finalMemory: this.currentMemoryUsage,
          memoryFreed: this.peakMemoryUsage - this.currentMemoryUsage,
        },
        duration,
      }

      logger.info('MemoryEfficientProcessor', 'Processing completed', {
        processed,
        total,
        errors: errors.length,
        duration,
        memoryFreed: this.formatBytes(result.memoryStats.memoryFreed),
      })

      this.emit('completed', result)
      return result

    } catch (error) {
      logger.error('MemoryEfficientProcessor', 'Processing failed', error)
      throw error
    } finally {
      this.isProcessing = false
    }
  }

  /**
   * Process batch with concurrency control
   */
  private async processBatchWithConcurrency<R>(
    batch: T[],
    processor: (batch: T[]) => Promise<R[]>,
    maxConcurrency: number
  ): Promise<R[]> {
    if (maxConcurrency === 1) {
      return processor(batch)
    }

    // Split batch into smaller chunks for concurrent processing
    const chunkSize = Math.ceil(batch.length / maxConcurrency)
    const chunks: T[][] = []
    
    for (let i = 0; i < batch.length; i += chunkSize) {
      chunks.push(batch.slice(i, i + chunkSize))
    }

    // Process chunks concurrently
    const chunkPromises = chunks.map(chunk => processor(chunk))
    const chunkResults = await Promise.all(chunkPromises)

    // Flatten results
    return chunkResults.flat()
  }

  /**
   * Perform memory cleanup
   */
  private async performMemoryCleanup(enableGarbageCollection: boolean): Promise<void> {
    try {
      // Trigger memory cleanup
      await memoryCleanup.performAutomaticCleanup()

      // Force garbage collection if enabled
      if (enableGarbageCollection) {
        memoryMonitor.forceGarbageCollection()
      }

      // Small delay to allow cleanup to complete
      await this.sleep(100)

    } catch (error) {
      logger.warn('MemoryEfficientProcessor', 'Memory cleanup failed', error)
    }
  }

  /**
   * Update current memory usage
   */
  private updateMemoryUsage(): void {
    this.currentMemoryUsage = this.getCurrentMemoryUsage()
    if (this.currentMemoryUsage > this.peakMemoryUsage) {
      this.peakMemoryUsage = this.currentMemoryUsage
    }
  }

  /**
   * Get current memory usage
   */
  private getCurrentMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed
    } else if (typeof window !== 'undefined' && 'performance' in window && 'memory' in performance) {
      return (performance as any).memory.usedJSHeapSize
    }
    return 0
  }

  /**
   * Calculate estimated time remaining
   */
  private calculateETA(startTime: number, processed: number, total: number): number {
    if (processed === 0) return 0
    
    const elapsed = Date.now() - startTime
    const rate = processed / elapsed
    const remaining = total - processed
    
    return remaining / rate
  }

  /**
   * Format bytes to human readable format
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Stop processing
   */
  stop(): void {
    this.shouldStop = true
    logger.info('MemoryEfficientProcessor', 'Stop requested')
  }

  /**
   * Get processing status
   */
  getStatus(): {
    isProcessing: boolean
    currentMemoryUsage: number
    peakMemoryUsage: number
  } {
    return {
      isProcessing: this.isProcessing,
      currentMemoryUsage: this.currentMemoryUsage,
      peakMemoryUsage: this.peakMemoryUsage,
    }
  }
}

/**
 * Utility function for processing business records with memory optimization
 */
export async function processBusinessRecords<R>(
  businesses: BusinessRecord[],
  processor: (batch: BusinessRecord[]) => Promise<R[]>,
  options: ProcessingOptions = {}
): Promise<ProcessingResult<R>> {
  const memoryProcessor = new MemoryEfficientProcessor<BusinessRecord>()
  
  try {
    return await memoryProcessor.processDataset(businesses, processor, options)
  } finally {
    memoryProcessor.removeAllListeners()
  }
}

/**
 * Utility function for streaming data processing
 */
export function createMemoryEfficientStream<T, R>(
  processor: (item: T) => Promise<R>,
  options: { batchSize?: number; memoryThreshold?: number } = {}
) {
  const { batchSize = 50, memoryThreshold = 300 * 1024 * 1024 } = options
  let buffer: T[] = []
  let processing = false

  return new TransformStream<T, R>({
    async transform(chunk, controller) {
      buffer.push(chunk)

      if (buffer.length >= batchSize && !processing) {
        processing = true
        
        try {
          // Check memory usage
          const currentMemory = typeof process !== 'undefined' && process.memoryUsage
            ? process.memoryUsage().heapUsed
            : 0

          if (currentMemory > memoryThreshold) {
            // Perform cleanup before processing
            await memoryCleanup.performAutomaticCleanup()
            memoryMonitor.forceGarbageCollection()
          }

          // Process batch
          const batch = buffer.splice(0, batchSize)
          for (const item of batch) {
            const result = await processor(item)
            controller.enqueue(result)
          }

        } catch (error) {
          logger.error('MemoryEfficientStream', 'Processing error', error)
          controller.error(error)
        } finally {
          processing = false
        }
      }
    },

    async flush(controller) {
      // Process remaining items
      if (buffer.length > 0) {
        try {
          for (const item of buffer) {
            const result = await processor(item)
            controller.enqueue(result)
          }
        } catch (error) {
          logger.error('MemoryEfficientStream', 'Flush error', error)
          controller.error(error)
        }
      }
    }
  })
}

// Create singleton instance for global use
export const memoryEfficientProcessor = new MemoryEfficientProcessor()
