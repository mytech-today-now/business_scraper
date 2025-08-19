/**
 * Streaming Export Service
 * Memory-efficient export of large datasets to various formats
 */

import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'
import { Readable, Transform } from 'stream'
import { pipeline } from 'stream/promises'

export interface ExportOptions {
  format: 'csv' | 'json' | 'xlsx'
  batchSize?: number
  includeHeaders?: boolean
  compression?: boolean
}

export interface ExportProgress {
  processed: number
  total: number
  percentage: number
  estimatedTimeRemaining: number
  status: 'preparing' | 'exporting' | 'completed' | 'error'
}

/**
 * Streaming Export Service for memory-efficient data export
 */
export class StreamingExportService {
  private activeExports: Map<string, boolean> = new Map()

  /**
   * Create a streaming CSV export
   */
  createStreamingCSV(businesses: BusinessRecord[]): ReadableStream<Uint8Array> {
    const encoder = new TextEncoder()
    let index = 0
    let headerSent = false

    return new ReadableStream({
      start(controller) {
        logger.info('StreamingExport', `Starting CSV export for ${businesses.length} businesses`)
      },

      async pull(controller) {
        try {
          // Send CSV header first
          if (!headerSent) {
            const header = 'Name,Phone,Email,Website,Address,City,State,ZIP,Industry,Description\n'
            controller.enqueue(encoder.encode(header))
            headerSent = true
            return
          }

          // Process businesses in batches
          const batchSize = 100
          const batch = businesses.slice(index, index + batchSize)

          if (batch.length === 0) {
            controller.close()
            return
          }

          for (const business of batch) {
            const csvRow = this.businessToCSV(business)
            controller.enqueue(encoder.encode(csvRow + '\n'))
          }

          index += batchSize

          // Allow other operations to proceed
          await new Promise(resolve => setTimeout(resolve, 0))
        } catch (error) {
          logger.error('StreamingExport', 'CSV export error', error)
          controller.error(error)
        }
      }
    })
  }

  /**
   * Create a streaming JSON export
   */
  createStreamingJSON(businesses: BusinessRecord[]): ReadableStream<Uint8Array> {
    const encoder = new TextEncoder()
    let index = 0
    let isFirst = true

    return new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('['))
        logger.info('StreamingExport', `Starting JSON export for ${businesses.length} businesses`)
      },

      async pull(controller) {
        try {
          const batchSize = 50
          const batch = businesses.slice(index, index + batchSize)

          if (batch.length === 0) {
            controller.enqueue(encoder.encode(']'))
            controller.close()
            return
          }

          for (const business of batch) {
            const prefix = isFirst ? '' : ','
            const jsonData = JSON.stringify(business, null, 2)
            controller.enqueue(encoder.encode(prefix + jsonData))
            isFirst = false
          }

          index += batchSize

          // Allow other operations to proceed
          await new Promise(resolve => setTimeout(resolve, 0))
        } catch (error) {
          logger.error('StreamingExport', 'JSON export error', error)
          controller.error(error)
        }
      }
    })
  }

  /**
   * Process large dataset with memory management
   */
  async processLargeDataset(
    businesses: BusinessRecord[],
    processor: (batch: BusinessRecord[]) => Promise<void>,
    options: { batchSize?: number; onProgress?: (progress: ExportProgress) => void } = {}
  ): Promise<void> {
    const { batchSize = 500, onProgress } = options
    const total = businesses.length
    let processed = 0
    const startTime = Date.now()

    logger.info('StreamingExport', `Processing large dataset: ${total} records`)

    for (let i = 0; i < total; i += batchSize) {
      const batch = businesses.slice(i, i + batchSize)
      
      try {
        await processor(batch)
        processed += batch.length

        // Report progress
        if (onProgress) {
          const elapsed = Date.now() - startTime
          const rate = processed / elapsed
          const remaining = total - processed
          const estimatedTimeRemaining = remaining / rate

          onProgress({
            processed,
            total,
            percentage: (processed / total) * 100,
            estimatedTimeRemaining,
            status: processed >= total ? 'completed' : 'exporting'
          })
        }

        // Clear processed data from memory
        batch.length = 0

        // Force garbage collection hint
        if (global.gc) {
          global.gc()
        }

        // Small delay to prevent overwhelming
        await new Promise(resolve => setTimeout(resolve, 10))
      } catch (error) {
        logger.error('StreamingExport', `Failed to process batch at index ${i}`, error)
        throw error
      }
    }

    logger.info('StreamingExport', `Completed processing ${processed} records`)
  }

  /**
   * Export with streaming and progress tracking
   */
  async exportWithProgress(
    businesses: BusinessRecord[],
    format: 'csv' | 'json',
    onProgress: (progress: ExportProgress) => void,
    onChunk: (chunk: Uint8Array) => void
  ): Promise<void> {
    const exportId = `export-${Date.now()}`
    this.activeExports.set(exportId, true)

    try {
      onProgress({
        processed: 0,
        total: businesses.length,
        percentage: 0,
        estimatedTimeRemaining: 0,
        status: 'preparing'
      })

      const stream = format === 'csv' 
        ? this.createStreamingCSV(businesses)
        : this.createStreamingJSON(businesses)

      const reader = stream.getReader()
      let processed = 0
      const startTime = Date.now()

      while (this.activeExports.get(exportId)) {
        const { done, value } = await reader.read()

        if (done) {
          onProgress({
            processed: businesses.length,
            total: businesses.length,
            percentage: 100,
            estimatedTimeRemaining: 0,
            status: 'completed'
          })
          break
        }

        if (value) {
          onChunk(value)
          processed += value.length

          // Estimate progress based on data size
          const estimatedTotal = businesses.length * 200 // Rough estimate
          const percentage = Math.min((processed / estimatedTotal) * 100, 99)
          
          const elapsed = Date.now() - startTime
          const rate = processed / elapsed
          const remaining = estimatedTotal - processed
          const estimatedTimeRemaining = remaining / rate

          onProgress({
            processed: Math.floor((percentage / 100) * businesses.length),
            total: businesses.length,
            percentage,
            estimatedTimeRemaining,
            status: 'exporting'
          })
        }
      }
    } catch (error) {
      logger.error('StreamingExport', `Export failed for ${exportId}`, error)
      onProgress({
        processed: 0,
        total: businesses.length,
        percentage: 0,
        estimatedTimeRemaining: 0,
        status: 'error'
      })
      throw error
    } finally {
      this.activeExports.delete(exportId)
    }
  }

  /**
   * Convert business record to CSV row
   */
  private businessToCSV(business: BusinessRecord): string {
    const fields = [
      business.name || '',
      business.phone || '',
      business.email || '',
      business.website || '',
      business.address || '',
      business.city || '',
      business.state || '',
      business.zipCode || '',
      business.industry || '',
      business.description || ''
    ]

    // Escape CSV fields
    return fields.map(field => {
      const escaped = String(field).replace(/"/g, '""')
      return field.includes(',') || field.includes('"') || field.includes('\n') 
        ? `"${escaped}"` 
        : escaped
    }).join(',')
  }

  /**
   * Create memory-efficient data processor
   */
  createDataProcessor<T>(
    processor: (item: T) => Promise<T>,
    options: { concurrency?: number; batchSize?: number } = {}
  ): Transform {
    const { concurrency = 3, batchSize = 100 } = options
    let buffer: T[] = []
    let processing = false

    return new Transform({
      objectMode: true,
      
      async transform(chunk: T, encoding, callback) {
        buffer.push(chunk)

        if (buffer.length >= batchSize && !processing) {
          processing = true
          const batch = buffer.splice(0, batchSize)

          try {
            // Process batch with limited concurrency
            const promises = batch.map(item => processor(item))
            const results = await Promise.allSettled(promises)

            for (const result of results) {
              if (result.status === 'fulfilled') {
                this.push(result.value)
              }
            }
          } catch (error) {
            callback(error)
            return
          }

          processing = false
        }

        callback()
      },

      async flush(callback) {
        // Process remaining items
        if (buffer.length > 0) {
          try {
            const promises = buffer.map(item => processor(item))
            const results = await Promise.allSettled(promises)

            for (const result of results) {
              if (result.status === 'fulfilled') {
                this.push(result.value)
              }
            }
          } catch (error) {
            callback(error)
            return
          }
        }

        callback()
      }
    })
  }

  /**
   * Cancel an active export
   */
  cancelExport(exportId: string): void {
    this.activeExports.set(exportId, false)
    logger.info('StreamingExport', `Cancelled export ${exportId}`)
  }

  /**
   * Get active export count
   */
  getActiveExportCount(): number {
    return Array.from(this.activeExports.values()).filter(active => active).length
  }
}

/**
 * Default streaming export service instance
 */
export const streamingExportService = new StreamingExportService()
