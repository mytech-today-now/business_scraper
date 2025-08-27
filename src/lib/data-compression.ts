/**
 * Data Compression Utilities
 * Provides transparent compression/decompression for IndexedDB storage
 */

import LZString from 'lz-string'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface CompressionStats {
  originalSize: number
  compressedSize: number
  compressionRatio: number
  compressionTime: number
}

export interface CompressedData<T = any> {
  data: string
  compressed: true
  originalType: string
  timestamp: number
  stats: CompressionStats
}

export class DataCompression {
  private static readonly COMPRESSION_THRESHOLD = 1024 // 1KB - only compress data larger than this
  private static readonly MAX_COMPRESSION_TIME = 5000 // 5 seconds max compression time

  /**
   * Compress data using LZ-String
   */
  static compress<T>(data: T): CompressedData<T> | T {
    const startTime = Date.now()

    try {
      // Convert data to JSON string
      const jsonString = JSON.stringify(data)
      const originalSize = new Blob([jsonString]).size

      // Only compress if data is larger than threshold
      if (originalSize < this.COMPRESSION_THRESHOLD) {
        logger.debug(
          'DataCompression',
          `Data size ${originalSize} bytes below compression threshold`
        )
        return data
      }

      // Compress the data
      const compressed = LZString.compress(jsonString)
      const compressionTime = Date.now() - startTime

      // Check if compression took too long
      if (compressionTime > this.MAX_COMPRESSION_TIME) {
        logger.warn(
          'DataCompression',
          `Compression took ${compressionTime}ms, returning original data`
        )
        return data
      }

      if (!compressed) {
        logger.warn('DataCompression', 'Compression failed, returning original data')
        return data
      }

      const compressedSize = new Blob([compressed]).size
      const compressionRatio = (1 - compressedSize / originalSize) * 100

      const stats: CompressionStats = {
        originalSize,
        compressedSize,
        compressionRatio,
        compressionTime,
      }

      logger.debug(
        'DataCompression',
        `Compressed data: ${originalSize} -> ${compressedSize} bytes (${compressionRatio.toFixed(1)}% reduction)`
      )

      return {
        data: compressed,
        compressed: true,
        originalType: typeof data,
        timestamp: Date.now(),
        stats,
      }
    } catch (error) {
      logger.error('DataCompression', 'Compression failed', error)
      return data
    }
  }

  /**
   * Decompress data
   */
  static decompress<T>(data: CompressedData<T> | T): T {
    try {
      // Check if data is compressed
      if (!this.isCompressed(data)) {
        return data as T
      }

      const startTime = Date.now()
      const decompressed = LZString.decompress(data.data)
      const decompressionTime = Date.now() - startTime

      if (!decompressed) {
        logger.error('DataCompression', 'Decompression failed, returning null')
        throw new Error('Decompression failed')
      }

      const result = JSON.parse(decompressed) as T

      logger.debug('DataCompression', `Decompressed data in ${decompressionTime}ms`)

      return result
    } catch (error) {
      logger.error('DataCompression', 'Decompression failed', error)
      throw error
    }
  }

  /**
   * Check if data is compressed
   */
  static isCompressed<T>(data: any): data is CompressedData<T> {
    return (
      typeof data === 'object' &&
      data !== null &&
      data.compressed === true &&
      typeof data.data === 'string' &&
      typeof data.originalType === 'string' &&
      typeof data.timestamp === 'number'
    )
  }

  /**
   * Compress business records array
   */
  static compressBusinessRecords(
    records: BusinessRecord[]
  ): CompressedData<BusinessRecord[]> | BusinessRecord[] {
    return this.compress(records)
  }

  /**
   * Decompress business records array
   */
  static decompressBusinessRecords(
    data: CompressedData<BusinessRecord[]> | BusinessRecord[]
  ): BusinessRecord[] {
    return this.decompress(data)
  }

  /**
   * Compress search results with metadata
   */
  static compressSearchResults(results: {
    businesses: BusinessRecord[]
    metadata: any
    timestamp: number
  }): CompressedData | any {
    return this.compress(results)
  }

  /**
   * Get compression statistics for data
   */
  static getCompressionStats(data: any): CompressionStats | null {
    if (this.isCompressed(data)) {
      return data.stats
    }
    return null
  }

  /**
   * Estimate compression ratio for data
   */
  static estimateCompressionRatio(data: any): number {
    try {
      const jsonString = JSON.stringify(data)
      const originalSize = new Blob([jsonString]).size

      // Quick compression test with a sample
      const sample = jsonString.substring(0, Math.min(1000, jsonString.length))
      const compressedSample = LZString.compress(sample)

      if (!compressedSample) return 0

      const sampleOriginalSize = new Blob([sample]).size
      const sampleCompressedSize = new Blob([compressedSample]).size

      return (1 - sampleCompressedSize / sampleOriginalSize) * 100
    } catch (error) {
      logger.error('DataCompression', 'Failed to estimate compression ratio', error)
      return 0
    }
  }

  /**
   * Batch compress multiple items
   */
  static batchCompress<T>(items: T[]): (CompressedData<T> | T)[] {
    return items.map(item => this.compress(item))
  }

  /**
   * Batch decompress multiple items
   */
  static batchDecompress<T>(items: (CompressedData<T> | T)[]): T[] {
    return items.map(item => this.decompress(item))
  }

  /**
   * Compress with custom options
   */
  static compressWithOptions<T>(
    data: T,
    options: {
      threshold?: number
      maxTime?: number
      forceCompress?: boolean
    } = {}
  ): CompressedData<T> | T {
    const {
      threshold = this.COMPRESSION_THRESHOLD,
      maxTime = this.MAX_COMPRESSION_TIME,
      forceCompress = false,
    } = options

    const startTime = Date.now()

    try {
      const jsonString = JSON.stringify(data)
      const originalSize = new Blob([jsonString]).size

      // Check threshold unless forced
      if (!forceCompress && originalSize < threshold) {
        return data
      }

      const compressed = LZString.compress(jsonString)
      const compressionTime = Date.now() - startTime

      // Check time limit
      if (compressionTime > maxTime) {
        logger.warn('DataCompression', `Compression exceeded time limit (${compressionTime}ms)`)
        return data
      }

      if (!compressed) {
        return data
      }

      const compressedSize = new Blob([compressed]).size
      const compressionRatio = (1 - compressedSize / originalSize) * 100

      const stats: CompressionStats = {
        originalSize,
        compressedSize,
        compressionRatio,
        compressionTime,
      }

      return {
        data: compressed,
        compressed: true,
        originalType: typeof data,
        timestamp: Date.now(),
        stats,
      }
    } catch (error) {
      logger.error('DataCompression', 'Custom compression failed', error)
      return data
    }
  }

  /**
   * Get total size of compressed vs uncompressed data
   */
  static calculateStorageSavings(items: any[]): {
    originalTotalSize: number
    compressedTotalSize: number
    totalSavings: number
    savingsPercentage: number
  } {
    let originalTotalSize = 0
    let compressedTotalSize = 0

    for (const item of items) {
      if (this.isCompressed(item)) {
        originalTotalSize += item.stats.originalSize
        compressedTotalSize += item.stats.compressedSize
      } else {
        const size = new Blob([JSON.stringify(item)]).size
        originalTotalSize += size
        compressedTotalSize += size
      }
    }

    const totalSavings = originalTotalSize - compressedTotalSize
    const savingsPercentage = originalTotalSize > 0 ? (totalSavings / originalTotalSize) * 100 : 0

    return {
      originalTotalSize,
      compressedTotalSize,
      totalSavings,
      savingsPercentage,
    }
  }
}

// Export convenience functions
export const {
  compress,
  decompress,
  isCompressed,
  compressBusinessRecords,
  decompressBusinessRecords,
  compressSearchResults,
  getCompressionStats,
  estimateCompressionRatio,
  batchCompress,
  batchDecompress,
  compressWithOptions,
  calculateStorageSavings,
} = DataCompression
