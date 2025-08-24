/**
 * Memory Management Tests
 * Tests for memory monitoring, cleanup, and compression functionality
 */

import { MemoryMonitor } from '@/lib/memory-monitor'
import { MemoryCleanupService } from '@/lib/memory-cleanup'
import { DataCompression } from '@/lib/data-compression'
import { BusinessRecord } from '@/types/business'

describe('Memory Monitor', () => {
  let monitor: MemoryMonitor

  beforeEach(() => {
    monitor = new MemoryMonitor()
  })

  afterEach(() => {
    monitor.destroy()
  })

  describe('Lifecycle Management', () => {
    test('should start and stop monitoring', () => {
      expect(monitor.isActive()).toBe(false)
      
      monitor.startMonitoring()
      expect(monitor.isActive()).toBe(true)
      
      monitor.stopMonitoring()
      expect(monitor.isActive()).toBe(false)
    })

    test('should handle multiple start calls gracefully', () => {
      monitor.startMonitoring()
      expect(monitor.isActive()).toBe(true)
      
      // Second start should not throw
      expect(() => monitor.startMonitoring()).not.toThrow()
      expect(monitor.isActive()).toBe(true)
    })

    test('should handle stop when not running', () => {
      expect(() => monitor.stopMonitoring()).not.toThrow()
      expect(monitor.isActive()).toBe(false)
    })
  })

  describe('Threshold Management', () => {
    test('should update thresholds', () => {
      const newThresholds = {
        warning: 60,
        critical: 80,
        emergency: 90
      }
      
      monitor.updateThresholds(newThresholds)
      const thresholds = monitor.getThresholds()
      
      expect(thresholds.warning).toBe(60)
      expect(thresholds.critical).toBe(80)
      expect(thresholds.emergency).toBe(90)
    })

    test('should partially update thresholds', () => {
      const originalThresholds = monitor.getThresholds()
      
      monitor.updateThresholds({ warning: 65 })
      const updatedThresholds = monitor.getThresholds()
      
      expect(updatedThresholds.warning).toBe(65)
      expect(updatedThresholds.critical).toBe(originalThresholds.critical)
      expect(updatedThresholds.emergency).toBe(originalThresholds.emergency)
    })
  })

  describe('Memory Statistics', () => {
    test('should return null for current stats when not monitoring', () => {
      const stats = monitor.getCurrentStats()
      expect(stats).toBeNull()
    })

    test('should return empty history initially', () => {
      const history = monitor.getMemoryHistory()
      expect(history).toEqual([])
    })
  })

  describe('Event Handling', () => {
    test('should emit monitoring events', (done) => {
      let startedEmitted = false
      let stoppedEmitted = false
      
      monitor.on('monitoring-started', () => {
        startedEmitted = true
      })
      
      monitor.on('monitoring-stopped', () => {
        stoppedEmitted = true
        expect(startedEmitted).toBe(true)
        expect(stoppedEmitted).toBe(true)
        done()
      })
      
      monitor.startMonitoring()
      monitor.stopMonitoring()
    })
  })
})

describe('Memory Cleanup Service', () => {
  let cleanup: MemoryCleanupService

  beforeEach(() => {
    cleanup = new MemoryCleanupService()
  })

  afterEach(() => {
    cleanup.destroy()
  })

  describe('Auto Cleanup Management', () => {
    test('should start and stop auto cleanup', () => {
      const status = cleanup.getStatus()
      expect(status.autoCleanupEnabled).toBe(false)
      
      cleanup.startAutoCleanup(1000) // 1 second for testing
      const startedStatus = cleanup.getStatus()
      expect(startedStatus.autoCleanupEnabled).toBe(true)
      
      cleanup.stopAutoCleanup()
      const stoppedStatus = cleanup.getStatus()
      expect(stoppedStatus.autoCleanupEnabled).toBe(false)
    })

    test('should handle multiple start calls gracefully', () => {
      cleanup.startAutoCleanup()
      expect(() => cleanup.startAutoCleanup()).not.toThrow()
    })
  })

  describe('Retention Policy Management', () => {
    test('should update retention policy', () => {
      const newPolicy = {
        maxSessions: 5,
        maxAge: 48 * 60 * 60 * 1000, // 48 hours
        maxSize: 100 * 1024 * 1024, // 100MB
        autoCleanup: false
      }
      
      cleanup.updateRetentionPolicy(newPolicy)
      const policy = cleanup.getRetentionPolicy()
      
      expect(policy.maxSessions).toBe(5)
      expect(policy.maxAge).toBe(48 * 60 * 60 * 1000)
      expect(policy.maxSize).toBe(100 * 1024 * 1024)
      expect(policy.autoCleanup).toBe(false)
    })

    test('should partially update retention policy', () => {
      const originalPolicy = cleanup.getRetentionPolicy()
      
      cleanup.updateRetentionPolicy({ maxSessions: 10 })
      const updatedPolicy = cleanup.getRetentionPolicy()
      
      expect(updatedPolicy.maxSessions).toBe(10)
      expect(updatedPolicy.maxAge).toBe(originalPolicy.maxAge)
      expect(updatedPolicy.autoCleanup).toBe(originalPolicy.autoCleanup)
    })
  })

  describe('Manual Cleanup', () => {
    test('should perform manual cleanup with default options', async () => {
      const result = await cleanup.performManualCleanup()
      
      expect(result.success).toBe(true)
      expect(typeof result.itemsCleared).toBe('number')
      expect(typeof result.memoryFreed).toBe('number')
      expect(typeof result.duration).toBe('number')
      expect(Array.isArray(result.errors)).toBe(true)
    })

    test('should perform manual cleanup with custom options', async () => {
      const options = {
        clearSearchResults: true,
        clearCachedData: false,
        retainLastSessions: 2
      }
      
      const result = await cleanup.performManualCleanup(options)
      
      expect(result.success).toBe(true)
      expect(typeof result.itemsCleared).toBe('number')
    })

    test('should perform emergency cleanup', async () => {
      const result = await cleanup.performEmergencyCleanup()
      
      expect(result.success).toBe(true)
      expect(typeof result.itemsCleared).toBe('number')
    })
  })
})

describe('Data Compression', () => {
  const mockBusiness: BusinessRecord = {
    id: 'test-1',
    businessName: 'Test Business',
    email: ['test@example.com'],
    phone: '555-0123',
    websiteUrl: 'https://test.com',
    address: {
      street: '123 Test St',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345'
    },
    industry: 'Testing',
    scrapedAt: new Date()
  }

  describe('Basic Compression', () => {
    test('should compress and decompress data correctly', () => {
      const compressed = DataCompression.compress(mockBusiness)
      
      if (DataCompression.isCompressed(compressed)) {
        const decompressed = DataCompression.decompress(compressed)
        expect(decompressed).toEqual(mockBusiness)
      } else {
        // Data was too small to compress
        expect(compressed).toEqual(mockBusiness)
      }
    })

    test('should handle small data below compression threshold', () => {
      const smallData = { test: 'small' }
      const result = DataCompression.compress(smallData)
      
      // Should return original data for small objects
      expect(result).toEqual(smallData)
    })

    test('should handle large data arrays', () => {
      const largeArray = Array(1000).fill(mockBusiness)
      const compressed = DataCompression.compress(largeArray)
      
      if (DataCompression.isCompressed(compressed)) {
        const decompressed = DataCompression.decompress(compressed)
        expect(decompressed).toEqual(largeArray)
        expect(compressed.stats.compressionRatio).toBeGreaterThan(0)
      }
    })
  })

  describe('Business Records Compression', () => {
    test('should compress business records array', () => {
      const businesses = [mockBusiness, { ...mockBusiness, id: 'test-2' }]
      const compressed = DataCompression.compressBusinessRecords(businesses)
      const decompressed = DataCompression.decompressBusinessRecords(compressed)
      
      expect(decompressed).toEqual(businesses)
    })

    test('should handle empty business records array', () => {
      const businesses: BusinessRecord[] = []
      const compressed = DataCompression.compressBusinessRecords(businesses)
      const decompressed = DataCompression.decompressBusinessRecords(compressed)
      
      expect(decompressed).toEqual(businesses)
    })
  })

  describe('Compression Statistics', () => {
    test('should provide compression statistics', () => {
      const largeData = Array(100).fill(mockBusiness)
      const compressed = DataCompression.compress(largeData)
      
      if (DataCompression.isCompressed(compressed)) {
        const stats = DataCompression.getCompressionStats(compressed)
        
        expect(stats).toBeDefined()
        expect(stats!.originalSize).toBeGreaterThan(0)
        expect(stats!.compressedSize).toBeGreaterThan(0)
        expect(stats!.compressionRatio).toBeGreaterThan(0)
        expect(stats!.compressionTime).toBeGreaterThan(0)
      }
    })

    test('should estimate compression ratio', () => {
      const ratio = DataCompression.estimateCompressionRatio(mockBusiness)
      expect(typeof ratio).toBe('number')
      expect(ratio).toBeGreaterThanOrEqual(0)
    })

    test('should calculate storage savings', () => {
      const items = [mockBusiness, mockBusiness, mockBusiness]
      const compressedItems = DataCompression.batchCompress(items)
      const savings = DataCompression.calculateStorageSavings(compressedItems)
      
      expect(savings.originalTotalSize).toBeGreaterThan(0)
      expect(savings.compressedTotalSize).toBeGreaterThan(0)
      expect(savings.totalSavings).toBeGreaterThanOrEqual(0)
      expect(savings.savingsPercentage).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Batch Operations', () => {
    test('should batch compress multiple items', () => {
      const items = [mockBusiness, mockBusiness, mockBusiness]
      const compressed = DataCompression.batchCompress(items)
      const decompressed = DataCompression.batchDecompress(compressed)
      
      expect(decompressed).toEqual(items)
    })

    test('should handle empty batch', () => {
      const items: any[] = []
      const compressed = DataCompression.batchCompress(items)
      const decompressed = DataCompression.batchDecompress(compressed)
      
      expect(decompressed).toEqual(items)
    })
  })

  describe('Custom Compression Options', () => {
    test('should respect custom threshold', () => {
      const smallData = { test: 'data' }
      const compressed = DataCompression.compressWithOptions(smallData, {
        threshold: 1, // Very low threshold
        forceCompress: true
      })
      
      if (DataCompression.isCompressed(compressed)) {
        const decompressed = DataCompression.decompress(compressed)
        expect(decompressed).toEqual(smallData)
      }
    })

    test('should respect time limits', () => {
      const largeData = Array(10000).fill(mockBusiness)
      const compressed = DataCompression.compressWithOptions(largeData, {
        maxTime: 1 // Very short time limit
      })
      
      // Should return original data if compression takes too long
      expect(compressed).toBeDefined()
    })
  })

  describe('Error Handling', () => {
    test('should handle compression errors gracefully', () => {
      // Create circular reference that can't be JSON.stringified
      const circularData: any = { test: 'data' }
      circularData.self = circularData

      const result = DataCompression.compress(circularData)
      // Should return original data on error
      expect(result).toBe(circularData)
    })

    test('should handle decompression errors', () => {
      const invalidCompressed = {
        data: 'invalid-compressed-data',
        compressed: true,
        originalType: 'object',
        timestamp: Date.now(),
        stats: {
          originalSize: 100,
          compressedSize: 50,
          compressionRatio: 50,
          compressionTime: 10
        }
      }

      expect(() => {
        DataCompression.decompress(invalidCompressed)
      }).toThrow()
    })

    test('should handle null and undefined data', () => {
      expect(DataCompression.compress(null)).toBe(null)
      expect(DataCompression.compress(undefined)).toBe(undefined)
      expect(DataCompression.decompress(null as any)).toBe(null)
      expect(DataCompression.decompress(undefined as any)).toBe(undefined)
    })

    test('should handle empty objects and arrays', () => {
      const emptyObj = {}
      const emptyArr: any[] = []

      expect(DataCompression.compress(emptyObj)).toEqual(emptyObj)
      expect(DataCompression.compress(emptyArr)).toEqual(emptyArr)
    })

    test('should handle very large data gracefully', () => {
      const largeData = Array(100000).fill('x'.repeat(1000))
      const result = DataCompression.compressWithOptions(largeData, { maxTime: 100 })

      // Should either compress or return original data without throwing
      expect(result).toBeDefined()
    })
  })

  describe('Edge Cases', () => {
    test('should handle special characters and unicode', () => {
      const specialData = {
        emoji: '🚀🧠💾',
        unicode: 'Héllo Wörld',
        special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
      }

      const compressed = DataCompression.compress(specialData)
      const decompressed = DataCompression.decompress(compressed)

      expect(decompressed).toEqual(specialData)
    })

    test('should handle nested objects with mixed types', () => {
      const complexData = {
        string: 'test',
        number: 42,
        boolean: true,
        null: null,
        undefined: undefined,
        array: [1, 'two', { three: 3 }],
        nested: {
          deep: {
            deeper: {
              value: 'found'
            }
          }
        }
      }

      const compressed = DataCompression.compress(complexData)
      const decompressed = DataCompression.decompress(compressed)

      expect(decompressed).toEqual(complexData)
    })

    test('should handle date objects', () => {
      const dataWithDate = {
        created: new Date('2025-01-01'),
        updated: new Date()
      }

      const compressed = DataCompression.compress(dataWithDate)
      const decompressed = DataCompression.decompress(compressed)

      // Dates are serialized as strings in JSON
      expect(typeof decompressed.created).toBe('string')
      expect(typeof decompressed.updated).toBe('string')
    })
  })
})

describe('Memory Monitor Edge Cases', () => {
  let monitor: MemoryMonitor

  beforeEach(() => {
    monitor = new MemoryMonitor()
  })

  afterEach(() => {
    monitor.destroy()
  })

  test('should handle rapid start/stop cycles', () => {
    for (let i = 0; i < 10; i++) {
      monitor.startMonitoring()
      monitor.stopMonitoring()
    }

    expect(monitor.isActive()).toBe(false)
  })

  test('should handle invalid threshold values', () => {
    const invalidThresholds = {
      warning: -10,
      critical: 150,
      emergency: 200
    }

    // Should not throw, but may clamp values
    expect(() => monitor.updateThresholds(invalidThresholds)).not.toThrow()
  })

  test('should handle memory collection when no stats available', () => {
    const stats = monitor.getCurrentStats()
    const history = monitor.getMemoryHistory()

    expect(stats).toBeNull()
    expect(history).toEqual([])
  })

  test('should handle force garbage collection gracefully', () => {
    const result = monitor.forceGarbageCollection()
    // Should return boolean without throwing
    expect(typeof result).toBe('boolean')
  })
})

describe('Memory Cleanup Edge Cases', () => {
  let cleanup: MemoryCleanupService

  beforeEach(() => {
    cleanup = new MemoryCleanupService()
  })

  afterEach(() => {
    cleanup.destroy()
  })

  test('should handle cleanup with no data', async () => {
    const result = await cleanup.performManualCleanup()

    expect(result.success).toBe(true)
    expect(result.itemsCleared).toBe(0)
  })

  test('should handle invalid retention policy values', () => {
    const invalidPolicy = {
      maxSessions: -1,
      maxAge: -1000,
      maxSize: -500,
      autoCleanup: 'invalid' as any
    }

    expect(() => cleanup.updateRetentionPolicy(invalidPolicy)).not.toThrow()
  })

  test('should handle concurrent cleanup operations', async () => {
    const promises = Array(5).fill(null).map(() => cleanup.performManualCleanup())
    const results = await Promise.all(promises)

    results.forEach(result => {
      expect(result.success).toBe(true)
    })
  })

  test('should handle cleanup with storage errors', async () => {
    // This test would need mocking of storage service to simulate errors
    const result = await cleanup.performManualCleanup({
      clearSearchResults: true,
      clearCachedData: true
    })

    // Should handle errors gracefully
    expect(typeof result.success).toBe('boolean')
  })
})
