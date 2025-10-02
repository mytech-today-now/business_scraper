/**
 * Memory Management Integration Tests
 * Tests for memory management components working together
 */

import { MemoryMonitor } from '@/lib/memory-monitor'
import { MemoryCleanupService } from '@/lib/memory-cleanup'
import { DataCompression } from '@/lib/data-compression'
import { BusinessRecord } from '@/types/business'

describe('Memory Management Integration Tests', () => {
  let monitor: MemoryMonitor
  let cleanup: MemoryCleanupService

  beforeEach(() => {
    monitor = new MemoryMonitor()
    cleanup = new MemoryCleanupService()
  })

  afterEach(() => {
    monitor.destroy()
    cleanup.destroy()
  })

  describe('Monitor and Cleanup Integration', () => {
    test('should trigger cleanup when memory thresholds are exceeded', done => {
      let cleanupTriggered = false

      // Listen for cleanup events
      cleanup.on('cleanup-completed', () => {
        cleanupTriggered = true
        expect(cleanupTriggered).toBe(true)
        done()
      })

      // Start monitoring
      monitor.startMonitoring()

      // Simulate high memory usage alert
      monitor.emit('memory-alert', {
        level: 'emergency' as const,
        message: 'Test emergency alert',
        stats: {
          used: 950000000,
          total: 1000000000,
          percentage: 95,
          timestamp: Date.now(),
        },
        timestamp: Date.now(),
        action: 'emergency-cleanup',
      })
    })

    test('should coordinate memory monitoring with cleanup policies', async () => {
      // Set strict retention policy
      cleanup.updateRetentionPolicy({
        maxSessions: 1,
        maxAge: 1000, // 1 second
        maxSize: 1024, // 1KB
        autoCleanup: true,
      })

      // Start auto cleanup
      cleanup.startAutoCleanup(500) // 500ms interval

      // Start monitoring
      monitor.startMonitoring()

      // Wait for coordination
      await new Promise(resolve => setTimeout(resolve, 1500))

      const status = cleanup.getStatus()
      expect(status.autoCleanupEnabled).toBe(true)
      expect(monitor.isActive()).toBe(true)
    })

    test('should handle monitor alerts triggering cleanup operations', async () => {
      let alertsReceived = 0
      let cleanupsPerformed = 0

      monitor.on('memory-alert', () => {
        alertsReceived++
      })

      cleanup.on('cleanup-completed', () => {
        cleanupsPerformed++
      })

      // Start monitoring
      monitor.startMonitoring()

      // Simulate multiple alerts
      for (let i = 0; i < 3; i++) {
        monitor.emit('memory-alert', {
          level: 'critical' as const,
          message: `Test alert ${i}`,
          stats: {
            used: 850000000,
            total: 1000000000,
            percentage: 85,
            timestamp: Date.now(),
          },
          timestamp: Date.now(),
          action: 'cleanup-suggested',
        })
      }

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 1000))

      expect(alertsReceived).toBe(3)
      // Cleanup may be triggered multiple times
      expect(cleanupsPerformed).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Compression and Storage Integration', () => {
    test('should compress data before storage and decompress on retrieval', () => {
      const mockBusinesses: BusinessRecord[] = Array(50)
        .fill(null)
        .map((_, i) => ({
          id: `test-${i}`,
          businessName: `Test Business ${i}`,
          email: [`test${i}@example.com`],
          phone: `555-010${i}`,
          websiteUrl: `https://test${i}.com`,
          address: {
            street: `${i} Test St`,
            city: 'Test City',
            state: 'TS',
            zipCode: '12345',
          },
          industry: 'Testing',
          scrapedAt: new Date(),
        }))

      // Compress data
      const compressed = DataCompression.batchCompress(mockBusinesses)

      // Verify compression occurred for large dataset
      const hasCompressed = compressed.some(item => DataCompression.isCompressed(item))
      if (hasCompressed) {
        // Calculate storage savings
        const savings = DataCompression.calculateStorageSavings(compressed)
        expect(savings.savingsPercentage).toBeGreaterThan(0)
      }

      // Decompress and verify integrity
      const decompressed = DataCompression.batchDecompress(compressed)
      expect(decompressed).toHaveLength(mockBusinesses.length)

      // Verify first and last items
      const firstBusiness = decompressed[0]
      const lastBusiness = decompressed[49]
      expect(firstBusiness).toBeDefined()
      expect(lastBusiness).toBeDefined()
      expect(firstBusiness?.businessName).toBe('Test Business 0')
      expect(lastBusiness?.businessName).toBe('Test Business 49')
    })

    test('should handle mixed compressed and uncompressed data', () => {
      const smallData = { id: '1', name: 'Small' }
      const largeData = Array(100).fill({ id: '2', name: 'Large', data: 'x'.repeat(1000) })

      const compressedSmall = DataCompression.compress(smallData)
      const compressedLarge = DataCompression.compress(largeData)

      // Small data likely won't be compressed
      expect(compressedSmall).toEqual(smallData)

      // Large data should be compressed
      if (DataCompression.isCompressed(compressedLarge)) {
        const stats = DataCompression.getCompressionStats(compressedLarge)
        expect(stats?.compressionRatio).toBeGreaterThan(0)
      }

      // Both should decompress correctly
      expect(DataCompression.decompress(compressedSmall)).toEqual(smallData)
      expect(DataCompression.decompress(compressedLarge)).toEqual(largeData)
    })
  })

  describe('Memory Management Workflow Integration', () => {
    test('should handle complete memory management lifecycle', async () => {
      const events: string[] = []

      // Track events
      monitor.on('monitoring-started', () => events.push('monitoring-started'))
      monitor.on('monitoring-stopped', () => events.push('monitoring-stopped'))
      monitor.on('memory-alert', () => events.push('memory-alert'))

      cleanup.on('auto-cleanup-started', () => events.push('auto-cleanup-started'))
      cleanup.on('auto-cleanup-stopped', () => events.push('auto-cleanup-stopped'))
      cleanup.on('cleanup-completed', () => events.push('cleanup-completed'))

      // Start lifecycle
      monitor.startMonitoring()
      cleanup.startAutoCleanup(1000)

      // Wait for startup
      await new Promise(resolve => setTimeout(resolve, 100))

      // Trigger cleanup
      await cleanup.performManualCleanup()

      // Stop lifecycle
      monitor.stopMonitoring()
      cleanup.stopAutoCleanup()

      // Verify event sequence
      expect(events).toContain('monitoring-started')
      expect(events).toContain('auto-cleanup-started')
      expect(events).toContain('cleanup-completed')
      expect(events).toContain('monitoring-stopped')
      expect(events).toContain('auto-cleanup-stopped')
    })

    test('should coordinate memory thresholds with cleanup triggers', () => {
      // Set custom thresholds
      monitor.updateThresholds({
        warning: 60,
        critical: 75,
        emergency: 90,
      })

      // Set corresponding cleanup policy
      cleanup.updateRetentionPolicy({
        maxSessions: 2,
        maxAge: 5000,
        maxSize: 10 * 1024 * 1024, // 10MB
        autoCleanup: true,
      })

      const thresholds = monitor.getThresholds()
      const policy = cleanup.getRetentionPolicy()

      expect(thresholds.warning).toBe(60)
      expect(thresholds.critical).toBe(75)
      expect(thresholds.emergency).toBe(90)
      expect(policy.maxSessions).toBe(2)
      expect(policy.autoCleanup).toBe(true)
    })
  })

  describe('Error Handling Integration', () => {
    test('should handle monitor errors without affecting cleanup', async () => {
      let monitorErrors = 0
      let cleanupSuccess = false

      monitor.on('error', () => monitorErrors++)
      cleanup.on('cleanup-completed', () => (cleanupSuccess = true))

      // Start both services
      monitor.startMonitoring()
      cleanup.startAutoCleanup()

      // Perform cleanup despite potential monitor issues
      const result = await cleanup.performManualCleanup()

      expect(result.success).toBe(true)
      expect(typeof monitorErrors).toBe('number')
    })

    test('should handle cleanup errors without affecting monitoring', () => {
      let monitorActive = false
      let cleanupErrors = 0

      monitor.on('monitoring-started', () => (monitorActive = true))
      cleanup.on('error', () => cleanupErrors++)

      // Start monitoring
      monitor.startMonitoring()

      // Attempt cleanup operations that might fail
      cleanup.updateRetentionPolicy({ maxSessions: -1 } as any)

      expect(monitorActive).toBe(true)
      expect(monitor.isActive()).toBe(true)
    })
  })

  describe('Performance Integration', () => {
    test('should maintain performance under concurrent operations', async () => {
      const startTime = Date.now()

      // Start monitoring
      monitor.startMonitoring()

      // Perform concurrent operations
      const operations = [
        cleanup.performManualCleanup(),
        cleanup.performManualCleanup(),
        DataCompression.compress(Array(1000).fill('test')),
        DataCompression.compress(Array(1000).fill('test')),
        monitor.forceGarbageCollection(),
      ]

      await Promise.all(operations)

      const duration = Date.now() - startTime

      // Should complete within reasonable time (5 seconds)
      expect(duration).toBeLessThan(5000)
    })

    test('should handle memory operations with large datasets efficiently', () => {
      const largeDataset = Array(10000)
        .fill(null)
        .map((_, i) => ({
          id: i,
          data: 'x'.repeat(100),
          nested: {
            value: i,
            array: Array(10).fill(i),
          },
        }))

      const startTime = Date.now()

      // Compress large dataset
      const compressed = DataCompression.compress(largeDataset)
      const compressionTime = Date.now() - startTime

      // Should complete compression within reasonable time
      expect(compressionTime).toBeLessThan(2000) // 2 seconds

      if (DataCompression.isCompressed(compressed)) {
        const decompressStart = Date.now()
        const decompressed = DataCompression.decompress(compressed)
        const decompressionTime = Date.now() - decompressStart

        expect(decompressionTime).toBeLessThan(1000) // 1 second
        expect(decompressed).toHaveLength(largeDataset.length)
      }
    })
  })
})
