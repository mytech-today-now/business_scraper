/**
 * Memory Stress Tests
 * Comprehensive tests for memory usage, leak detection, and optimization
 */

import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { memoryLeakDetector } from '@/lib/memory-leak-detector'
import { memoryEfficientProcessor } from '@/lib/memory-efficient-processor'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

// Mock business record generator
function generateMockBusinessRecord(id: number): BusinessRecord {
  return {
    id: `business-${id}`,
    business_name: `Business ${id}`,
    phone: [`555-${String(id).padStart(4, '0')}`],
    email: [`contact${id}@business${id}.com`],
    website: `https://business${id}.com`,
    address: `${id} Main St`,
    city: 'Test City',
    state: 'TS',
    zip_code: String(id).padStart(5, '0'),
    industry: 'Technology',
    description: `Test business ${id} description with some additional text to make it more realistic`,
    scraped_at: new Date().toISOString(),
    coordinates: { lat: 40.7128 + (id * 0.001), lng: -74.0060 + (id * 0.001) },
    confidence_score: Math.random(),
    data_completeness: Math.random(),
    ai_insights: {
      lead_score: Math.random() * 100,
      business_category: 'Technology',
      growth_potential: Math.random() * 10,
      market_presence: Math.random() * 10,
    },
  }
}

describe('Memory Stress Tests', () => {
  beforeAll(() => {
    // Start memory monitoring for tests
    memoryMonitor.startMonitoring()
    memoryLeakDetector.startDetection()
  })

  afterAll(() => {
    // Stop monitoring and cleanup
    memoryMonitor.stopMonitoring()
    memoryLeakDetector.stopDetection()
    memoryCleanup.stopAutoCleanup()
  })

  beforeEach(() => {
    // Force garbage collection before each test
    if (global.gc) {
      global.gc()
    }
  })

  describe('Memory Usage Thresholds', () => {
    test('should maintain memory usage below 400MB threshold', async () => {
      const initialMemory = process.memoryUsage().heapUsed
      const threshold = 400 * 1024 * 1024 // 400MB

      // Generate large dataset
      const businesses = Array.from({ length: 10000 }, (_, i) => generateMockBusinessRecord(i))

      // Process data
      const result = await memoryEfficientProcessor.processDataset(
        businesses,
        async (batch) => batch.map(b => ({ ...b, processed: true })),
        {
          batchSize: 100,
          memoryThreshold: threshold,
          enableGarbageCollection: true,
        }
      )

      expect(result.success).toBe(true)
      expect(result.memoryStats.peakMemory).toBeLessThan(threshold)

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory increase should be minimal after processing
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024) // Less than 50MB increase
    }, 60000)

    test('should trigger cleanup when memory threshold is exceeded', async () => {
      const cleanupSpy = jest.spyOn(memoryCleanup, 'performAutomaticCleanup')
      
      // Set very low threshold to trigger cleanup
      memoryMonitor.updateThresholds({
        warning: 30,
        critical: 40,
        emergency: 50,
      })

      // Generate data that should trigger cleanup
      const businesses = Array.from({ length: 5000 }, (_, i) => generateMockBusinessRecord(i))

      await memoryEfficientProcessor.processDataset(
        businesses,
        async (batch) => {
          // Simulate memory-intensive operation
          const largeData = Array.from({ length: 1000 }, () => 'x'.repeat(1000))
          return batch.map(b => ({ ...b, largeData }))
        },
        {
          batchSize: 50,
          memoryThreshold: 100 * 1024 * 1024, // 100MB
          enableGarbageCollection: true,
        }
      )

      expect(cleanupSpy).toHaveBeenCalled()
      cleanupSpy.mockRestore()

      // Reset thresholds
      memoryMonitor.updateThresholds({
        warning: 50,
        critical: 65,
        emergency: 80,
      })
    }, 30000)
  })

  describe('Memory Leak Detection', () => {
    test('should detect component memory leaks', async () => {
      const alerts: any[] = []
      
      memoryLeakDetector.on('memory-leak-detected', (alert) => {
        alerts.push(alert)
      })

      // Simulate component with memory leak
      const trackerId = memoryLeakDetector.trackComponent('TestComponent')

      // Simulate memory increase
      for (let i = 0; i < 10; i++) {
        // Create large objects to simulate memory leak
        const largeData = Array.from({ length: 100000 }, () => Math.random())
        
        memoryLeakDetector.updateComponentMemory(trackerId)
        
        // Keep reference to prevent GC
        ;(global as any)[`testData${i}`] = largeData
        
        await new Promise(resolve => setTimeout(resolve, 100))
      }

      memoryLeakDetector.stopTrackingComponent(trackerId)

      // Cleanup test data
      for (let i = 0; i < 10; i++) {
        delete (global as any)[`testData${i}`]
      }

      // Should have detected memory leak
      expect(alerts.length).toBeGreaterThan(0)
      expect(alerts[0].type).toBe('component')
    }, 15000)

    test('should detect async operation timeouts', async () => {
      const alerts: any[] = []
      
      memoryLeakDetector.on('memory-leak-detected', (alert) => {
        alerts.push(alert)
      })

      // Track async operation with short timeout
      const operationId = memoryLeakDetector.trackAsyncOperation('TestOperation', 1000)

      // Wait for timeout
      await new Promise(resolve => setTimeout(resolve, 1500))

      // Should have detected timeout
      const timeoutAlerts = alerts.filter(alert => alert.type === 'async')
      expect(timeoutAlerts.length).toBeGreaterThan(0)

      // Complete the operation
      memoryLeakDetector.completeAsyncOperation(operationId)
    }, 5000)
  })

  describe('Large Dataset Processing', () => {
    test('should handle 50,000 records without memory issues', async () => {
      const initialMemory = process.memoryUsage().heapUsed
      const businesses = Array.from({ length: 50000 }, (_, i) => generateMockBusinessRecord(i))

      const result = await memoryEfficientProcessor.processDataset(
        businesses,
        async (batch) => {
          // Simulate processing
          return batch.map(b => ({
            id: b.id,
            name: b.business_name,
            processed: true,
          }))
        },
        {
          batchSize: 200,
          maxConcurrency: 2,
          memoryThreshold: 500 * 1024 * 1024, // 500MB
          enableGarbageCollection: true,
        }
      )

      expect(result.success).toBe(true)
      expect(result.processed).toBe(50000)
      expect(result.data.length).toBe(50000)

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory increase should be reasonable
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024) // Less than 100MB increase

      logger.info('LargeDatasetTest', 'Memory stats', {
        initialMemory: Math.round(initialMemory / 1024 / 1024),
        finalMemory: Math.round(finalMemory / 1024 / 1024),
        memoryIncrease: Math.round(memoryIncrease / 1024 / 1024),
        peakMemory: Math.round(result.memoryStats.peakMemory / 1024 / 1024),
      })
    }, 120000)

    test('should handle concurrent processing without memory leaks', async () => {
      const initialMemory = process.memoryUsage().heapUsed
      const businesses = Array.from({ length: 10000 }, (_, i) => generateMockBusinessRecord(i))

      // Process multiple datasets concurrently
      const promises = Array.from({ length: 3 }, async (_, index) => {
        return memoryEfficientProcessor.processDataset(
          businesses.slice(index * 3000, (index + 1) * 3000),
          async (batch) => {
            // Simulate async processing
            await new Promise(resolve => setTimeout(resolve, 10))
            return batch.map(b => ({ ...b, processedBy: index }))
          },
          {
            batchSize: 100,
            maxConcurrency: 1,
            enableGarbageCollection: true,
          }
        )
      })

      const results = await Promise.all(promises)

      // All should succeed
      results.forEach(result => {
        expect(result.success).toBe(true)
      })

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory increase should be minimal
      expect(memoryIncrease).toBeLessThan(75 * 1024 * 1024) // Less than 75MB increase
    }, 60000)
  })

  describe('Memory Cleanup Effectiveness', () => {
    test('should effectively clean up memory after processing', async () => {
      const initialMemory = process.memoryUsage().heapUsed

      // Create large dataset and process it
      const businesses = Array.from({ length: 20000 }, (_, i) => generateMockBusinessRecord(i))

      await memoryEfficientProcessor.processDataset(
        businesses,
        async (batch) => {
          // Create temporary large objects
          const tempData = Array.from({ length: 1000 }, () => 'x'.repeat(100))
          return batch.map(b => ({ ...b, tempData }))
        },
        {
          batchSize: 100,
          enableGarbageCollection: true,
        }
      )

      // Perform manual cleanup
      const cleanupResult = await memoryCleanup.performManualCleanup({
        clearSearchResults: true,
        clearCachedData: true,
        forceGarbageCollection: true,
      })

      expect(cleanupResult.success).toBe(true)

      // Wait for cleanup to complete
      await new Promise(resolve => setTimeout(resolve, 1000))

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory should be close to initial level
      expect(memoryIncrease).toBeLessThan(30 * 1024 * 1024) // Less than 30MB increase
    }, 45000)

    test('should maintain stable memory usage over multiple operations', async () => {
      const memoryReadings: number[] = []
      const businesses = Array.from({ length: 5000 }, (_, i) => generateMockBusinessRecord(i))

      // Perform multiple processing operations
      for (let i = 0; i < 5; i++) {
        await memoryEfficientProcessor.processDataset(
          businesses,
          async (batch) => batch.map(b => ({ ...b, iteration: i })),
          {
            batchSize: 200,
            enableGarbageCollection: true,
          }
        )

        // Record memory usage
        memoryReadings.push(process.memoryUsage().heapUsed)

        // Cleanup between operations
        await memoryCleanup.performAutomaticCleanup()
        
        if (global.gc) {
          global.gc()
        }

        await new Promise(resolve => setTimeout(resolve, 500))
      }

      // Memory usage should remain relatively stable
      const maxMemory = Math.max(...memoryReadings)
      const minMemory = Math.min(...memoryReadings)
      const memoryVariation = maxMemory - minMemory

      // Variation should be less than 50MB
      expect(memoryVariation).toBeLessThan(50 * 1024 * 1024)

      logger.info('StableMemoryTest', 'Memory readings (MB)', {
        readings: memoryReadings.map(m => Math.round(m / 1024 / 1024)),
        variation: Math.round(memoryVariation / 1024 / 1024),
      })
    }, 60000)
  })

  describe('Error Handling and Recovery', () => {
    test('should handle processing errors without memory leaks', async () => {
      const initialMemory = process.memoryUsage().heapUsed
      const businesses = Array.from({ length: 1000 }, (_, i) => generateMockBusinessRecord(i))

      const result = await memoryEfficientProcessor.processDataset(
        businesses,
        async (batch) => {
          // Simulate random errors
          if (Math.random() < 0.1) {
            throw new Error('Simulated processing error')
          }
          return batch.map(b => ({ ...b, processed: true }))
        },
        {
          batchSize: 50,
          enableGarbageCollection: true,
        }
      )

      // Should have some errors but continue processing
      expect(result.errors.length).toBeGreaterThan(0)
      expect(result.processed).toBeGreaterThan(0)

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory should not leak despite errors
      expect(memoryIncrease).toBeLessThan(20 * 1024 * 1024) // Less than 20MB increase
    }, 30000)
  })
})
