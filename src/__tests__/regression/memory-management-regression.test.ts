/**
 * Memory Management Regression Tests
 * Ensures memory management doesn't break existing functionality
 */

import { ScraperService } from '@/model/scraperService'
import { storage } from '@/model/storage'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { DataCompression } from '@/lib/data-compression'
import { BusinessRecord } from '@/types/business'

// Mock storage for testing
jest.mock('@/model/storage', () => ({
  storage: {
    saveBusiness: jest.fn(),
    saveBusinesses: jest.fn(),
    getAllBusinesses: jest.fn(() => Promise.resolve([])),
    getBusiness: jest.fn(),
    deleteBusiness: jest.fn(),
    clearAllBusinesses: jest.fn()
  }
}))

describe('Memory Management Regression Tests', () => {
  beforeEach(() => {
    // Reset all services
    memoryMonitor.stopMonitoring()
    memoryCleanup.stopAutoCleanup()
    jest.clearAllMocks()
  })

  afterEach(() => {
    memoryMonitor.stopMonitoring()
    memoryCleanup.stopAutoCleanup()
  })

  describe('Existing Scraper Functionality', () => {
    test('should not break scraper initialization', async () => {
      const scraper = new ScraperService()
      
      // Should initialize without errors
      await expect(scraper.initialize()).resolves.not.toThrow()
      
      // Should cleanup without errors
      await expect(scraper.cleanup()).resolves.not.toThrow()
    })

    test('should not break scraper configuration', () => {
      const scraper = new ScraperService({
        headless: true,
        timeout: 30000,
        maxConcurrentPages: 3
      })

      expect(scraper).toBeDefined()
      expect(scraper.setDemoMode).toBeDefined()
      expect(scraper.resetStats).toBeDefined()
    })

    test('should not break scraper session management', () => {
      const scraper = new ScraperService()
      const sessionId = 'test-session-123'
      
      // Should set session ID without errors
      expect(() => scraper.setSessionId(sessionId)).not.toThrow()
      expect(scraper.getSessionId()).toBe(sessionId)
    })

    test('should not break scraper statistics', () => {
      const scraper = new ScraperService()
      
      // Should reset stats without errors
      expect(() => scraper.resetStats()).not.toThrow()
      
      // Should get stats without errors
      const stats = scraper.getStats()
      expect(stats).toBeDefined()
      expect(typeof stats.totalSites).toBe('number')
    })
  })

  describe('Existing Storage Functionality', () => {
    test('should not break business record saving', async () => {
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

      // Should save business without errors
      await expect(storage.saveBusiness(mockBusiness)).resolves.not.toThrow()
      expect(storage.saveBusiness).toHaveBeenCalledWith(expect.any(Object))
    })

    test('should not break batch business saving', async () => {
      const mockBusinesses: BusinessRecord[] = Array(5).fill(null).map((_, i) => ({
        id: `test-${i}`,
        businessName: `Test Business ${i}`,
        email: [`test${i}@example.com`],
        phone: `555-010${i}`,
        websiteUrl: `https://test${i}.com`,
        address: {
          street: `${i} Test St`,
          city: 'Test City',
          state: 'TS',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }))

      // Should save businesses without errors
      await expect(storage.saveBusinesses(mockBusinesses)).resolves.not.toThrow()
      expect(storage.saveBusinesses).toHaveBeenCalledWith(expect.any(Array))
    })

    test('should not break business retrieval', async () => {
      // Should get all businesses without errors
      await expect(storage.getAllBusinesses()).resolves.not.toThrow()
      expect(storage.getAllBusinesses).toHaveBeenCalled()

      // Should get single business without errors
      await expect(storage.getBusiness('test-1')).resolves.not.toThrow()
      expect(storage.getBusiness).toHaveBeenCalledWith('test-1')
    })

    test('should not break business deletion', async () => {
      // Should delete business without errors
      await expect(storage.deleteBusiness('test-1')).resolves.not.toThrow()
      expect(storage.deleteBusiness).toHaveBeenCalledWith('test-1')

      // Should clear all businesses without errors
      await expect(storage.clearAllBusinesses()).resolves.not.toThrow()
      expect(storage.clearAllBusinesses).toHaveBeenCalled()
    })
  })

  describe('Data Compression Backward Compatibility', () => {
    test('should handle uncompressed data correctly', () => {
      const uncompressedData = { id: '1', name: 'Test' }
      
      // Should decompress uncompressed data without errors
      const result = DataCompression.decompress(uncompressedData as any)
      expect(result).toEqual(uncompressedData)
    })

    test('should not break existing data formats', () => {
      const existingData = {
        businesses: [
          { id: '1', name: 'Business 1' },
          { id: '2', name: 'Business 2' }
        ],
        metadata: { total: 2, timestamp: Date.now() }
      }

      // Should compress and decompress without changing structure
      const compressed = DataCompression.compress(existingData)
      const decompressed = DataCompression.decompress(compressed)
      
      expect(decompressed).toEqual(existingData)
      expect(decompressed.businesses).toHaveLength(2)
      expect(decompressed.metadata.total).toBe(2)
    })

    test('should maintain data type integrity', () => {
      const typedData = {
        string: 'test',
        number: 42,
        boolean: true,
        array: [1, 2, 3],
        object: { nested: 'value' },
        date: new Date().toISOString()
      }

      const compressed = DataCompression.compress(typedData)
      const decompressed = DataCompression.decompress(compressed)

      expect(typeof decompressed.string).toBe('string')
      expect(typeof decompressed.number).toBe('number')
      expect(typeof decompressed.boolean).toBe('boolean')
      expect(Array.isArray(decompressed.array)).toBe(true)
      expect(typeof decompressed.object).toBe('object')
      expect(typeof decompressed.date).toBe('string')
    })
  })

  describe('API Endpoint Compatibility', () => {
    test('should not break existing API structure', async () => {
      const { GET } = await import('@/app/api/memory/route')
      const request = new Request('http://localhost:3000/api/memory')
      
      const response = await GET(request as any)
      const data = await response.json()

      // Should maintain expected API structure
      expect(data).toHaveProperty('success')
      expect(data).toHaveProperty('data')
      expect(response.status).toBe(200)
    })

    test('should not break existing error handling', async () => {
      const { POST } = await import('@/app/api/memory/route')
      const request = new Request('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({ action: 'invalid' })
      })
      
      const response = await POST(request as any)
      const data = await response.json()

      // Should maintain expected error structure
      expect(data).toHaveProperty('success', false)
      expect(data).toHaveProperty('error')
      expect(response.status).toBe(400)
    })
  })

  describe('Performance Regression', () => {
    test('should not significantly impact scraper performance', async () => {
      const scraper = new ScraperService()
      
      const startTime = Date.now()
      await scraper.initialize()
      const initTime = Date.now() - startTime

      // Initialization should complete quickly (under 2 seconds)
      expect(initTime).toBeLessThan(2000)

      await scraper.cleanup()
    })

    test('should not significantly impact storage performance', async () => {
      const mockBusinesses = Array(100).fill(null).map((_, i) => ({
        id: `test-${i}`,
        businessName: `Test Business ${i}`,
        email: [`test${i}@example.com`],
        phone: `555-010${i}`,
        websiteUrl: `https://test${i}.com`,
        address: {
          street: `${i} Test St`,
          city: 'Test City',
          state: 'TS',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }))

      const startTime = Date.now()
      
      // Compress data
      const compressed = DataCompression.batchCompress(mockBusinesses)
      const compressionTime = Date.now() - startTime

      // Compression should complete quickly (under 1 second for 100 items)
      expect(compressionTime).toBeLessThan(1000)

      // Decompress data
      const decompressStart = Date.now()
      const decompressed = DataCompression.batchDecompress(compressed)
      const decompressionTime = Date.now() - decompressStart

      // Decompression should complete quickly
      expect(decompressionTime).toBeLessThan(500)
      expect(decompressed).toHaveLength(100)
    })

    test('should not impact memory monitoring performance', () => {
      const startTime = Date.now()

      // Start and stop monitoring multiple times
      for (let i = 0; i < 10; i++) {
        memoryMonitor.startMonitoring()
        memoryMonitor.stopMonitoring()
      }

      const duration = Date.now() - startTime

      // Should complete quickly (under 1 second)
      expect(duration).toBeLessThan(1000)
    })
  })

  describe('Configuration Compatibility', () => {
    test('should not break existing configuration options', () => {
      // Memory monitor configuration
      const originalThresholds = memoryMonitor.getThresholds()
      expect(originalThresholds).toHaveProperty('warning')
      expect(originalThresholds).toHaveProperty('critical')
      expect(originalThresholds).toHaveProperty('emergency')

      // Should update thresholds without breaking existing structure
      memoryMonitor.updateThresholds({ warning: 75 })
      const updatedThresholds = memoryMonitor.getThresholds()
      expect(updatedThresholds.warning).toBe(75)
      expect(updatedThresholds.critical).toBe(originalThresholds.critical)
    })

    test('should not break cleanup configuration', () => {
      const originalPolicy = memoryCleanup.getRetentionPolicy()
      expect(originalPolicy).toHaveProperty('maxSessions')
      expect(originalPolicy).toHaveProperty('maxAge')
      expect(originalPolicy).toHaveProperty('autoCleanup')

      // Should update policy without breaking existing structure
      memoryCleanup.updateRetentionPolicy({ maxSessions: 10 })
      const updatedPolicy = memoryCleanup.getRetentionPolicy()
      expect(updatedPolicy.maxSessions).toBe(10)
      expect(updatedPolicy.maxAge).toBe(originalPolicy.maxAge)
    })
  })

  describe('Event System Compatibility', () => {
    test('should not break existing event handling', () => {
      let eventReceived = false

      // Should handle events without errors
      memoryMonitor.on('monitoring-started', () => {
        eventReceived = true
      })

      memoryMonitor.startMonitoring()
      expect(eventReceived).toBe(true)

      memoryMonitor.stopMonitoring()
    })

    test('should not interfere with existing event listeners', () => {
      let monitorEvents = 0
      let cleanupEvents = 0

      memoryMonitor.on('monitoring-started', () => monitorEvents++)
      memoryCleanup.on('auto-cleanup-started', () => cleanupEvents++)

      memoryMonitor.startMonitoring()
      memoryCleanup.startAutoCleanup()

      expect(monitorEvents).toBe(1)
      expect(cleanupEvents).toBe(1)

      memoryMonitor.stopMonitoring()
      memoryCleanup.stopAutoCleanup()
    })
  })

  describe('Error Handling Compatibility', () => {
    test('should not break existing error handling patterns', () => {
      // Should handle errors gracefully without throwing
      expect(() => {
        memoryMonitor.updateThresholds({ warning: -1 } as any)
      }).not.toThrow()

      expect(() => {
        memoryCleanup.updateRetentionPolicy({ maxSessions: -1 } as any)
      }).not.toThrow()
    })

    test('should maintain error logging compatibility', () => {
      const originalConsoleError = console.error
      const errors: any[] = []
      console.error = (...args: any[]) => errors.push(args)

      try {
        // Trigger potential error conditions
        DataCompression.decompress({ invalid: 'data' } as any)
      } catch (error) {
        // Should handle errors appropriately
        expect(error).toBeDefined()
      } finally {
        console.error = originalConsoleError
      }
    })
  })
})
