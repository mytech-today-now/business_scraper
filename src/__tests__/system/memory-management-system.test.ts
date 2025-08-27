/**
 * Memory Management System Tests
 * Tests memory management in full application context
 */

import { NextRequest } from 'next/server'
import { GET, POST } from '@/app/api/memory/route'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { ScraperService } from '@/model/scraperService'
import { storage } from '@/model/storage'

// Mock dependencies for system testing
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1'),
}))

describe('Memory Management System Tests', () => {
  beforeEach(() => {
    // Reset services before each test
    memoryMonitor.stopMonitoring()
    memoryCleanup.stopAutoCleanup()
  })

  afterEach(() => {
    // Cleanup after each test
    memoryMonitor.stopMonitoring()
    memoryCleanup.stopAutoCleanup()
  })

  describe('Full System Memory API Integration', () => {
    test('should handle complete memory management API workflow', async () => {
      // Test GET endpoint - status
      const getRequest = new NextRequest('http://localhost:3000/api/memory')
      const getResponse = await GET(getRequest)
      const getResult = await getResponse.json()

      expect(getResponse.status).toBe(200)
      expect(getResult.success).toBe(true)
      expect(getResult.data).toBeDefined()
      expect(getResult.data.isMonitoring).toBeDefined()

      // Test POST endpoint - start monitoring
      const startRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({ action: 'start-monitoring' }),
      })
      const startResponse = await POST(startRequest)
      const startResult = await startResponse.json()

      expect(startResponse.status).toBe(200)
      expect(startResult.success).toBe(true)
      expect(startResult.data.isMonitoring).toBe(true)

      // Test POST endpoint - cleanup
      const cleanupRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({
          action: 'cleanup',
          options: {
            clearSearchResults: true,
            clearCachedData: true,
          },
        }),
      })
      const cleanupResponse = await POST(cleanupRequest)
      const cleanupResult = await cleanupResponse.json()

      expect(cleanupResponse.status).toBe(200)
      expect(cleanupResult.success).toBe(true)
      expect(cleanupResult.data).toBeDefined()

      // Test POST endpoint - stop monitoring
      const stopRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({ action: 'stop-monitoring' }),
      })
      const stopResponse = await POST(stopRequest)
      const stopResult = await stopResponse.json()

      expect(stopResponse.status).toBe(200)
      expect(stopResult.success).toBe(true)
      expect(stopResult.data.isMonitoring).toBe(false)
    })

    test('should handle invalid API requests gracefully', async () => {
      // Test invalid action
      const invalidRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({ action: 'invalid-action' }),
      })
      const invalidResponse = await POST(invalidRequest)
      const invalidResult = await invalidResponse.json()

      expect(invalidResponse.status).toBe(400)
      expect(invalidResult.success).toBe(false)
      expect(invalidResult.error).toBe('Invalid action')

      // Test malformed JSON
      const malformedRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: 'invalid-json',
      })
      const malformedResponse = await POST(malformedRequest)

      expect(malformedResponse.status).toBe(500)
    })

    test('should handle concurrent API requests', async () => {
      const requests = Array(10)
        .fill(null)
        .map(() => GET(new NextRequest('http://localhost:3000/api/memory')))

      const responses = await Promise.all(requests)

      responses.forEach(response => {
        expect(response.status).toBe(200)
      })
    })
  })

  describe('Memory Management with Scraper Integration', () => {
    test('should integrate memory monitoring with scraper lifecycle', async () => {
      const scraper = new ScraperService()

      // Initialize scraper (should start memory monitoring)
      await scraper.initialize()

      // Verify memory monitoring is active
      expect(memoryMonitor.isActive()).toBe(true)

      // Cleanup scraper (should stop memory monitoring)
      await scraper.cleanup()

      // Verify memory monitoring is stopped
      expect(memoryMonitor.isActive()).toBe(false)
    })

    test('should handle memory cleanup during scraping operations', async () => {
      const scraper = new ScraperService()
      await scraper.initialize()

      // Start memory monitoring
      memoryMonitor.startMonitoring()

      // Simulate scraping operation
      const mockUrls = ['https://example.com', 'https://test.com']

      // This would normally trigger memory usage
      // In a real test, we'd scrape actual data

      // Perform cleanup during operation
      const cleanupResult = await memoryCleanup.performManualCleanup()
      expect(cleanupResult.success).toBe(true)

      await scraper.cleanup()
    })

    test('should handle memory alerts during high-volume scraping', async () => {
      const scraper = new ScraperService()
      await scraper.initialize()

      let alertsReceived = 0
      memoryMonitor.on('memory-alert', () => {
        alertsReceived++
      })

      // Start monitoring
      memoryMonitor.startMonitoring()

      // Simulate high memory usage alert
      memoryMonitor.emit('memory-alert', {
        level: 'critical' as const,
        message: 'High memory usage during scraping',
        stats: {
          used: 850000000,
          total: 1000000000,
          percentage: 85,
          timestamp: Date.now(),
        },
        timestamp: Date.now(),
        action: 'cleanup-suggested',
      })

      expect(alertsReceived).toBe(1)

      await scraper.cleanup()
    })
  })

  describe('Storage Integration with Compression', () => {
    test('should handle compressed storage operations in system context', async () => {
      // This test would need to mock the storage service
      // since IndexedDB is not available in Node.js test environment

      const mockBusinesses = Array(10)
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

      // In a real system test, this would save to actual storage
      // For now, we verify the compression logic works
      const { DataCompression } = require('@/lib/data-compression')
      const compressed = DataCompression.batchCompress(mockBusinesses)
      const decompressed = DataCompression.batchDecompress(compressed)

      expect(decompressed).toHaveLength(mockBusinesses.length)
      expect(decompressed[0].businessName).toBe('Test Business 0')
    })

    test('should handle storage cleanup in system context', async () => {
      // Start auto cleanup
      memoryCleanup.startAutoCleanup(1000)

      // Perform system-level cleanup
      const result = await memoryCleanup.performManualCleanup({
        clearSearchResults: true,
        clearCachedData: true,
        forceGarbageCollection: true,
      })

      expect(result.success).toBe(true)
      expect(typeof result.itemsCleared).toBe('number')
      expect(typeof result.duration).toBe('number')

      memoryCleanup.stopAutoCleanup()
    })
  })

  describe('System Error Handling', () => {
    test('should handle system-wide memory management errors', async () => {
      // Test error handling when services fail
      const originalConsoleError = console.error
      const errors: any[] = []
      console.error = (...args: any[]) => errors.push(args)

      try {
        // Force an error condition
        memoryMonitor.updateThresholds({ warning: -1 } as any)

        // System should continue functioning
        expect(memoryMonitor.getThresholds()).toBeDefined()
      } finally {
        console.error = originalConsoleError
      }
    })

    test('should handle memory service failures gracefully', async () => {
      // Test system resilience when memory services fail
      const scraper = new ScraperService()

      // Even if memory monitoring fails, scraper should work
      await scraper.initialize()
      expect(scraper).toBeDefined()

      await scraper.cleanup()
    })

    test('should handle API service failures', async () => {
      // Test API error handling
      const errorRequest = new NextRequest('http://localhost:3000/api/memory', {
        method: 'POST',
        body: JSON.stringify({ action: 'update-thresholds', options: null }),
      })

      const errorResponse = await POST(errorRequest)
      const errorResult = await errorResponse.json()

      expect(errorResponse.status).toBe(400)
      expect(errorResult.success).toBe(false)
    })
  })

  describe('System Performance', () => {
    test('should maintain system performance with memory management enabled', async () => {
      const startTime = Date.now()

      // Start all memory services
      memoryMonitor.startMonitoring()
      memoryCleanup.startAutoCleanup()

      // Perform typical system operations
      const operations = [
        memoryCleanup.performManualCleanup(),
        memoryMonitor.forceGarbageCollection(),
        GET(new NextRequest('http://localhost:3000/api/memory')),
      ]

      await Promise.all(operations)

      const duration = Date.now() - startTime

      // Should complete within reasonable time
      expect(duration).toBeLessThan(3000) // 3 seconds

      // Cleanup
      memoryMonitor.stopMonitoring()
      memoryCleanup.stopAutoCleanup()
    })

    test('should handle high-frequency memory operations', async () => {
      memoryMonitor.startMonitoring()

      // Perform rapid operations
      const operations = Array(100)
        .fill(null)
        .map(() => memoryMonitor.getCurrentStats())

      const results = operations.map(op => op)

      // Should handle all operations without errors
      expect(results).toHaveLength(100)

      memoryMonitor.stopMonitoring()
    })
  })

  describe('System Configuration', () => {
    test('should handle system-wide memory configuration', async () => {
      // Configure memory thresholds
      memoryMonitor.updateThresholds({
        warning: 70,
        critical: 85,
        emergency: 95,
      })

      // Configure cleanup policy
      memoryCleanup.updateRetentionPolicy({
        maxSessions: 5,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        maxSize: 100 * 1024 * 1024, // 100MB
        autoCleanup: true,
      })

      // Verify configuration is applied
      const thresholds = memoryMonitor.getThresholds()
      const policy = memoryCleanup.getRetentionPolicy()

      expect(thresholds.warning).toBe(70)
      expect(policy.maxSessions).toBe(5)
      expect(policy.autoCleanup).toBe(true)
    })

    test('should persist configuration across service restarts', async () => {
      // Set configuration
      memoryMonitor.updateThresholds({ warning: 65 })
      const originalThresholds = memoryMonitor.getThresholds()

      // Restart monitoring
      memoryMonitor.stopMonitoring()
      memoryMonitor.startMonitoring()

      // Configuration should persist
      const newThresholds = memoryMonitor.getThresholds()
      expect(newThresholds.warning).toBe(originalThresholds.warning)

      memoryMonitor.stopMonitoring()
    })
  })
})
