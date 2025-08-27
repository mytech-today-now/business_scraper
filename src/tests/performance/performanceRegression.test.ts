/**
 * Performance Regression Testing
 * Monitors performance metrics to detect regressions
 */

import { jest } from '@jest/globals'
import { scraperService } from '@/model/scraperService'
import { enhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'
import { clientScraperService } from '@/model/clientScraperService'
import { logger } from '@/utils/logger'
import fs from 'fs/promises'
import path from 'path'

// Mock external dependencies
jest.mock('@/utils/logger')
jest.mock('puppeteer')

interface PerformanceBaseline {
  testName: string
  averageResponseTime: number
  maxResponseTime: number
  throughput: number
  memoryUsage: number
  errorRate: number
  timestamp: string
}

interface PerformanceMetrics {
  responseTime: number
  memoryUsage: number
  cpuUsage?: number
  throughput: number
  errorRate: number
}

class PerformanceMonitor {
  private baselines: Map<string, PerformanceBaseline> = new Map()
  private baselineFile = path.join(process.cwd(), 'performance-baselines.json')

  async loadBaselines(): Promise<void> {
    try {
      const data = await fs.readFile(this.baselineFile, 'utf-8')
      const baselines: PerformanceBaseline[] = JSON.parse(data)

      baselines.forEach(baseline => {
        this.baselines.set(baseline.testName, baseline)
      })

      logger.info('PerformanceMonitor', `Loaded ${baselines.length} performance baselines`)
    } catch (error) {
      logger.warn('PerformanceMonitor', 'No existing baselines found, will create new ones')
    }
  }

  async saveBaselines(): Promise<void> {
    const baselines = Array.from(this.baselines.values())
    await fs.writeFile(this.baselineFile, JSON.stringify(baselines, null, 2))
    logger.info('PerformanceMonitor', `Saved ${baselines.length} performance baselines`)
  }

  async measurePerformance<T>(
    testName: string,
    operation: () => Promise<T>
  ): Promise<{ result: T; metrics: PerformanceMetrics }> {
    const startTime = Date.now()
    const startMemory = process.memoryUsage()

    let result: T
    let error: Error | null = null

    try {
      result = await operation()
    } catch (err) {
      error = err as Error
      throw err
    } finally {
      const endTime = Date.now()
      const endMemory = process.memoryUsage()

      const metrics: PerformanceMetrics = {
        responseTime: endTime - startTime,
        memoryUsage: endMemory.heapUsed - startMemory.heapUsed,
        throughput: error ? 0 : 1000 / (endTime - startTime), // operations per second
        errorRate: error ? 100 : 0,
      }

      await this.recordMetrics(testName, metrics)

      if (!error) {
        return { result: result!, metrics }
      }
    }

    throw new Error('This should never be reached')
  }

  private async recordMetrics(testName: string, metrics: PerformanceMetrics): Promise<void> {
    const baseline = this.baselines.get(testName)

    if (!baseline) {
      // Create new baseline
      const newBaseline: PerformanceBaseline = {
        testName,
        averageResponseTime: metrics.responseTime,
        maxResponseTime: metrics.responseTime,
        throughput: metrics.throughput,
        memoryUsage: metrics.memoryUsage,
        errorRate: metrics.errorRate,
        timestamp: new Date().toISOString(),
      }

      this.baselines.set(testName, newBaseline)
      logger.info('PerformanceMonitor', `Created new baseline for ${testName}`)
    } else {
      // Check for regression
      this.checkForRegression(testName, metrics, baseline)
    }
  }

  private checkForRegression(
    testName: string,
    current: PerformanceMetrics,
    baseline: PerformanceBaseline
  ): void {
    const regressionThreshold = 1.5 // 50% increase is considered regression
    const improvementThreshold = 0.8 // 20% improvement updates baseline

    // Check response time regression
    if (current.responseTime > baseline.averageResponseTime * regressionThreshold) {
      logger.warn(
        'PerformanceMonitor',
        `Performance regression detected in ${testName}: ` +
          `Response time increased from ${baseline.averageResponseTime}ms to ${current.responseTime}ms`
      )
    }

    // Check memory usage regression
    if (current.memoryUsage > baseline.memoryUsage * regressionThreshold) {
      logger.warn(
        'PerformanceMonitor',
        `Memory regression detected in ${testName}: ` +
          `Memory usage increased from ${baseline.memoryUsage} to ${current.memoryUsage} bytes`
      )
    }

    // Check throughput regression
    if (current.throughput < baseline.throughput * improvementThreshold) {
      logger.warn(
        'PerformanceMonitor',
        `Throughput regression detected in ${testName}: ` +
          `Throughput decreased from ${baseline.throughput} to ${current.throughput} ops/sec`
      )
    }

    // Update baseline if significant improvement
    if (
      current.responseTime < baseline.averageResponseTime * improvementThreshold &&
      current.memoryUsage < baseline.memoryUsage * improvementThreshold
    ) {
      this.baselines.set(testName, {
        ...baseline,
        averageResponseTime: current.responseTime,
        memoryUsage: current.memoryUsage,
        throughput: current.throughput,
        timestamp: new Date().toISOString(),
      })

      logger.info(
        'PerformanceMonitor',
        `Updated baseline for ${testName} due to performance improvement`
      )
    }
  }

  getBaseline(testName: string): PerformanceBaseline | undefined {
    return this.baselines.get(testName)
  }
}

describe('Performance Regression Testing', () => {
  let performanceMonitor: PerformanceMonitor

  beforeAll(async () => {
    performanceMonitor = new PerformanceMonitor()
    await performanceMonitor.loadBaselines()
  })

  afterAll(async () => {
    await performanceMonitor.saveBaselines()
    await scraperService.cleanup()
  })

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Scraper Service Performance', () => {
    test('single website scraping performance', async () => {
      const { result, metrics } = await performanceMonitor.measurePerformance(
        'single-website-scraping',
        () => scraperService.scrapeWebsite('https://example.com', 1, 2)
      )

      expect(result).toBeDefined()
      expect(metrics.responseTime).toBeLessThan(10000) // 10 seconds max
      expect(metrics.memoryUsage).toBeLessThan(50 * 1024 * 1024) // 50MB max
      expect(metrics.errorRate).toBe(0)
    }, 30000)

    test('multiple website scraping performance', async () => {
      const urls = ['https://example.com', 'https://test.com', 'https://demo.com']

      const { result, metrics } = await performanceMonitor.measurePerformance(
        'multiple-website-scraping',
        async () => {
          const results = []
          for (const url of urls) {
            const businesses = await scraperService.scrapeWebsite(url, 1, 1)
            results.push(...businesses)
          }
          return results
        }
      )

      expect(result).toBeDefined()
      expect(metrics.responseTime).toBeLessThan(30000) // 30 seconds max
      expect(metrics.memoryUsage).toBeLessThan(100 * 1024 * 1024) // 100MB max
    }, 60000)

    test('enhanced scraping engine performance', async () => {
      const { result, metrics } = await performanceMonitor.measurePerformance(
        'enhanced-scraping-engine',
        async () => {
          await enhancedScrapingEngine.initialize()
          const jobId = await enhancedScrapingEngine.addJob('https://example.com', 1, 5, 2)
          await enhancedScrapingEngine.shutdown()
          return jobId
        }
      )

      expect(result).toBeDefined()
      expect(metrics.responseTime).toBeLessThan(5000) // 5 seconds max
      expect(metrics.memoryUsage).toBeLessThan(30 * 1024 * 1024) // 30MB max
    }, 30000)
  })

  describe('Client Scraper Service Performance', () => {
    test('website search performance', async () => {
      const { result, metrics } = await performanceMonitor.measurePerformance(
        'website-search',
        () => clientScraperService.searchForWebsites('restaurants', '12345', 10)
      )

      expect(result).toBeDefined()
      expect(metrics.responseTime).toBeLessThan(15000) // 15 seconds max
      expect(metrics.memoryUsage).toBeLessThan(40 * 1024 * 1024) // 40MB max
    }, 30000)

    test('client website scraping performance', async () => {
      const { result, metrics } = await performanceMonitor.measurePerformance(
        'client-website-scraping',
        () => clientScraperService.scrapeWebsite('https://example.com', 1, 2)
      )

      expect(result).toBeDefined()
      expect(metrics.responseTime).toBeLessThan(8000) // 8 seconds max
      expect(metrics.memoryUsage).toBeLessThan(25 * 1024 * 1024) // 25MB max
    }, 30000)
  })

  describe('Memory Leak Detection', () => {
    test('should not leak memory during repeated operations', async () => {
      const initialMemory = process.memoryUsage().heapUsed

      // Perform multiple operations
      for (let i = 0; i < 10; i++) {
        await scraperService.scrapeWebsite('https://example.com', 1, 1).catch(() => {}) // Ignore errors for this test

        // Force garbage collection if available
        if (global.gc) {
          global.gc()
        }
      }

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory increase should be minimal (less than 20MB)
      expect(memoryIncrease).toBeLessThan(20 * 1024 * 1024)
    }, 60000)

    test('should clean up resources properly', async () => {
      const initialMemory = process.memoryUsage().heapUsed

      // Initialize and shutdown enhanced scraping engine multiple times
      for (let i = 0; i < 5; i++) {
        await enhancedScrapingEngine.initialize()
        await enhancedScrapingEngine.addJob('https://example.com', 1, 1, 1)
        await enhancedScrapingEngine.shutdown()
      }

      // Force garbage collection
      if (global.gc) {
        global.gc()
      }

      const finalMemory = process.memoryUsage().heapUsed
      const memoryIncrease = finalMemory - initialMemory

      // Memory should not increase significantly
      expect(memoryIncrease).toBeLessThan(15 * 1024 * 1024)
    }, 45000)
  })

  describe('Baseline Comparison', () => {
    test('should compare against historical baselines', async () => {
      const testName = 'baseline-comparison-test'

      const { metrics } = await performanceMonitor.measurePerformance(testName, () =>
        scraperService.scrapeWebsite('https://example.com', 1, 1)
      )

      const baseline = performanceMonitor.getBaseline(testName)

      if (baseline) {
        // Compare against baseline with tolerance
        const responseTimeRatio = metrics.responseTime / baseline.averageResponseTime
        const memoryRatio = metrics.memoryUsage / baseline.memoryUsage

        // Performance should not degrade by more than 50%
        expect(responseTimeRatio).toBeLessThan(1.5)
        expect(memoryRatio).toBeLessThan(1.5)

        logger.info(
          'PerformanceMonitor',
          `Performance comparison - Response time ratio: ${responseTimeRatio.toFixed(2)}, ` +
            `Memory ratio: ${memoryRatio.toFixed(2)}`
        )
      }
    }, 30000)
  })
})
