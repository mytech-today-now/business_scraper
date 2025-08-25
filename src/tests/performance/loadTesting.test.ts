/**
 * Load Testing for Scraping Operations
 * Tests performance under various load conditions
 */

import { jest } from '@jest/globals'
import { scraperService } from '@/model/scraperService'
import { enhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'
import { logger } from '@/utils/logger'

// Mock external dependencies
jest.mock('@/utils/logger')
jest.mock('puppeteer')

interface LoadTestMetrics {
  totalRequests: number
  successfulRequests: number
  failedRequests: number
  averageResponseTime: number
  maxResponseTime: number
  minResponseTime: number
  throughput: number // requests per second
  errorRate: number
  memoryUsage: NodeJS.MemoryUsage
}

interface LoadTestConfig {
  concurrentUsers: number
  requestsPerUser: number
  rampUpTime: number // milliseconds
  testDuration: number // milliseconds
  targetUrls: string[]
}

class LoadTestRunner {
  private metrics: LoadTestMetrics = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    averageResponseTime: 0,
    maxResponseTime: 0,
    minResponseTime: Infinity,
    throughput: 0,
    errorRate: 0,
    memoryUsage: process.memoryUsage()
  }

  private responseTimes: number[] = []
  private startTime: number = 0

  async runLoadTest(config: LoadTestConfig): Promise<LoadTestMetrics> {
    this.startTime = Date.now()
    this.resetMetrics()

    logger.info('LoadTest', `Starting load test with ${config.concurrentUsers} concurrent users`)

    // Create user simulation promises
    const userPromises: Promise<void>[] = []
    
    for (let i = 0; i < config.concurrentUsers; i++) {
      const userDelay = (config.rampUpTime / config.concurrentUsers) * i
      userPromises.push(this.simulateUser(config, userDelay))
    }

    // Wait for all users to complete or timeout
    await Promise.allSettled(userPromises)

    // Calculate final metrics
    this.calculateFinalMetrics()
    
    logger.info('LoadTest', 'Load test completed', this.metrics)
    return this.metrics
  }

  private async simulateUser(config: LoadTestConfig, delay: number): Promise<void> {
    // Ramp-up delay
    if (delay > 0) {
      await this.sleep(delay)
    }

    const endTime = this.startTime + config.testDuration
    let requestCount = 0

    while (Date.now() < endTime && requestCount < config.requestsPerUser) {
      const url = config.targetUrls[requestCount % config.targetUrls.length]
      await this.makeRequest(url)
      requestCount++

      // Small delay between requests to simulate realistic user behavior
      await this.sleep(Math.random() * 1000 + 500)
    }
  }

  private async makeRequest(url: string): Promise<void> {
    const startTime = Date.now()
    this.metrics.totalRequests++

    try {
      // Simulate scraping request
      await scraperService.scrapeWebsite(url, 1, 2)
      
      const responseTime = Date.now() - startTime
      this.recordSuccessfulRequest(responseTime)
      
    } catch (error) {
      this.metrics.failedRequests++
      logger.error('LoadTest', `Request failed for ${url}`, error)
    }
  }

  private recordSuccessfulRequest(responseTime: number): void {
    this.metrics.successfulRequests++
    this.responseTimes.push(responseTime)
    
    if (responseTime > this.metrics.maxResponseTime) {
      this.metrics.maxResponseTime = responseTime
    }
    
    if (responseTime < this.metrics.minResponseTime) {
      this.metrics.minResponseTime = responseTime
    }
  }

  private calculateFinalMetrics(): void {
    const totalDuration = Date.now() - this.startTime
    
    // Calculate average response time
    if (this.responseTimes.length > 0) {
      this.metrics.averageResponseTime = 
        this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length
    }

    // Calculate throughput (requests per second)
    this.metrics.throughput = (this.metrics.totalRequests / totalDuration) * 1000

    // Calculate error rate
    this.metrics.errorRate = (this.metrics.failedRequests / this.metrics.totalRequests) * 100

    // Record memory usage
    this.metrics.memoryUsage = process.memoryUsage()
  }

  private resetMetrics(): void {
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      maxResponseTime: 0,
      minResponseTime: Infinity,
      throughput: 0,
      errorRate: 0,
      memoryUsage: process.memoryUsage()
    }
    this.responseTimes = []
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

describe('Load Testing for Scraping Operations', () => {
  let loadTestRunner: LoadTestRunner

  beforeEach(() => {
    loadTestRunner = new LoadTestRunner()
    jest.clearAllMocks()
  })

  afterEach(async () => {
    await scraperService.cleanup()
  })

  describe('Basic Load Tests', () => {
    test('should handle low concurrent load (5 users)', async () => {
      const config: LoadTestConfig = {
        concurrentUsers: 5,
        requestsPerUser: 10,
        rampUpTime: 2000,
        testDuration: 30000,
        targetUrls: [
          'https://example.com',
          'https://test.com',
          'https://demo.com'
        ]
      }

      const metrics = await loadTestRunner.runLoadTest(config)

      // Assertions for low load
      expect(metrics.totalRequests).toBeGreaterThan(0)
      expect(metrics.errorRate).toBeLessThan(10) // Less than 10% error rate
      expect(metrics.averageResponseTime).toBeLessThan(5000) // Under 5 seconds
      expect(metrics.throughput).toBeGreaterThan(0.1) // At least 0.1 requests/second
    }, 60000)

    test('should handle medium concurrent load (15 users)', async () => {
      const config: LoadTestConfig = {
        concurrentUsers: 15,
        requestsPerUser: 8,
        rampUpTime: 5000,
        testDuration: 45000,
        targetUrls: [
          'https://example.com',
          'https://test.com',
          'https://demo.com',
          'https://sample.com'
        ]
      }

      const metrics = await loadTestRunner.runLoadTest(config)

      // Assertions for medium load
      expect(metrics.totalRequests).toBeGreaterThan(50)
      expect(metrics.errorRate).toBeLessThan(15) // Less than 15% error rate
      expect(metrics.averageResponseTime).toBeLessThan(8000) // Under 8 seconds
      expect(metrics.throughput).toBeGreaterThan(0.5) // At least 0.5 requests/second
    }, 90000)

    test('should handle high concurrent load (30 users)', async () => {
      const config: LoadTestConfig = {
        concurrentUsers: 30,
        requestsPerUser: 5,
        rampUpTime: 10000,
        testDuration: 60000,
        targetUrls: [
          'https://example.com',
          'https://test.com',
          'https://demo.com',
          'https://sample.com',
          'https://mock.com'
        ]
      }

      const metrics = await loadTestRunner.runLoadTest(config)

      // Assertions for high load - more lenient thresholds
      expect(metrics.totalRequests).toBeGreaterThan(100)
      expect(metrics.errorRate).toBeLessThan(25) // Less than 25% error rate
      expect(metrics.averageResponseTime).toBeLessThan(15000) // Under 15 seconds
      expect(metrics.throughput).toBeGreaterThan(1) // At least 1 request/second
    }, 120000)
  })

  describe('Enhanced Scraping Engine Load Tests', () => {
    test('should handle concurrent job processing', async () => {
      await enhancedScrapingEngine.initialize()

      const startTime = Date.now()
      const jobPromises: Promise<string>[] = []

      // Add multiple jobs concurrently
      for (let i = 0; i < 20; i++) {
        const jobPromise = enhancedScrapingEngine.addJob(
          `https://example${i}.com`,
          1,
          Math.floor(Math.random() * 10) + 1,
          2
        )
        jobPromises.push(jobPromise)
      }

      const jobIds = await Promise.all(jobPromises)
      const addJobsTime = Date.now() - startTime

      expect(jobIds).toHaveLength(20)
      expect(addJobsTime).toBeLessThan(5000) // Should add jobs quickly
      
      // Cleanup
      await enhancedScrapingEngine.shutdown()
    }, 30000)

    test('should maintain performance under memory pressure', async () => {
      const initialMemory = process.memoryUsage()
      
      // Create memory pressure by running multiple scraping operations
      const promises: Promise<any>[] = []
      
      for (let i = 0; i < 50; i++) {
        promises.push(
          scraperService.scrapeWebsite(`https://test${i}.com`, 1, 1)
            .catch(() => {}) // Ignore errors for this test
        )
      }

      await Promise.allSettled(promises)
      
      const finalMemory = process.memoryUsage()
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed

      // Memory increase should be reasonable (less than 100MB)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024)
    }, 60000)
  })

  describe('Performance Regression Tests', () => {
    test('should maintain baseline performance metrics', async () => {
      const baselineConfig: LoadTestConfig = {
        concurrentUsers: 10,
        requestsPerUser: 5,
        rampUpTime: 3000,
        testDuration: 20000,
        targetUrls: ['https://example.com']
      }

      const metrics = await loadTestRunner.runLoadTest(baselineConfig)

      // Baseline performance thresholds
      expect(metrics.averageResponseTime).toBeLessThan(6000) // 6 seconds
      expect(metrics.errorRate).toBeLessThan(20) // 20% error rate
      expect(metrics.throughput).toBeGreaterThan(0.3) // 0.3 requests/second
      
      // Memory usage should be reasonable
      expect(metrics.memoryUsage.heapUsed).toBeLessThan(200 * 1024 * 1024) // 200MB
    }, 45000)
  })
})
