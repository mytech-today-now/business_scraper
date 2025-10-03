/**
 * Performance Test Optimizer Mock for Testing
 * Provides a mock implementation of performance test optimization functionality
 */

import { logger } from '@/utils/logger'

export interface MockPerformanceTestConfig {
  testEnvironment: 'development' | 'ci' | 'production'
  enableBrowserTests: boolean
  enableMemoryTests: boolean
  enableLoadTests: boolean
  
  browserPool: {
    maxBrowsers: number
    maxPagesPerBrowser: number
    browserTimeout: number
    pageTimeout: number
    headless: boolean
    enableGPU: boolean
    memoryOptimization: boolean
  }
  
  memoryTesting: {
    maxMemoryIncrease: number
    memoryCheckInterval: number
    gcForceInterval: number
    memoryLeakThreshold: number
    enableDetailedTracking: boolean
  }
  
  loadTesting: {
    maxConcurrentUsers: number
    maxRequestsPerUser: number
    maxTestDuration: number
    responseTimeThreshold: number
    errorRateThreshold: number
    throughputThreshold: number
  }
}

export const mockDefaultPerformanceTestConfig: MockPerformanceTestConfig = {
  testEnvironment: process.env.NODE_ENV === 'production' ? 'production' : 
                   process.env.CI ? 'ci' : 'development',
  enableBrowserTests: process.env.ENABLE_BROWSER_TESTS !== 'false',
  enableMemoryTests: true,
  enableLoadTests: process.env.ENABLE_LOAD_TESTS !== 'false',
  
  browserPool: {
    maxBrowsers: process.env.CI ? 2 : 4,
    maxPagesPerBrowser: process.env.CI ? 2 : 3,
    browserTimeout: process.env.CI ? 30000 : 60000,
    pageTimeout: process.env.CI ? 15000 : 30000,
    headless: process.env.CI ? true : process.env.HEADLESS !== 'false',
    enableGPU: false,
    memoryOptimization: true
  },
  
  memoryTesting: {
    maxMemoryIncrease: process.env.CI ? 50 * 1024 * 1024 : 100 * 1024 * 1024,
    memoryCheckInterval: 5000,
    gcForceInterval: 10000,
    memoryLeakThreshold: 20 * 1024 * 1024,
    enableDetailedTracking: !process.env.CI
  },
  
  loadTesting: {
    maxConcurrentUsers: process.env.CI ? 5 : 10,
    maxRequestsPerUser: process.env.CI ? 3 : 5,
    maxTestDuration: process.env.CI ? 30000 : 60000,
    responseTimeThreshold: process.env.CI ? 10000 : 5000,
    errorRateThreshold: process.env.CI ? 30 : 20,
    throughputThreshold: process.env.CI ? 0.1 : 0.3
  }
}

export class MockPerformanceTestOptimizer {
  private config: MockPerformanceTestConfig
  private memoryBaseline: number = 0
  private testStartTime: number = 0

  constructor(config?: Partial<MockPerformanceTestConfig>) {
    this.config = { ...mockDefaultPerformanceTestConfig, ...config }
    this.memoryBaseline = process.memoryUsage().heapUsed
    logger.debug('MockPerformanceTestOptimizer', 'Initialized with config', this.config)
  }

  /**
   * Initialize performance testing environment
   */
  async initializeTestEnvironment(): Promise<void> {
    this.testStartTime = Date.now()
    this.memoryBaseline = process.memoryUsage().heapUsed

    logger.info('MockPerformanceTestOptimizer', 'Initializing performance test environment', {
      environment: this.config.testEnvironment,
      browserTests: this.config.enableBrowserTests,
      memoryTests: this.config.enableMemoryTests,
      loadTests: this.config.enableLoadTests
    })

    // Force garbage collection if available
    if (global.gc && this.config.memoryTesting.enableDetailedTracking) {
      global.gc()
      this.memoryBaseline = process.memoryUsage().heapUsed
    }

    // Simulate initialization delay
    await new Promise(resolve => setTimeout(resolve, 100))
  }

  /**
   * Get browser pool configuration
   */
  getBrowserPoolConfig() {
    return { ...this.config.browserPool }
  }

  /**
   * Get memory testing configuration
   */
  getMemoryTestingConfig() {
    return { ...this.config.memoryTesting }
  }

  /**
   * Get load testing configuration
   */
  getLoadTestingConfig() {
    return { ...this.config.loadTesting }
  }

  /**
   * Force memory cleanup
   */
  forceMemoryCleanup(): void {
    if (global.gc) {
      global.gc()
      logger.debug('MockPerformanceTestOptimizer', 'Forced garbage collection')
    }
  }

  /**
   * Get memory baseline
   */
  getMemoryBaseline(): number {
    return this.memoryBaseline
  }

  /**
   * Get test duration
   */
  getTestDuration(): number {
    return Date.now() - this.testStartTime
  }

  /**
   * Check if browser tests are enabled
   */
  isBrowserTestingEnabled(): boolean {
    return this.config.enableBrowserTests
  }

  /**
   * Check if memory tests are enabled
   */
  isMemoryTestingEnabled(): boolean {
    return this.config.enableMemoryTests
  }

  /**
   * Check if load tests are enabled
   */
  isLoadTestingEnabled(): boolean {
    return this.config.enableLoadTests
  }

  /**
   * Optimize test configuration for environment
   */
  optimizeForEnvironment(environment: 'development' | 'ci' | 'production'): void {
    this.config.testEnvironment = environment

    if (environment === 'ci') {
      // Reduce resource usage for CI
      this.config.browserPool.maxBrowsers = Math.min(this.config.browserPool.maxBrowsers, 2)
      this.config.browserPool.maxPagesPerBrowser = Math.min(this.config.browserPool.maxPagesPerBrowser, 2)
      this.config.loadTesting.maxConcurrentUsers = Math.min(this.config.loadTesting.maxConcurrentUsers, 5)
      this.config.memoryTesting.enableDetailedTracking = false
    }

    logger.info('MockPerformanceTestOptimizer', `Optimized configuration for ${environment}`, this.config)
  }

  /**
   * Get performance metrics
   */
  getPerformanceMetrics() {
    const memoryUsage = process.memoryUsage()
    const duration = this.getTestDuration()

    return {
      memoryUsage: {
        current: memoryUsage.heapUsed,
        baseline: this.memoryBaseline,
        increase: memoryUsage.heapUsed - this.memoryBaseline,
        percentage: ((memoryUsage.heapUsed - this.memoryBaseline) / this.memoryBaseline) * 100
      },
      timing: {
        duration,
        startTime: this.testStartTime
      },
      environment: this.config.testEnvironment
    }
  }

  /**
   * Reset optimizer state
   */
  reset(): void {
    this.testStartTime = Date.now()
    this.memoryBaseline = process.memoryUsage().heapUsed
    logger.debug('MockPerformanceTestOptimizer', 'Performance test optimizer reset')
  }
}

// Export singleton instance
export const mockPerformanceTestOptimizer = new MockPerformanceTestOptimizer()
