/**
 * Performance Test Optimizer
 * 
 * Optimizes performance testing framework for better reliability and accuracy
 * in test environments while maintaining realistic performance measurements.
 */

import { logger } from '@/utils/logger'

export interface PerformanceTestConfig {
  // Test Environment Settings
  testEnvironment: 'development' | 'ci' | 'production'
  enableBrowserTests: boolean
  enableMemoryTests: boolean
  enableLoadTests: boolean
  
  // Browser Pool Optimization
  browserPool: {
    maxBrowsers: number
    maxPagesPerBrowser: number
    browserTimeout: number
    pageTimeout: number
    headless: boolean
    enableGPU: boolean
    memoryOptimization: boolean
  }
  
  // Memory Testing Configuration
  memoryTesting: {
    maxMemoryIncrease: number // bytes
    memoryCheckInterval: number // ms
    gcForceInterval: number // ms
    memoryLeakThreshold: number // bytes
    enableDetailedTracking: boolean
  }
  
  // Load Testing Configuration
  loadTesting: {
    maxConcurrentUsers: number
    maxRequestsPerUser: number
    maxTestDuration: number // ms
    responseTimeThreshold: number // ms
    errorRateThreshold: number // percentage
    throughputThreshold: number // requests/second
  }
  
  // Performance Thresholds
  thresholds: {
    responseTime: {
      fast: number // ms
      acceptable: number // ms
      slow: number // ms
    }
    memoryUsage: {
      low: number // bytes
      medium: number // bytes
      high: number // bytes
    }
    throughput: {
      minimum: number // requests/second
      target: number // requests/second
      optimal: number // requests/second
    }
  }
}

export const defaultPerformanceTestConfig: PerformanceTestConfig = {
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
    enableGPU: false, // Disable GPU in tests for consistency
    memoryOptimization: true
  },
  
  memoryTesting: {
    maxMemoryIncrease: process.env.CI ? 50 * 1024 * 1024 : 100 * 1024 * 1024, // 50MB CI, 100MB local
    memoryCheckInterval: 5000,
    gcForceInterval: 10000,
    memoryLeakThreshold: 20 * 1024 * 1024, // 20MB
    enableDetailedTracking: !process.env.CI
  },
  
  loadTesting: {
    maxConcurrentUsers: process.env.CI ? 5 : 10,
    maxRequestsPerUser: process.env.CI ? 3 : 5,
    maxTestDuration: process.env.CI ? 30000 : 60000,
    responseTimeThreshold: process.env.CI ? 10000 : 5000,
    errorRateThreshold: process.env.CI ? 30 : 20,
    throughputThreshold: process.env.CI ? 0.1 : 0.3
  },
  
  thresholds: {
    responseTime: {
      fast: 1000,
      acceptable: 5000,
      slow: 10000
    },
    memoryUsage: {
      low: 50 * 1024 * 1024,   // 50MB
      medium: 100 * 1024 * 1024, // 100MB
      high: 200 * 1024 * 1024   // 200MB
    },
    throughput: {
      minimum: 0.1,
      target: 1.0,
      optimal: 5.0
    }
  }
}

export class PerformanceTestOptimizer {
  private config: PerformanceTestConfig
  private memoryBaseline: number = 0
  private testStartTime: number = 0

  constructor(config?: Partial<PerformanceTestConfig>) {
    this.config = { ...defaultPerformanceTestConfig, ...config }
    this.memoryBaseline = process.memoryUsage().heapUsed
  }

  /**
   * Initialize performance testing environment
   */
  async initializeTestEnvironment(): Promise<void> {
    this.testStartTime = Date.now()
    this.memoryBaseline = process.memoryUsage().heapUsed

    logger.info('PerformanceTestOptimizer', 'Initializing performance test environment', {
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

    // Set up memory monitoring if enabled
    if (this.config.enableMemoryTests) {
      this.setupMemoryMonitoring()
    }
  }

  /**
   * Get optimized browser pool configuration for tests
   */
  getBrowserPoolConfig() {
    return {
      maxBrowsers: this.config.browserPool.maxBrowsers,
      maxPagesPerBrowser: this.config.browserPool.maxPagesPerBrowser,
      browserTimeout: this.config.browserPool.browserTimeout,
      pageTimeout: this.config.browserPool.pageTimeout,
      headless: this.config.browserPool.headless,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI',
        '--disable-ipc-flooding-protection',
        ...(this.config.browserPool.memoryOptimization ? [
          '--memory-pressure-off',
          '--max_old_space_size=4096'
        ] : [])
      ]
    }
  }

  /**
   * Get optimized load test configuration
   */
  getLoadTestConfig() {
    return {
      maxConcurrentUsers: this.config.loadTesting.maxConcurrentUsers,
      maxRequestsPerUser: this.config.loadTesting.maxRequestsPerUser,
      maxTestDuration: this.config.loadTesting.maxTestDuration,
      responseTimeThreshold: this.config.loadTesting.responseTimeThreshold,
      errorRateThreshold: this.config.loadTesting.errorRateThreshold,
      throughputThreshold: this.config.loadTesting.throughputThreshold
    }
  }

  /**
   * Check if current memory usage is within acceptable limits
   */
  checkMemoryUsage(): { withinLimits: boolean; currentUsage: number; increase: number } {
    const currentMemory = process.memoryUsage().heapUsed
    const memoryIncrease = currentMemory - this.memoryBaseline

    return {
      withinLimits: memoryIncrease <= this.config.memoryTesting.maxMemoryIncrease,
      currentUsage: currentMemory,
      increase: memoryIncrease
    }
  }

  /**
   * Evaluate performance metrics against thresholds
   */
  evaluatePerformance(metrics: {
    responseTime?: number
    memoryUsage?: number
    throughput?: number
    errorRate?: number
  }): {
    overall: 'excellent' | 'good' | 'acceptable' | 'poor'
    details: Record<string, string>
  } {
    const details: Record<string, string> = {}
    let score = 0
    let maxScore = 0

    // Evaluate response time
    if (metrics.responseTime !== undefined) {
      maxScore += 3
      if (metrics.responseTime <= this.config.thresholds.responseTime.fast) {
        details.responseTime = 'excellent'
        score += 3
      } else if (metrics.responseTime <= this.config.thresholds.responseTime.acceptable) {
        details.responseTime = 'good'
        score += 2
      } else if (metrics.responseTime <= this.config.thresholds.responseTime.slow) {
        details.responseTime = 'acceptable'
        score += 1
      } else {
        details.responseTime = 'poor'
      }
    }

    // Evaluate memory usage
    if (metrics.memoryUsage !== undefined) {
      maxScore += 3
      if (metrics.memoryUsage <= this.config.thresholds.memoryUsage.low) {
        details.memoryUsage = 'excellent'
        score += 3
      } else if (metrics.memoryUsage <= this.config.thresholds.memoryUsage.medium) {
        details.memoryUsage = 'good'
        score += 2
      } else if (metrics.memoryUsage <= this.config.thresholds.memoryUsage.high) {
        details.memoryUsage = 'acceptable'
        score += 1
      } else {
        details.memoryUsage = 'poor'
      }
    }

    // Evaluate throughput
    if (metrics.throughput !== undefined) {
      maxScore += 3
      if (metrics.throughput >= this.config.thresholds.throughput.optimal) {
        details.throughput = 'excellent'
        score += 3
      } else if (metrics.throughput >= this.config.thresholds.throughput.target) {
        details.throughput = 'good'
        score += 2
      } else if (metrics.throughput >= this.config.thresholds.throughput.minimum) {
        details.throughput = 'acceptable'
        score += 1
      } else {
        details.throughput = 'poor'
      }
    }

    // Evaluate error rate
    if (metrics.errorRate !== undefined) {
      maxScore += 3
      if (metrics.errorRate <= 5) {
        details.errorRate = 'excellent'
        score += 3
      } else if (metrics.errorRate <= 15) {
        details.errorRate = 'good'
        score += 2
      } else if (metrics.errorRate <= 25) {
        details.errorRate = 'acceptable'
        score += 1
      } else {
        details.errorRate = 'poor'
      }
    }

    // Calculate overall rating
    const percentage = maxScore > 0 ? (score / maxScore) * 100 : 0
    let overall: 'excellent' | 'good' | 'acceptable' | 'poor'

    if (percentage >= 90) {
      overall = 'excellent'
    } else if (percentage >= 75) {
      overall = 'good'
    } else if (percentage >= 60) {
      overall = 'acceptable'
    } else {
      overall = 'poor'
    }

    return { overall, details }
  }

  /**
   * Force garbage collection and memory cleanup
   */
  forceMemoryCleanup(): void {
    if (global.gc) {
      global.gc()
      logger.debug('PerformanceTestOptimizer', 'Forced garbage collection')
    }
  }

  /**
   * Setup memory monitoring for tests
   */
  private setupMemoryMonitoring(): void {
    if (!this.config.enableMemoryTests) return

    const checkInterval = setInterval(() => {
      const memoryCheck = this.checkMemoryUsage()
      
      if (!memoryCheck.withinLimits) {
        logger.warn('PerformanceTestOptimizer', 'Memory usage exceeds threshold', {
          currentUsage: this.formatBytes(memoryCheck.currentUsage),
          increase: this.formatBytes(memoryCheck.increase),
          threshold: this.formatBytes(this.config.memoryTesting.maxMemoryIncrease)
        })
      }
    }, this.config.memoryTesting.memoryCheckInterval)

    // Clean up interval after test duration
    setTimeout(() => {
      clearInterval(checkInterval)
    }, this.config.loadTesting.maxTestDuration * 2)
  }

  /**
   * Format bytes to human readable string
   */
  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    if (bytes === 0) return '0 Bytes'
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
  }

  /**
   * Get current configuration
   */
  getConfig(): PerformanceTestConfig {
    return { ...this.config }
  }
}

// Export singleton instance
export const performanceTestOptimizer = new PerformanceTestOptimizer()
