/**
 * Enhanced Performance Monitoring Service
 * Tracks and analyzes application performance metrics
 */

import { logger } from '@/utils/logger'
import { EventEmitter } from 'events'

export interface PerformanceMetrics {
  pageLoadTime: number
  bundleSize: number
  memoryUsage: {
    used: number
    total: number
    percentage: number
  }
  cachePerformance: {
    hitRatio: number
    averageAccessTime: number
  }
  scrapingPerformance: {
    averageJobTime: number
    concurrentJobs: number
    successRate: number
  }
  e2eTestPerformance: {
    averageTestTime: number
    totalTests: number
    passRate: number
  }
  coreWebVitals: {
    lcp: number // Largest Contentful Paint
    fid: number // First Input Delay
    cls: number // Cumulative Layout Shift
  }
}

export interface PerformanceTarget {
  pageLoadTime: number // Target: <5000ms
  e2eTestTime: number // Target: <30000ms
  memoryUsage: number // Target: <80%
  cacheHitRatio: number // Target: >90%
  scrapingSuccessRate: number // Target: >95%
}

export interface PerformanceBenchmark {
  timestamp: Date
  metrics: PerformanceMetrics
  targets: PerformanceTarget
  score: number // Overall performance score (0-100)
  improvements: string[]
  issues: string[]
}

export class PerformanceMonitor extends EventEmitter {
  private metrics: PerformanceMetrics
  private targets: PerformanceTarget
  private benchmarks: PerformanceBenchmark[] = []
  private monitoring = false
  private monitoringInterval?: NodeJS.Timeout

  constructor() {
    super()

    // Set max listeners to prevent memory leak warnings
    this.setMaxListeners(20)

    this.targets = {
      pageLoadTime: 5000, // 5 seconds
      e2eTestTime: 30000, // 30 seconds
      memoryUsage: 90, // Increased from 80% to 90% for more realistic target
      cacheHitRatio: 90, // 90%
      scrapingSuccessRate: 95 // 95%
    }

    this.metrics = {
      pageLoadTime: 0,
      bundleSize: 0,
      memoryUsage: { used: 0, total: 0, percentage: 0 },
      cachePerformance: { hitRatio: 0, averageAccessTime: 0 },
      scrapingPerformance: { averageJobTime: 0, concurrentJobs: 0, successRate: 0 },
      e2eTestPerformance: { averageTestTime: 0, totalTests: 0, passRate: 0 },
      coreWebVitals: { lcp: 0, fid: 0, cls: 0 }
    }
  }

  /**
   * Start performance monitoring
   */
  startMonitoring(interval = 30000): void {
    if (this.monitoring) return

    this.monitoring = true
    logger.info('PerformanceMonitor', 'Starting performance monitoring')

    this.monitoringInterval = setInterval(() => {
      this.collectMetrics()
    }, interval)

    // Initial metrics collection
    this.collectMetrics()
  }

  /**
   * Stop performance monitoring
   */
  stopMonitoring(): void {
    if (!this.monitoring) return

    this.monitoring = false
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval)
    }

    logger.info('PerformanceMonitor', 'Performance monitoring stopped')
  }

  /**
   * Collect current performance metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      // Memory usage
      const memUsage = process.memoryUsage()
      this.metrics.memoryUsage = {
        used: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
        total: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
        percentage: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100)
      }

      // Page load time (simulated - would be collected from client-side)
      this.metrics.pageLoadTime = await this.measurePageLoadTime()

      // Bundle size (would be collected from build process)
      this.metrics.bundleSize = await this.getBundleSize()

      // Emit metrics update
      this.emit('metricsUpdate', this.metrics)

      // Check if benchmark should be created
      if (this.shouldCreateBenchmark()) {
        this.createBenchmark()
      }

    } catch (error) {
      logger.error('PerformanceMonitor', 'Failed to collect metrics', error)
    }
  }

  /**
   * Measure page load time
   */
  private async measurePageLoadTime(): Promise<number> {
    // This would typically be measured on the client-side
    // For now, return a simulated value based on current performance
    const baseTime = 2000 // Base load time
    const memoryPenalty = this.metrics.memoryUsage.percentage > 80 ? 1000 : 0
    return baseTime + memoryPenalty + Math.random() * 1000
  }

  /**
   * Get bundle size
   */
  private async getBundleSize(): Promise<number> {
    // This would typically be read from build artifacts
    // For now, return a simulated value
    return 2500000 // 2.5MB
  }

  /**
   * Update cache performance metrics
   */
  updateCacheMetrics(hitRatio: number, averageAccessTime: number): void {
    this.metrics.cachePerformance = { hitRatio, averageAccessTime }
    this.emit('cacheMetricsUpdate', this.metrics.cachePerformance)
  }

  /**
   * Update scraping performance metrics
   */
  updateScrapingMetrics(averageJobTime: number, concurrentJobs: number, successRate: number): void {
    this.metrics.scrapingPerformance = { averageJobTime, concurrentJobs, successRate }
    this.emit('scrapingMetricsUpdate', this.metrics.scrapingPerformance)
  }

  /**
   * Update E2E test performance metrics
   */
  updateE2EMetrics(averageTestTime: number, totalTests: number, passRate: number): void {
    this.metrics.e2eTestPerformance = { averageTestTime, totalTests, passRate }
    this.emit('e2eMetricsUpdate', this.metrics.e2eTestPerformance)
  }

  /**
   * Update Core Web Vitals
   */
  updateCoreWebVitals(lcp: number, fid: number, cls: number): void {
    this.metrics.coreWebVitals = { lcp, fid, cls }
    this.emit('coreWebVitalsUpdate', this.metrics.coreWebVitals)
  }

  /**
   * Check if a new benchmark should be created
   */
  private shouldCreateBenchmark(): boolean {
    const lastBenchmark = this.benchmarks[this.benchmarks.length - 1]
    if (!lastBenchmark) return true

    // Create benchmark every 5 minutes
    const timeSinceLastBenchmark = Date.now() - lastBenchmark.timestamp.getTime()
    return timeSinceLastBenchmark > 300000 // 5 minutes
  }

  /**
   * Create performance benchmark
   */
  createBenchmark(): void {
    try {
      const score = this.calculatePerformanceScore()
      const improvements = this.identifyImprovements()
      const issues = this.identifyIssues()

      const benchmark: PerformanceBenchmark = {
        timestamp: new Date(),
        metrics: { ...this.metrics },
        targets: { ...this.targets },
        score,
        improvements,
        issues
      }

      this.benchmarks.push(benchmark)

      // Keep only last 100 benchmarks
      if (this.benchmarks.length > 100) {
        this.benchmarks.shift()
      }

      logger.info('PerformanceMonitor', `Performance benchmark created. Score: ${score}`)

      // Use setImmediate to ensure event is emitted asynchronously
      setImmediate(() => {
        this.emit('benchmarkCreated', benchmark)
      })

    } catch (error) {
      logger.error('PerformanceMonitor', 'Failed to create benchmark', error)
    }
  }

  /**
   * Calculate overall performance score
   */
  private calculatePerformanceScore(): number {
    let score = 100

    // Page load time penalty
    if (this.metrics.pageLoadTime > this.targets.pageLoadTime) {
      const penalty = Math.min(30, (this.metrics.pageLoadTime - this.targets.pageLoadTime) / 1000 * 5)
      score -= penalty
    }

    // Memory usage penalty
    if (this.metrics.memoryUsage.percentage > this.targets.memoryUsage) {
      const penalty = Math.min(20, (this.metrics.memoryUsage.percentage - this.targets.memoryUsage) / 2)
      score -= penalty
    }

    // Cache performance penalty
    if (this.metrics.cachePerformance.hitRatio < this.targets.cacheHitRatio) {
      const penalty = Math.min(15, (this.targets.cacheHitRatio - this.metrics.cachePerformance.hitRatio) / 2)
      score -= penalty
    }

    // E2E test performance penalty
    if (this.metrics.e2eTestPerformance.averageTestTime > this.targets.e2eTestTime) {
      const penalty = Math.min(20, (this.metrics.e2eTestPerformance.averageTestTime - this.targets.e2eTestTime) / 5000 * 10)
      score -= penalty
    }

    // Scraping success rate penalty
    if (this.metrics.scrapingPerformance.successRate < this.targets.scrapingSuccessRate) {
      const penalty = Math.min(15, (this.targets.scrapingSuccessRate - this.metrics.scrapingPerformance.successRate) * 2)
      score -= penalty
    }

    return Math.max(0, Math.round(score))
  }

  /**
   * Identify performance improvements
   */
  private identifyImprovements(): string[] {
    const improvements: string[] = []

    if (this.metrics.pageLoadTime <= this.targets.pageLoadTime) {
      improvements.push('Page load time within target')
    }

    if (this.metrics.memoryUsage.percentage <= this.targets.memoryUsage) {
      improvements.push('Memory usage optimized')
    }

    if (this.metrics.cachePerformance.hitRatio >= this.targets.cacheHitRatio) {
      improvements.push('Cache performance excellent')
    }

    if (this.metrics.e2eTestPerformance.averageTestTime <= this.targets.e2eTestTime) {
      improvements.push('E2E test performance optimized')
    }

    if (this.metrics.scrapingPerformance.successRate >= this.targets.scrapingSuccessRate) {
      improvements.push('Scraping success rate excellent')
    }

    return improvements
  }

  /**
   * Identify performance issues
   */
  private identifyIssues(): string[] {
    const issues: string[] = []

    if (this.metrics.pageLoadTime > this.targets.pageLoadTime) {
      issues.push(`Page load time too slow: ${this.metrics.pageLoadTime}ms (target: ${this.targets.pageLoadTime}ms)`)
    }

    if (this.metrics.memoryUsage.percentage > this.targets.memoryUsage) {
      issues.push(`High memory usage: ${this.metrics.memoryUsage.percentage}% (target: <${this.targets.memoryUsage}%)`)
    }

    if (this.metrics.cachePerformance.hitRatio < this.targets.cacheHitRatio) {
      issues.push(`Low cache hit ratio: ${this.metrics.cachePerformance.hitRatio}% (target: >${this.targets.cacheHitRatio}%)`)
    }

    if (this.metrics.e2eTestPerformance.averageTestTime > this.targets.e2eTestTime) {
      issues.push(`E2E tests too slow: ${this.metrics.e2eTestPerformance.averageTestTime}ms (target: <${this.targets.e2eTestTime}ms)`)
    }

    if (this.metrics.scrapingPerformance.successRate < this.targets.scrapingSuccessRate) {
      issues.push(`Low scraping success rate: ${this.metrics.scrapingPerformance.successRate}% (target: >${this.targets.scrapingSuccessRate}%)`)
    }

    return issues
  }

  /**
   * Get current metrics
   */
  getMetrics(): PerformanceMetrics {
    return { ...this.metrics }
  }

  /**
   * Get performance targets
   */
  getTargets(): PerformanceTarget {
    return { ...this.targets }
  }

  /**
   * Get recent benchmarks
   */
  getBenchmarks(limit = 10): PerformanceBenchmark[] {
    return this.benchmarks.slice(-limit)
  }

  /**
   * Get performance trend
   */
  getPerformanceTrend(): { improving: boolean; score: number; change: number } {
    if (this.benchmarks.length < 2) {
      return { improving: false, score: 0, change: 0 }
    }

    const recent = this.benchmarks.slice(-5)
    const current = recent[recent.length - 1].score
    const previous = recent[0].score
    const change = current - previous

    return {
      improving: change > 0,
      score: current,
      change
    }
  }
}

// Export singleton instance
export const performanceMonitor = new PerformanceMonitor()
