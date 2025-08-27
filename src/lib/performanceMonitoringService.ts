/**
 * Performance Monitoring Service for Virtual Scrolling and UI Performance
 * Tracks rendering times, memory usage, scroll performance, and frame rates
 */

import { logger } from '@/utils/logger'

export interface PerformanceMetrics {
  renderTime: number
  scrollPosition: number
  visibleItemsCount: number
  totalItemsCount: number
  memoryUsage?: number
  timestamp: number
  scrollVelocity?: number
  frameRate?: number
  componentName?: string
  operation?: string
}

export interface ScrollMetrics {
  position: number
  velocity: number
  direction: 'up' | 'down' | 'none'
  timestamp: number
}

export interface PerformanceThresholds {
  renderTime: {
    good: number
    acceptable: number
  }
  frameRate: {
    good: number
    acceptable: number
  }
  memoryUsage: {
    warning: number
    critical: number
  }
}

export interface PerformanceAlert {
  type: 'warning' | 'critical'
  metric: string
  value: number
  threshold: number
  timestamp: number
  componentName?: string
}

class PerformanceMonitoringService {
  private metrics: PerformanceMetrics[] = []
  private alerts: PerformanceAlert[] = []
  private frameRateCounters: Map<string, number> = new Map()
  private frameRateTimers: Map<string, number> = new Map()
  private isEnabled: boolean = true

  private readonly thresholds: PerformanceThresholds = {
    renderTime: {
      good: 8, // 8ms for smooth 60fps
      acceptable: 16.67, // 16.67ms for 60fps
    },
    frameRate: {
      good: 50,
      acceptable: 30,
    },
    memoryUsage: {
      warning: 100 * 1024 * 1024, // 100MB
      critical: 200 * 1024 * 1024, // 200MB
    },
  }

  /**
   * Enable or disable performance monitoring
   */
  setEnabled(enabled: boolean): void {
    this.isEnabled = enabled
    if (!enabled) {
      this.cleanup()
    }
  }

  /**
   * Start frame rate monitoring for a component
   */
  startFrameRateMonitoring(componentName: string): void {
    if (!this.isEnabled) return

    this.frameRateCounters.set(componentName, 0)

    const timer = window.setInterval(() => {
      this.frameRateCounters.set(componentName, 0)
    }, 1000)

    this.frameRateTimers.set(componentName, timer)
  }

  /**
   * Stop frame rate monitoring for a component
   */
  stopFrameRateMonitoring(componentName: string): void {
    const timer = this.frameRateTimers.get(componentName)
    if (timer) {
      clearInterval(timer)
      this.frameRateTimers.delete(componentName)
    }
    this.frameRateCounters.delete(componentName)
  }

  /**
   * Increment frame counter
   */
  incrementFrameCount(componentName: string): void {
    if (!this.isEnabled) return

    const current = this.frameRateCounters.get(componentName) || 0
    this.frameRateCounters.set(componentName, current + 1)
  }

  /**
   * Get current frame rate for a component
   */
  getFrameRate(componentName: string): number {
    return this.frameRateCounters.get(componentName) || 0
  }

  /**
   * Record a performance metric
   */
  recordMetric(metric: PerformanceMetrics): void {
    if (!this.isEnabled) return

    // Add current frame rate if available
    if (metric.componentName) {
      metric.frameRate = this.getFrameRate(metric.componentName)
    }

    this.metrics.push(metric)

    // Keep only last 1000 metrics to prevent memory bloat
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-1000)
    }

    // Check for performance issues and create alerts
    this.checkPerformanceThresholds(metric)

    // Log performance issues
    if (metric.renderTime > this.thresholds.renderTime.acceptable) {
      logger.warn('Performance: Slow render detected', {
        renderTime: metric.renderTime,
        componentName: metric.componentName,
        operation: metric.operation,
        totalItems: metric.totalItemsCount,
        visibleItems: metric.visibleItemsCount,
      })
    }
  }

  /**
   * Check performance thresholds and create alerts
   */
  private checkPerformanceThresholds(metric: PerformanceMetrics): void {
    // Check render time
    if (metric.renderTime > this.thresholds.renderTime.acceptable) {
      this.createAlert(
        'critical',
        'renderTime',
        metric.renderTime,
        this.thresholds.renderTime.acceptable,
        metric.componentName
      )
    } else if (metric.renderTime > this.thresholds.renderTime.good) {
      this.createAlert(
        'warning',
        'renderTime',
        metric.renderTime,
        this.thresholds.renderTime.good,
        metric.componentName
      )
    }

    // Check frame rate
    if (metric.frameRate !== undefined) {
      if (metric.frameRate < this.thresholds.frameRate.acceptable) {
        this.createAlert(
          'critical',
          'frameRate',
          metric.frameRate,
          this.thresholds.frameRate.acceptable,
          metric.componentName
        )
      } else if (metric.frameRate < this.thresholds.frameRate.good) {
        this.createAlert(
          'warning',
          'frameRate',
          metric.frameRate,
          this.thresholds.frameRate.good,
          metric.componentName
        )
      }
    }

    // Check memory usage
    if (metric.memoryUsage !== undefined) {
      if (metric.memoryUsage > this.thresholds.memoryUsage.critical) {
        this.createAlert(
          'critical',
          'memoryUsage',
          metric.memoryUsage,
          this.thresholds.memoryUsage.critical,
          metric.componentName
        )
      } else if (metric.memoryUsage > this.thresholds.memoryUsage.warning) {
        this.createAlert(
          'warning',
          'memoryUsage',
          metric.memoryUsage,
          this.thresholds.memoryUsage.warning,
          metric.componentName
        )
      }
    }
  }

  /**
   * Create a performance alert
   */
  private createAlert(
    type: 'warning' | 'critical',
    metric: string,
    value: number,
    threshold: number,
    componentName?: string
  ): void {
    const alert: PerformanceAlert = {
      type,
      metric,
      value,
      threshold,
      timestamp: Date.now(),
      componentName,
    }

    this.alerts.push(alert)

    // Keep only last 100 alerts
    if (this.alerts.length > 100) {
      this.alerts = this.alerts.slice(-100)
    }
  }

  /**
   * Get performance metrics
   */
  getMetrics(componentName?: string, limit?: number): PerformanceMetrics[] {
    let filtered = componentName
      ? this.metrics.filter(m => m.componentName === componentName)
      : this.metrics

    if (limit) {
      filtered = filtered.slice(-limit)
    }

    return filtered
  }

  /**
   * Get performance alerts
   */
  getAlerts(componentName?: string, limit?: number): PerformanceAlert[] {
    let filtered = componentName
      ? this.alerts.filter(a => a.componentName === componentName)
      : this.alerts

    if (limit) {
      filtered = filtered.slice(-limit)
    }

    return filtered
  }

  /**
   * Get performance statistics
   */
  getStatistics(componentName?: string): {
    avgRenderTime: number
    maxRenderTime: number
    minRenderTime: number
    avgFrameRate: number
    currentMemoryUsage: number
    alertCount: number
    metricsCount: number
  } {
    const metrics = this.getMetrics(componentName)
    const alerts = this.getAlerts(componentName)

    if (metrics.length === 0) {
      return {
        avgRenderTime: 0,
        maxRenderTime: 0,
        minRenderTime: 0,
        avgFrameRate: 0,
        currentMemoryUsage: 0,
        alertCount: alerts.length,
        metricsCount: 0,
      }
    }

    const renderTimes = metrics.map(m => m.renderTime)
    const frameRates = metrics.filter(m => m.frameRate !== undefined).map(m => m.frameRate!)
    const latestMetric = metrics[metrics.length - 1]

    return {
      avgRenderTime: renderTimes.reduce((sum, time) => sum + time, 0) / renderTimes.length,
      maxRenderTime: Math.max(...renderTimes),
      minRenderTime: Math.min(...renderTimes),
      avgFrameRate:
        frameRates.length > 0
          ? frameRates.reduce((sum, rate) => sum + rate, 0) / frameRates.length
          : 0,
      currentMemoryUsage: latestMetric.memoryUsage || 0,
      alertCount: alerts.length,
      metricsCount: metrics.length,
    }
  }

  /**
   * Clear all metrics and alerts
   */
  clear(): void {
    this.metrics = []
    this.alerts = []
  }

  /**
   * Clear metrics for a specific component
   */
  clearComponent(componentName: string): void {
    this.metrics = this.metrics.filter(m => m.componentName !== componentName)
    this.alerts = this.alerts.filter(a => a.componentName !== componentName)
  }

  /**
   * Get performance score (0-100)
   */
  getPerformanceScore(componentName?: string): number {
    const stats = this.getStatistics(componentName)

    if (stats.metricsCount === 0) return 100

    let score = 100

    // Render time score (40% weight)
    if (stats.avgRenderTime > this.thresholds.renderTime.acceptable) {
      score -= 40
    } else if (stats.avgRenderTime > this.thresholds.renderTime.good) {
      score -= 20
    }

    // Frame rate score (30% weight)
    if (stats.avgFrameRate < this.thresholds.frameRate.acceptable) {
      score -= 30
    } else if (stats.avgFrameRate < this.thresholds.frameRate.good) {
      score -= 15
    }

    // Memory usage score (20% weight)
    if (stats.currentMemoryUsage > this.thresholds.memoryUsage.critical) {
      score -= 20
    } else if (stats.currentMemoryUsage > this.thresholds.memoryUsage.warning) {
      score -= 10
    }

    // Alert count score (10% weight)
    if (stats.alertCount > 10) {
      score -= 10
    } else if (stats.alertCount > 5) {
      score -= 5
    }

    return Math.max(0, score)
  }

  /**
   * Cleanup resources
   */
  cleanup(): void {
    // Clear all timers
    for (const timer of this.frameRateTimers.values()) {
      clearInterval(timer)
    }
    this.frameRateTimers.clear()
    this.frameRateCounters.clear()
  }
}

// Export singleton instance
export const performanceMonitoringService = new PerformanceMonitoringService()

// Auto-enable in development mode
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  performanceMonitoringService.setEnabled(true)
}

export default performanceMonitoringService
