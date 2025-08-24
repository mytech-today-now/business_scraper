/**
 * Memory Management and Monitoring Service
 * Provides real-time memory tracking, cleanup, and optimization
 */

import { logger } from '@/utils/logger'
import { EventEmitter } from 'events'

export interface MemoryStats {
  used: number
  total: number
  percentage: number
  timestamp: number
}

export interface BrowserMemoryStats {
  heapUsed: number
  heapTotal: number
  external: number
  rss: number
  timestamp: number
}

export interface MemoryThresholds {
  warning: number    // 70%
  critical: number   // 85%
  emergency: number  // 95%
}

export interface MemoryAlert {
  level: 'warning' | 'critical' | 'emergency'
  message: string
  stats: MemoryStats
  timestamp: number
  action?: string
}

export class MemoryMonitor extends EventEmitter {
  private isMonitoring: boolean = false
  private monitoringInterval: NodeJS.Timeout | null = null
  private memoryHistory: MemoryStats[] = []
  private browserMemoryHistory: BrowserMemoryStats[] = []
  private readonly maxHistorySize = 100
  private readonly monitoringIntervalMs = 5000 // 5 seconds

  private thresholds: MemoryThresholds = {
    warning: 70,
    critical: 85,
    emergency: 95
  }

  constructor() {
    super()
    this.setupBrowserMemoryAPI()
  }

  /**
   * Setup browser memory API if available
   */
  private setupBrowserMemoryAPI(): void {
    if (typeof window !== 'undefined' && 'performance' in window) {
      // Browser environment - use Performance API
      logger.info('MemoryMonitor', 'Browser memory monitoring available')
    } else if (typeof process !== 'undefined' && process.memoryUsage) {
      // Node.js environment - use process.memoryUsage
      logger.info('MemoryMonitor', 'Node.js memory monitoring available')
    } else {
      logger.warn('MemoryMonitor', 'Memory monitoring APIs not available')
    }
  }

  /**
   * Start memory monitoring
   */
  startMonitoring(): void {
    if (this.isMonitoring) {
      logger.warn('MemoryMonitor', 'Memory monitoring already active')
      return
    }

    this.isMonitoring = true
    this.monitoringInterval = setInterval(() => {
      this.collectMemoryStats()
    }, this.monitoringIntervalMs)

    logger.info('MemoryMonitor', 'Memory monitoring started')
    this.emit('monitoring-started')
  }

  /**
   * Stop memory monitoring
   */
  stopMonitoring(): void {
    if (!this.isMonitoring) {
      return
    }

    this.isMonitoring = false
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval)
      this.monitoringInterval = null
    }

    logger.info('MemoryMonitor', 'Memory monitoring stopped')
    this.emit('monitoring-stopped')
  }

  /**
   * Collect current memory statistics
   */
  private collectMemoryStats(): void {
    try {
      const stats = this.getCurrentMemoryStats()
      if (stats) {
        this.addMemoryStats(stats)
        this.checkThresholds(stats)
        this.emit('memory-update', stats)
      }

      // Collect browser-specific memory stats if available
      const browserStats = this.getBrowserMemoryStats()
      if (browserStats) {
        this.addBrowserMemoryStats(browserStats)
        this.emit('browser-memory-update', browserStats)
      }
    } catch (error) {
      logger.error('MemoryMonitor', 'Failed to collect memory stats', error)
    }
  }

  /**
   * Get current memory statistics
   */
  private getCurrentMemoryStats(): MemoryStats | null {
    try {
      if (typeof window !== 'undefined' && 'performance' in window) {
        // Browser environment
        const memory = (performance as any).memory
        if (memory) {
          return {
            used: memory.usedJSHeapSize,
            total: memory.totalJSHeapSize,
            percentage: (memory.usedJSHeapSize / memory.totalJSHeapSize) * 100,
            timestamp: Date.now()
          }
        }
      } else if (typeof process !== 'undefined' && process.memoryUsage) {
        // Node.js environment
        const usage = process.memoryUsage()
        return {
          used: usage.heapUsed,
          total: usage.heapTotal,
          percentage: (usage.heapUsed / usage.heapTotal) * 100,
          timestamp: Date.now()
        }
      }
    } catch (error) {
      logger.error('MemoryMonitor', 'Failed to get memory stats', error)
    }
    return null
  }

  /**
   * Get browser-specific memory statistics
   */
  private getBrowserMemoryStats(): BrowserMemoryStats | null {
    try {
      if (typeof process !== 'undefined' && process.memoryUsage) {
        const usage = process.memoryUsage()
        return {
          heapUsed: usage.heapUsed,
          heapTotal: usage.heapTotal,
          external: usage.external,
          rss: usage.rss,
          timestamp: Date.now()
        }
      }
    } catch (error) {
      logger.error('MemoryMonitor', 'Failed to get browser memory stats', error)
    }
    return null
  }

  /**
   * Add memory stats to history
   */
  private addMemoryStats(stats: MemoryStats): void {
    this.memoryHistory.push(stats)
    if (this.memoryHistory.length > this.maxHistorySize) {
      this.memoryHistory.shift()
    }
  }

  /**
   * Add browser memory stats to history
   */
  private addBrowserMemoryStats(stats: BrowserMemoryStats): void {
    this.browserMemoryHistory.push(stats)
    if (this.browserMemoryHistory.length > this.maxHistorySize) {
      this.browserMemoryHistory.shift()
    }
  }

  /**
   * Check memory thresholds and emit alerts
   */
  private checkThresholds(stats: MemoryStats): void {
    const { percentage } = stats

    if (percentage >= this.thresholds.emergency) {
      this.emitAlert('emergency', 'Critical memory usage detected! Immediate cleanup required.', stats, 'emergency-cleanup')
    } else if (percentage >= this.thresholds.critical) {
      this.emitAlert('critical', 'High memory usage detected. Consider clearing old data.', stats, 'cleanup-suggested')
    } else if (percentage >= this.thresholds.warning) {
      this.emitAlert('warning', 'Memory usage is elevated. Monitor closely.', stats)
    }
  }

  /**
   * Emit memory alert
   */
  private emitAlert(level: MemoryAlert['level'], message: string, stats: MemoryStats, action?: string): void {
    const alert: MemoryAlert = {
      level,
      message,
      stats,
      timestamp: Date.now(),
      action
    }

    logger.warn('MemoryMonitor', `Memory alert: ${level} - ${message}`, {
      percentage: stats.percentage,
      used: this.formatBytes(stats.used),
      total: this.formatBytes(stats.total)
    })

    this.emit('memory-alert', alert)
  }

  /**
   * Get current memory statistics
   */
  getCurrentStats(): MemoryStats | null {
    return this.memoryHistory.length > 0 ? this.memoryHistory[this.memoryHistory.length - 1] : null
  }

  /**
   * Get memory history
   */
  getMemoryHistory(): MemoryStats[] {
    return [...this.memoryHistory]
  }

  /**
   * Get browser memory history
   */
  getBrowserMemoryHistory(): BrowserMemoryStats[] {
    return [...this.browserMemoryHistory]
  }

  /**
   * Update memory thresholds
   */
  updateThresholds(thresholds: Partial<MemoryThresholds>): void {
    this.thresholds = { ...this.thresholds, ...thresholds }
    logger.info('MemoryMonitor', 'Memory thresholds updated', this.thresholds)
  }

  /**
   * Get current thresholds
   */
  getThresholds(): MemoryThresholds {
    return { ...this.thresholds }
  }

  /**
   * Format bytes to human readable format
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  /**
   * Force garbage collection if available
   */
  forceGarbageCollection(): boolean {
    try {
      if (typeof global !== 'undefined' && global.gc) {
        global.gc()
        logger.info('MemoryMonitor', 'Forced garbage collection')
        return true
      }
    } catch (error) {
      logger.warn('MemoryMonitor', 'Failed to force garbage collection', error)
    }
    return false
  }

  /**
   * Get monitoring status
   */
  isActive(): boolean {
    return this.isMonitoring
  }

  /**
   * Cleanup and destroy monitor
   */
  destroy(): void {
    this.stopMonitoring()
    this.removeAllListeners()
    this.memoryHistory = []
    this.browserMemoryHistory = []
    logger.info('MemoryMonitor', 'Memory monitor destroyed')
  }
}

// Create singleton instance
export const memoryMonitor = new MemoryMonitor()
