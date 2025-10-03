/**
 * Memory Monitor Mock for Testing
 * Provides a mock implementation of memory monitoring functionality
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'

export interface MockMemoryStats {
  used: number
  total: number
  percentage: number
  timestamp: number
}

export interface MockMemoryAlert {
  level: 'warning' | 'critical' | 'emergency'
  message: string
  stats: MockMemoryStats
  timestamp: number
  action?: string
}

export class MockMemoryMonitor extends EventEmitter {
  private isMonitoring: boolean = false
  private monitoringInterval: NodeJS.Timeout | null = null
  private memoryHistory: MockMemoryStats[] = []
  private readonly maxHistorySize = 100
  private readonly monitoringIntervalMs = 3000

  private thresholds = {
    warning: 50,
    critical: 65,
    emergency: 80,
  }

  constructor() {
    super()
    logger.debug('MockMemoryMonitor', 'Initialized memory monitor mock')
  }

  /**
   * Start memory monitoring
   */
  startMonitoring(): void {
    if (this.isMonitoring) {
      logger.warn('MockMemoryMonitor', 'Memory monitoring is already active')
      return
    }

    this.isMonitoring = true
    this.monitoringInterval = setInterval(() => {
      this.checkMemoryUsage()
    }, this.monitoringIntervalMs)

    logger.info('MockMemoryMonitor', 'Memory monitoring started')
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

    logger.info('MockMemoryMonitor', 'Memory monitoring stopped')
    this.emit('monitoring-stopped')
  }

  /**
   * Check if monitoring is active
   */
  isActive(): boolean {
    return this.isMonitoring
  }

  /**
   * Get current memory stats
   */
  getCurrentStats(): MockMemoryStats {
    const memoryUsage = process.memoryUsage()
    const used = memoryUsage.heapUsed
    const total = memoryUsage.heapTotal
    const percentage = (used / total) * 100

    return {
      used,
      total,
      percentage,
      timestamp: Date.now()
    }
  }

  /**
   * Get memory history
   */
  getMemoryHistory(): MockMemoryStats[] {
    return [...this.memoryHistory]
  }

  /**
   * Force memory check
   */
  forceMemoryCheck(): MockMemoryStats {
    return this.checkMemoryUsage()
  }

  /**
   * Check memory usage and emit alerts if needed
   */
  private checkMemoryUsage(): MockMemoryStats {
    const stats = this.getCurrentStats()
    
    // Add to history
    this.memoryHistory.push(stats)
    if (this.memoryHistory.length > this.maxHistorySize) {
      this.memoryHistory.shift()
    }

    // Check thresholds and emit alerts
    if (stats.percentage >= this.thresholds.emergency) {
      this.emitAlert('emergency', 'Emergency memory usage detected', stats)
    } else if (stats.percentage >= this.thresholds.critical) {
      this.emitAlert('critical', 'Critical memory usage detected', stats)
    } else if (stats.percentage >= this.thresholds.warning) {
      this.emitAlert('warning', 'High memory usage detected', stats)
    }

    this.emit('memory-stats', stats)
    return stats
  }

  /**
   * Emit memory alert
   */
  private emitAlert(level: 'warning' | 'critical' | 'emergency', message: string, stats: MockMemoryStats): void {
    const alert: MockMemoryAlert = {
      level,
      message,
      stats,
      timestamp: Date.now(),
      action: level === 'emergency' ? 'cleanup-required' : undefined
    }

    logger.warn('MockMemoryMonitor', `Memory alert: ${level}`, alert)
    this.emit('memory-alert', alert)
  }

  /**
   * Set memory thresholds
   */
  setThresholds(thresholds: Partial<typeof this.thresholds>): void {
    this.thresholds = { ...this.thresholds, ...thresholds }
    logger.debug('MockMemoryMonitor', 'Updated memory thresholds', this.thresholds)
  }

  /**
   * Get current thresholds
   */
  getThresholds() {
    return { ...this.thresholds }
  }

  /**
   * Reset monitoring state
   */
  reset(): void {
    this.stopMonitoring()
    this.memoryHistory = []
    this.removeAllListeners()
    logger.debug('MockMemoryMonitor', 'Memory monitor reset')
  }
}

// Export singleton instance
export const mockMemoryMonitor = new MockMemoryMonitor()
