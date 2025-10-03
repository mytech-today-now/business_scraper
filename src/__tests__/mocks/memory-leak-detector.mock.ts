/**
 * Memory Leak Detector Mock for Testing
 * Provides a mock implementation of memory leak detection functionality
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'

export interface MockMemoryLeakAlert {
  type: 'component' | 'websocket' | 'async' | 'database' | 'browser'
  component?: string
  description: string
  memoryIncrease: number
  timestamp: Date
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export interface MockComponentMemoryTracker {
  componentName: string
  mountTime: Date
  initialMemory: number
  currentMemory: number
  memoryHistory: number[]
  isActive: boolean
}

export class MockMemoryLeakDetector extends EventEmitter {
  private isDetectionActive: boolean = false
  private componentTrackers: Map<string, MockComponentMemoryTracker> = new Map()
  private detectionInterval: NodeJS.Timeout | null = null
  private readonly detectionIntervalMs = 5000

  constructor() {
    super()
    logger.debug('MockMemoryLeakDetector', 'Initialized memory leak detector mock')
  }

  /**
   * Start memory leak detection
   */
  startDetection(): void {
    if (this.isDetectionActive) {
      logger.warn('MockMemoryLeakDetector', 'Memory leak detection is already active')
      return
    }

    this.isDetectionActive = true
    this.detectionInterval = setInterval(() => {
      this.performLeakDetection()
    }, this.detectionIntervalMs)

    logger.info('MockMemoryLeakDetector', 'Memory leak detection started')
    this.emit('detection-started')
  }

  /**
   * Stop memory leak detection
   */
  stopDetection(): void {
    if (!this.isDetectionActive) {
      return
    }

    this.isDetectionActive = false
    if (this.detectionInterval) {
      clearInterval(this.detectionInterval)
      this.detectionInterval = null
    }

    logger.info('MockMemoryLeakDetector', 'Memory leak detection stopped')
    this.emit('detection-stopped')
  }

  /**
   * Get detection status
   */
  getStatus() {
    return {
      isActive: this.isDetectionActive,
      trackedComponents: this.componentTrackers.size,
      lastCheck: new Date()
    }
  }

  /**
   * Track a component for memory leaks
   */
  trackComponent(componentName: string): string {
    const trackerId = `tracker-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    const currentMemory = this.getCurrentMemoryUsage()

    const tracker: MockComponentMemoryTracker = {
      componentName,
      mountTime: new Date(),
      initialMemory: currentMemory,
      currentMemory,
      memoryHistory: [currentMemory],
      isActive: true
    }

    this.componentTrackers.set(trackerId, tracker)
    logger.debug('MockMemoryLeakDetector', `Started tracking component: ${componentName}`, { trackerId })

    return trackerId
  }

  /**
   * Stop tracking a component
   */
  stopTrackingComponent(trackerId: string): void {
    const tracker = this.componentTrackers.get(trackerId)
    if (tracker) {
      tracker.isActive = false
      this.componentTrackers.delete(trackerId)
      logger.debug('MockMemoryLeakDetector', `Stopped tracking component: ${tracker.componentName}`, { trackerId })
    }
  }

  /**
   * Update component memory usage
   */
  updateComponentMemory(trackerId: string): void {
    const tracker = this.componentTrackers.get(trackerId)
    if (tracker && tracker.isActive) {
      const currentMemory = this.getCurrentMemoryUsage()
      tracker.currentMemory = currentMemory
      tracker.memoryHistory.push(currentMemory)

      // Keep only last 10 memory readings
      if (tracker.memoryHistory.length > 10) {
        tracker.memoryHistory.shift()
      }

      // Check for memory leaks
      this.checkComponentForLeaks(trackerId, tracker)
    }
  }

  /**
   * Get all tracked components
   */
  getTrackedComponents(): Map<string, MockComponentMemoryTracker> {
    return new Map(this.componentTrackers)
  }

  /**
   * Force leak detection check
   */
  forceLeakDetection(): void {
    this.performLeakDetection()
  }

  /**
   * Perform memory leak detection
   */
  private performLeakDetection(): void {
    for (const [trackerId, tracker] of this.componentTrackers) {
      if (tracker.isActive) {
        this.updateComponentMemory(trackerId)
      }
    }
  }

  /**
   * Check component for memory leaks
   */
  private checkComponentForLeaks(trackerId: string, tracker: MockComponentMemoryTracker): void {
    const memoryIncrease = tracker.currentMemory - tracker.initialMemory
    const thresholds = {
      low: 10 * 1024 * 1024,    // 10MB
      medium: 25 * 1024 * 1024, // 25MB
      high: 50 * 1024 * 1024,   // 50MB
      critical: 100 * 1024 * 1024 // 100MB
    }

    let severity: 'low' | 'medium' | 'high' | 'critical' | null = null

    if (memoryIncrease > thresholds.critical) {
      severity = 'critical'
    } else if (memoryIncrease > thresholds.high) {
      severity = 'high'
    } else if (memoryIncrease > thresholds.medium) {
      severity = 'medium'
    } else if (memoryIncrease > thresholds.low) {
      severity = 'low'
    }

    if (severity) {
      const alert: MockMemoryLeakAlert = {
        type: 'component',
        component: tracker.componentName,
        description: `Memory leak detected in ${tracker.componentName}: ${this.formatBytes(memoryIncrease)} increase`,
        memoryIncrease,
        timestamp: new Date(),
        severity
      }

      logger.warn('MockMemoryLeakDetector', `Memory leak detected: ${severity}`, alert)
      this.emit('memory-leak-detected', alert)
    }
  }

  /**
   * Get current memory usage
   */
  private getCurrentMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed
    }
    return 50 * 1024 * 1024 + Math.random() * 50 * 1024 * 1024 // Mock memory usage
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
   * Reset detector state
   */
  reset(): void {
    this.stopDetection()
    this.componentTrackers.clear()
    this.removeAllListeners()
    logger.debug('MockMemoryLeakDetector', 'Memory leak detector reset')
  }
}

// Export singleton instance
export const mockMemoryLeakDetector = new MockMemoryLeakDetector()
