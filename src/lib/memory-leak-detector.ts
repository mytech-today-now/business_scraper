/**
 * Memory Leak Detection Service
 * Provides comprehensive memory leak detection for React components, WebSocket connections, and async operations
 */

import { logger } from '@/utils/logger'
import { EventEmitter } from 'events'

export interface MemoryLeakAlert {
  type: 'component' | 'websocket' | 'async' | 'database' | 'browser'
  component?: string
  description: string
  memoryIncrease: number
  timestamp: Date
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export interface ComponentMemoryTracker {
  componentName: string
  mountTime: Date
  initialMemory: number
  currentMemory: number
  memoryHistory: number[]
  isActive: boolean
}

export interface AsyncOperationTracker {
  operationId: string
  operationType: string
  startTime: Date
  initialMemory: number
  isCompleted: boolean
  timeout?: NodeJS.Timeout
}

export interface WebSocketTracker {
  connectionId: string
  url: string
  connectTime: Date
  initialMemory: number
  messageCount: number
  isActive: boolean
}

export class MemoryLeakDetector extends EventEmitter {
  private componentTrackers: Map<string, ComponentMemoryTracker> = new Map()
  private asyncOperationTrackers: Map<string, AsyncOperationTracker> = new Map()
  private webSocketTrackers: Map<string, WebSocketTracker> = new Map()
  private detectionInterval: NodeJS.Timeout | null = null
  private isActive: boolean = false
  
  private readonly thresholds = {
    componentMemoryIncrease: 10 * 1024 * 1024, // 10MB
    asyncOperationTimeout: 60000, // 60 seconds
    webSocketMemoryIncrease: 5 * 1024 * 1024, // 5MB
    globalMemoryIncrease: 50 * 1024 * 1024, // 50MB
  }

  constructor() {
    super()
  }

  /**
   * Start memory leak detection
   */
  startDetection(intervalMs: number = 10000): void {
    if (this.isActive) {
      logger.warn('MemoryLeakDetector', 'Memory leak detection already active')
      return
    }

    this.isActive = true
    this.detectionInterval = setInterval(() => {
      this.performLeakDetection()
    }, intervalMs)

    logger.info('MemoryLeakDetector', 'Memory leak detection started')
    this.emit('detection-started')
  }

  /**
   * Stop memory leak detection
   */
  stopDetection(): void {
    if (!this.isActive) {
      return
    }

    this.isActive = false
    if (this.detectionInterval) {
      clearInterval(this.detectionInterval)
      this.detectionInterval = null
    }

    logger.info('MemoryLeakDetector', 'Memory leak detection stopped')
    this.emit('detection-stopped')
  }

  /**
   * Track React component memory usage
   */
  trackComponent(componentName: string): string {
    const trackerId = `${componentName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const tracker: ComponentMemoryTracker = {
      componentName,
      mountTime: new Date(),
      initialMemory: this.getCurrentMemoryUsage(),
      currentMemory: this.getCurrentMemoryUsage(),
      memoryHistory: [],
      isActive: true,
    }

    this.componentTrackers.set(trackerId, tracker)
    logger.debug('MemoryLeakDetector', `Started tracking component: ${componentName}`)
    
    return trackerId
  }

  /**
   * Update component memory usage
   */
  updateComponentMemory(trackerId: string): void {
    const tracker = this.componentTrackers.get(trackerId)
    if (!tracker || !tracker.isActive) {
      return
    }

    const currentMemory = this.getCurrentMemoryUsage()
    tracker.currentMemory = currentMemory
    tracker.memoryHistory.push(currentMemory)

    // Keep only last 20 measurements
    if (tracker.memoryHistory.length > 20) {
      tracker.memoryHistory.shift()
    }

    // Check for memory leak
    const memoryIncrease = currentMemory - tracker.initialMemory
    if (memoryIncrease > this.thresholds.componentMemoryIncrease) {
      this.emitMemoryLeakAlert({
        type: 'component',
        component: tracker.componentName,
        description: `Component ${tracker.componentName} has increased memory usage by ${this.formatBytes(memoryIncrease)}`,
        memoryIncrease,
        timestamp: new Date(),
        severity: this.getSeverityLevel(memoryIncrease),
      })
    }
  }

  /**
   * Stop tracking component
   */
  stopTrackingComponent(trackerId: string): void {
    const tracker = this.componentTrackers.get(trackerId)
    if (tracker) {
      tracker.isActive = false
      logger.debug('MemoryLeakDetector', `Stopped tracking component: ${tracker.componentName}`)
    }
  }

  /**
   * Track async operation
   */
  trackAsyncOperation(operationType: string, timeoutMs?: number): string {
    const operationId = `${operationType}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const tracker: AsyncOperationTracker = {
      operationId,
      operationType,
      startTime: new Date(),
      initialMemory: this.getCurrentMemoryUsage(),
      isCompleted: false,
    }

    // Set timeout for operation
    if (timeoutMs) {
      tracker.timeout = setTimeout(() => {
        if (!tracker.isCompleted) {
          this.emitMemoryLeakAlert({
            type: 'async',
            description: `Async operation ${operationType} has not completed after ${timeoutMs}ms`,
            memoryIncrease: this.getCurrentMemoryUsage() - tracker.initialMemory,
            timestamp: new Date(),
            severity: 'high',
          })
        }
      }, timeoutMs)
    }

    this.asyncOperationTrackers.set(operationId, tracker)
    logger.debug('MemoryLeakDetector', `Started tracking async operation: ${operationType}`)
    
    return operationId
  }

  /**
   * Complete async operation tracking
   */
  completeAsyncOperation(operationId: string): void {
    const tracker = this.asyncOperationTrackers.get(operationId)
    if (tracker) {
      tracker.isCompleted = true
      if (tracker.timeout) {
        clearTimeout(tracker.timeout)
      }
      
      const duration = Date.now() - tracker.startTime.getTime()
      const memoryIncrease = this.getCurrentMemoryUsage() - tracker.initialMemory
      
      logger.debug('MemoryLeakDetector', `Completed async operation: ${tracker.operationType} (${duration}ms, ${this.formatBytes(memoryIncrease)} memory change)`)
      
      // Remove completed operation after a delay
      setTimeout(() => {
        this.asyncOperationTrackers.delete(operationId)
      }, 5000)
    }
  }

  /**
   * Track WebSocket connection
   */
  trackWebSocket(url: string): string {
    const connectionId = `ws-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const tracker: WebSocketTracker = {
      connectionId,
      url,
      connectTime: new Date(),
      initialMemory: this.getCurrentMemoryUsage(),
      messageCount: 0,
      isActive: true,
    }

    this.webSocketTrackers.set(connectionId, tracker)
    logger.debug('MemoryLeakDetector', `Started tracking WebSocket: ${url}`)
    
    return connectionId
  }

  /**
   * Update WebSocket message count
   */
  updateWebSocketActivity(connectionId: string): void {
    const tracker = this.webSocketTrackers.get(connectionId)
    if (tracker && tracker.isActive) {
      tracker.messageCount++
      
      // Check for memory increase
      const currentMemory = this.getCurrentMemoryUsage()
      const memoryIncrease = currentMemory - tracker.initialMemory
      
      if (memoryIncrease > this.thresholds.webSocketMemoryIncrease) {
        this.emitMemoryLeakAlert({
          type: 'websocket',
          description: `WebSocket connection to ${tracker.url} has increased memory usage by ${this.formatBytes(memoryIncrease)}`,
          memoryIncrease,
          timestamp: new Date(),
          severity: this.getSeverityLevel(memoryIncrease),
        })
      }
    }
  }

  /**
   * Stop tracking WebSocket
   */
  stopTrackingWebSocket(connectionId: string): void {
    const tracker = this.webSocketTrackers.get(connectionId)
    if (tracker) {
      tracker.isActive = false
      logger.debug('MemoryLeakDetector', `Stopped tracking WebSocket: ${tracker.url}`)
    }
  }

  /**
   * Perform comprehensive leak detection
   */
  private performLeakDetection(): void {
    try {
      // Check for stale async operations
      this.checkStaleAsyncOperations()
      
      // Check for inactive WebSocket connections
      this.checkInactiveWebSockets()
      
      // Check for component memory leaks
      this.checkComponentMemoryLeaks()
      
      // Check global memory trends
      this.checkGlobalMemoryTrends()
      
    } catch (error) {
      logger.error('MemoryLeakDetector', 'Failed to perform leak detection', error)
    }
  }

  /**
   * Check for stale async operations
   */
  private checkStaleAsyncOperations(): void {
    const now = Date.now()
    
    for (const [operationId, tracker] of this.asyncOperationTrackers) {
      if (!tracker.isCompleted && (now - tracker.startTime.getTime()) > this.thresholds.asyncOperationTimeout) {
        this.emitMemoryLeakAlert({
          type: 'async',
          description: `Stale async operation detected: ${tracker.operationType}`,
          memoryIncrease: this.getCurrentMemoryUsage() - tracker.initialMemory,
          timestamp: new Date(),
          severity: 'medium',
        })
      }
    }
  }

  /**
   * Check for inactive WebSocket connections
   */
  private checkInactiveWebSockets(): void {
    const now = Date.now()
    
    for (const [connectionId, tracker] of this.webSocketTrackers) {
      if (tracker.isActive && (now - tracker.connectTime.getTime()) > 300000) { // 5 minutes
        const memoryIncrease = this.getCurrentMemoryUsage() - tracker.initialMemory
        
        if (memoryIncrease > this.thresholds.webSocketMemoryIncrease) {
          this.emitMemoryLeakAlert({
            type: 'websocket',
            description: `Long-running WebSocket connection may be leaking memory: ${tracker.url}`,
            memoryIncrease,
            timestamp: new Date(),
            severity: 'medium',
          })
        }
      }
    }
  }

  /**
   * Check component memory leaks
   */
  private checkComponentMemoryLeaks(): void {
    for (const [trackerId, tracker] of this.componentTrackers) {
      if (tracker.isActive && tracker.memoryHistory.length >= 5) {
        // Check for consistent memory increase
        const recentMemory = tracker.memoryHistory.slice(-5)
        const isIncreasing = recentMemory.every((mem, index) => 
          index === 0 || mem >= recentMemory[index - 1]
        )
        
        if (isIncreasing) {
          const memoryIncrease = tracker.currentMemory - tracker.initialMemory
          if (memoryIncrease > this.thresholds.componentMemoryIncrease) {
            this.emitMemoryLeakAlert({
              type: 'component',
              component: tracker.componentName,
              description: `Consistent memory increase detected in component: ${tracker.componentName}`,
              memoryIncrease,
              timestamp: new Date(),
              severity: this.getSeverityLevel(memoryIncrease),
            })
          }
        }
      }
    }
  }

  /**
   * Check global memory trends
   */
  private checkGlobalMemoryTrends(): void {
    // This would be implemented with historical memory data
    // For now, just emit current memory status
    const currentMemory = this.getCurrentMemoryUsage()
    this.emit('memory-status', { currentMemory, timestamp: new Date() })
  }

  /**
   * Get current memory usage
   */
  private getCurrentMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed
    } else if (typeof window !== 'undefined' && 'performance' in window && 'memory' in performance) {
      return (performance as any).memory.usedJSHeapSize
    }
    return 0
  }

  /**
   * Emit memory leak alert
   */
  private emitMemoryLeakAlert(alert: MemoryLeakAlert): void {
    logger.warn('MemoryLeakDetector', `Memory leak detected: ${alert.description}`, {
      type: alert.type,
      component: alert.component,
      memoryIncrease: this.formatBytes(alert.memoryIncrease),
      severity: alert.severity,
    })

    this.emit('memory-leak-detected', alert)
  }

  /**
   * Get severity level based on memory increase
   */
  private getSeverityLevel(memoryIncrease: number): 'low' | 'medium' | 'high' | 'critical' {
    if (memoryIncrease > 100 * 1024 * 1024) return 'critical' // 100MB
    if (memoryIncrease > 50 * 1024 * 1024) return 'high' // 50MB
    if (memoryIncrease > 20 * 1024 * 1024) return 'medium' // 20MB
    return 'low'
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
   * Get detection status
   */
  getStatus(): {
    isActive: boolean
    componentTrackers: number
    asyncOperationTrackers: number
    webSocketTrackers: number
  } {
    return {
      isActive: this.isActive,
      componentTrackers: this.componentTrackers.size,
      asyncOperationTrackers: this.asyncOperationTrackers.size,
      webSocketTrackers: this.webSocketTrackers.size,
    }
  }

  /**
   * Clear all trackers
   */
  clearAllTrackers(): void {
    this.componentTrackers.clear()
    this.asyncOperationTrackers.clear()
    this.webSocketTrackers.clear()
    logger.info('MemoryLeakDetector', 'Cleared all memory trackers')
  }

  /**
   * Destroy detector
   */
  destroy(): void {
    this.stopDetection()
    this.clearAllTrackers()
    this.removeAllListeners()
    logger.info('MemoryLeakDetector', 'Memory leak detector destroyed')
  }
}

// Create singleton instance
export const memoryLeakDetector = new MemoryLeakDetector()
