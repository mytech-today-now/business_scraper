/**
 * React Hook for Memory Leak Detection
 * Provides automatic memory leak detection for React components
 */

import { useEffect, useRef, useCallback } from 'react'
import { memoryLeakDetector, MemoryLeakAlert } from '@/lib/memory-leak-detector'
import { logger } from '@/utils/logger'

export interface UseMemoryLeakDetectionOptions {
  componentName: string
  trackAsyncOperations?: boolean
  trackWebSockets?: boolean
  updateInterval?: number
  onMemoryLeak?: (alert: MemoryLeakAlert) => void
}

export interface MemoryLeakDetectionState {
  isTracking: boolean
  currentMemoryUsage: number
  memoryIncrease: number
  alerts: MemoryLeakAlert[]
}

export function useMemoryLeakDetection(options: UseMemoryLeakDetectionOptions) {
  const {
    componentName,
    trackAsyncOperations = true,
    trackWebSockets = true,
    updateInterval = 5000,
    onMemoryLeak,
  } = options

  const trackerIdRef = useRef<string | null>(null)
  const alertsRef = useRef<MemoryLeakAlert[]>([])
  const updateIntervalRef = useRef<NodeJS.Timeout | null>(null)

  /**
   * Start tracking component memory usage
   */
  const startTracking = useCallback(() => {
    if (trackerIdRef.current) {
      return // Already tracking
    }

    try {
      trackerIdRef.current = memoryLeakDetector.trackComponent(componentName)
      
      // Set up memory update interval
      updateIntervalRef.current = setInterval(() => {
        if (trackerIdRef.current) {
          memoryLeakDetector.updateComponentMemory(trackerIdRef.current)
        }
      }, updateInterval)

      logger.debug('useMemoryLeakDetection', `Started tracking component: ${componentName}`)
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to start tracking component: ${componentName}`, error)
    }
  }, [componentName, updateInterval])

  /**
   * Stop tracking component memory usage
   */
  const stopTracking = useCallback(() => {
    if (trackerIdRef.current) {
      memoryLeakDetector.stopTrackingComponent(trackerIdRef.current)
      trackerIdRef.current = null
    }

    if (updateIntervalRef.current) {
      clearInterval(updateIntervalRef.current)
      updateIntervalRef.current = null
    }

    logger.debug('useMemoryLeakDetection', `Stopped tracking component: ${componentName}`)
  }, [componentName])

  /**
   * Track async operation
   */
  const trackAsyncOperation = useCallback((operationType: string, timeoutMs?: number): string => {
    if (!trackAsyncOperations) {
      return ''
    }

    try {
      const operationId = memoryLeakDetector.trackAsyncOperation(operationType, timeoutMs)
      logger.debug('useMemoryLeakDetection', `Started tracking async operation: ${operationType}`)
      return operationId
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to track async operation: ${operationType}`, error)
      return ''
    }
  }, [trackAsyncOperations])

  /**
   * Complete async operation tracking
   */
  const completeAsyncOperation = useCallback((operationId: string) => {
    if (!trackAsyncOperations || !operationId) {
      return
    }

    try {
      memoryLeakDetector.completeAsyncOperation(operationId)
      logger.debug('useMemoryLeakDetection', `Completed async operation: ${operationId}`)
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to complete async operation: ${operationId}`, error)
    }
  }, [trackAsyncOperations])

  /**
   * Track WebSocket connection
   */
  const trackWebSocket = useCallback((url: string): string => {
    if (!trackWebSockets) {
      return ''
    }

    try {
      const connectionId = memoryLeakDetector.trackWebSocket(url)
      logger.debug('useMemoryLeakDetection', `Started tracking WebSocket: ${url}`)
      return connectionId
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to track WebSocket: ${url}`, error)
      return ''
    }
  }, [trackWebSockets])

  /**
   * Update WebSocket activity
   */
  const updateWebSocketActivity = useCallback((connectionId: string) => {
    if (!trackWebSockets || !connectionId) {
      return
    }

    try {
      memoryLeakDetector.updateWebSocketActivity(connectionId)
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to update WebSocket activity: ${connectionId}`, error)
    }
  }, [trackWebSockets])

  /**
   * Stop tracking WebSocket
   */
  const stopTrackingWebSocket = useCallback((connectionId: string) => {
    if (!trackWebSockets || !connectionId) {
      return
    }

    try {
      memoryLeakDetector.stopTrackingWebSocket(connectionId)
      logger.debug('useMemoryLeakDetection', `Stopped tracking WebSocket: ${connectionId}`)
    } catch (error) {
      logger.error('useMemoryLeakDetection', `Failed to stop tracking WebSocket: ${connectionId}`, error)
    }
  }, [trackWebSockets])

  /**
   * Handle memory leak alerts
   */
  const handleMemoryLeakAlert = useCallback((alert: MemoryLeakAlert) => {
    // Only handle alerts for this component
    if (alert.component && alert.component !== componentName) {
      return
    }

    alertsRef.current.push(alert)
    
    // Keep only last 10 alerts
    if (alertsRef.current.length > 10) {
      alertsRef.current.shift()
    }

    logger.warn('useMemoryLeakDetection', `Memory leak detected in component: ${componentName}`, {
      type: alert.type,
      description: alert.description,
      memoryIncrease: alert.memoryIncrease,
      severity: alert.severity,
    })

    if (onMemoryLeak) {
      onMemoryLeak(alert)
    }
  }, [componentName, onMemoryLeak])

  /**
   * Get current memory status
   */
  const getMemoryStatus = useCallback((): MemoryLeakDetectionState => {
    const currentMemoryUsage = typeof process !== 'undefined' && process.memoryUsage
      ? process.memoryUsage().heapUsed
      : typeof window !== 'undefined' && 'performance' in window && 'memory' in performance
      ? (performance as any).memory.usedJSHeapSize
      : 0

    return {
      isTracking: trackerIdRef.current !== null,
      currentMemoryUsage,
      memoryIncrease: 0, // This would be calculated from initial memory
      alerts: [...alertsRef.current],
    }
  }, [])

  /**
   * Clear alerts
   */
  const clearAlerts = useCallback(() => {
    alertsRef.current = []
  }, [])

  // Set up component lifecycle tracking
  useEffect(() => {
    startTracking()

    // Set up memory leak alert listener
    memoryLeakDetector.on('memory-leak-detected', handleMemoryLeakAlert)

    return () => {
      stopTracking()
      memoryLeakDetector.off('memory-leak-detected', handleMemoryLeakAlert)
    }
  }, [startTracking, stopTracking, handleMemoryLeakAlert])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopTracking()
    }
  }, [stopTracking])

  return {
    // State
    isTracking: trackerIdRef.current !== null,
    alerts: alertsRef.current,
    
    // Actions
    startTracking,
    stopTracking,
    trackAsyncOperation,
    completeAsyncOperation,
    trackWebSocket,
    updateWebSocketActivity,
    stopTrackingWebSocket,
    getMemoryStatus,
    clearAlerts,
  }
}

/**
 * Higher-order component for automatic memory leak detection
 */
export function withMemoryLeakDetection<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  componentName?: string
) {
  const WithMemoryLeakDetection = (props: P) => {
    const detectedComponentName = componentName || WrappedComponent.displayName || WrappedComponent.name || 'UnknownComponent'
    
    useMemoryLeakDetection({
      componentName: detectedComponentName,
      onMemoryLeak: (alert) => {
        logger.warn('withMemoryLeakDetection', `Memory leak detected in HOC-wrapped component: ${detectedComponentName}`, alert)
      },
    })

    return <WrappedComponent {...props} />
  }

  WithMemoryLeakDetection.displayName = `withMemoryLeakDetection(${componentName || WrappedComponent.displayName || WrappedComponent.name})`

  return WithMemoryLeakDetection
}

/**
 * Hook for tracking async operations with automatic cleanup
 */
export function useAsyncOperationTracking(operationType: string, timeoutMs: number = 30000) {
  const operationIdRef = useRef<string | null>(null)

  const startOperation = useCallback(() => {
    if (operationIdRef.current) {
      memoryLeakDetector.completeAsyncOperation(operationIdRef.current)
    }
    
    operationIdRef.current = memoryLeakDetector.trackAsyncOperation(operationType, timeoutMs)
    return operationIdRef.current
  }, [operationType, timeoutMs])

  const completeOperation = useCallback(() => {
    if (operationIdRef.current) {
      memoryLeakDetector.completeAsyncOperation(operationIdRef.current)
      operationIdRef.current = null
    }
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      completeOperation()
    }
  }, [completeOperation])

  return {
    startOperation,
    completeOperation,
    operationId: operationIdRef.current,
  }
}

/**
 * Hook for tracking WebSocket connections with automatic cleanup
 */
export function useWebSocketTracking(url: string) {
  const connectionIdRef = useRef<string | null>(null)

  const startTracking = useCallback(() => {
    if (connectionIdRef.current) {
      memoryLeakDetector.stopTrackingWebSocket(connectionIdRef.current)
    }
    
    connectionIdRef.current = memoryLeakDetector.trackWebSocket(url)
    return connectionIdRef.current
  }, [url])

  const updateActivity = useCallback(() => {
    if (connectionIdRef.current) {
      memoryLeakDetector.updateWebSocketActivity(connectionIdRef.current)
    }
  }, [])

  const stopTracking = useCallback(() => {
    if (connectionIdRef.current) {
      memoryLeakDetector.stopTrackingWebSocket(connectionIdRef.current)
      connectionIdRef.current = null
    }
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopTracking()
    }
  }, [stopTracking])

  return {
    startTracking,
    updateActivity,
    stopTracking,
    connectionId: connectionIdRef.current,
  }
}
