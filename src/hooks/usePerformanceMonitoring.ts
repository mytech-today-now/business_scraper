'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { logger } from '@/utils/logger'

/**
 * Performance monitoring metrics
 */
export interface PerformanceMetrics {
  /** Memory usage in bytes */
  memoryUsage: number
  /** Memory usage in MB for display */
  memoryUsageMB: number
  /** Memory trend */
  memoryTrend: 'increasing' | 'decreasing' | 'stable'
  /** Render time in milliseconds */
  renderTime: number
  /** Average render time over last 10 renders */
  averageRenderTime: number
  /** FPS (frames per second) */
  fps: number
  /** Performance score (0-100) */
  performanceScore: number
  /** DOM node count */
  domNodeCount: number
  /** Is high memory usage */
  isHighMemoryUsage: boolean
  /** Is performance degraded */
  isPerformanceDegraded: boolean
}

/**
 * Performance monitoring configuration
 */
export interface PerformanceMonitoringConfig {
  /** Monitoring interval in milliseconds */
  interval: number
  /** Memory threshold in bytes */
  memoryThreshold: number
  /** Render time threshold in milliseconds */
  renderTimeThreshold: number
  /** Enable FPS monitoring */
  enableFpsMonitoring: boolean
  /** Enable memory monitoring */
  enableMemoryMonitoring: boolean
  /** Enable render time monitoring */
  enableRenderTimeMonitoring: boolean
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: PerformanceMonitoringConfig = {
  interval: 5000, // 5 seconds
  memoryThreshold: 500 * 1024 * 1024, // 500MB
  renderTimeThreshold: 100, // 100ms
  enableFpsMonitoring: true,
  enableMemoryMonitoring: true,
  enableRenderTimeMonitoring: true,
}

/**
 * Performance monitoring hook
 * Provides real-time performance metrics and monitoring capabilities
 */
export function usePerformanceMonitoring(config: Partial<PerformanceMonitoringConfig> = {}) {
  const finalConfig = { ...DEFAULT_CONFIG, ...config }
  
  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    memoryUsage: 0,
    memoryUsageMB: 0,
    memoryTrend: 'stable',
    renderTime: 0,
    averageRenderTime: 0,
    fps: 0,
    performanceScore: 100,
    domNodeCount: 0,
    isHighMemoryUsage: false,
    isPerformanceDegraded: false,
  })

  const [isMonitoring, setIsMonitoring] = useState(false)
  const intervalRef = useRef<NodeJS.Timeout | null>(null)
  const renderTimesRef = useRef<number[]>([])
  const lastMemoryUsageRef = useRef<number>(0)
  const fpsCounterRef = useRef<{ frames: number; lastTime: number }>({ frames: 0, lastTime: 0 })

  /**
   * Get current memory usage
   */
  const getMemoryUsage = useCallback((): number => {
    if (typeof window !== 'undefined' && 'performance' in window && 'memory' in performance) {
      return (performance as any).memory?.usedJSHeapSize || 0
    }
    return 0
  }, [])

  /**
   * Get DOM node count
   */
  const getDomNodeCount = useCallback((): number => {
    if (typeof document !== 'undefined') {
      return document.querySelectorAll('*').length
    }
    return 0
  }, [])

  /**
   * Calculate memory trend
   */
  const calculateMemoryTrend = useCallback((current: number, previous: number): 'increasing' | 'decreasing' | 'stable' => {
    const diff = current - previous
    const threshold = 10 * 1024 * 1024 // 10MB threshold
    
    if (diff > threshold) return 'increasing'
    if (diff < -threshold) return 'decreasing'
    return 'stable'
  }, [])

  /**
   * Calculate performance score
   */
  const calculatePerformanceScore = useCallback((metrics: Partial<PerformanceMetrics>): number => {
    let score = 100

    // Memory score (0-40 points)
    if (metrics.memoryUsage) {
      const memoryScore = Math.max(0, 40 - (metrics.memoryUsage / finalConfig.memoryThreshold) * 40)
      score -= (40 - memoryScore)
    }

    // Render time score (0-30 points)
    if (metrics.averageRenderTime) {
      const renderScore = Math.max(0, 30 - (metrics.averageRenderTime / finalConfig.renderTimeThreshold) * 30)
      score -= (30 - renderScore)
    }

    // FPS score (0-20 points)
    if (metrics.fps !== undefined) {
      const fpsScore = Math.max(0, Math.min(20, (metrics.fps / 60) * 20))
      score -= (20 - fpsScore)
    }

    // DOM node count score (0-10 points)
    if (metrics.domNodeCount) {
      const domScore = Math.max(0, 10 - Math.max(0, (metrics.domNodeCount - 1000) / 100))
      score -= (10 - domScore)
    }

    return Math.round(Math.max(0, Math.min(100, score)))
  }, [finalConfig])

  /**
   * Update FPS counter
   */
  const updateFps = useCallback(() => {
    if (!finalConfig.enableFpsMonitoring) return

    const now = performance.now()
    fpsCounterRef.current.frames++

    if (now - fpsCounterRef.current.lastTime >= 1000) {
      const fps = Math.round((fpsCounterRef.current.frames * 1000) / (now - fpsCounterRef.current.lastTime))
      fpsCounterRef.current.frames = 0
      fpsCounterRef.current.lastTime = now

      setMetrics(prev => ({ ...prev, fps }))
    }

    if (isMonitoring) {
      requestAnimationFrame(updateFps)
    }
  }, [finalConfig.enableFpsMonitoring, isMonitoring])

  /**
   * Record render time
   */
  const recordRenderTime = useCallback((renderTime: number) => {
    if (!finalConfig.enableRenderTimeMonitoring) return

    renderTimesRef.current.push(renderTime)
    
    // Keep only last 10 render times
    if (renderTimesRef.current.length > 10) {
      renderTimesRef.current.shift()
    }

    const averageRenderTime = renderTimesRef.current.reduce((sum, time) => sum + time, 0) / renderTimesRef.current.length

    setMetrics(prev => ({
      ...prev,
      renderTime,
      averageRenderTime: Math.round(averageRenderTime),
    }))
  }, [finalConfig.enableRenderTimeMonitoring])

  /**
   * Update metrics
   */
  const updateMetrics = useCallback(() => {
    const memoryUsage = finalConfig.enableMemoryMonitoring ? getMemoryUsage() : 0
    const memoryUsageMB = Math.round(memoryUsage / 1024 / 1024)
    const memoryTrend = calculateMemoryTrend(memoryUsage, lastMemoryUsageRef.current)
    const domNodeCount = getDomNodeCount()

    const newMetrics: Partial<PerformanceMetrics> = {
      memoryUsage,
      memoryUsageMB,
      memoryTrend,
      domNodeCount,
      isHighMemoryUsage: memoryUsage > finalConfig.memoryThreshold,
    }

    // Calculate performance score
    setMetrics(prev => {
      const updatedMetrics = { ...prev, ...newMetrics }
      const performanceScore = calculatePerformanceScore(updatedMetrics)
      const isPerformanceDegraded = performanceScore < 60

      return {
        ...updatedMetrics,
        performanceScore,
        isPerformanceDegraded,
      }
    })

    lastMemoryUsageRef.current = memoryUsage

    logger.debug('PerformanceMonitoring', 'Metrics updated', {
      memoryUsageMB,
      memoryTrend,
      domNodeCount,
      isHighMemoryUsage: memoryUsage > finalConfig.memoryThreshold,
    })
  }, [finalConfig, getMemoryUsage, calculateMemoryTrend, getDomNodeCount, calculatePerformanceScore])

  /**
   * Start monitoring
   */
  const startMonitoring = useCallback(() => {
    if (isMonitoring) return

    setIsMonitoring(true)
    
    // Start metrics collection
    intervalRef.current = setInterval(updateMetrics, finalConfig.interval)
    
    // Start FPS monitoring
    if (finalConfig.enableFpsMonitoring) {
      fpsCounterRef.current = { frames: 0, lastTime: performance.now() }
      requestAnimationFrame(updateFps)
    }

    // Initial metrics update
    updateMetrics()

    logger.info('PerformanceMonitoring', 'Started monitoring', finalConfig)
  }, [isMonitoring, finalConfig, updateMetrics, updateFps])

  /**
   * Stop monitoring
   */
  const stopMonitoring = useCallback(() => {
    if (!isMonitoring) return

    setIsMonitoring(false)

    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }

    logger.info('PerformanceMonitoring', 'Stopped monitoring')
  }, [isMonitoring])

  /**
   * Reset metrics
   */
  const resetMetrics = useCallback(() => {
    setMetrics({
      memoryUsage: 0,
      memoryUsageMB: 0,
      memoryTrend: 'stable',
      renderTime: 0,
      averageRenderTime: 0,
      fps: 0,
      performanceScore: 100,
      domNodeCount: 0,
      isHighMemoryUsage: false,
      isPerformanceDegraded: false,
    })
    renderTimesRef.current = []
    lastMemoryUsageRef.current = 0
  }, [])

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      stopMonitoring()
    }
  }, [stopMonitoring])

  return {
    metrics,
    isMonitoring,
    startMonitoring,
    stopMonitoring,
    resetMetrics,
    recordRenderTime,
    config: finalConfig,
  }
}
