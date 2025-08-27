import React, { useState, useEffect, useCallback, useRef } from 'react'
import { logger } from '@/utils/logger'

/**
 * Performance metrics interface
 */
export interface PerformanceMetrics {
  renderTime: number
  memoryUsage: number
  scrollEvents: number
  lastRenderTime: number
  averageRenderTime: number
  peakMemoryUsage: number
  totalScrollEvents: number
  frameRate: number
  isPerformanceGood: boolean
}

/**
 * Performance thresholds for monitoring
 */
export interface PerformanceThresholds {
  maxRenderTime: number // milliseconds
  maxMemoryUsage: number // bytes
  minFrameRate: number // fps
}

/**
 * Default performance thresholds
 */
const DEFAULT_THRESHOLDS: PerformanceThresholds = {
  maxRenderTime: 16, // 60fps = 16.67ms per frame
  maxMemoryUsage: 100 * 1024 * 1024, // 100MB
  minFrameRate: 30, // 30fps minimum
}

/**
 * Custom hook for tracking and monitoring performance metrics
 * Tracks rendering times, memory usage, scroll events, and frame rates
 */
export function usePerformanceMetrics(
  componentName: string = 'Component',
  thresholds: PerformanceThresholds = DEFAULT_THRESHOLDS
) {
  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    renderTime: 0,
    memoryUsage: 0,
    scrollEvents: 0,
    lastRenderTime: 0,
    averageRenderTime: 0,
    peakMemoryUsage: 0,
    totalScrollEvents: 0,
    frameRate: 0,
    isPerformanceGood: true,
  })

  // Refs for tracking performance data
  const renderTimes = useRef<number[]>([])
  const scrollEventCount = useRef(0)
  const frameRateRef = useRef(0)
  const lastFrameTime = useRef(performance.now())
  const renderStartTime = useRef<number | null>(null)

  /**
   * Start measuring render time
   */
  const startRenderMeasurement = useCallback(() => {
    renderStartTime.current = performance.now()
  }, [])

  /**
   * End measuring render time and update metrics
   */
  const endRenderMeasurement = useCallback(() => {
    if (renderStartTime.current === null) return

    const renderTime = performance.now() - renderStartTime.current
    renderTimes.current.push(renderTime)

    // Keep only last 100 measurements for average calculation
    if (renderTimes.current.length > 100) {
      renderTimes.current.shift()
    }

    const averageRenderTime =
      renderTimes.current.reduce((a, b) => a + b, 0) / renderTimes.current.length

    // Log warning if render time exceeds threshold
    if (renderTime > thresholds.maxRenderTime) {
      logger.warn(`${componentName} render time exceeded threshold`, {
        renderTime,
        threshold: thresholds.maxRenderTime,
        componentName,
      })
    }

    renderStartTime.current = null

    setMetrics(prev => ({
      ...prev,
      renderTime,
      lastRenderTime: renderTime,
      averageRenderTime,
    }))
  }, [componentName, thresholds.maxRenderTime])

  /**
   * Track scroll events
   */
  const trackScrollEvent = useCallback(() => {
    scrollEventCount.current += 1
    setMetrics(prev => ({
      ...prev,
      scrollEvents: prev.scrollEvents + 1,
      totalScrollEvents: scrollEventCount.current,
    }))
  }, [])

  /**
   * Update memory usage metrics
   */
  const updateMemoryUsage = useCallback(() => {
    if ('memory' in performance) {
      const memoryInfo = (performance as any).memory
      const currentMemory = memoryInfo.usedJSHeapSize

      // Log warning if memory usage exceeds threshold
      if (currentMemory > thresholds.maxMemoryUsage) {
        logger.warn(`${componentName} memory usage exceeded threshold`, {
          memoryUsage: currentMemory,
          threshold: thresholds.maxMemoryUsage,
          componentName,
        })
      }

      setMetrics(prev => ({
        ...prev,
        memoryUsage: currentMemory,
        peakMemoryUsage: Math.max(prev.peakMemoryUsage, currentMemory),
      }))
    }
  }, [componentName, thresholds.maxMemoryUsage])

  /**
   * Calculate frame rate
   */
  const updateFrameRate = useCallback(() => {
    const now = performance.now()
    const delta = now - lastFrameTime.current
    frameRateRef.current = 1000 / delta
    lastFrameTime.current = now

    // Log warning if frame rate drops below threshold
    if (frameRateRef.current < thresholds.minFrameRate) {
      logger.warn(`${componentName} frame rate below threshold`, {
        frameRate: frameRateRef.current,
        threshold: thresholds.minFrameRate,
        componentName,
      })
    }

    setMetrics(prev => ({
      ...prev,
      frameRate: frameRateRef.current,
    }))
  }, [componentName, thresholds.minFrameRate])

  /**
   * Determine if overall performance is good
   */
  const updatePerformanceStatus = useCallback(() => {
    setMetrics(prev => {
      const isPerformanceGood =
        prev.lastRenderTime <= thresholds.maxRenderTime &&
        prev.memoryUsage <= thresholds.maxMemoryUsage &&
        prev.frameRate >= thresholds.minFrameRate

      return {
        ...prev,
        isPerformanceGood,
      }
    })
  }, [thresholds])

  /**
   * Reset all metrics
   */
  const resetMetrics = useCallback(() => {
    renderTimes.current = []
    scrollEventCount.current = 0
    frameRateRef.current = 0
    lastFrameTime.current = performance.now()
    renderStartTime.current = null

    setMetrics({
      renderTime: 0,
      memoryUsage: 0,
      scrollEvents: 0,
      lastRenderTime: 0,
      averageRenderTime: 0,
      peakMemoryUsage: 0,
      totalScrollEvents: 0,
      frameRate: 0,
      isPerformanceGood: true,
    })
  }, [])

  /**
   * Get performance summary for logging/debugging
   */
  const getPerformanceSummary = useCallback(() => {
    return {
      componentName,
      metrics,
      thresholds,
      timestamp: new Date().toISOString(),
    }
  }, [componentName, metrics, thresholds])

  // Set up periodic memory and frame rate monitoring
  useEffect(() => {
    const memoryInterval = setInterval(updateMemoryUsage, 1000) // Check memory every second
    const frameRateInterval = setInterval(updateFrameRate, 100) // Check frame rate every 100ms
    const statusInterval = setInterval(updatePerformanceStatus, 500) // Update status every 500ms

    return () => {
      clearInterval(memoryInterval)
      clearInterval(frameRateInterval)
      clearInterval(statusInterval)
    }
  }, [updateMemoryUsage, updateFrameRate, updatePerformanceStatus])

  // Log performance summary periodically in development
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      const logInterval = setInterval(() => {
        logger.info(`Performance metrics for ${componentName}`, getPerformanceSummary())
      }, 10000) // Log every 10 seconds

      return () => clearInterval(logInterval)
    }
  }, [componentName, getPerformanceSummary])

  return {
    metrics,
    startRenderMeasurement,
    endRenderMeasurement,
    trackScrollEvent,
    resetMetrics,
    getPerformanceSummary,
    thresholds,
  }
}

/**
 * Higher-order component for automatic performance tracking
 */
export function withPerformanceTracking<T extends object>(
  Component: React.ComponentType<T>,
  componentName?: string
) {
  return function PerformanceTrackedComponent(props: T) {
    const { startRenderMeasurement, endRenderMeasurement } = usePerformanceMetrics(
      componentName || Component.displayName || Component.name || 'Component'
    )

    React.useEffect(() => {
      startRenderMeasurement()
      return () => {
        endRenderMeasurement()
      }
    })

    return React.createElement(Component, props)
  }
}
