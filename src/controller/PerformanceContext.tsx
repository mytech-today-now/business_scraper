'use client'

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import {
  PerformanceContextType,
  PerformanceState,
  PerformanceMode,
  PerformanceMetrics,
  DEFAULT_PERFORMANCE_THRESHOLDS,
  DEFAULT_PERFORMANCE_PREFERENCES,
} from '@/types/performance'
import { logger } from '@/utils/logger'

/**
 * Performance Context for managing intelligent performance optimization
 */
const PerformanceContext = createContext<PerformanceContextType | null>(null)

/**
 * Default performance state
 */
const defaultState: PerformanceState = {
  mode: 'normal',
  metrics: {
    memoryUsage: 0,
    datasetSize: 0,
    currentMode: 'normal',
    lastRenderTime: 0,
    averageRenderTime: 0,
    memoryTrend: 'stable',
    performanceScore: 100,
  },
  preferences: DEFAULT_PERFORMANCE_PREFERENCES,
  showAdvisoryBanner: false,
  showPaginationPrompt: false,
  currentPage: 1,
  isMonitoring: false,
  lastModeChange: Date.now(),
}

/**
 * Performance Provider Props
 */
interface PerformanceProviderProps {
  children: ReactNode
  datasetSize?: number
}

/**
 * Performance Provider Component
 * Manages intelligent performance optimization and auto-detection
 */
export function PerformanceProvider({ children, datasetSize = 0 }: PerformanceProviderProps) {
  const [state, setState] = useState<PerformanceState>(defaultState)
  const [renderTimes, setRenderTimes] = useState<number[]>([])

  /**
   * Load preferences from localStorage
   */
  const loadPreferences = useCallback(() => {
    try {
      const saved = localStorage.getItem('performancePreferences')
      if (saved) {
        const preferences = { ...DEFAULT_PERFORMANCE_PREFERENCES, ...JSON.parse(saved) }
        setState(prev => ({ ...prev, preferences }))
      }
    } catch (error) {
      logger.error('PerformanceProvider', 'Failed to load preferences', error)
    }
  }, [])

  /**
   * Save preferences to localStorage
   */
  const savePreferences = useCallback((preferences: typeof state.preferences) => {
    try {
      localStorage.setItem('performancePreferences', JSON.stringify(preferences))
    } catch (error) {
      logger.error('PerformanceProvider', 'Failed to save preferences', error)
    }
  }, [])

  /**
   * Get current memory usage
   */
  const getMemoryUsage = useCallback((): number => {
    if (typeof window !== 'undefined' && 'performance' in window && 'memory' in performance) {
      return (performance as any).memory.usedJSHeapSize || 0
    }
    return 0
  }, [])

  /**
   * Calculate performance score based on metrics
   */
  const calculatePerformanceScore = useCallback((metrics: PerformanceMetrics): number => {
    const memoryScore = Math.max(0, 100 - (metrics.memoryUsage / (500 * 1024 * 1024)) * 50)
    const renderScore = Math.max(0, 100 - (metrics.averageRenderTime / 1000) * 30)
    const sizeScore = Math.max(0, 100 - (metrics.datasetSize / 10000) * 20)
    
    return Math.round((memoryScore + renderScore + sizeScore) / 3)
  }, [])

  /**
   * Determine optimal performance mode based on dataset size and preferences
   */
  const determineOptimalMode = useCallback((size: number): PerformanceMode => {
    const thresholds = { ...DEFAULT_PERFORMANCE_THRESHOLDS, ...state.preferences.customThresholds }

    // Check user overrides first
    if (state.preferences.forceDisableVirtualization && size >= thresholds.virtualization) {
      return state.preferences.forceEnablePagination ? 'pagination' : 'advisory'
    }

    if (state.preferences.forceEnablePagination && size >= thresholds.pagination) {
      return 'pagination'
    }

    // Auto-detection logic
    if (!state.preferences.autoDetection) {
      return 'normal'
    }

    if (size >= thresholds.virtualization) {
      return 'virtualized'
    }

    if (size >= thresholds.pagination) {
      return 'pagination'
    }

    if (size >= thresholds.advisory) {
      return 'advisory'
    }

    return 'normal'
  }, [state.preferences])

  /**
   * Update performance metrics
   */
  const updateMetrics = useCallback(() => {
    if (!state.isMonitoring) return

    const memoryUsage = getMemoryUsage()
    const currentTime = Date.now()
    
    setState(prev => {
      const newMetrics: PerformanceMetrics = {
        ...prev.metrics,
        memoryUsage,
        datasetSize,
        currentMode: prev.mode,
        performanceScore: 0, // Will be calculated below
      }

      // Calculate memory trend
      const memoryDiff = memoryUsage - prev.metrics.memoryUsage
      newMetrics.memoryTrend = memoryDiff > 10 * 1024 * 1024 ? 'increasing' 
                             : memoryDiff < -10 * 1024 * 1024 ? 'decreasing' 
                             : 'stable'

      // Calculate performance score
      newMetrics.performanceScore = calculatePerformanceScore(newMetrics)

      return { ...prev, metrics: newMetrics }
    })
  }, [state.isMonitoring, getMemoryUsage, datasetSize, calculatePerformanceScore])

  /**
   * Auto-detect and update performance mode
   */
  const autoDetectMode = useCallback(() => {
    if (!state.preferences.autoDetection) return

    const optimalMode = determineOptimalMode(datasetSize)
    const thresholds = { ...DEFAULT_PERFORMANCE_THRESHOLDS, ...state.preferences.customThresholds }

    setState(prev => {
      const updates: Partial<PerformanceState> = {}
      let hasUpdates = false

      // Update mode if different
      if (optimalMode !== prev.mode) {
        updates.mode = optimalMode
        updates.lastModeChange = Date.now()
        hasUpdates = true
        logger.info('PerformanceProvider', `Mode changed to ${optimalMode} for dataset size ${datasetSize}`)
      }

      // Show/hide advisory banner
      const shouldShowAdvisory = datasetSize >= thresholds.advisory && datasetSize < thresholds.pagination
      if (shouldShowAdvisory !== prev.showAdvisoryBanner) {
        updates.showAdvisoryBanner = shouldShowAdvisory
        hasUpdates = true
      }

      // Show/hide pagination prompt
      const shouldShowPagination = datasetSize >= thresholds.pagination && datasetSize < thresholds.virtualization && !prev.showPaginationPrompt
      if (shouldShowPagination !== prev.showPaginationPrompt) {
        updates.showPaginationPrompt = shouldShowPagination
        hasUpdates = true
      }

      // Only update if there are actual changes
      return hasUpdates ? { ...prev, ...updates } : prev
    })
  }, [datasetSize, state.preferences.autoDetection, state.preferences.customThresholds, state.preferences.forceDisableVirtualization, state.preferences.forceEnablePagination])

  /**
   * Performance monitoring effect
   */
  useEffect(() => {
    if (state.isMonitoring) {
      const interval = setInterval(updateMetrics, 5000) // Update every 5 seconds
      return () => clearInterval(interval)
    }
  }, [state.isMonitoring, updateMetrics])

  /**
   * Auto-detection effect
   */
  useEffect(() => {
    autoDetectMode()
  }, [datasetSize, state.preferences.autoDetection])

  /**
   * Load preferences on mount
   */
  useEffect(() => {
    loadPreferences()
  }, [loadPreferences])

  /**
   * Start monitoring automatically if enabled
   */
  useEffect(() => {
    if (state.preferences.enableMonitoring && !state.isMonitoring) {
      setState(prev => ({ ...prev, isMonitoring: true }))
    }
  }, [state.preferences.enableMonitoring, state.isMonitoring])

  // Action implementations
  const updatePreferences = useCallback((updates: Partial<typeof state.preferences>) => {
    setState(prev => {
      const newPreferences = { ...prev.preferences, ...updates }
      savePreferences(newPreferences)
      return { ...prev, preferences: newPreferences }
    })
  }, [savePreferences])

  const setMode = useCallback((mode: PerformanceMode) => {
    setState(prev => ({
      ...prev,
      mode,
      lastModeChange: Date.now(),
    }))
    logger.info('PerformanceProvider', `Manual mode change to ${mode}`)
  }, [])

  const dismissAdvisoryBanner = useCallback(() => {
    setState(prev => ({ ...prev, showAdvisoryBanner: false }))
  }, [])

  const acceptPagination = useCallback(() => {
    setState(prev => ({
      ...prev,
      mode: 'pagination',
      showPaginationPrompt: false,
      lastModeChange: Date.now(),
    }))
  }, [])

  const declinePagination = useCallback(() => {
    setState(prev => ({ ...prev, showPaginationPrompt: false }))
  }, [])

  const setCurrentPage = useCallback((page: number) => {
    setState(prev => ({ ...prev, currentPage: page }))
  }, [])

  const startMonitoring = useCallback(() => {
    setState(prev => ({ ...prev, isMonitoring: true }))
  }, [])

  const stopMonitoring = useCallback(() => {
    setState(prev => ({ ...prev, isMonitoring: false }))
  }, [])

  const resetPerformance = useCallback(() => {
    setState(defaultState)
  }, [])

  const contextValue: PerformanceContextType = {
    ...state,
    updatePreferences,
    setMode,
    dismissAdvisoryBanner,
    acceptPagination,
    declinePagination,
    setCurrentPage,
    startMonitoring,
    stopMonitoring,
    resetPerformance,
  }

  return (
    <PerformanceContext.Provider value={contextValue}>
      {children}
    </PerformanceContext.Provider>
  )
}

/**
 * Hook to use performance context
 */
export function usePerformance(): PerformanceContextType {
  const context = useContext(PerformanceContext)
  if (!context) {
    throw new Error('usePerformance must be used within a PerformanceProvider')
  }
  return context
}
