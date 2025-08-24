/**
 * React Hook for Memory Monitoring
 * Provides real-time memory statistics and alerts
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { memoryMonitor, MemoryStats, MemoryAlert, MemoryThresholds } from '@/lib/memory-monitor'
import { memoryCleanup, CleanupResult, CleanupOptions } from '@/lib/memory-cleanup'
import { logger } from '@/utils/logger'

export interface MemoryMonitorState {
  isMonitoring: boolean
  currentStats: MemoryStats | null
  memoryHistory: MemoryStats[]
  alerts: MemoryAlert[]
  thresholds: MemoryThresholds
  isCleanupInProgress: boolean
  lastCleanupResult: CleanupResult | null
}

export interface MemoryMonitorActions {
  startMonitoring: () => void
  stopMonitoring: () => void
  clearAlerts: () => void
  updateThresholds: (thresholds: Partial<MemoryThresholds>) => void
  performCleanup: (options?: CleanupOptions) => Promise<CleanupResult>
  performEmergencyCleanup: () => Promise<CleanupResult>
  dismissAlert: (index: number) => void
}

export function useMemoryMonitor(): MemoryMonitorState & MemoryMonitorActions {
  const [state, setState] = useState<MemoryMonitorState>({
    isMonitoring: false,
    currentStats: null,
    memoryHistory: [],
    alerts: [],
    thresholds: memoryMonitor.getThresholds(),
    isCleanupInProgress: false,
    lastCleanupResult: null
  })

  const alertsRef = useRef<MemoryAlert[]>([])
  const maxAlerts = 10

  // Update alerts ref when state changes
  useEffect(() => {
    alertsRef.current = state.alerts
  }, [state.alerts])

  // Setup memory monitor event listeners
  useEffect(() => {
    const handleMemoryUpdate = (stats: MemoryStats) => {
      setState(prev => ({
        ...prev,
        currentStats: stats,
        memoryHistory: [...prev.memoryHistory.slice(-99), stats] // Keep last 100 entries
      }))
    }

    const handleMemoryAlert = (alert: MemoryAlert) => {
      setState(prev => {
        const newAlerts = [...prev.alerts, alert].slice(-maxAlerts)
        return {
          ...prev,
          alerts: newAlerts
        }
      })
      
      logger.warn('MemoryMonitor', `Memory alert: ${alert.level}`, alert)
    }

    const handleMonitoringStarted = () => {
      setState(prev => ({ ...prev, isMonitoring: true }))
    }

    const handleMonitoringStopped = () => {
      setState(prev => ({ ...prev, isMonitoring: false }))
    }

    // Add event listeners
    memoryMonitor.on('memory-update', handleMemoryUpdate)
    memoryMonitor.on('memory-alert', handleMemoryAlert)
    memoryMonitor.on('monitoring-started', handleMonitoringStarted)
    memoryMonitor.on('monitoring-stopped', handleMonitoringStopped)

    // Initialize with current state
    setState(prev => ({
      ...prev,
      isMonitoring: memoryMonitor.isActive(),
      currentStats: memoryMonitor.getCurrentStats(),
      memoryHistory: memoryMonitor.getMemoryHistory(),
      thresholds: memoryMonitor.getThresholds()
    }))

    // Cleanup on unmount
    return () => {
      memoryMonitor.off('memory-update', handleMemoryUpdate)
      memoryMonitor.off('memory-alert', handleMemoryAlert)
      memoryMonitor.off('monitoring-started', handleMonitoringStarted)
      memoryMonitor.off('monitoring-stopped', handleMonitoringStopped)
    }
  }, [])

  // Actions
  const startMonitoring = useCallback(() => {
    memoryMonitor.startMonitoring()
  }, [])

  const stopMonitoring = useCallback(() => {
    memoryMonitor.stopMonitoring()
  }, [])

  const clearAlerts = useCallback(() => {
    setState(prev => ({ ...prev, alerts: [] }))
  }, [])

  const updateThresholds = useCallback((thresholds: Partial<MemoryThresholds>) => {
    memoryMonitor.updateThresholds(thresholds)
    setState(prev => ({
      ...prev,
      thresholds: memoryMonitor.getThresholds()
    }))
  }, [])

  const performCleanup = useCallback(async (options: CleanupOptions = {}): Promise<CleanupResult> => {
    setState(prev => ({ ...prev, isCleanupInProgress: true }))
    
    try {
      const result = await memoryCleanup.performManualCleanup(options)
      
      setState(prev => ({
        ...prev,
        isCleanupInProgress: false,
        lastCleanupResult: result
      }))
      
      return result
    } catch (error) {
      setState(prev => ({ ...prev, isCleanupInProgress: false }))
      throw error
    }
  }, [])

  const performEmergencyCleanup = useCallback(async (): Promise<CleanupResult> => {
    setState(prev => ({ ...prev, isCleanupInProgress: true }))
    
    try {
      const result = await memoryCleanup.performEmergencyCleanup()
      
      setState(prev => ({
        ...prev,
        isCleanupInProgress: false,
        lastCleanupResult: result
      }))
      
      return result
    } catch (error) {
      setState(prev => ({ ...prev, isCleanupInProgress: false }))
      throw error
    }
  }, [])

  const dismissAlert = useCallback((index: number) => {
    setState(prev => ({
      ...prev,
      alerts: prev.alerts.filter((_, i) => i !== index)
    }))
  }, [])

  return {
    ...state,
    startMonitoring,
    stopMonitoring,
    clearAlerts,
    updateThresholds,
    performCleanup,
    performEmergencyCleanup,
    dismissAlert
  }
}

/**
 * Hook for memory statistics formatting
 */
export function useMemoryFormatter() {
  const formatBytes = useCallback((bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }, [])

  const formatPercentage = useCallback((percentage: number): string => {
    return `${percentage.toFixed(1)}%`
  }, [])

  const getMemoryStatusColor = useCallback((percentage: number, thresholds: MemoryThresholds): string => {
    if (percentage >= thresholds.emergency) return 'text-red-600 dark:text-red-400'
    if (percentage >= thresholds.critical) return 'text-orange-600 dark:text-orange-400'
    if (percentage >= thresholds.warning) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-green-600 dark:text-green-400'
  }, [])

  const getMemoryStatusBgColor = useCallback((percentage: number, thresholds: MemoryThresholds): string => {
    if (percentage >= thresholds.emergency) return 'bg-red-500'
    if (percentage >= thresholds.critical) return 'bg-orange-500'
    if (percentage >= thresholds.warning) return 'bg-yellow-500'
    return 'bg-green-500'
  }, [])

  const getAlertIcon = useCallback((level: MemoryAlert['level']): string => {
    switch (level) {
      case 'emergency': return '🚨'
      case 'critical': return '⚠️'
      case 'warning': return '⚡'
      default: return 'ℹ️'
    }
  }, [])

  const getAlertColor = useCallback((level: MemoryAlert['level']): string => {
    switch (level) {
      case 'emergency': return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20'
      case 'critical': return 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20'
      case 'warning': return 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20'
      default: return 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20'
    }
  }, [])

  return {
    formatBytes,
    formatPercentage,
    getMemoryStatusColor,
    getMemoryStatusBgColor,
    getAlertIcon,
    getAlertColor
  }
}
