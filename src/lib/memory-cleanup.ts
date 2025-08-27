/**
 * Memory Cleanup Service
 * Provides automatic and manual memory cleanup functionality
 */

import { logger } from '@/utils/logger'
import { memoryMonitor } from './memory-monitor'
import { storage } from '@/model/storage'
import { EventEmitter } from 'events'

export interface CleanupOptions {
  clearSearchResults?: boolean
  clearProcessingSteps?: boolean
  clearErrorLogs?: boolean
  clearCachedData?: boolean
  forceGarbageCollection?: boolean
  retainLastSessions?: number
}

export interface CleanupResult {
  success: boolean
  itemsCleared: number
  memoryFreed: number
  errors: string[]
  duration: number
}

export interface RetentionPolicy {
  maxSessions: number
  maxAge: number // in milliseconds
  maxSize: number // in bytes
  autoCleanup: boolean
}

export class MemoryCleanupService extends EventEmitter {
  private cleanupInterval: NodeJS.Timeout | null = null
  private isAutoCleanupEnabled: boolean = false
  private readonly defaultRetentionPolicy: RetentionPolicy = {
    maxSessions: 3,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    maxSize: 50 * 1024 * 1024, // 50MB
    autoCleanup: true,
  }

  private retentionPolicy: RetentionPolicy = { ...this.defaultRetentionPolicy }

  constructor() {
    super()
    this.setupMemoryMonitorListeners()
  }

  /**
   * Setup memory monitor event listeners
   */
  private setupMemoryMonitorListeners(): void {
    memoryMonitor.on('memory-alert', alert => {
      if (alert.level === 'emergency' && alert.action === 'emergency-cleanup') {
        logger.warn('MemoryCleanup', 'Emergency cleanup triggered by memory alert')
        this.performEmergencyCleanup()
      } else if (alert.level === 'critical' && alert.action === 'cleanup-suggested') {
        logger.info('MemoryCleanup', 'Automatic cleanup triggered by memory alert')
        this.performAutomaticCleanup()
      }
    })
  }

  /**
   * Start automatic cleanup monitoring
   */
  startAutoCleanup(intervalMs: number = 30000): void {
    // 30 seconds
    if (this.isAutoCleanupEnabled) {
      logger.warn('MemoryCleanup', 'Auto cleanup already enabled')
      return
    }

    this.isAutoCleanupEnabled = true
    this.cleanupInterval = setInterval(() => {
      this.performScheduledCleanup()
    }, intervalMs)

    logger.info('MemoryCleanup', `Auto cleanup started with ${intervalMs}ms interval`)
    this.emit('auto-cleanup-started')
  }

  /**
   * Stop automatic cleanup
   */
  stopAutoCleanup(): void {
    if (!this.isAutoCleanupEnabled) {
      return
    }

    this.isAutoCleanupEnabled = false
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }

    logger.info('MemoryCleanup', 'Auto cleanup stopped')
    this.emit('auto-cleanup-stopped')
  }

  /**
   * Perform manual cleanup with options
   */
  async performManualCleanup(options: CleanupOptions = {}): Promise<CleanupResult> {
    const startTime = Date.now()
    const initialMemory = memoryMonitor.getCurrentStats()

    logger.info('MemoryCleanup', 'Starting manual cleanup', options)

    const result: CleanupResult = {
      success: true,
      itemsCleared: 0,
      memoryFreed: 0,
      errors: [],
      duration: 0,
    }

    try {
      // Clear search results
      if (options.clearSearchResults !== false) {
        const cleared = await this.clearSearchResults(options.retainLastSessions)
        result.itemsCleared += cleared
      }

      // Clear processing steps
      if (options.clearProcessingSteps) {
        const cleared = await this.clearProcessingSteps()
        result.itemsCleared += cleared
      }

      // Clear error logs
      if (options.clearErrorLogs) {
        const cleared = await this.clearErrorLogs()
        result.itemsCleared += cleared
      }

      // Clear cached data
      if (options.clearCachedData) {
        const cleared = await this.clearCachedData()
        result.itemsCleared += cleared
      }

      // Force garbage collection
      if (options.forceGarbageCollection) {
        memoryMonitor.forceGarbageCollection()
      }

      // Calculate memory freed
      const finalMemory = memoryMonitor.getCurrentStats()
      if (initialMemory && finalMemory) {
        result.memoryFreed = initialMemory.used - finalMemory.used
      }

      result.duration = Date.now() - startTime

      logger.info('MemoryCleanup', 'Manual cleanup completed', {
        itemsCleared: result.itemsCleared,
        memoryFreed: result.memoryFreed,
        duration: result.duration,
      })

      this.emit('cleanup-completed', result)
    } catch (error) {
      result.success = false
      result.errors.push(error instanceof Error ? error.message : 'Unknown error')
      logger.error('MemoryCleanup', 'Manual cleanup failed', error)
    }

    return result
  }

  /**
   * Perform emergency cleanup (aggressive)
   */
  async performEmergencyCleanup(): Promise<CleanupResult> {
    logger.warn('MemoryCleanup', 'Performing emergency cleanup')

    return this.performManualCleanup({
      clearSearchResults: true,
      clearProcessingSteps: true,
      clearErrorLogs: true,
      clearCachedData: true,
      forceGarbageCollection: true,
      retainLastSessions: 1, // Only keep the most recent session
    })
  }

  /**
   * Perform automatic cleanup (moderate)
   */
  async performAutomaticCleanup(): Promise<CleanupResult> {
    logger.info('MemoryCleanup', 'Performing automatic cleanup')

    return this.performManualCleanup({
      clearSearchResults: true,
      clearProcessingSteps: false,
      clearErrorLogs: false,
      clearCachedData: true,
      forceGarbageCollection: false,
      retainLastSessions: this.retentionPolicy.maxSessions,
    })
  }

  /**
   * Perform scheduled cleanup based on retention policy
   */
  private async performScheduledCleanup(): Promise<void> {
    if (!this.retentionPolicy.autoCleanup) {
      return
    }

    try {
      // Check if cleanup is needed based on retention policy
      const needsCleanup = await this.checkCleanupNeeded()

      if (needsCleanup) {
        logger.info('MemoryCleanup', 'Scheduled cleanup triggered by retention policy')
        await this.performAutomaticCleanup()
      }
    } catch (error) {
      logger.error('MemoryCleanup', 'Scheduled cleanup failed', error)
    }
  }

  /**
   * Check if cleanup is needed based on retention policy
   */
  private async checkCleanupNeeded(): Promise<boolean> {
    try {
      // Check age-based cleanup
      const oldDataExists = await this.hasDataOlderThan(this.retentionPolicy.maxAge)
      if (oldDataExists) {
        return true
      }

      // Check size-based cleanup
      const totalSize = await this.getTotalStorageSize()
      if (totalSize > this.retentionPolicy.maxSize) {
        return true
      }

      // Check session count-based cleanup
      const sessionCount = await this.getSessionCount()
      if (sessionCount > this.retentionPolicy.maxSessions) {
        return true
      }

      return false
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to check cleanup needed', error)
      return false
    }
  }

  /**
   * Clear search results with optional retention
   */
  private async clearSearchResults(retainLastSessions?: number): Promise<number> {
    try {
      const businesses = await storage.getAllBusinesses()

      if (retainLastSessions && retainLastSessions > 0) {
        // Sort by scrapedAt and keep only the most recent sessions
        const sortedBusinesses = businesses.sort(
          (a, b) => new Date(b.scrapedAt).getTime() - new Date(a.scrapedAt).getTime()
        )

        // Group by session (approximate by time proximity)
        const sessions = this.groupBusinessesBySessions(sortedBusinesses)
        const sessionsToKeep = sessions.slice(0, retainLastSessions)
        const businessesToKeep = sessionsToKeep.flat()

        // Clear businesses not in the keep list
        const businessesToClear = businesses.filter(
          b => !businessesToKeep.some(keep => keep.id === b.id)
        )

        for (const business of businessesToClear) {
          await storage.deleteBusiness(business.id)
        }

        return businessesToClear.length
      } else {
        // Clear all search results
        for (const business of businesses) {
          await storage.deleteBusiness(business.id)
        }
        return businesses.length
      }
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to clear search results', error)
      return 0
    }
  }

  /**
   * Group businesses by sessions based on time proximity
   */
  private groupBusinessesBySessions(businesses: any[]): any[][] {
    const sessions: any[][] = []
    const sessionThreshold = 30 * 60 * 1000 // 30 minutes

    for (const business of businesses) {
      const businessTime = new Date(business.scrapedAt).getTime()

      // Find existing session within threshold
      let addedToSession = false
      for (const session of sessions) {
        if (session.length > 0) {
          const sessionTime = new Date(session[0].scrapedAt).getTime()
          if (Math.abs(businessTime - sessionTime) <= sessionThreshold) {
            session.push(business)
            addedToSession = true
            break
          }
        }
      }

      // Create new session if not added to existing one
      if (!addedToSession) {
        sessions.push([business])
      }
    }

    return sessions
  }

  /**
   * Clear processing steps
   */
  private async clearProcessingSteps(): Promise<number> {
    // This would integrate with the processing steps storage
    // For now, return 0 as placeholder
    return 0
  }

  /**
   * Clear error logs
   */
  private async clearErrorLogs(): Promise<number> {
    // This would integrate with error log storage
    // For now, return 0 as placeholder
    return 0
  }

  /**
   * Clear cached data
   */
  private async clearCachedData(): Promise<number> {
    try {
      // Clear browser caches if available
      if (typeof window !== 'undefined' && 'caches' in window) {
        const cacheNames = await caches.keys()
        for (const cacheName of cacheNames) {
          await caches.delete(cacheName)
        }
        return cacheNames.length
      }
      return 0
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to clear cached data', error)
      return 0
    }
  }

  /**
   * Check if data older than specified age exists
   */
  private async hasDataOlderThan(maxAge: number): Promise<boolean> {
    try {
      const businesses = await storage.getAllBusinesses()
      const cutoffTime = Date.now() - maxAge

      return businesses.some(business => new Date(business.scrapedAt).getTime() < cutoffTime)
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to check data age', error)
      return false
    }
  }

  /**
   * Get total storage size
   */
  private async getTotalStorageSize(): Promise<number> {
    try {
      // Estimate storage size based on business records
      const businesses = await storage.getAllBusinesses()
      const totalSize = businesses.reduce((size, business) => {
        return size + new Blob([JSON.stringify(business)]).size
      }, 0)

      return totalSize
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to get storage size', error)
      return 0
    }
  }

  /**
   * Get session count
   */
  private async getSessionCount(): Promise<number> {
    try {
      const businesses = await storage.getAllBusinesses()
      const sessions = this.groupBusinessesBySessions(businesses)
      return sessions.length
    } catch (error) {
      logger.error('MemoryCleanup', 'Failed to get session count', error)
      return 0
    }
  }

  /**
   * Update retention policy
   */
  updateRetentionPolicy(policy: Partial<RetentionPolicy>): void {
    this.retentionPolicy = { ...this.retentionPolicy, ...policy }
    logger.info('MemoryCleanup', 'Retention policy updated', this.retentionPolicy)
    this.emit('retention-policy-updated', this.retentionPolicy)
  }

  /**
   * Get current retention policy
   */
  getRetentionPolicy(): RetentionPolicy {
    return { ...this.retentionPolicy }
  }

  /**
   * Get cleanup status
   */
  getStatus(): {
    autoCleanupEnabled: boolean
    retentionPolicy: RetentionPolicy
  } {
    return {
      autoCleanupEnabled: this.isAutoCleanupEnabled,
      retentionPolicy: this.getRetentionPolicy(),
    }
  }

  /**
   * Destroy cleanup service
   */
  destroy(): void {
    this.stopAutoCleanup()
    this.removeAllListeners()
    logger.info('MemoryCleanup', 'Memory cleanup service destroyed')
  }
}

// Create singleton instance
export const memoryCleanup = new MemoryCleanupService()
