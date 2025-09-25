/**
 * Toast Deduplication Utility
 * 
 * Prevents duplicate toast notifications from appearing within a short time period.
 * This is particularly useful for preventing multiple identical toasts during
 * component initialization or rapid state changes.
 */

import { logger } from '@/utils/logger'

interface ToastRecord {
  message: string
  type: 'success' | 'error' | 'warning' | 'info'
  timestamp: number
}

class ToastDeduplicationManager {
  private recentToasts: Map<string, ToastRecord> = new Map()
  private readonly DEDUPLICATION_WINDOW_MS = 5000 // 5 seconds (increased from 2)
  private readonly MAX_RECORDS = 50 // Prevent memory leaks
  private readonly ZIP_CODE_DEDUPLICATION_WINDOW_MS = 15000 // 15 seconds for ZIP code toasts (increased)
  private readonly COMPONENT_DEDUPLICATION_WINDOW_MS = 8000 // 8 seconds for component-level deduplication

  /**
   * Check if a toast should be shown or if it's a duplicate
   * Enhanced with better deduplication logic for different toast types
   */
  shouldShowToast(message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info'): boolean {
    const now = Date.now()
    const key = this.generateKey(message, type)

    // Clean up old records periodically
    this.cleanupOldRecords(now)

    const existingRecord = this.recentToasts.get(key)

    if (existingRecord) {
      const timeSinceLastToast = now - existingRecord.timestamp

      // Use appropriate deduplication window based on toast type and content
      const deduplicationWindow = this.getDeduplicationWindow(message, type)

      if (timeSinceLastToast < deduplicationWindow) {
        logger.debug('ToastDeduplication', `Suppressing duplicate toast: "${message}" (${type}) - ${timeSinceLastToast}ms since last (window: ${deduplicationWindow}ms)`)
        return false
      }
    }

    // Clean up again if we're at the limit before adding new record
    if (this.recentToasts.size >= this.MAX_RECORDS) {
      this.cleanupOldRecords(now)
    }

    // Record this toast
    this.recentToasts.set(key, {
      message,
      type,
      timestamp: now
    })

    logger.debug('ToastDeduplication', `Allowing toast: "${message}" (${type})`)
    return true
  }

  /**
   * Check if a toast message is related to ZIP code validation
   */
  private isZipCodeToast(message: string): boolean {
    return message.toLowerCase().includes('zip code') && message.toLowerCase().includes('valid')
  }

  /**
   * Generate a unique key for the toast message and type
   */
  private generateKey(message: string, type: string): string {
    return `${type}:${message}`
  }

  /**
   * Get appropriate deduplication window based on message content and type
   */
  private getDeduplicationWindow(message: string, type: 'success' | 'error' | 'warning' | 'info'): number {
    // ZIP code validation toasts need longer deduplication
    if (this.isZipCodeToast(message)) {
      return this.ZIP_CODE_DEDUPLICATION_WINDOW_MS
    }

    // Component initialization or configuration toasts
    if (message.includes('initialized') || message.includes('configuration') || message.includes('loaded')) {
      return this.COMPONENT_DEDUPLICATION_WINDOW_MS
    }

    // Error toasts should have shorter deduplication to ensure visibility
    if (type === 'error') {
      return Math.min(this.DEDUPLICATION_WINDOW_MS, 3000)
    }

    // Default deduplication window
    return this.DEDUPLICATION_WINDOW_MS
  }

  /**
   * Clean up old toast records to prevent memory leaks
   */
  private cleanupOldRecords(currentTime: number): void {
    let removedCount = 0

    // Remove expired records using the appropriate window for each toast type
    for (const [key, record] of this.recentToasts.entries()) {
      const deduplicationWindow = this.getDeduplicationWindow(record.message, record.type)
      const cutoffTime = currentTime - deduplicationWindow

      if (record.timestamp < cutoffTime) {
        this.recentToasts.delete(key)
        removedCount++
      }
    }

    // If we still have too many records, remove the oldest ones
    if (this.recentToasts.size > this.MAX_RECORDS) {
      const sortedEntries = Array.from(this.recentToasts.entries())
        .sort(([, a], [, b]) => a.timestamp - b.timestamp)

      const excessCount = this.recentToasts.size - this.MAX_RECORDS
      const toRemove = sortedEntries.slice(0, excessCount)
      toRemove.forEach(([key]) => this.recentToasts.delete(key))

      removedCount += toRemove.length
      logger.debug('ToastDeduplication', `Cleaned up ${toRemove.length} excess toast records`)
    }

    if (removedCount > 0) {
      logger.debug('ToastDeduplication', `Total cleaned up: ${removedCount} toast records`)
    }
  }

  /**
   * Clear all toast records (useful for testing)
   */
  clear(): void {
    this.recentToasts.clear()
    logger.debug('ToastDeduplication', 'Cleared all toast records')
  }

  /**
   * Get the number of tracked toast records (useful for testing)
   */
  getRecordCount(): number {
    return this.recentToasts.size
  }

  /**
   * Force allow a toast even if it would normally be deduplicated
   */
  forceShowToast(message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info'): void {
    const key = this.generateKey(message, type)
    this.recentToasts.delete(key)
    logger.debug('ToastDeduplication', `Force allowing toast: "${message}" (${type})`)
  }
}

// Export a singleton instance
export const toastDeduplication = new ToastDeduplicationManager()

/**
 * Utility function to show a deduplicated toast
 * This wraps the toast library call with deduplication logic
 */
export function showDeduplicatedToast(
  toastFunction: (message: string) => void,
  message: string,
  type: 'success' | 'error' | 'warning' | 'info' = 'info'
): boolean {
  if (toastDeduplication.shouldShowToast(message, type)) {
    toastFunction(message)
    return true
  }
  return false
}

/**
 * Specific helper for success toasts (most common use case)
 */
export function showDeduplicatedSuccessToast(
  toastFunction: (message: string) => void,
  message: string
): boolean {
  return showDeduplicatedToast(toastFunction, message, 'success')
}

/**
 * Specific helper for error toasts
 */
export function showDeduplicatedErrorToast(
  toastFunction: (message: string) => void,
  message: string
): boolean {
  return showDeduplicatedToast(toastFunction, message, 'error')
}
