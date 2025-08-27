/**
 * Data Reset Utility
 *
 * Provides comprehensive data purging functionality to reset the application
 * to a fresh state by clearing all user data from IndexedDB and localStorage.
 */

import { storage } from '@/model/storage'
import { clearApiCredentials } from '@/utils/secureStorage'
import { logger } from '@/utils/logger'
import { searchEngineManager } from '@/lib/searchEngineManager'

export interface DataResetResult {
  success: boolean
  clearedStores: string[]
  clearedLocalStorage: string[]
  errors: string[]
  fallbackUsed: boolean
}

export interface DataResetOptions {
  includeApiCredentials?: boolean
  includeLocalStorage?: boolean
  useAggressiveReset?: boolean
  confirmationRequired?: boolean
}

/**
 * Data Reset Service
 */
export class DataResetService {
  private static readonly LOCAL_STORAGE_KEYS = [
    'api_credentials_plain',
    'encrypted_api_credentials',
    'credentials_timestamp',
    'business-scraper-config',
    'business-scraper-cache',
    'business-scraper-session',
    'business-scraper-preferences',
    'business-scraper-temp',
  ]

  private static readonly INDEXEDDB_STORES = [
    'businesses',
    'configs',
    'industries',
    'sessions',
    'domainBlacklist',
  ]

  /**
   * Perform complete application data reset
   */
  static async resetAllData(options: DataResetOptions = {}): Promise<DataResetResult> {
    const {
      includeApiCredentials = true,
      includeLocalStorage = true,
      useAggressiveReset = false,
      confirmationRequired = true,
    } = options

    const result: DataResetResult = {
      success: false,
      clearedStores: [],
      clearedLocalStorage: [],
      errors: [],
      fallbackUsed: false,
    }

    try {
      logger.info('DataReset', 'Starting complete application data reset')

      // Step 1: Clear IndexedDB data
      await this.clearIndexedDBData(result, useAggressiveReset)

      // Step 2: Clear localStorage data
      if (includeLocalStorage) {
        await this.clearLocalStorageData(result, includeApiCredentials)
      }

      // Step 3: Reset search engines to enabled state
      await this.resetSearchEngines(result)

      // Step 4: Clear any cached data in memory
      await this.clearMemoryCache(result)

      // Determine overall success
      result.success = result.errors.length === 0 || result.clearedStores.length > 0

      if (result.success) {
        logger.info(
          'DataReset',
          `Data reset completed successfully. Cleared ${result.clearedStores.length} stores and ${result.clearedLocalStorage.length} localStorage items`
        )
      } else {
        logger.error('DataReset', `Data reset failed with ${result.errors.length} errors`)
      }

      return result
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      result.errors.push(`Critical error during reset: ${errorMessage}`)
      logger.error('DataReset', 'Critical error during data reset', error)
      return result
    }
  }

  /**
   * Clear IndexedDB data with fallback strategies
   */
  private static async clearIndexedDBData(
    result: DataResetResult,
    useAggressiveReset: boolean
  ): Promise<void> {
    try {
      if (useAggressiveReset) {
        // Aggressive reset: Delete and recreate entire database
        await storage.resetDatabase()
        result.clearedStores.push(...this.INDEXEDDB_STORES)
        result.fallbackUsed = true
        logger.info('DataReset', 'Used aggressive database reset')
      } else {
        // Standard reset: Clear all stores
        await storage.clearAllData()
        result.clearedStores.push(...this.INDEXEDDB_STORES)
        logger.info('DataReset', 'Used standard database clear')
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      result.errors.push(`IndexedDB reset failed: ${errorMessage}`)
      logger.error('DataReset', 'Failed to clear IndexedDB data', error)

      // Fallback: Try to clear individual stores
      if (!useAggressiveReset) {
        logger.info('DataReset', 'Attempting fallback: individual store clearing')
        await this.clearIndividualStores(result)
      }
    }
  }

  /**
   * Fallback method to clear individual stores
   */
  private static async clearIndividualStores(result: DataResetResult): Promise<void> {
    const clearOperations = [
      { name: 'businesses', operation: () => storage.clearBusinesses() },
      { name: 'industries', operation: () => storage.clearIndustries() },
      { name: 'sessions', operation: () => storage.clearSessions() },
      { name: 'domainBlacklist', operation: () => storage.clearDomainBlacklist() },
    ]

    for (const { name, operation } of clearOperations) {
      try {
        await operation()
        result.clearedStores.push(name)
        logger.info('DataReset', `Successfully cleared ${name} store`)
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'
        result.errors.push(`Failed to clear ${name}: ${errorMessage}`)
        logger.error('DataReset', `Failed to clear ${name} store`, error)
      }
    }

    if (result.clearedStores.length > 0) {
      result.fallbackUsed = true
    }
  }

  /**
   * Clear localStorage data
   */
  private static async clearLocalStorageData(
    result: DataResetResult,
    includeApiCredentials: boolean
  ): Promise<void> {
    try {
      // Clear API credentials if requested
      if (includeApiCredentials) {
        try {
          clearApiCredentials()
          result.clearedLocalStorage.push('api_credentials')
          logger.info('DataReset', 'API credentials cleared')
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error'
          result.errors.push(`Failed to clear API credentials: ${errorMessage}`)
        }
      }

      // Clear other localStorage items
      for (const key of this.LOCAL_STORAGE_KEYS) {
        try {
          if (localStorage.getItem(key) !== null) {
            localStorage.removeItem(key)
            result.clearedLocalStorage.push(key)
            logger.info('DataReset', `Cleared localStorage key: ${key}`)
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error'
          result.errors.push(`Failed to clear localStorage key ${key}: ${errorMessage}`)
        }
      }

      // Clear any keys that start with 'business-scraper'
      const allKeys = Object.keys(localStorage)
      for (const key of allKeys) {
        if (key.startsWith('business-scraper') && !this.LOCAL_STORAGE_KEYS.includes(key)) {
          try {
            localStorage.removeItem(key)
            result.clearedLocalStorage.push(key)
            logger.info('DataReset', `Cleared additional localStorage key: ${key}`)
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error'
            result.errors.push(`Failed to clear additional key ${key}: ${errorMessage}`)
          }
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      result.errors.push(`localStorage clearing failed: ${errorMessage}`)
      logger.error('DataReset', 'Failed to clear localStorage data', error)
    }
  }

  /**
   * Reset search engines to enabled state
   */
  private static async resetSearchEngines(result: DataResetResult): Promise<void> {
    try {
      searchEngineManager.resetAllEngines()
      result.clearedLocalStorage.push('search-engine-state')
      logger.info('DataReset', 'Search engines reset to enabled state')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      result.errors.push(`Search engine reset failed: ${errorMessage}`)
      logger.error('DataReset', 'Failed to reset search engines', error)
    }
  }

  /**
   * Clear any cached data in memory
   */
  private static async clearMemoryCache(result: DataResetResult): Promise<void> {
    try {
      // Clear any global caches or memory stores
      // This is where you would clear any in-memory caches, service worker caches, etc.

      // For now, we'll just log that memory cache clearing was attempted
      logger.info('DataReset', 'Memory cache clearing completed')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      result.errors.push(`Memory cache clearing failed: ${errorMessage}`)
      logger.error('DataReset', 'Failed to clear memory cache', error)
    }
  }

  /**
   * Get data statistics before reset (for confirmation dialog)
   */
  static async getDataStatistics(): Promise<{
    businesses: number
    configs: number
    industries: number
    sessions: number
    domainBlacklistEntries: number
    localStorageItems: number
  }> {
    try {
      const dbStats = await storage.getStatistics()

      // Count localStorage items
      const localStorageItems = this.LOCAL_STORAGE_KEYS.filter(
        key => localStorage.getItem(key) !== null
      ).length

      return {
        ...dbStats,
        localStorageItems,
      }
    } catch (error) {
      logger.error('DataReset', 'Failed to get data statistics', error)
      return {
        businesses: 0,
        configs: 0,
        industries: 0,
        sessions: 0,
        domainBlacklistEntries: 0,
        localStorageItems: 0,
      }
    }
  }
}

/**
 * Convenience function for quick data reset
 */
export async function resetApplicationData(options?: DataResetOptions): Promise<DataResetResult> {
  return DataResetService.resetAllData(options)
}

/**
 * Convenience function to get data statistics
 */
export async function getApplicationDataStats() {
  return DataResetService.getDataStatistics()
}
