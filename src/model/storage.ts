'use strict'

import { openDB, DBSchema, IDBPDatabase } from 'idb'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'
import { logger } from '@/utils/logger'

/**
 * Database schema interface
 */
interface BusinessScraperDB extends DBSchema {
  businesses: {
    key: string
    value: BusinessRecord
    indexes: {
      'by-industry': string
      'by-scraped-date': Date
      'by-business-name': string
    }
  }
  configs: {
    key: string
    value: ScrapingConfig
  }
  industries: {
    key: string
    value: IndustryCategory
    indexes: {
      'by-custom': boolean
    }
  }
  sessions: {
    key: string
    value: {
      id: string
      name: string
      businesses: string[]
      createdAt: Date
      updatedAt: Date
    }
  }
}

/**
 * Storage service for managing IndexedDB operations
 */
export class StorageService {
  private db: IDBPDatabase<BusinessScraperDB> | null = null
  private readonly dbName = 'business-scraper-db'
  private readonly dbVersion = 1

  /**
   * Initialize the database connection
   */
  async initialize(): Promise<void> {
    try {
      this.db = await openDB<BusinessScraperDB>(this.dbName, this.dbVersion, {
        upgrade(db) {
          // Create businesses store
          const businessStore = db.createObjectStore('businesses', {
            keyPath: 'id',
          })
          businessStore.createIndex('by-industry', 'industry')
          businessStore.createIndex('by-scraped-date', 'scrapedAt')
          businessStore.createIndex('by-business-name', 'businessName')

          // Create configs store
          db.createObjectStore('configs', {
            keyPath: 'id',
          })

          // Create industries store
          const industryStore = db.createObjectStore('industries', {
            keyPath: 'id',
          })
          industryStore.createIndex('by-custom', 'isCustom')

          // Create sessions store
          db.createObjectStore('sessions', {
            keyPath: 'id',
          })
        },
      })

      logger.info('Storage', 'Database initialized successfully')
    } catch (error) {
      logger.error('Storage', 'Failed to initialize database', error)
      throw error
    }
  }

  /**
   * Ensure database is initialized
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.db) {
      await this.initialize()
    }
  }

  // Business Records Operations

  /**
   * Save a business record
   * @param business - Business record to save
   */
  async saveBusiness(business: BusinessRecord): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.put('businesses', business)
      logger.info('Storage', `Saved business: ${business.businessName}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save business', error)
      throw error
    }
  }

  /**
   * Save multiple business records
   * @param businesses - Array of business records
   */
  async saveBusinesses(businesses: BusinessRecord[]): Promise<void> {
    await this.ensureInitialized()
    const tx = this.db!.transaction('businesses', 'readwrite')
    
    try {
      await Promise.all([
        ...businesses.map(business => tx.store.put(business)),
        tx.done,
      ])
      logger.info('Storage', `Saved ${businesses.length} businesses`)
    } catch (error) {
      logger.error('Storage', 'Failed to save businesses', error)
      throw error
    }
  }

  /**
   * Get all business records
   * @returns Promise resolving to array of business records
   */
  async getAllBusinesses(): Promise<BusinessRecord[]> {
    await this.ensureInitialized()
    try {
      const businesses = await this.db!.getAll('businesses')
      return businesses.sort((a, b) => b.scrapedAt.getTime() - a.scrapedAt.getTime())
    } catch (error) {
      logger.error('Storage', 'Failed to get businesses', error)
      return []
    }
  }

  /**
   * Get businesses by industry
   * @param industry - Industry to filter by
   * @returns Promise resolving to array of business records
   */
  async getBusinessesByIndustry(industry: string): Promise<BusinessRecord[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAllFromIndex('businesses', 'by-industry', industry)
    } catch (error) {
      logger.error('Storage', 'Failed to get businesses by industry', error)
      return []
    }
  }

  /**
   * Delete a business record
   * @param id - Business ID to delete
   */
  async deleteBusiness(id: string): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.delete('businesses', id)
      logger.info('Storage', `Deleted business: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete business', error)
      throw error
    }
  }

  /**
   * Clear all business records
   */
  async clearBusinesses(): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.clear('businesses')
      logger.info('Storage', 'Cleared all businesses')
    } catch (error) {
      logger.error('Storage', 'Failed to clear businesses', error)
      throw error
    }
  }

  // Configuration Operations

  /**
   * Save scraping configuration
   * @param config - Configuration to save
   */
  async saveConfig(config: ScrapingConfig & { id: string }): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.put('configs', config)
      logger.info('Storage', 'Saved configuration')
    } catch (error) {
      logger.error('Storage', 'Failed to save configuration', error)
      throw error
    }
  }

  /**
   * Get configuration by ID
   * @param id - Configuration ID
   * @returns Promise resolving to configuration or null
   */
  async getConfig(id: string): Promise<(ScrapingConfig & { id: string }) | null> {
    await this.ensureInitialized()
    try {
      const config = await this.db!.get('configs', id)
      return config || null
    } catch (error) {
      logger.error('Storage', 'Failed to get configuration', error)
      return null
    }
  }

  /**
   * Get all configurations
   * @returns Promise resolving to array of configurations
   */
  async getAllConfigs(): Promise<(ScrapingConfig & { id: string })[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAll('configs')
    } catch (error) {
      logger.error('Storage', 'Failed to get configurations', error)
      return []
    }
  }

  // Industry Operations

  /**
   * Save industry category
   * @param industry - Industry category to save
   */
  async saveIndustry(industry: IndustryCategory): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.put('industries', industry)
      logger.info('Storage', `Saved industry: ${industry.name}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save industry', error)
      throw error
    }
  }

  /**
   * Get all industry categories
   * @returns Promise resolving to array of industry categories
   */
  async getAllIndustries(): Promise<IndustryCategory[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAll('industries')
    } catch (error) {
      logger.error('Storage', 'Failed to get industries', error)
      return []
    }
  }

  /**
   * Get custom industry categories
   * @returns Promise resolving to array of custom industry categories
   */
  async getCustomIndustries(): Promise<IndustryCategory[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAllFromIndex('industries', 'by-custom', true)
    } catch (error) {
      logger.error('Storage', 'Failed to get custom industries', error)
      return []
    }
  }

  /**
   * Delete industry category
   * @param id - Industry ID to delete
   */
  async deleteIndustry(id: string): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.delete('industries', id)
      logger.info('Storage', `Deleted industry: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete industry', error)
      throw error
    }
  }

  // Session Operations

  /**
   * Save scraping session
   * @param session - Session data to save
   */
  async saveSession(session: {
    id: string
    name: string
    businesses: string[]
    createdAt: Date
    updatedAt: Date
  }): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.put('sessions', session)
      logger.info('Storage', `Saved session: ${session.name}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save session', error)
      throw error
    }
  }

  /**
   * Get all sessions
   * @returns Promise resolving to array of sessions
   */
  async getAllSessions(): Promise<Array<{
    id: string
    name: string
    businesses: string[]
    createdAt: Date
    updatedAt: Date
  }>> {
    await this.ensureInitialized()
    try {
      const sessions = await this.db!.getAll('sessions')
      return sessions.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())
    } catch (error) {
      logger.error('Storage', 'Failed to get sessions', error)
      return []
    }
  }

  /**
   * Delete session
   * @param id - Session ID to delete
   */
  async deleteSession(id: string): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.delete('sessions', id)
      logger.info('Storage', `Deleted session: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete session', error)
      throw error
    }
  }

  /**
   * Get database statistics
   * @returns Promise resolving to database statistics
   */
  async getStats(): Promise<{
    businesses: number
    configs: number
    industries: number
    sessions: number
  }> {
    await this.ensureInitialized()
    try {
      const [businesses, configs, industries, sessions] = await Promise.all([
        this.db!.count('businesses'),
        this.db!.count('configs'),
        this.db!.count('industries'),
        this.db!.count('sessions'),
      ])

      return { businesses, configs, industries, sessions }
    } catch (error) {
      logger.error('Storage', 'Failed to get statistics', error)
      return { businesses: 0, configs: 0, industries: 0, sessions: 0 }
    }
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    if (this.db) {
      this.db.close()
      this.db = null
      logger.info('Storage', 'Database connection closed')
    }
  }
}

/**
 * Default storage instance
 */
export const storage = new StorageService()
