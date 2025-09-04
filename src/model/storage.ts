'use strict'

import { openDB, DBSchema, IDBPDatabase } from 'idb'
import {
  BusinessRecord,
  ScrapingConfig,
  IndustryCategory,
  IndustrySubCategory,
} from '@/types/business'
import { PredictiveAnalytics, AIProcessingJob, AIInsightsSummary } from '@/types/ai'
import {
  UserPaymentProfile,
  PaymentTransaction,
  Invoice,
  PaymentAuditLog,
  PaymentAnalytics,
} from '@/types/payment'
import { User } from './types/user'
import { logger } from '@/utils/logger'
import { DataCompression, CompressedData } from '@/lib/data-compression'
import { AnalyticsEvent } from './analyticsService'

/**
 * Database schema interface
 */
interface BusinessScraperDB extends DBSchema {
  users: {
    key: string
    value: User
    indexes: {
      'by-email': string
      'by-stripe-customer-id': string
      'by-subscription-status': string
      'by-subscription-plan': string
      'by-created-date': Date
      'by-last-login': Date
      'by-email-verified': boolean
    }
  }
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
      'by-custom': string
      'by-subcategory': string
    }
  }
  subCategories: {
    key: string
    value: IndustrySubCategory
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
  domainBlacklist: {
    key: string
    value: {
      id: string
      domains: string[]
      createdAt: Date
      updatedAt: Date
    }
  }
  aiAnalytics: {
    key: string
    value: PredictiveAnalytics & { businessId: string }
    indexes: {
      'by-business-id': string
      'by-generated-date': Date
    }
  }
  aiJobs: {
    key: string
    value: AIProcessingJob
    indexes: {
      'by-status': string
      'by-business-id': string
      'by-created-date': Date
    }
  }
  aiInsights: {
    key: string
    value: AIInsightsSummary
    indexes: {
      'by-generated-date': Date
    }
  }
  userPaymentProfiles: {
    key: string
    value: UserPaymentProfile
    indexes: {
      'by-stripe-customer-id': string
      'by-subscription-status': string
      'by-subscription-tier': string
      'by-email': string
    }
  }
  paymentTransactions: {
    key: string
    value: PaymentTransaction
    indexes: {
      'by-user-id': string
      'by-status': string
      'by-created-date': Date
      'by-stripe-payment-intent-id': string
    }
  }
  invoices: {
    key: string
    value: Invoice
    indexes: {
      'by-user-id': string
      'by-status': string
      'by-stripe-invoice-id': string
      'by-created-date': Date
    }
  }
  paymentAuditLogs: {
    key: string
    value: PaymentAuditLog
    indexes: {
      'by-user-id': string
      'by-entity-type': string
      'by-action': string
      'by-timestamp': Date
    }
  }
  paymentAnalytics: {
    key: string
    value: PaymentAnalytics
    indexes: {
      'by-user-id': string
      'by-period-start': Date
    }
  }
  analyticsEvents: {
    key: string
    value: AnalyticsEvent
    indexes: {
      'by-user-id': string
      'by-event-type': string
      'by-timestamp': Date
      'by-session-id': string
    }
  }
}

/**
 * Storage service for managing IndexedDB operations
 */
export class StorageService {
  private db: IDBPDatabase<BusinessScraperDB> | null = null
  private readonly dbName = 'business-scraper-db'
  private readonly dbVersion = 7

  /**
   * Check if we're running in a browser environment
   */
  private isBrowser(): boolean {
    return typeof window !== 'undefined' && typeof indexedDB !== 'undefined'
  }

  /**
   * Initialize the database connection with timeout
   */
  async initialize(): Promise<void> {
    try {
      // Only initialize IndexedDB in browser environment
      if (!this.isBrowser()) {
        logger.warn('Storage', 'IndexedDB not available in server environment')
        return
      }

      if (this.db) {
        return // Already initialized
      }

      logger.info('Storage', 'Initializing database connection...')

      // Add timeout to prevent hanging
      let initPromise = openDB<BusinessScraperDB>(this.dbName, this.dbVersion, {
        upgrade(db, oldVersion, newVersion, transaction) {
          // Create businesses store (version 1)
          if (oldVersion < 1) {
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
            industryStore.createIndex('by-subcategory', 'subCategoryId')

            // Create sessions store
            db.createObjectStore('sessions', {
              keyPath: 'id',
            })
          }

          // Add domain blacklist store (version 2)
          if (oldVersion < 2) {
            db.createObjectStore('domainBlacklist', {
              keyPath: 'id',
            })
          }

          // Add AI analytics stores (version 3)
          if (oldVersion < 3) {
            // AI Analytics store
            const aiAnalyticsStore = db.createObjectStore('aiAnalytics', {
              keyPath: 'businessId',
            })
            aiAnalyticsStore.createIndex('by-business-id', 'businessId')
            aiAnalyticsStore.createIndex('by-generated-date', 'generatedAt')

            // AI Jobs store
            const aiJobsStore = db.createObjectStore('aiJobs', {
              keyPath: 'id',
            })
            aiJobsStore.createIndex('by-status', 'status')
            aiJobsStore.createIndex('by-business-id', 'businessId')
            aiJobsStore.createIndex('by-created-date', 'createdAt')

            // AI Insights store
            const aiInsightsStore = db.createObjectStore('aiInsights', {
              keyPath: 'generatedAt',
            })
            aiInsightsStore.createIndex('by-generated-date', 'generatedAt')
          }

          // Add sub-categories store (version 4)
          if (oldVersion < 4) {
            // Sub-categories store
            db.createObjectStore('subCategories', {
              keyPath: 'id',
            })

            // Add sub-category index to existing industries store if it doesn't exist
            if (oldVersion >= 1) {
              const industryStore = transaction.objectStore('industries')
              if (!industryStore.indexNames.contains('by-subcategory')) {
                industryStore.createIndex('by-subcategory', 'subCategoryId')
              }
            }
          }

          // Add payment-related stores (version 5)
          if (oldVersion < 5) {
            // User Payment Profiles store
            const userPaymentProfilesStore = db.createObjectStore('userPaymentProfiles', {
              keyPath: 'userId',
            })
            userPaymentProfilesStore.createIndex('by-stripe-customer-id', 'stripeCustomerId')
            userPaymentProfilesStore.createIndex('by-subscription-status', 'subscriptionStatus')
            userPaymentProfilesStore.createIndex('by-subscription-tier', 'subscriptionTier')
            userPaymentProfilesStore.createIndex('by-email', 'email')

            // Payment Transactions store
            const paymentTransactionsStore = db.createObjectStore('paymentTransactions', {
              keyPath: 'id',
            })
            paymentTransactionsStore.createIndex('by-user-id', 'userId')
            paymentTransactionsStore.createIndex('by-status', 'status')
            paymentTransactionsStore.createIndex('by-created-date', 'createdAt')
            paymentTransactionsStore.createIndex(
              'by-stripe-payment-intent-id',
              'stripePaymentIntentId'
            )

            // Invoices store
            const invoicesStore = db.createObjectStore('invoices', {
              keyPath: 'id',
            })
            invoicesStore.createIndex('by-user-id', 'userId')
            invoicesStore.createIndex('by-status', 'status')
            invoicesStore.createIndex('by-stripe-invoice-id', 'stripeInvoiceId')
            invoicesStore.createIndex('by-created-date', 'createdAt')

            // Payment Audit Logs store
            const paymentAuditLogsStore = db.createObjectStore('paymentAuditLogs', {
              keyPath: 'id',
            })
            paymentAuditLogsStore.createIndex('by-user-id', 'userId')
            paymentAuditLogsStore.createIndex('by-entity-type', 'entityType')
            paymentAuditLogsStore.createIndex('by-action', 'action')
            paymentAuditLogsStore.createIndex('by-timestamp', 'timestamp')

            // Payment Analytics store
            const paymentAnalyticsStore = db.createObjectStore('paymentAnalytics', {
              keyPath: 'userId',
            })
            paymentAnalyticsStore.createIndex('by-user-id', 'userId')
            paymentAnalyticsStore.createIndex('by-period-start', 'period.start')
          }

          // Add users store (version 6)
          if (oldVersion < 6) {
            // Users store
            const usersStore = db.createObjectStore('users', {
              keyPath: 'id',
            })
            usersStore.createIndex('by-email', 'email')
            usersStore.createIndex('by-stripe-customer-id', 'stripeCustomerId')
            usersStore.createIndex('by-subscription-status', 'subscriptionStatus')
            usersStore.createIndex('by-subscription-plan', 'subscriptionPlan')
            usersStore.createIndex('by-created-date', 'createdAt')
            usersStore.createIndex('by-last-login', 'lastLoginAt')
            usersStore.createIndex('by-email-verified', 'emailVerified')
          }

          // Add analytics events store (version 7)
          if (oldVersion < 7) {
            // Analytics Events store
            const analyticsEventsStore = db.createObjectStore('analyticsEvents', {
              keyPath: 'id',
            })
            analyticsEventsStore.createIndex('by-user-id', 'userId')
            analyticsEventsStore.createIndex('by-event-type', 'eventType')
            analyticsEventsStore.createIndex('by-timestamp', 'timestamp')
            analyticsEventsStore.createIndex('by-session-id', 'sessionId')
          }
        },
      })

      // Create timeout promise with increased timeout and retry logic
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error('Database initialization timeout after 30 seconds'))
        }, 30000) // Increased to 30 second timeout
      })

      // Add retry logic with exponential backoff
      let retryCount = 0
      const maxRetries = 3

      while (retryCount < maxRetries) {
        try {
          // Race between initialization and timeout
          this.db = await Promise.race([initPromise, timeoutPromise])
          break // Success, exit retry loop
        } catch (error) {
          retryCount++
          if (retryCount >= maxRetries) {
            throw error // Final attempt failed
          }

          const backoffDelay = Math.pow(2, retryCount) * 1000 // Exponential backoff
          logger.warn(
            'Storage',
            `Database initialization attempt ${retryCount} failed, retrying in ${backoffDelay}ms`,
            error
          )

          await new Promise(resolve => setTimeout(resolve, backoffDelay))

          // Create new initialization promise for retry
          initPromise = openDB<BusinessScraperDB>(this.dbName, this.dbVersion, {
            upgrade(db, oldVersion, newVersion, transaction) {
              // Create businesses store (version 1)
              if (oldVersion < 1) {
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
                industryStore.createIndex('by-category', 'category')
                industryStore.createIndex('by-name', 'name')

                // Create users store
                const userStore = db.createObjectStore('users', {
                  keyPath: 'id',
                })
                userStore.createIndex('by-email', 'email')
                userStore.createIndex('by-created-date', 'createdAt')
              }

              // Add payment-related stores (version 2)
              if (oldVersion < 2) {
                // Payment profiles store
                const paymentProfileStore = db.createObjectStore('paymentProfiles', {
                  keyPath: 'id',
                })
                paymentProfileStore.createIndex('by-user-id', 'userId')
                paymentProfileStore.createIndex('by-stripe-customer-id', 'stripeCustomerId')

                // Payment transactions store
                const transactionStore = db.createObjectStore('paymentTransactions', {
                  keyPath: 'id',
                })
                transactionStore.createIndex('by-user-id', 'userId')
                transactionStore.createIndex('by-status', 'status')
                transactionStore.createIndex('by-created-date', 'createdAt')

                // Invoices store
                const invoiceStore = db.createObjectStore('invoices', {
                  keyPath: 'id',
                })
                invoiceStore.createIndex('by-user-id', 'userId')
                invoiceStore.createIndex('by-status', 'status')
                invoiceStore.createIndex('by-due-date', 'dueDate')

                // Payment audit logs store
                const auditLogStore = db.createObjectStore('paymentAuditLogs', {
                  keyPath: 'id',
                })
                auditLogStore.createIndex('by-user-id', 'userId')
                auditLogStore.createIndex('by-action', 'action')
                auditLogStore.createIndex('by-timestamp', 'timestamp')

                // Payment analytics store
                const analyticsStore = db.createObjectStore('paymentAnalytics', {
                  keyPath: 'id',
                })
                analyticsStore.createIndex('by-user-id', 'userId')
                analyticsStore.createIndex('by-date', 'date')
                analyticsStore.createIndex('by-metric-type', 'metricType')
              }

              // Add AI and analytics stores (version 3)
              if (oldVersion < 3) {
                // AI processing jobs store
                const aiJobsStore = db.createObjectStore('aiProcessingJobs', {
                  keyPath: 'id',
                })
                aiJobsStore.createIndex('by-status', 'status')
                aiJobsStore.createIndex('by-created-date', 'createdAt')
                aiJobsStore.createIndex('by-user-id', 'userId')

                // Predictive analytics store
                const predictiveStore = db.createObjectStore('predictiveAnalytics', {
                  keyPath: 'id',
                })
                predictiveStore.createIndex('by-business-id', 'businessId')
                predictiveStore.createIndex('by-prediction-type', 'predictionType')
                predictiveStore.createIndex('by-confidence', 'confidence')

                // AI insights store
                const insightsStore = db.createObjectStore('aiInsights', {
                  keyPath: 'id',
                })
                insightsStore.createIndex('by-business-id', 'businessId')
                insightsStore.createIndex('by-insight-type', 'insightType')
                insightsStore.createIndex('by-created-date', 'createdAt')

                // Analytics events store
                const analyticsEventsStore = db.createObjectStore('analyticsEvents', {
                  keyPath: 'id',
                })
                analyticsEventsStore.createIndex('by-event-type', 'eventType')
                analyticsEventsStore.createIndex('by-timestamp', 'timestamp')
                analyticsEventsStore.createIndex('by-session-id', 'sessionId')
              }
            },
          })
        }
      }

      logger.info('Storage', 'Database initialized successfully')
    } catch (error) {
      logger.error('Storage', 'Failed to initialize database', error)

      // If initialization fails, set a flag to prevent further attempts
      if (this.isBrowser()) {
        logger.warn('Storage', 'Database initialization failed, will operate in fallback mode')
        // Don't throw error to prevent app from hanging
        return
      }

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

  /**
   * Get the database instance with proper error handling and fallback support
   */
  private async getDatabase(): Promise<IDBPDatabase<BusinessScraperDB> | null> {
    if (!this.isBrowser()) {
      logger.warn('Storage', 'Database operations not available in server environment')
      return null
    }

    try {
      await this.ensureInitialized()
      if (!this.db) {
        logger.warn(
          'Storage',
          'Database not available - initialization may have failed or timed out, operating in fallback mode'
        )
        return null
      }
      return this.db
    } catch (error) {
      logger.error('Storage', 'Failed to get database instance', error)
      return null
    }
  }

  /**
   * Check if database is available
   */
  private isDatabaseAvailable(): boolean {
    return this.db !== null && this.isBrowser()
  }

  // Business Records Operations

  /**
   * Save a business record
   * @param business - Business record to save
   */
  async saveBusiness(business: BusinessRecord): Promise<void> {
    try {
      const db = await this.getDatabase()

      if (!db) {
        logger.warn(
          'Storage',
          `Cannot save business ${business.businessName} - database unavailable, operating in fallback mode`
        )
        return // Gracefully handle database unavailability
      }

      // Compress business data before storing
      const compressedBusiness = DataCompression.compress(business)

      await db.put('businesses', compressedBusiness as any)
      logger.info('Storage', `Saved business: ${business.businessName}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save business', error)
      // Don't throw error to prevent cascading failures
      logger.warn('Storage', 'Continuing in fallback mode due to storage error')
    }
  }

  /**
   * Save multiple business records
   * @param businesses - Array of business records
   */
  async saveBusinesses(businesses: BusinessRecord[]): Promise<void> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('businesses', 'readwrite')

      // Compress businesses in batches for better performance
      const compressedBusinesses = DataCompression.batchCompress(businesses)

      await Promise.all([
        ...compressedBusinesses.map(business => tx.store.put(business as any)),
        tx.done,
      ])
      logger.info('Storage', `Saved ${businesses.length} businesses with compression`)
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
      const compressedBusinesses = await this.db!.getAll('businesses')

      // Decompress businesses
      const businesses = DataCompression.batchDecompress(compressedBusinesses)

      return businesses.sort((a, b) => b.scrapedAt.getTime() - a.scrapedAt.getTime())
    } catch (error) {
      logger.error('Storage', 'Failed to get businesses', error)
      return []
    }
  }

  /**
   * Get business by ID
   * @param id - Business ID to get
   * @returns Promise resolving to business record or null
   */
  async getBusiness(id: string): Promise<BusinessRecord | null> {
    await this.ensureInitialized()
    try {
      const compressedBusiness = await this.db!.get('businesses', id)
      if (!compressedBusiness) return null

      // Decompress business data
      const business = DataCompression.decompress(compressedBusiness)
      return business
    } catch (error) {
      logger.error('Storage', 'Failed to get business', error)
      return null
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
    try {
      const db = await this.getDatabase()
      await db.delete('businesses', id)
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
    try {
      const db = await this.getDatabase()
      await db.clear('businesses')
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
    try {
      const db = await this.getDatabase()

      if (!db) {
        logger.warn(
          'Storage',
          `Cannot get configuration ${id} - database unavailable, returning null`
        )
        return null
      }

      const config = await db.get('configs', id)
      return config ? { ...config, id } : null
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
      const configs = await this.db!.getAll('configs')
      return configs.map((config, index) => ({ ...config, id: `config-${index}` }))
    } catch (error) {
      logger.error('Storage', 'Failed to get configurations', error)
      return []
    }
  }

  /**
   * Delete configuration by ID
   * @param id - Configuration ID to delete
   */
  async deleteConfig(id: string): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.delete('configs', id)
      logger.info('Storage', `Deleted configuration: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete configuration', error)
      throw error
    }
  }

  // Industry Operations

  /**
   * Save industry category
   * @param industry - Industry category to save
   */
  async saveIndustry(industry: IndustryCategory): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('industries', industry)
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
    try {
      const db = await this.getDatabase()

      if (!db) {
        logger.warn(
          'Storage',
          'Cannot get industries - database unavailable, returning empty array'
        )
        return []
      }

      return await db.getAll('industries')
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
      // Get all industries and filter for custom ones
      const allIndustries = await this.db!.getAll('industries')
      return allIndustries.filter(industry => industry.isCustom === true)
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
    try {
      const db = await this.getDatabase()
      await db.delete('industries', id)
      logger.info('Storage', `Deleted industry: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete industry', error)
      throw error
    }
  }

  /**
   * Clear all industry categories
   */
  async clearIndustries(): Promise<void> {
    try {
      const db = await this.getDatabase()

      if (!db) {
        logger.warn('Storage', 'Cannot clear industries - database unavailable, skipping operation')
        return
      }

      await db.clear('industries')
      logger.info('Storage', 'Cleared all industries')
    } catch (error) {
      logger.error('Storage', 'Failed to clear industries', error)
      // Don't throw error to prevent cascading failures
      logger.warn('Storage', 'Continuing in fallback mode due to storage error')
    }
  }

  /**
   * Get industries by sub-category
   * @param subCategoryId - Sub-category ID to filter by
   * @returns Promise resolving to array of industry categories
   */
  async getIndustriesBySubCategory(subCategoryId: string): Promise<IndustryCategory[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAllFromIndex('industries', 'by-subcategory', subCategoryId)
    } catch (error) {
      logger.error('Storage', 'Failed to get industries by sub-category', error)
      return []
    }
  }

  // Sub-Category Operations

  /**
   * Save sub-category
   * @param subCategory - Sub-category to save
   */
  async saveSubCategory(subCategory: IndustrySubCategory): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.put('subCategories', subCategory)
      logger.info('Storage', `Saved sub-category: ${subCategory.name}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save sub-category', error)
      throw error
    }
  }

  /**
   * Get all sub-categories
   * @returns Promise resolving to array of sub-categories
   */
  async getAllSubCategories(): Promise<IndustrySubCategory[]> {
    await this.ensureInitialized()
    try {
      return await this.db!.getAll('subCategories')
    } catch (error) {
      logger.error('Storage', 'Failed to get sub-categories', error)
      return []
    }
  }

  /**
   * Get sub-category by ID
   * @param id - Sub-category ID
   * @returns Promise resolving to sub-category or null
   */
  async getSubCategory(id: string): Promise<IndustrySubCategory | null> {
    await this.ensureInitialized()
    try {
      return await this.db!.get('subCategories', id)
    } catch (error) {
      logger.error('Storage', 'Failed to get sub-category', error)
      return null
    }
  }

  /**
   * Delete sub-category
   * @param id - Sub-category ID to delete
   */
  async deleteSubCategory(id: string): Promise<void> {
    await this.ensureInitialized()
    try {
      await this.db!.delete('subCategories', id)
      logger.info('Storage', `Deleted sub-category: ${id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete sub-category', error)
      throw error
    }
  }

  /**
   * Clear all sub-categories
   */
  async clearSubCategories(): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.clear('subCategories')
      logger.info('Storage', 'Cleared all sub-categories')
    } catch (error) {
      logger.error('Storage', 'Failed to clear sub-categories', error)
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
  async getAllSessions(): Promise<
    Array<{
      id: string
      name: string
      businesses: string[]
      createdAt: Date
      updatedAt: Date
    }>
  > {
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
   * Clear all sessions
   */
  async clearSessions(): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.clear('sessions')
      logger.info('Storage', 'Cleared all sessions')
    } catch (error) {
      logger.error('Storage', 'Failed to clear sessions', error)
      throw error
    }
  }

  /**
   * Save domain blacklist
   * @param domains - Array of domain strings to blacklist
   */
  async saveDomainBlacklist(domains: string[]): Promise<void> {
    try {
      const db = await this.getDatabase()
      const blacklistData = {
        id: 'global-blacklist',
        domains: domains.filter(domain => domain.trim().length > 0),
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      await db.put('domainBlacklist', blacklistData)
      logger.info('Storage', `Saved domain blacklist with ${domains.length} domains`)
    } catch (error) {
      logger.error('Storage', 'Failed to save domain blacklist', error)
      throw error
    }
  }

  /**
   * Get domain blacklist
   * @returns Promise resolving to array of blacklisted domains
   */
  async getDomainBlacklist(): Promise<string[]> {
    await this.ensureInitialized()
    try {
      const blacklistData = await this.db!.get('domainBlacklist', 'global-blacklist')
      return blacklistData?.domains || []
    } catch (error) {
      logger.error('Storage', 'Failed to get domain blacklist', error)
      return []
    }
  }

  /**
   * Add domain to blacklist
   * @param domain - Domain to add to blacklist
   */
  async addDomainToBlacklist(domain: string): Promise<void> {
    const currentBlacklist = await this.getDomainBlacklist()
    const cleanDomain = domain.trim().toLowerCase()

    if (!currentBlacklist.includes(cleanDomain)) {
      const updatedBlacklist = [...currentBlacklist, cleanDomain]
      await this.saveDomainBlacklist(updatedBlacklist)
      logger.info('Storage', `Added domain to blacklist: ${cleanDomain}`)
    }
  }

  /**
   * Remove domain from blacklist
   * @param domain - Domain to remove from blacklist
   */
  async removeDomainFromBlacklist(domain: string): Promise<void> {
    const currentBlacklist = await this.getDomainBlacklist()
    const cleanDomain = domain.trim().toLowerCase()
    const updatedBlacklist = currentBlacklist.filter(d => d !== cleanDomain)

    if (updatedBlacklist.length !== currentBlacklist.length) {
      await this.saveDomainBlacklist(updatedBlacklist)
      logger.info('Storage', `Removed domain from blacklist: ${cleanDomain}`)
    }
  }

  /**
   * Clear domain blacklist
   */
  async clearDomainBlacklist(): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.delete('domainBlacklist', 'global-blacklist')
      logger.info('Storage', 'Cleared domain blacklist')
    } catch (error) {
      logger.error('Storage', 'Failed to clear domain blacklist', error)
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
    domainBlacklistEntries: number
  }> {
    await this.ensureInitialized()
    try {
      const [businesses, configs, industries, sessions, domainBlacklist] = await Promise.all([
        this.db!.count('businesses'),
        this.db!.count('configs'),
        this.db!.count('industries'),
        this.db!.count('sessions'),
        this.getDomainBlacklist().then(domains => domains.length),
      ])

      return { businesses, configs, industries, sessions, domainBlacklistEntries: domainBlacklist }
    } catch (error) {
      logger.error('Storage', 'Failed to get statistics', error)
      return { businesses: 0, configs: 0, industries: 0, sessions: 0, domainBlacklistEntries: 0 }
    }
  }

  /**
   * Clear all data from IndexedDB (complete reset)
   * This will purge all user data and reset the application to a fresh state
   */
  async clearAllData(): Promise<void> {
    try {
      await this.ensureInitialized()
      const db = await this.getDatabase()

      // Clear all object stores
      const storeNames = ['businesses', 'configs', 'industries', 'sessions', 'domainBlacklist']
      const clearPromises = storeNames.map(storeName => {
        try {
          return db.clear(storeName as keyof BusinessScraperDB)
        } catch (error) {
          logger.warn('Storage', `Failed to clear store ${storeName}`, error)
          return Promise.resolve()
        }
      })

      await Promise.allSettled(clearPromises)
      logger.info('Storage', 'All IndexedDB data cleared successfully')
    } catch (error) {
      logger.error('Storage', 'Failed to clear all data', error)
      throw error
    }
  }

  /**
   * Reset database (delete and recreate)
   * This is a more aggressive reset that completely removes the database
   */
  async resetDatabase(): Promise<void> {
    try {
      // Close current connection
      if (this.db) {
        this.db.close()
        this.db = null
      }

      // Delete the entire database
      await new Promise<void>((resolve, reject) => {
        const deleteRequest = indexedDB.deleteDatabase(this.dbName)

        deleteRequest.onsuccess = () => {
          logger.info('Storage', 'Database deleted successfully')
          resolve()
        }

        deleteRequest.onerror = () => {
          logger.error('Storage', 'Failed to delete database', deleteRequest.error)
          reject(deleteRequest.error)
        }

        deleteRequest.onblocked = () => {
          logger.warn('Storage', 'Database deletion blocked - other connections may be open')
          // Continue anyway after a short delay
          setTimeout(() => resolve(), 1000)
        }
      })

      // Reinitialize the database
      await this.initialize()
      logger.info('Storage', 'Database reset and reinitialized successfully')
    } catch (error) {
      logger.error('Storage', 'Failed to reset database', error)
      throw error
    }
  }

  /**
   * Get database statistics for all stores
   */
  async getStatistics(): Promise<{
    businesses: number
    configs: number
    industries: number
    sessions: number
    domainBlacklistEntries: number
    aiAnalytics: number
    aiJobs: number
    aiInsights: number
  }> {
    try {
      await this.ensureInitialized()
      const db = await this.getDatabase()

      const [
        businesses,
        configs,
        industries,
        sessions,
        domainBlacklistEntries,
        aiAnalytics,
        aiJobs,
        aiInsights,
      ] = await Promise.all([
        db.count('businesses'),
        db.count('configs'),
        db.count('industries'),
        db.count('sessions'),
        db.count('domainBlacklist'),
        db.count('aiAnalytics'),
        db.count('aiJobs'),
        db.count('aiInsights'),
      ])

      return {
        businesses,
        configs,
        industries,
        sessions,
        domainBlacklistEntries,
        aiAnalytics,
        aiJobs,
        aiInsights,
      }
    } catch (error) {
      logger.error('Storage', 'Failed to get database statistics', error)
      return {
        businesses: 0,
        configs: 0,
        industries: 0,
        sessions: 0,
        domainBlacklistEntries: 0,
        aiAnalytics: 0,
        aiJobs: 0,
        aiInsights: 0,
      }
    }
  }

  // AI Analytics Operations

  /**
   * Save AI analytics for a business
   */
  async saveAIAnalytics(businessId: string, analytics: PredictiveAnalytics): Promise<void> {
    try {
      const db = await this.getDatabase()
      const analyticsWithId = { ...analytics, businessId }
      await db.put('aiAnalytics', analyticsWithId)
      logger.info('Storage', `Saved AI analytics for business: ${businessId}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save AI analytics', error)
      throw error
    }
  }

  /**
   * Get AI analytics for a business
   */
  async getAIAnalytics(businessId: string): Promise<PredictiveAnalytics | null> {
    try {
      const db = await this.getDatabase()
      const result = await db.get('aiAnalytics', businessId)
      return result || null
    } catch (error) {
      logger.error('Storage', 'Failed to get AI analytics', error)
      return null
    }
  }

  /**
   * Get all AI analytics
   */
  async getAllAIAnalytics(): Promise<(PredictiveAnalytics & { businessId: string })[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAll('aiAnalytics')
    } catch (error) {
      logger.error('Storage', 'Failed to get all AI analytics', error)
      return []
    }
  }

  /**
   * Delete AI analytics for a business
   */
  async deleteAIAnalytics(businessId: string): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.delete('aiAnalytics', businessId)
      logger.info('Storage', `Deleted AI analytics for business: ${businessId}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete AI analytics', error)
      throw error
    }
  }

  // AI Jobs Operations

  /**
   * Save AI processing job
   */
  async saveAIJob(job: AIProcessingJob): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('aiJobs', job)
      logger.info('Storage', `Saved AI job: ${job.id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save AI job', error)
      throw error
    }
  }

  /**
   * Get AI job by ID
   */
  async getAIJob(jobId: string): Promise<AIProcessingJob | null> {
    try {
      const db = await this.getDatabase()
      const result = await db.get('aiJobs', jobId)
      return result || null
    } catch (error) {
      logger.error('Storage', 'Failed to get AI job', error)
      return null
    }
  }

  /**
   * Get AI jobs by status
   */
  async getAIJobsByStatus(status: string): Promise<AIProcessingJob[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAllFromIndex('aiJobs', 'by-status', status)
    } catch (error) {
      logger.error('Storage', 'Failed to get AI jobs by status', error)
      return []
    }
  }

  /**
   * Get AI jobs for a business
   */
  async getAIJobsForBusiness(businessId: string): Promise<AIProcessingJob[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAllFromIndex('aiJobs', 'by-business-id', businessId)
    } catch (error) {
      logger.error('Storage', 'Failed to get AI jobs for business', error)
      return []
    }
  }

  /**
   * Update AI job status
   */
  async updateAIJobStatus(
    jobId: string,
    status: string,
    result?: PredictiveAnalytics,
    error?: string
  ): Promise<void> {
    try {
      const db = await this.getDatabase()
      const job = await db.get('aiJobs', jobId)
      if (job) {
        job.status = status as any
        job.result = result || job.result
        job.error = error || job.error
        if (status === 'running' && !job.startedAt) {
          job.startedAt = new Date()
        }
        if (status === 'completed' || status === 'failed') {
          job.completedAt = new Date()
        }
        await db.put('aiJobs', job)
        logger.info('Storage', `Updated AI job status: ${jobId} -> ${status}`)
      }
    } catch (error) {
      logger.error('Storage', 'Failed to update AI job status', error)
      throw error
    }
  }

  /**
   * Delete AI job
   */
  async deleteAIJob(jobId: string): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.delete('aiJobs', jobId)
      logger.info('Storage', `Deleted AI job: ${jobId}`)
    } catch (error) {
      logger.error('Storage', 'Failed to delete AI job', error)
      throw error
    }
  }

  // AI Insights Operations

  /**
   * Save AI insights summary
   */
  async saveAIInsights(insights: AIInsightsSummary): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('aiInsights', insights)
      logger.info('Storage', 'Saved AI insights summary')
    } catch (error) {
      logger.error('Storage', 'Failed to save AI insights', error)
      throw error
    }
  }

  // Payment Operations

  /**
   * Save user payment profile
   */
  async saveUserPaymentProfile(profile: UserPaymentProfile): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('userPaymentProfiles', profile)
      logger.info('Storage', `Saved payment profile for user: ${profile.userId}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save user payment profile', error)
      throw error
    }
  }

  /**
   * Get user payment profile
   */
  async getUserPaymentProfile(userId: string): Promise<UserPaymentProfile | undefined> {
    try {
      const db = await this.getDatabase()
      return await db.get('userPaymentProfiles', userId)
    } catch (error) {
      logger.error('Storage', `Failed to get payment profile for user: ${userId}`, error)
      return undefined
    }
  }

  /**
   * Save payment transaction
   */
  async savePaymentTransaction(transaction: PaymentTransaction): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('paymentTransactions', transaction)
      logger.info('Storage', `Saved payment transaction: ${transaction.id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save payment transaction', error)
      throw error
    }
  }

  /**
   * Get payment transactions for user
   */
  async getPaymentTransactionsByUser(userId: string): Promise<PaymentTransaction[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAllFromIndex('paymentTransactions', 'by-user-id', userId)
    } catch (error) {
      logger.error('Storage', `Failed to get payment transactions for user: ${userId}`, error)
      return []
    }
  }

  /**
   * Save invoice
   */
  async saveInvoice(invoice: Invoice): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('invoices', invoice)
      logger.info('Storage', `Saved invoice: ${invoice.id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save invoice', error)
      throw error
    }
  }

  /**
   * Get invoices for user
   */
  async getInvoicesByUser(userId: string): Promise<Invoice[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAllFromIndex('invoices', 'by-user-id', userId)
    } catch (error) {
      logger.error('Storage', `Failed to get invoices for user: ${userId}`, error)
      return []
    }
  }

  /**
   * Save payment audit log
   */
  async savePaymentAuditLog(auditLog: PaymentAuditLog): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('paymentAuditLogs', auditLog)
      logger.info('Storage', `Saved payment audit log: ${auditLog.id}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save payment audit log', error)
      throw error
    }
  }

  /**
   * Get payment audit logs for user
   */
  async getPaymentAuditLogsByUser(userId: string): Promise<PaymentAuditLog[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAllFromIndex('paymentAuditLogs', 'by-user-id', userId)
    } catch (error) {
      logger.error('Storage', `Failed to get payment audit logs for user: ${userId}`, error)
      return []
    }
  }

  /**
   * Save payment analytics
   */
  async savePaymentAnalytics(analytics: PaymentAnalytics): Promise<void> {
    try {
      const db = await this.getDatabase()
      await db.put('paymentAnalytics', analytics)
      logger.info('Storage', `Saved payment analytics for user: ${analytics.userId}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save payment analytics', error)
      throw error
    }
  }

  /**
   * Get payment analytics for user
   */
  async getPaymentAnalytics(userId: string): Promise<PaymentAnalytics | undefined> {
    try {
      const db = await this.getDatabase()
      return await db.get('paymentAnalytics', userId)
    } catch (error) {
      logger.error('Storage', `Failed to get payment analytics for user: ${userId}`, error)
      return undefined
    }
  }

  /**
   * Get latest AI insights
   */
  async getLatestAIInsights(): Promise<AIInsightsSummary | null> {
    try {
      const db = await this.getDatabase()
      const insights = await db.getAllFromIndex('aiInsights', 'by-generated-date')
      return insights.length > 0 ? insights[insights.length - 1] : null
    } catch (error) {
      logger.error('Storage', 'Failed to get latest AI insights', error)
      return null
    }
  }

  /**
   * Get all AI insights
   */
  async getAllAIInsights(): Promise<AIInsightsSummary[]> {
    try {
      const db = await this.getDatabase()
      return await db.getAll('aiInsights')
    } catch (error) {
      logger.error('Storage', 'Failed to get all AI insights', error)
      return []
    }
  }

  // Analytics Events Operations

  /**
   * Save an analytics event
   */
  async saveAnalyticsEvent(event: AnalyticsEvent): Promise<void> {
    try {
      const db = await this.getDatabase()

      if (!db) {
        logger.warn(
          'Storage',
          `Cannot save analytics event ${event.eventType} - database unavailable, skipping operation`
        )
        return
      }

      await db.put('analyticsEvents', event)
      logger.info('Storage', `Saved analytics event: ${event.eventType}`)
    } catch (error) {
      logger.error('Storage', 'Failed to save analytics event', error)
      // Don't throw error to prevent cascading failures in analytics
      logger.warn(
        'Storage',
        'Analytics event lost due to storage error, continuing in fallback mode'
      )
    }
  }

  /**
   * Get analytics events by date range
   */
  async getAnalyticsEvents(startDate: Date, endDate: Date): Promise<AnalyticsEvent[]> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('analyticsEvents', 'readonly')
      const store = tx.objectStore('analyticsEvents')
      const index = store.index('by-timestamp')

      const range = IDBKeyRange.bound(startDate, endDate)
      const events = await index.getAll(range)

      return events
    } catch (error) {
      logger.error('Storage', 'Failed to get analytics events', error)
      return []
    }
  }

  /**
   * Get analytics events by user ID
   */
  async getAnalyticsEventsByUser(userId: string): Promise<AnalyticsEvent[]> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('analyticsEvents', 'readonly')
      const store = tx.objectStore('analyticsEvents')
      const index = store.index('by-user-id')

      return await index.getAll(userId)
    } catch (error) {
      logger.error('Storage', 'Failed to get analytics events by user', error)
      return []
    }
  }

  /**
   * Get analytics events by event type
   */
  async getAnalyticsEventsByType(eventType: string): Promise<AnalyticsEvent[]> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('analyticsEvents', 'readonly')
      const store = tx.objectStore('analyticsEvents')
      const index = store.index('by-event-type')

      return await index.getAll(eventType)
    } catch (error) {
      logger.error('Storage', 'Failed to get analytics events by type', error)
      return []
    }
  }

  /**
   * Get analytics events by session ID
   */
  async getAnalyticsEventsBySession(sessionId: string): Promise<AnalyticsEvent[]> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('analyticsEvents', 'readonly')
      const store = tx.objectStore('analyticsEvents')
      const index = store.index('by-session-id')

      return await index.getAll(sessionId)
    } catch (error) {
      logger.error('Storage', 'Failed to get analytics events by session', error)
      return []
    }
  }

  /**
   * Delete old analytics events (for cleanup)
   */
  async deleteOldAnalyticsEvents(beforeDate: Date): Promise<number> {
    try {
      const db = await this.getDatabase()
      const tx = db.transaction('analyticsEvents', 'readwrite')
      const store = tx.objectStore('analyticsEvents')
      const index = store.index('by-timestamp')

      const range = IDBKeyRange.upperBound(beforeDate)
      const keys = await index.getAllKeys(range)

      for (const key of keys) {
        await store.delete(key)
      }

      logger.info('Storage', `Deleted ${keys.length} old analytics events`)
      return keys.length
    } catch (error) {
      logger.error('Storage', 'Failed to delete old analytics events', error)
      return 0
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
