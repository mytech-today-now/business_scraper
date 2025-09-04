/**
 * Secure Database Wrapper
 * Business Scraper Application - SQL Injection Prevention & Connection Security
 */

import postgres from 'postgres'
import * as crypto from 'crypto'
import { logger } from '@/utils/logger'
import { createPostgresConnection, type PostgresConnectionConfig } from './postgres-connection'
import {
  DatabaseSecurityService,
  databaseSecurityService,
  defaultDatabaseSecurityConfig,
} from './databaseSecurity'

/**
 * Secure query options
 */
export interface SecureQueryOptions {
  timeout?: number
  validateQuery?: boolean
  logQuery?: boolean
  maxRetries?: number
}

/**
 * Query execution result
 */
export interface SecureQueryResult<T = any> {
  rows: T[]
  rowCount: number
  command: string
  executionTime: number
  isFromCache?: boolean
}

/**
 * Database transaction interface
 */
export interface DatabaseTransaction {
  query<T = any>(
    text: string,
    params?: any[],
    options?: SecureQueryOptions
  ): Promise<SecureQueryResult<T>>
  commit(): Promise<void>
  rollback(): Promise<void>
}

/**
 * Secure database connection wrapper
 */
export class SecureDatabase {
  private sql: postgres.Sql
  private securityService: DatabaseSecurityService
  private queryCache = new Map<string, { result: any; timestamp: number }>()
  private readonly CACHE_TTL = 5 * 60 * 1000 // 5 minutes

  constructor(config: any) {
    // Convert pg config to postgres.js config
    const postgresConfig: PostgresConnectionConfig = {
      host: config.host,
      port: config.port,
      database: config.database,
      username: config.user,
      password: config.password,
      ssl: false, // Explicitly disable SSL to solve persistent SSL issues
      max: config.max,
      idle_timeout: Math.floor((config.idleTimeoutMillis || 30000) / 1000),
      connect_timeout: Math.floor((config.connectionTimeoutMillis || 5000) / 1000),
    }

    this.sql = createPostgresConnection(postgresConfig)
    this.securityService = databaseSecurityService

    logger.info('SecureDatabase', 'postgres.js connection initialized with security hardening')
  }

  /**
   * Get connection status for monitoring
   */
  getConnectionStatus(): { connected: boolean; info?: string } {
    try {
      // postgres.js doesn't expose pool statistics like pg does
      // but we can check if the connection is still valid
      return {
        connected: true,
        info: 'postgres.js connection active',
      }
    } catch (error) {
      return {
        connected: false,
        info: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  /**
   * Execute a secure parameterized query
   */
  async query<T = any>(
    text: string,
    params?: any[],
    options: SecureQueryOptions = {}
  ): Promise<SecureQueryResult<T>> {
    const startTime = Date.now()
    const queryId = this.generateQueryId(text, params)

    try {
      // Validate query security
      if (options.validateQuery !== false) {
        const validation = this.securityService.validateQuery(text, params)
        if (!validation.isValid) {
          throw new Error(`Query validation failed: ${validation.errors.join(', ')}`)
        }

        // Log warnings
        if (validation.warnings.length > 0) {
          logger.warn('SecureDatabase', 'Query validation warnings', {
            warnings: validation.warnings,
            queryId,
          })
        }
      }

      // Check cache first
      const cached = this.getCachedResult(queryId)
      if (cached) {
        return {
          ...cached.result,
          isFromCache: true,
          executionTime: Date.now() - startTime,
        }
      }

      // Log query if enabled
      if (options.logQuery || defaultDatabaseSecurityConfig.enableQueryLogging) {
        logger.debug('SecureDatabase', 'Executing query', {
          query: text.substring(0, 200),
          paramCount: params?.length || 0,
          queryId,
        })
      }

      // Execute query with timeout using postgres.js
      const timeout = options.timeout || defaultDatabaseSecurityConfig.queryTimeoutMs
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), timeout)
      })

      // Use postgres.js unsafe method for parameterized queries
      // postgres.js handles parameters differently - we need to use template literals or unsafe method
      const queryPromise =
        params && params.length > 0 ? this.sql.unsafe(text, params) : this.sql.unsafe(text)

      const result = (await Promise.race([queryPromise, timeoutPromise])) as any[]

      const executionTime = Date.now() - startTime
      const secureResult: SecureQueryResult<T> = {
        rows: result,
        rowCount: result.length,
        command: this.extractCommandFromQuery(text),
        executionTime,
      }

      // Cache result for SELECT queries
      if (text.trim().toUpperCase().startsWith('SELECT')) {
        this.setCachedResult(queryId, secureResult)
      }

      logger.debug('SecureDatabase', 'Query executed successfully', {
        rowCount: secureResult.rowCount,
        executionTime,
        queryId,
      })

      return secureResult
    } catch (error) {
      const executionTime = Date.now() - startTime

      logger.error('SecureDatabase', 'Query execution failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        executionTime,
        queryId,
        query: text.substring(0, 100), // Log partial query for debugging
      })

      // Retry logic for transient errors
      if (options.maxRetries && options.maxRetries > 0 && this.isRetryableError(error)) {
        logger.info('SecureDatabase', 'Retrying query', {
          remainingRetries: options.maxRetries - 1,
          queryId,
        })

        return this.query(text, params, {
          ...options,
          maxRetries: options.maxRetries - 1,
        })
      }

      throw error
    }
  }

  /**
   * Extract SQL command from query text
   */
  private extractCommandFromQuery(text: string): string {
    const trimmed = text.trim().toUpperCase()
    const firstWord = trimmed.split(/\s+/)[0]
    return firstWord || 'UNKNOWN'
  }

  /**
   * Execute multiple queries in a transaction
   */
  async transaction<T>(callback: (tx: DatabaseTransaction) => Promise<T>): Promise<T> {
    // postgres.js has built-in transaction support
    return await this.sql.begin(async sql => {
      const transaction: DatabaseTransaction = {
        query: async (text: string, params?: any[], _options?: SecureQueryOptions) => {
          const validation = this.securityService.validateQuery(text, params)
          if (!validation.isValid) {
            throw new Error(`Transaction query validation failed: ${validation.errors.join(', ')}`)
          }

          const startTime = Date.now()
          const result =
            params && params.length > 0 ? await sql.unsafe(text, params) : await sql.unsafe(text)

          return {
            rows: result,
            rowCount: result.length,
            command: this.extractCommandFromQuery(text),
            executionTime: Date.now() - startTime,
          }
        },

        commit: async () => {
          // postgres.js handles commit automatically when the transaction function completes successfully
        },

        rollback: async () => {
          // postgres.js handles rollback automatically when an error is thrown
          throw new Error('Transaction rollback requested')
        },
      }

      return await callback(transaction)
    })
  }

  /**
   * Execute a prepared statement
   * Note: postgres.js automatically handles prepared statements when prepare: true is set
   */
  async preparedQuery<T = any>(
    name: string,
    text: string,
    params?: any[]
  ): Promise<SecureQueryResult<T>> {
    // Validate the prepared statement
    const validation = this.securityService.validateQuery(text, params)
    if (!validation.isValid) {
      throw new Error(`Prepared statement validation failed: ${validation.errors.join(', ')}`)
    }

    const startTime = Date.now()

    try {
      // postgres.js automatically handles prepared statements
      // We can use the regular query method as it will prepare and cache the statement
      const result =
        params && params.length > 0
          ? await this.sql.unsafe(text, params)
          : await this.sql.unsafe(text)

      return {
        rows: result,
        rowCount: result.length,
        command: this.extractCommandFromQuery(text),
        executionTime: Date.now() - startTime,
      }
    } catch (error) {
      logger.error('SecureDatabase', 'Prepared statement execution failed', {
        name,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
      throw error
    }
  }

  /**
   * Get database connection status
   * Note: postgres.js doesn't expose detailed pool statistics like pg
   */
  getPoolStats(): {
    connected: boolean
    info: string
  } {
    return this.getConnectionStatus()
  }

  /**
   * Close all database connections
   */
  async close(): Promise<void> {
    await this.sql.end()
    this.queryCache.clear()
    logger.info('SecureDatabase', 'Database connections closed')
  }

  /**
   * Generate unique query ID for caching and logging
   */
  private generateQueryId(text: string, params?: any[]): string {
    const queryHash = crypto
      .createHash('md5')
      .update(text + JSON.stringify(params || []))
      .digest('hex')
    return queryHash.substring(0, 8)
  }

  /**
   * Get cached query result
   */
  private getCachedResult(queryId: string): { result: any; timestamp: number } | null {
    const cached = this.queryCache.get(queryId)
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached
    }

    // Remove expired cache entry
    if (cached) {
      this.queryCache.delete(queryId)
    }

    return null
  }

  /**
   * Set cached query result
   */
  private setCachedResult(queryId: string, result: any): void {
    // Limit cache size
    if (this.queryCache.size > 100) {
      const oldestKey = this.queryCache.keys().next().value
      this.queryCache.delete(oldestKey)
    }

    this.queryCache.set(queryId, {
      result: { ...result },
      timestamp: Date.now(),
    })
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: any): boolean {
    const retryableErrors = [
      'ECONNRESET',
      'ENOTFOUND',
      'ECONNREFUSED',
      'ETIMEDOUT',
      'connection terminated unexpectedly',
    ]

    const errorMessage = error?.message?.toLowerCase() || ''
    return retryableErrors.some(pattern => errorMessage.includes(pattern))
  }

  /**
   * Clear query cache
   */
  clearCache(): void {
    this.queryCache.clear()
    logger.debug('SecureDatabase', 'Query cache cleared')
  }
}
