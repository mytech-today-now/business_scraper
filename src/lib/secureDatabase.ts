/**
 * Secure Database Wrapper
 * Business Scraper Application - SQL Injection Prevention & Connection Security
 */

import { Pool, PoolClient, QueryResult } from 'pg'
import { logger } from '@/utils/logger'
import { 
  DatabaseSecurityService, 
  databaseSecurityService,
  defaultDatabaseSecurityConfig 
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
  query<T = any>(text: string, params?: any[], options?: SecureQueryOptions): Promise<SecureQueryResult<T>>
  commit(): Promise<void>
  rollback(): Promise<void>
}

/**
 * Secure database connection wrapper
 */
export class SecureDatabase {
  private pool: Pool
  private securityService: DatabaseSecurityService
  private queryCache = new Map<string, { result: any; timestamp: number }>()
  private readonly CACHE_TTL = 5 * 60 * 1000 // 5 minutes

  constructor(config: any) {
    // Apply security hardening to connection config
    const secureConfig = DatabaseSecurityService.createSecureConnectionConfig(config)
    
    this.pool = new Pool(secureConfig)
    this.securityService = databaseSecurityService
    
    // Set up pool event handlers
    this.setupPoolEventHandlers()
  }

  /**
   * Set up pool event handlers for monitoring
   */
  private setupPoolEventHandlers(): void {
    this.pool.on('error', (err, client) => {
      logger.error('SecureDatabase', 'Pool error occurred', {
        error: err.message,
        stack: err.stack,
        clientProcessId: client?.processID
      })
    })

    this.pool.on('connect', (client) => {
      logger.debug('SecureDatabase', 'New client connected', {
        processId: client.processID,
        totalCount: this.pool.totalCount,
        idleCount: this.pool.idleCount
      })
    })

    this.pool.on('acquire', (client) => {
      logger.debug('SecureDatabase', 'Client acquired from pool', {
        processId: client.processID,
        waitingCount: this.pool.waitingCount
      })
    })

    this.pool.on('remove', (client) => {
      logger.debug('SecureDatabase', 'Client removed from pool', {
        processId: client.processID,
        totalCount: this.pool.totalCount
      })
    })
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
            queryId
          })
        }
      }

      // Check cache first
      const cached = this.getCachedResult(queryId)
      if (cached) {
        return {
          ...cached.result,
          isFromCache: true,
          executionTime: Date.now() - startTime
        }
      }

      // Log query if enabled
      if (options.logQuery || defaultDatabaseSecurityConfig.enableQueryLogging) {
        logger.debug('SecureDatabase', 'Executing query', {
          query: text.substring(0, 200),
          paramCount: params?.length || 0,
          queryId
        })
      }

      // Execute query with timeout
      const client = await this.pool.connect()
      let result: QueryResult

      try {
        // Set query timeout
        const timeout = options.timeout || defaultDatabaseSecurityConfig.queryTimeoutMs
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Query timeout')), timeout)
        })

        const queryPromise = client.query(text, params)
        result = await Promise.race([queryPromise, timeoutPromise]) as QueryResult

      } finally {
        client.release()
      }

      const executionTime = Date.now() - startTime
      const secureResult: SecureQueryResult<T> = {
        rows: result.rows,
        rowCount: result.rowCount || 0,
        command: result.command,
        executionTime
      }

      // Cache result for SELECT queries
      if (text.trim().toUpperCase().startsWith('SELECT')) {
        this.setCachedResult(queryId, secureResult)
      }

      logger.debug('SecureDatabase', 'Query executed successfully', {
        rowCount: secureResult.rowCount,
        executionTime,
        queryId
      })

      return secureResult

    } catch (error) {
      const executionTime = Date.now() - startTime
      
      logger.error('SecureDatabase', 'Query execution failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        executionTime,
        queryId,
        query: text.substring(0, 100) // Log partial query for debugging
      })

      // Retry logic for transient errors
      if (options.maxRetries && options.maxRetries > 0 && this.isRetryableError(error)) {
        logger.info('SecureDatabase', 'Retrying query', {
          remainingRetries: options.maxRetries - 1,
          queryId
        })
        
        return this.query(text, params, {
          ...options,
          maxRetries: options.maxRetries - 1
        })
      }

      throw error
    }
  }

  /**
   * Execute multiple queries in a transaction
   */
  async transaction<T>(
    callback: (tx: DatabaseTransaction) => Promise<T>
  ): Promise<T> {
    const client = await this.pool.connect()
    
    try {
      await client.query('BEGIN')
      
      const transaction: DatabaseTransaction = {
        query: async <U = any>(text: string, params?: any[], options?: SecureQueryOptions) => {
          const validation = this.securityService.validateQuery(text, params)
          if (!validation.isValid) {
            throw new Error(`Transaction query validation failed: ${validation.errors.join(', ')}`)
          }

          const startTime = Date.now()
          const result = await client.query(text, params)
          
          return {
            rows: result.rows,
            rowCount: result.rowCount || 0,
            command: result.command,
            executionTime: Date.now() - startTime
          }
        },
        
        commit: async () => {
          await client.query('COMMIT')
        },
        
        rollback: async () => {
          await client.query('ROLLBACK')
        }
      }

      const result = await callback(transaction)
      await transaction.commit()
      
      return result
      
    } catch (error) {
      try {
        await client.query('ROLLBACK')
      } catch (rollbackError) {
        logger.error('SecureDatabase', 'Failed to rollback transaction', rollbackError)
      }
      throw error
    } finally {
      client.release()
    }
  }

  /**
   * Execute a prepared statement
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

    const client = await this.pool.connect()
    
    try {
      const startTime = Date.now()
      
      // Prepare the statement if not already prepared
      await client.query(`PREPARE ${name} AS ${text}`)
      
      // Execute the prepared statement
      const result = await client.query(`EXECUTE ${name}`, params)
      
      return {
        rows: result.rows,
        rowCount: result.rowCount || 0,
        command: result.command,
        executionTime: Date.now() - startTime
      }
      
    } finally {
      // Clean up the prepared statement
      try {
        await client.query(`DEALLOCATE ${name}`)
      } catch (error) {
        logger.warn('SecureDatabase', 'Failed to deallocate prepared statement', { name })
      }
      client.release()
    }
  }

  /**
   * Get database connection pool statistics
   */
  getPoolStats(): {
    totalCount: number
    idleCount: number
    waitingCount: number
  } {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount
    }
  }

  /**
   * Close all database connections
   */
  async close(): Promise<void> {
    await this.pool.end()
    this.queryCache.clear()
    logger.info('SecureDatabase', 'Database connections closed')
  }

  /**
   * Generate unique query ID for caching and logging
   */
  private generateQueryId(text: string, params?: any[]): string {
    const queryHash = require('crypto')
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
      timestamp: Date.now()
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
      'connection terminated unexpectedly'
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
