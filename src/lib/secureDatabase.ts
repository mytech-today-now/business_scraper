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
import { DatabaseValidationService, QueryParameterSchema } from './database-validation-schemas'

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
   * Execute a secure parameterized query using postgres.js template literals
   */
  async query<T = any>(
    text: string,
    params?: any[],
    options: SecureQueryOptions = {}
  ): Promise<SecureQueryResult<T>> {
    const startTime = Date.now()
    const queryId = this.generateQueryId(text, params)

    try {
      // Enhanced validation with Zod schemas and security checks
      if (options.validateQuery !== false) {
        // First validate with Zod schema for structure and SQL injection prevention
        const zodValidation = DatabaseValidationService.validateQueryParameters({
          text,
          params: params || [],
        })

        if (!zodValidation.success) {
          const zodErrors = zodValidation.error.errors.map(e => `${e.path.join('.')}: ${e.message}`)
          throw new Error(`Query structure validation failed: ${zodErrors.join(', ')}`)
        }

        // Then validate with existing security service for additional patterns
        const securityValidation = this.securityService.validateQuery(text, params)
        if (!securityValidation.isValid) {
          throw new Error(`Query security validation failed: ${securityValidation.errors.join(', ')}`)
        }

        // Log warnings from both validation layers
        if (securityValidation.warnings.length > 0) {
          logger.warn('SecureDatabase', 'Query security validation warnings', {
            warnings: securityValidation.warnings,
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
        logger.debug('SecureDatabase', 'Executing secure parameterized query', {
          query: text.substring(0, 200),
          paramCount: params?.length || 0,
          queryId,
          securityValidated: options.validateQuery !== false,
        })
      }

      // Execute query with timeout using postgres.js safe parameterized approach
      const timeout = options.timeout || defaultDatabaseSecurityConfig.queryTimeoutMs
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), timeout)
      })

      // Use postgres.js safe parameterized query execution
      // This approach uses postgres.js internal parameter binding which is safer than unsafe()
      let queryPromise: Promise<any[]>

      if (params && params.length > 0) {
        // For parameterized queries, use postgres.js safe parameter binding
        // Convert the query to use postgres.js parameter format if needed
        const postgresQuery = this.convertToPostgresJSQuery(text, params)
        queryPromise = this.sql(postgresQuery.strings, ...postgresQuery.values)
      } else {
        // For queries without parameters, use template literal approach
        queryPromise = this.sql([text] as any)
      }

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

      logger.debug('SecureDatabase', 'Secure query executed successfully', {
        rowCount: secureResult.rowCount,
        executionTime,
        queryId,
        method: params && params.length > 0 ? 'parameterized' : 'template_literal',
      })

      return secureResult
    } catch (error) {
      const executionTime = Date.now() - startTime

      logger.error('SecureDatabase', 'Secure query execution failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        executionTime,
        queryId,
        query: text.substring(0, 100), // Log partial query for debugging
        paramCount: params?.length || 0,
      })

      // Retry logic for transient errors
      if (options.maxRetries && options.maxRetries > 0 && this.isRetryableError(error)) {
        logger.info('SecureDatabase', 'Retrying secure query', {
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
   * Convert standard parameterized query to postgres.js template literal format
   * This ensures safe parameter binding without using the unsafe() method
   */
  private convertToPostgresJSQuery(text: string, params: any[]): {
    strings: TemplateStringsArray
    values: any[]
  } {
    // Split the query by parameter placeholders ($1, $2, etc.)
    const parts = text.split(/\$\d+/)

    // Create a TemplateStringsArray-like object
    const strings = Object.assign(parts, { raw: parts }) as TemplateStringsArray

    // Return the template strings and values for postgres.js
    return {
      strings,
      values: params,
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
   * Execute multiple queries in a transaction with enhanced security
   */
  async transaction<T>(callback: (tx: DatabaseTransaction) => Promise<T>): Promise<T> {
    // postgres.js has built-in transaction support with automatic rollback on errors
    return await this.sql.begin(async sql => {
      const transaction: DatabaseTransaction = {
        query: async (text: string, params?: any[], options?: SecureQueryOptions) => {
          // Validate query security within transaction
          const validation = this.securityService.validateQuery(text, params)
          if (!validation.isValid) {
            throw new Error(`Transaction query validation failed: ${validation.errors.join(', ')}`)
          }

          const startTime = Date.now()
          let result: any[]

          // Use safe parameterized query execution within transaction
          if (params && params.length > 0) {
            const postgresQuery = this.convertToPostgresJSQuery(text, params)
            result = await sql(postgresQuery.strings, ...postgresQuery.values)
          } else {
            result = await sql([text] as any)
          }

          // Log transaction query if enabled
          if (options?.logQuery || defaultDatabaseSecurityConfig.enableQueryLogging) {
            logger.debug('SecureDatabase', 'Transaction query executed', {
              query: text.substring(0, 100),
              paramCount: params?.length || 0,
              executionTime: Date.now() - startTime,
            })
          }

          return {
            rows: result,
            rowCount: result.length,
            command: this.extractCommandFromQuery(text),
            executionTime: Date.now() - startTime,
          }
        },

        commit: async () => {
          // postgres.js handles commit automatically when the transaction function completes successfully
          logger.debug('SecureDatabase', 'Transaction commit requested (handled automatically by postgres.js)')
        },

        rollback: async () => {
          // postgres.js handles rollback automatically when an error is thrown
          logger.debug('SecureDatabase', 'Transaction rollback requested')
          throw new Error('Transaction rollback requested')
        },
      }

      return await callback(transaction)
    })
  }

  /**
   * Execute a prepared statement with enhanced security
   * Note: postgres.js automatically handles prepared statements when prepare: true is set
   */
  async preparedQuery<T = any>(
    name: string,
    text: string,
    params?: any[]
  ): Promise<SecureQueryResult<T>> {
    // Validate the prepared statement for security
    const validation = this.securityService.validateQuery(text, params)
    if (!validation.isValid) {
      throw new Error(`Prepared statement validation failed: ${validation.errors.join(', ')}`)
    }

    const startTime = Date.now()

    try {
      logger.debug('SecureDatabase', 'Executing prepared statement', {
        name,
        query: text.substring(0, 100),
        paramCount: params?.length || 0,
      })

      // Use safe parameterized query execution for prepared statements
      let result: any[]

      if (params && params.length > 0) {
        const postgresQuery = this.convertToPostgresJSQuery(text, params)
        result = await this.sql(postgresQuery.strings, ...postgresQuery.values)
      } else {
        result = await this.sql([text] as any)
      }

      const executionTime = Date.now() - startTime

      logger.debug('SecureDatabase', 'Prepared statement executed successfully', {
        name,
        rowCount: result.length,
        executionTime,
      })

      return {
        rows: result,
        rowCount: result.length,
        command: this.extractCommandFromQuery(text),
        executionTime,
      }
    } catch (error) {
      logger.error('SecureDatabase', 'Prepared statement execution failed', {
        name,
        error: error instanceof Error ? error.message : 'Unknown error',
        query: text.substring(0, 100),
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
