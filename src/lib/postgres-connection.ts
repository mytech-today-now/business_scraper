/**
 * PostgreSQL Connection Module using postgres.js
 * Enhanced with robust hostname resolution and connection retry logic
 * Replaces pg library with modern postgres.js for better SSL handling and performance
 */

import postgres from 'postgres'
import { logger } from '@/utils/logger'

// Connection configuration interface
export interface PostgresConnectionConfig {
  host?: string
  port?: number
  database?: string
  username?: string
  password?: string
  ssl?: boolean | 'require' | 'prefer' | 'disable'
  max?: number
  idle_timeout?: number
  connect_timeout?: number
  connectionString?: string
}

// Connection retry configuration
interface RetryConfig {
  maxRetries: number
  baseDelay: number
  maxDelay: number
  backoffMultiplier: number
}

// Global connection instance
let globalSql: postgres.Sql | null = null

// Default retry configuration
const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 5,
  baseDelay: 1000, // 1 second
  maxDelay: 30000, // 30 seconds
  backoffMultiplier: 2,
}

/**
 * Resolve and validate database hostname
 * Ensures proper hostname resolution for Docker environments
 */
function resolveHostname(config: PostgresConnectionConfig): string {
  // Priority order for hostname resolution:
  // 1. Explicit host from config
  // 2. Parse from connection string if provided
  // 3. Environment variable DB_HOST
  // 4. Default to 'postgres' for Docker environments

  let resolvedHost = config.host

  // If connection string is provided, parse hostname from it
  if (config.connectionString && !resolvedHost) {
    try {
      const url = new URL(config.connectionString.replace('postgresql://', 'http://'))
      resolvedHost = url.hostname
      logger.debug('PostgreSQL Connection', 'Parsed hostname from connection string', {
        connectionString: config.connectionString.replace(/:[^:@]*@/, ':***@'),
        parsedHost: resolvedHost,
      })
    } catch (error) {
      logger.warn('PostgreSQL Connection', 'Failed to parse hostname from connection string', {
        error: error instanceof Error ? error.message : 'Unknown error',
        connectionString: config.connectionString?.replace(/:[^:@]*@/, ':***@'),
      })
    }
  }

  // Fallback to environment variable or default
  if (!resolvedHost) {
    resolvedHost = process.env.DB_HOST || 'postgres'
  }

  // Validate hostname - ensure it's not localhost in Docker environments
  if (resolvedHost === 'localhost' && process.env.NODE_ENV === 'production') {
    logger.warn('PostgreSQL Connection', 'Localhost detected in production, forcing to postgres', {
      originalHost: resolvedHost,
      environment: process.env.NODE_ENV,
    })
    resolvedHost = 'postgres'
  }

  logger.info('PostgreSQL Connection', 'Hostname resolved', {
    originalHost: config.host,
    resolvedHost,
    source: config.host ? 'config' : config.connectionString ? 'connectionString' : 'environment',
  })

  return resolvedHost
}

/**
 * Create a postgres.js connection with enhanced error handling and retry logic
 */
export function createPostgresConnection(config: PostgresConnectionConfig): postgres.Sql {
  try {
    // Resolve hostname with enhanced logic
    const resolvedHost = resolveHostname(config)

    // Create enhanced configuration
    const enhancedConfig = {
      ...config,
      host: resolvedHost,
    }

    // Log the configuration being used for debugging
    logger.info('PostgreSQL Connection', 'Creating connection with resolved configuration', {
      host: enhancedConfig.host,
      port: enhancedConfig.port || 5432,
      database: enhancedConfig.database || 'business_scraper',
      username: enhancedConfig.username || 'postgres',
      ssl: enhancedConfig.ssl || false,
      connectionString: enhancedConfig.connectionString?.replace(/:[^:@]*@/, ':***@'),
    })

    // Build connection string with resolved hostname
    const connectionString =
      enhancedConfig.connectionString ||
      `postgresql://${enhancedConfig.username || 'postgres'}:${enhancedConfig.password || 'password'}@${resolvedHost}:${enhancedConfig.port || 5432}/${enhancedConfig.database || 'business_scraper'}`

    logger.info('PostgreSQL Connection', 'Final connection string built', {
      connectionString: connectionString.replace(/:[^:@]*@/, ':***@'),
      resolvedHost,
    })

    // Create postgres.js connection with enhanced configuration
    const sql = postgres(connectionString, {
      // Connection pool settings
      max: enhancedConfig.max || 10,
      idle_timeout: enhancedConfig.idle_timeout || 30,
      connect_timeout: enhancedConfig.connect_timeout || 30,

      // SSL configuration - explicitly disable SSL to solve the persistent SSL issues
      ssl: false,

      // Performance optimizations
      prepare: true, // Use prepared statements for better performance
      transform: {
        undefined: null, // Transform undefined values to null
      },

      // Connection options
      connection: {
        application_name: 'business-scraper-app',
      },

      // Error handling
      onnotice: notice => {
        logger.debug('PostgreSQL Notice', notice.message)
      },

      // Enhanced debug logging
      debug:
        process.env.NODE_ENV === 'development'
          ? (connection, query, parameters) => {
              logger.debug('PostgreSQL Query', {
                query: query.substring(0, 200),
                parameters: parameters?.length || 0,
                connection: connection.id,
              })
            }
          : false,
    })

    logger.info('PostgreSQL Connection', 'postgres.js connection created successfully', {
      host: resolvedHost,
      port: enhancedConfig.port || 5432,
      database: enhancedConfig.database || 'business_scraper',
      ssl: false,
      max_connections: enhancedConfig.max || 10,
    })

    return sql
  } catch (error) {
    logger.error('PostgreSQL Connection', 'Failed to create postgres.js connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      config: {
        host: enhancedConfig.host,
        port: enhancedConfig.port,
        database: enhancedConfig.database,
        ssl: enhancedConfig.ssl,
      },
      resolvedHost,
    })
    throw new Error(
      `Failed to create PostgreSQL connection: ${error instanceof Error ? error.message : 'Unknown error'}`
    )
  }
}

/**
 * Get or create the global postgres.js connection with enhanced configuration
 */
export function getPostgresConnection(config?: PostgresConnectionConfig): postgres.Sql {
  if (!globalSql) {
    // Create configuration from environment variables with enhanced defaults
    const envConfig: PostgresConnectionConfig = {
      host: process.env.DB_HOST || 'postgres',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'business_scraper',
      username: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
      ssl: false, // Explicitly disable SSL
      max: parseInt(process.env.DB_POOL_MAX || '10'),
      idle_timeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30'),
      connect_timeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30'),
    }

    // Merge provided config with environment config (provided config takes precedence)
    const finalConfig: PostgresConnectionConfig = {
      ...envConfig,
      ...config,
    }

    // Log the configuration being used for debugging
    logger.info('PostgreSQL Connection', 'Creating global connection with merged config', {
      host: finalConfig.host,
      port: finalConfig.port,
      database: finalConfig.database,
      username: finalConfig.username,
      ssl: finalConfig.ssl,
      connectionString: finalConfig.connectionString ? finalConfig.connectionString.replace(/:[^:@]*@/, ':***@') : undefined,
      source: config ? 'merged_with_provided' : 'environment_variables',
    })

    globalSql = createPostgresConnection(finalConfig)
  }

  return globalSql
}

/**
 * Close the global postgres.js connection
 */
export async function closePostgresConnection(): Promise<void> {
  if (globalSql) {
    try {
      await globalSql.end()
      globalSql = null
      logger.info('PostgreSQL Connection', 'postgres.js connection closed successfully')
    } catch (error) {
      logger.error('PostgreSQL Connection', 'Error closing postgres.js connection', error)
      throw error
    }
  }
}

/**
 * Sleep utility for retry delays
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Calculate exponential backoff delay
 */
function calculateBackoffDelay(attempt: number, config: RetryConfig): number {
  const delay = config.baseDelay * Math.pow(config.backoffMultiplier, attempt - 1)
  return Math.min(delay, config.maxDelay)
}

/**
 * Test PostgreSQL connection with retry logic and enhanced error handling
 */
export async function testPostgresConnection(
  config?: PostgresConnectionConfig,
  retryConfig: RetryConfig = DEFAULT_RETRY_CONFIG
): Promise<boolean> {
  let sql: postgres.Sql | null = null
  let lastError: Error | null = null

  for (let attempt = 1; attempt <= retryConfig.maxRetries; attempt++) {
    try {
      logger.info('PostgreSQL Connection', 'Testing connection', {
        attempt,
        maxRetries: retryConfig.maxRetries,
        config: config ? {
          host: config.host,
          port: config.port,
          database: config.database,
        } : 'global',
      })

      // Use provided config or get global connection
      if (config) {
        sql = createPostgresConnection(config)
      } else {
        sql = getPostgresConnection()
      }

      // Test the connection with a simple query
      const result = await sql`SELECT 1 as test, current_timestamp as timestamp`

      if (result && result.length > 0 && result[0].test === 1) {
        logger.info('PostgreSQL Connection', 'Connection test successful', {
          attempt,
          timestamp: result[0].timestamp,
          host: config?.host || 'global',
        })
        return true
      } else {
        throw new Error(`Unexpected result: ${JSON.stringify(result)}`)
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error('Unknown error')

      logger.warn('PostgreSQL Connection', 'Connection test failed', {
        attempt,
        maxRetries: retryConfig.maxRetries,
        error: lastError.message,
        willRetry: attempt < retryConfig.maxRetries,
      })

      // If this is not the last attempt, wait before retrying
      if (attempt < retryConfig.maxRetries) {
        const delay = calculateBackoffDelay(attempt, retryConfig)
        logger.info('PostgreSQL Connection', 'Retrying connection', {
          nextAttempt: attempt + 1,
          delayMs: delay,
        })
        await sleep(delay)
      }
    } finally {
      // Only close the connection if we created it specifically for this test
      if (config && sql) {
        try {
          await sql.end()
          sql = null
        } catch (error) {
          logger.warn('PostgreSQL Connection', 'Failed to close test connection', {
            error: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      }
    }
  }

  // All attempts failed
  logger.error('PostgreSQL Connection', 'All connection attempts failed', {
    totalAttempts: retryConfig.maxRetries,
    lastError: lastError?.message,
  })

  return false
}

/**
 * Execute a health check query
 */
export async function healthCheck(): Promise<{
  connected: boolean
  latency?: number
  error?: string
}> {
  const startTime = Date.now()

  try {
    const sql = getPostgresConnection()
    await sql`SELECT 1`

    const latency = Date.now() - startTime

    return {
      connected: true,
      latency,
    }
  } catch (error) {
    return {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    }
  }
}

// Export the postgres.js types for use in other modules
export type { postgres }
export default postgres
