/**
 * PostgreSQL Connection Module using postgres.js
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

// Global connection instance
let globalSql: postgres.Sql | null = null

/**
 * Create a postgres.js connection with proper SSL configuration
 */
export function createPostgresConnection(config: PostgresConnectionConfig): postgres.Sql {
  try {
    // Use connection string if provided, otherwise build from individual parameters
    const connectionString = config.connectionString || 
      `postgresql://${config.username || 'postgres'}:${config.password || 'password'}@${config.host || 'localhost'}:${config.port || 5432}/${config.database || 'business_scraper'}`

    // Create postgres.js connection with explicit SSL configuration
    const sql = postgres(connectionString, {
      // Connection pool settings
      max: config.max || 10,
      idle_timeout: config.idle_timeout || 30,
      connect_timeout: config.connect_timeout || 30,
      
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
      onnotice: (notice) => {
        logger.debug('PostgreSQL Notice', notice.message)
      },
      
      // Debug logging in development
      debug: process.env.NODE_ENV === 'development' ? 
        (connection, query, parameters) => {
          logger.debug('PostgreSQL Query', {
            query: query.substring(0, 200),
            parameters: parameters?.length || 0,
            connection: connection.id
          })
        } : false,
    })

    logger.info('PostgreSQL Connection', 'postgres.js connection created successfully', {
      host: config.host || 'localhost',
      port: config.port || 5432,
      database: config.database || 'business_scraper',
      ssl: false,
      max_connections: config.max || 10
    })

    return sql
  } catch (error) {
    logger.error('PostgreSQL Connection', 'Failed to create postgres.js connection', error)
    throw new Error(`Failed to create PostgreSQL connection: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Get or create the global postgres.js connection
 */
export function getPostgresConnection(config?: PostgresConnectionConfig): postgres.Sql {
  if (!globalSql) {
    const finalConfig = config || {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'business_scraper',
      username: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
      ssl: false, // Explicitly disable SSL
      max: parseInt(process.env.DB_POOL_MAX || '10'),
      idle_timeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30'),
      connect_timeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30'),
    }

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
 * Test the postgres.js connection
 */
export async function testPostgresConnection(config?: PostgresConnectionConfig): Promise<boolean> {
  let testSql: postgres.Sql | null = null
  
  try {
    testSql = config ? createPostgresConnection(config) : getPostgresConnection()
    
    // Test with a simple query
    const result = await testSql`SELECT 1 as test`
    
    if (result.length > 0 && result[0].test === 1) {
      logger.info('PostgreSQL Connection', 'Connection test successful')
      return true
    } else {
      logger.error('PostgreSQL Connection', 'Connection test failed - unexpected result')
      return false
    }
  } catch (error) {
    logger.error('PostgreSQL Connection', 'Connection test failed', error)
    return false
  } finally {
    // Close test connection if it was created specifically for testing
    if (testSql && config) {
      try {
        await testSql.end()
      } catch (error) {
        logger.warn('PostgreSQL Connection', 'Error closing test connection', error)
      }
    }
  }
}

/**
 * Execute a health check query
 */
export async function healthCheck(): Promise<{ connected: boolean; latency?: number; error?: string }> {
  const startTime = Date.now()
  
  try {
    const sql = getPostgresConnection()
    await sql`SELECT 1`
    
    const latency = Date.now() - startTime
    
    return {
      connected: true,
      latency
    }
  } catch (error) {
    return {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }
  }
}

// Export the postgres.js types for use in other modules
export type { postgres }
export default postgres
