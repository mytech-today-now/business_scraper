/**
 * Database Factory - Environment-aware database selection
 * Returns PostgreSQL for server-side operations and IndexedDB for client-side
 */

import { DatabaseInterface } from './database'
import { logger } from '@/utils/logger'

let serverDatabase: any = null
let clientDatabase: any = null

/**
 * Determines if we're running in a server environment
 */
function isServerEnvironment(): boolean {
  return typeof window === 'undefined' && typeof process !== 'undefined' && process.env
}

/**
 * Determines if we're running in a browser environment
 */
function isBrowserEnvironment(): boolean {
  return typeof window !== 'undefined' && typeof window.indexedDB !== 'undefined'
}

/**
 * Gets the appropriate database implementation based on environment
 */
export async function getDatabaseInstance(): Promise<DatabaseInterface> {
  if (isServerEnvironment()) {
    // Server-side: Use PostgreSQL
    if (!serverDatabase) {
      const config = {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME || 'business_scraper',
        username: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: process.env.DB_SSL === 'true',
        poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
        poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
        idleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
        connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '5000'),
      }

      try {
        const { PostgreSQLDatabase } = await import('./postgresql-database')
        serverDatabase = new PostgreSQLDatabase(config)
        logger.info('DatabaseFactory', 'Initialized PostgreSQL database for server environment')
      } catch (error) {
        logger.error('DatabaseFactory', 'Failed to initialize PostgreSQL database', error)
        throw new Error('Failed to initialize server database')
      }
    }
    return serverDatabase
  } else if (isBrowserEnvironment()) {
    // Client-side: Use IndexedDB
    if (!clientDatabase) {
      try {
        const { IndexedDBDatabase } = await import('./indexeddb-database')
        clientDatabase = new IndexedDBDatabase()
        await clientDatabase.init()
        logger.info('DatabaseFactory', 'Initialized IndexedDB database for browser environment')
      } catch (error) {
        logger.error('DatabaseFactory', 'Failed to initialize IndexedDB database', error)
        throw new Error('Failed to initialize client database')
      }
    }
    return clientDatabase
  } else {
    throw new Error('Unable to determine appropriate database for current environment')
  }
}

/**
 * Closes all database connections
 */
export async function closeDatabaseConnections(): Promise<void> {
  const promises: Promise<void>[] = []

  if (serverDatabase) {
    promises.push(serverDatabase.close())
    serverDatabase = null
  }

  if (clientDatabase) {
    promises.push(clientDatabase.close())
    clientDatabase = null
  }

  await Promise.all(promises)
  logger.info('DatabaseFactory', 'Closed all database connections')
}

/**
 * Runs database migrations (server-side only)
 */
export async function runDatabaseMigrations(): Promise<void> {
  if (!isServerEnvironment()) {
    logger.warn('DatabaseFactory', 'Database migrations can only be run in server environment')
    return
  }

  try {
    const db = await getDatabaseInstance()

    // Check if AI tables exist, if not run migration
    const checkQuery = `
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'ai_analytics'
      ) as ai_tables_exist
    `

    const result = await db.executeQuery(checkQuery)
    const aiTablesExist = result.rows[0]?.ai_tables_exist

    if (!aiTablesExist) {
      logger.info('DatabaseFactory', 'AI tables not found, running migration...')

      // Read and execute migration file
      const fs = await import('fs/promises')
      const path = await import('path')

      const migrationPath = path.join(process.cwd(), 'src/lib/migrations/003_add_ai_tables.sql')
      const migrationSQL = await fs.readFile(migrationPath, 'utf-8')

      // Execute migration
      await db.executeQuery(migrationSQL)
      logger.info('DatabaseFactory', 'AI tables migration completed successfully')
    } else {
      logger.info('DatabaseFactory', 'AI tables already exist, skipping migration')
    }
  } catch (error) {
    logger.error('DatabaseFactory', 'Failed to run database migrations', error)
    throw error
  }
}

/**
 * Health check for database connections
 */
export async function checkDatabaseHealth(): Promise<{ server: boolean; client: boolean }> {
  const health = { server: false, client: false }

  // Check server database
  if (isServerEnvironment()) {
    try {
      const db = await getDatabaseInstance()
      await db.getStats()
      health.server = true
    } catch (error) {
      logger.error('DatabaseFactory', 'Server database health check failed', error)
    }
  }

  // Check client database
  if (isBrowserEnvironment()) {
    try {
      const db = await getDatabaseInstance()
      await db.getStats()
      health.client = true
    } catch (error) {
      logger.error('DatabaseFactory', 'Client database health check failed', error)
    }
  }

  return health
}
