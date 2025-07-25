/**
 * Database configuration and connection management
 * Supports both PostgreSQL (production) and IndexedDB (development/offline)
 */

import { logger } from '@/utils/logger'

// Database configuration interface
export interface DatabaseConfig {
  type: 'postgresql' | 'indexeddb'
  host?: string
  port?: number
  database?: string
  username?: string
  password?: string
  ssl?: boolean
  poolMin?: number
  poolMax?: number
  idleTimeout?: number
  connectionTimeout?: number
}

// Environment-based configuration
export function getDatabaseConfig(): DatabaseConfig {
  try {
    // Try to use centralized configuration
    const { getDatabaseConfig: getCentralizedDbConfig } = require('./config')
    const dbConfig = getCentralizedDbConfig()

    if (dbConfig.url && dbConfig.type === 'postgresql') {
      // Parse DATABASE_URL if provided
      try {
        const url = new URL(dbConfig.url)
        return {
          type: 'postgresql',
          host: url.hostname,
          port: parseInt(url.port) || 5432,
          database: url.pathname.slice(1), // Remove leading slash
          username: url.username,
          password: url.password,
          ssl: url.searchParams.get('ssl') === 'true' || dbConfig.ssl,
          poolMin: dbConfig.poolMin,
          poolMax: dbConfig.poolMax,
          idleTimeout: dbConfig.idleTimeout,
          connectionTimeout: dbConfig.connectionTimeout,
        }
      } catch (error) {
        logger.error('Database', 'Invalid DATABASE_URL format', error)
        throw new Error('Invalid DATABASE_URL format')
      }
    } else if (dbConfig.type === 'postgresql' && dbConfig.host) {
      // Use individual configuration values for PostgreSQL
      return {
        type: 'postgresql',
        host: dbConfig.host,
        port: dbConfig.port,
        database: dbConfig.name,
        username: dbConfig.user,
        password: dbConfig.password,
        ssl: dbConfig.ssl,
        poolMin: dbConfig.poolMin,
        poolMax: dbConfig.poolMax,
        idleTimeout: dbConfig.idleTimeout,
        connectionTimeout: dbConfig.connectionTimeout,
      }
    } else {
      // Use IndexedDB (default or explicitly configured)
      return {
        type: 'indexeddb',
      }
    }
  } catch (error) {
    // Fallback to environment variables if centralized config not available
    const databaseUrl = process.env.DATABASE_URL
    const dbType = process.env.DB_TYPE || 'indexeddb'

    if (dbType === 'postgresql' && databaseUrl) {
      try {
        const url = new URL(databaseUrl)
        return {
          type: 'postgresql',
          host: url.hostname,
          port: parseInt(url.port) || 5432,
          database: url.pathname.slice(1),
          username: url.username,
          password: url.password,
          ssl: url.searchParams.get('ssl') === 'true',
          poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
          poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
          idleTimeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30000'),
          connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '5000'),
        }
      } catch (error) {
        logger.error('Database', 'Invalid DATABASE_URL format', error)
        throw new Error('Invalid DATABASE_URL format')
      }
    } else if (dbType === 'postgresql') {
      return {
        type: 'postgresql',
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME || 'business_scraper_db',
        username: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: process.env.DB_SSL === 'true',
        poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
        poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
        idleTimeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30000'),
        connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '5000'),
      }
    } else {
      return {
        type: 'indexeddb',
      }
    }
  }
}

// Database connection status
export interface ConnectionStatus {
  connected: boolean
  type: 'postgresql' | 'indexeddb'
  error?: string
  lastChecked: Date
}

// Abstract database interface for consistent API
export interface DatabaseInterface {
  // Campaign operations
  createCampaign(campaign: any): Promise<string>
  getCampaign(id: string): Promise<any | null>
  updateCampaign(id: string, updates: any): Promise<void>
  deleteCampaign(id: string): Promise<void>
  listCampaigns(filters?: any): Promise<any[]>

  // Business operations
  createBusiness(business: any): Promise<string>
  getBusiness(id: string): Promise<any | null>
  updateBusiness(id: string, updates: any): Promise<void>
  deleteBusiness(id: string): Promise<void>
  listBusinesses(campaignId?: string, filters?: any): Promise<any[]>

  // Scraping session operations
  createSession(session: any): Promise<string>
  getSession(id: string): Promise<any | null>
  updateSession(id: string, updates: any): Promise<void>
  deleteSession(id: string): Promise<void>
  listSessions(campaignId?: string, filters?: any): Promise<any[]>

  // Settings operations
  getSetting(key: string): Promise<any | null>
  setSetting(key: string, value: any, type?: string): Promise<void>
  getSettings(category?: string): Promise<any[]>

  // Utility operations
  getStats(): Promise<any>
  close(): Promise<void>
}

// Database factory function
export async function createDatabase(config?: DatabaseConfig): Promise<DatabaseInterface> {
  const dbConfig = config || getDatabaseConfig()

  if (dbConfig.type === 'postgresql') {
    // Import PostgreSQL implementation (server-side only)
    if (typeof window === 'undefined') {
      try {
        const { PostgreSQLDatabase } = await import('./postgresql-database')
        return new PostgreSQLDatabase(dbConfig)
      } catch (error) {
        logger.error('Database', 'Failed to load PostgreSQL database', error)
        throw new Error('PostgreSQL database not available')
      }
    } else {
      logger.warn('Database', 'PostgreSQL not available in browser, falling back to IndexedDB')
      const { IndexedDBDatabase } = await import('./indexeddb-database')
      return new IndexedDBDatabase()
    }
  } else {
    // Use IndexedDB implementation (client-side)
    const { IndexedDBDatabase } = await import('./indexeddb-database')
    return new IndexedDBDatabase()
  }
}

// Connection health check
export async function checkDatabaseConnection(config?: DatabaseConfig): Promise<ConnectionStatus> {
  const dbConfig = config || getDatabaseConfig()
  const lastChecked = new Date()

  try {
    if (dbConfig.type === 'postgresql' && typeof window === 'undefined') {
      // Server-side PostgreSQL check
      const { Pool } = await import('pg')
      const pool = new Pool({
        host: dbConfig.host,
        port: dbConfig.port,
        database: dbConfig.database,
        user: dbConfig.username,
        password: dbConfig.password,
        ssl: dbConfig.ssl,
        connectionTimeoutMillis: dbConfig.connectionTimeout,
      })

      try {
        const client = await pool.connect()
        await client.query('SELECT 1')
        client.release()
        await pool.end()

        return {
          connected: true,
          type: 'postgresql',
          lastChecked,
        }
      } catch (error) {
        await pool.end()
        throw error
      }
    } else {
      // IndexedDB check (client-side)
      if (typeof window !== 'undefined' && 'indexedDB' in window) {
        return {
          connected: true,
          type: 'indexeddb',
          lastChecked,
        }
      } else {
        throw new Error('IndexedDB not supported')
      }
    }
  } catch (error) {
    logger.error('Database', 'Connection check failed', error)
    return {
      connected: false,
      type: dbConfig.type,
      error: error instanceof Error ? error.message : 'Unknown error',
      lastChecked,
    }
  }
}

// Migration utilities
export interface MigrationInfo {
  version: string
  name: string
  applied: boolean
  appliedAt?: Date
  checksum?: string
}

export async function getMigrationStatus(): Promise<MigrationInfo[]> {
  const config = getDatabaseConfig()
  
  if (config.type === 'postgresql' && typeof window === 'undefined') {
    try {
      const { Pool } = await import('pg')
      const pool = new Pool({
        host: config.host,
        port: config.port,
        database: config.database,
        user: config.username,
        password: config.password,
        ssl: config.ssl,
      })

      try {
        const result = await pool.query(`
          SELECT version, name, applied_at, checksum
          FROM schema_migrations
          ORDER BY version
        `)

        await pool.end()

        return result.rows.map(row => ({
          version: row.version,
          name: row.name,
          applied: true,
          appliedAt: row.applied_at,
          checksum: row.checksum,
        }))
      } catch (error) {
        await pool.end()
        throw error
      }
    } catch (error) {
      logger.error('Database', 'Failed to get migration status', error)
      return []
    }
  } else {
    // IndexedDB doesn't use migrations in the same way
    return [
      {
        version: '001',
        name: 'indexeddb_schema',
        applied: true,
        appliedAt: new Date(),
      }
    ]
  }
}

// Export configuration for use in other modules
export const dbConfig = getDatabaseConfig()

// Default database instance (lazy-loaded)
let defaultDatabase: DatabaseInterface | null = null

export async function getDatabase(): Promise<DatabaseInterface> {
  if (!defaultDatabase) {
    defaultDatabase = await createDatabase()
  }
  return defaultDatabase
}

// Cleanup function
export async function closeDatabase(): Promise<void> {
  if (defaultDatabase) {
    await defaultDatabase.close()
    defaultDatabase = null
  }
}
