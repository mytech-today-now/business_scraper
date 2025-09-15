/**
 * Database configuration and connection management
 * Supports both PostgreSQL (production) and IndexedDB (development/offline)
 */

import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'
import { getDatabaseConfig as getCentralizedDbConfig } from './config'

// Campaign data interface
export interface CampaignData {
  id?: string
  name: string
  description?: string
  industries: string[]
  zipCode: string
  searchRadius: number
  searchDepth: number
  pagesPerSite: number
  status: 'active' | 'paused' | 'completed' | 'cancelled'
  createdAt?: Date
  updatedAt?: Date
  settings?: Record<string, unknown>
}

// Scraping session data interface
export interface SessionData {
  id?: string
  campaignId: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  startedAt?: Date
  completedAt?: Date
  progress: {
    totalBusinesses: number
    processedBusinesses: number
    validBusinesses: number
    errors: number
  }
  settings: {
    industries: string[]
    zipCode: string
    searchRadius: number
    maxResults: number
  }
  results?: {
    businesses: BusinessRecord[]
    errors: string[]
    warnings: string[]
  }
  metadata?: Record<string, unknown>
}

// Setting data interface
export interface SettingData {
  key: string
  value: unknown
  type: 'string' | 'number' | 'boolean' | 'object' | 'array'
  category?: string
  description?: string
  createdAt?: Date
  updatedAt?: Date
}

// Database statistics interface
export interface DatabaseStats {
  campaigns: {
    total: number
    active: number
    completed: number
  }
  businesses: {
    total: number
    validated: number
    withEmails: number
  }
  sessions: {
    total: number
    running: number
    completed: number
    failed: number
  }
  storage: {
    size: number
    tables: Record<string, number>
  }
}

// Filter interfaces
export interface CampaignFilters {
  status?: CampaignData['status']
  industry?: string
  zipCode?: string
  createdAfter?: Date
  createdBefore?: Date
}

export interface BusinessFilters {
  industry?: string
  zipCode?: string
  hasEmail?: boolean
  hasPhone?: boolean
  validated?: boolean
  createdAfter?: Date
  createdBefore?: Date
}

export interface SessionFilters {
  status?: SessionData['status']
  campaignId?: string
  startedAfter?: Date
  startedBefore?: Date
}

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
          ssl: false, // Force SSL to false for local PostgreSQL containers
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
        ssl: false, // Force SSL to false for local PostgreSQL containers
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
          ssl: false, // Force SSL to false for local PostgreSQL containers
          poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
          poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
          idleTimeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30000'),
          connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
        }
      } catch (error) {
        logger.error('Database', 'Invalid DATABASE_URL format', error)
        throw new Error('Invalid DATABASE_URL format')
      }
    } else if (dbType === 'postgresql') {
      return {
        type: 'postgresql',
        host: process.env.DB_HOST || 'postgres',
        port: parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME || 'business_scraper_db',
        username: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: false, // Explicitly disable SSL for local PostgreSQL container
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
  createCampaign(campaign: Omit<CampaignData, 'id' | 'createdAt' | 'updatedAt'>): Promise<string>
  getCampaign(id: string): Promise<CampaignData | null>
  updateCampaign(id: string, updates: Partial<CampaignData>): Promise<void>
  deleteCampaign(id: string): Promise<void>
  listCampaigns(filters?: CampaignFilters): Promise<CampaignData[]>

  // Business operations
  createBusiness(business: Omit<BusinessRecord, 'id' | 'scrapedAt'>): Promise<string>
  getBusiness(id: string): Promise<BusinessRecord | null>
  updateBusiness(id: string, updates: Partial<BusinessRecord>): Promise<void>
  deleteBusiness(id: string): Promise<void>
  listBusinesses(campaignId?: string, filters?: BusinessFilters): Promise<BusinessRecord[]>

  // Scraping session operations
  createSession(session: Omit<SessionData, 'id' | 'startedAt' | 'completedAt'>): Promise<string>
  getSession(id: string): Promise<SessionData | null>
  updateSession(id: string, updates: Partial<SessionData>): Promise<void>
  deleteSession(id: string): Promise<void>
  listSessions(campaignId?: string, filters?: SessionFilters): Promise<SessionData[]>

  // Settings operations
  getSetting(key: string): Promise<SettingData | null>
  setSetting(key: string, value: unknown, type?: SettingData['type']): Promise<void>
  getSettings(category?: string): Promise<SettingData[]>

  // Utility operations
  getStats(): Promise<DatabaseStats>
  close(): Promise<void>
}

// Database factory function
export async function createDatabase(config?: DatabaseConfig): Promise<DatabaseInterface> {
  // Use DATABASE_URL if available, otherwise build from individual components
  let connectionString: string

  if (process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0) {
    // Use the pre-configured DATABASE_URL (already properly URL-encoded)
    connectionString = process.env.DATABASE_URL
    logger.info('Database', 'Using DATABASE_URL environment variable', {
      connectionString: connectionString.replace(/:[^:@]*@/, ':***@')
    })
  } else {
    // Build connection string from individual environment variables
    const dbHost = process.env.DB_HOST || 'postgres'
    const dbPort = process.env.DB_PORT || '5432'
    const dbName = process.env.DB_NAME || 'business_scraper'
    const dbUser = process.env.DB_USER || 'postgres'
    const dbPassword = process.env.DB_PASSWORD || 'SecurePassword123'

    // Build the connection string with proper URL encoding for the password
    const encodedPassword = encodeURIComponent(dbPassword)
    connectionString = `postgresql://${dbUser}:${encodedPassword}@${dbHost}:${dbPort}/${dbName}`

    logger.info('Database', 'Built connection string from individual environment variables', {
      connectionString: connectionString.replace(/:[^:@]*@/, ':***@'),
      host: dbHost,
      port: dbPort,
      database: dbName,
      user: dbUser
    })
  }

  // Create configuration using connection string to bypass all SSL complexity
  const dbConfig = {
    connectionString,
    ssl: false, // Explicitly disable SSL as additional safeguard
    connectionTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
    max: 10,
    type: 'postgresql' as const,
  }

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

// Connection health check with enhanced debugging
export async function checkDatabaseConnection(config?: DatabaseConfig): Promise<ConnectionStatus> {
  const lastChecked = new Date()

  try {
    // Always check for PostgreSQL on server-side, regardless of global config
    if (typeof window === 'undefined' && process.env.DB_TYPE === 'postgresql') {
      // Server-side PostgreSQL check using postgres.js
      const { testPostgresConnection } = await import('./postgres-connection')

      // Use DATABASE_URL if available, otherwise build from individual components
      let connectionString: string
      let dbHost: string
      let dbPort: string
      let dbName: string
      let dbUser: string
      let dbPassword: string

      if (process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0) {
        // Use the pre-configured DATABASE_URL (already properly URL-encoded)
        connectionString = process.env.DATABASE_URL

        // Parse DATABASE_URL to extract individual components for logging
        try {
          const url = new URL(connectionString)
          dbHost = url.hostname
          dbPort = url.port || '5432'
          dbName = url.pathname.slice(1) // Remove leading slash
          dbUser = url.username
          dbPassword = url.password || ''
        } catch (error) {
          logger.error('Database Health Check', 'Failed to parse DATABASE_URL', error)
          throw new Error('Invalid DATABASE_URL format')
        }
      } else {
        // Build connection string from individual environment variables
        dbHost = process.env.DB_HOST || 'postgres'
        dbPort = process.env.DB_PORT || '5432'
        dbName = process.env.DB_NAME || 'business_scraper'
        dbUser = process.env.DB_USER || 'postgres'
        dbPassword = process.env.DB_PASSWORD || 'SecurePassword123'

        // Build the connection string with proper URL encoding for the password
        const encodedPassword = encodeURIComponent(dbPassword)
        connectionString = `postgresql://${dbUser}:${encodedPassword}@${dbHost}:${dbPort}/${dbName}`
      }

      const connectionConfig = {
        connectionString, // Use the determined connection string
        host: dbHost,
        port: parseInt(dbPort),
        database: dbName,
        username: dbUser,
        password: dbPassword,
        ssl: false, // Explicitly disable SSL
        max: 10,
        connect_timeout: 30,
      }

      // Enhanced debugging for connection configuration
      logger.info('Database Health Check', 'Testing PostgreSQL connection', {
        config: {
          hasConnectionString: !!connectionConfig.connectionString,
          connectionStringLength: connectionConfig.connectionString?.length || 0,
          connectionStringPreview: connectionConfig.connectionString ? connectionConfig.connectionString.substring(0, 30) + '...' : 'MISSING',
          host: connectionConfig.host,
          port: connectionConfig.port,
          database: connectionConfig.database,
          username: connectionConfig.username,
          ssl: connectionConfig.ssl,
          usingDatabaseUrl: !!(process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0),
        },
        environment: {
          DB_HOST: dbHost,
          DB_PORT: dbPort,
          DB_NAME: dbName,
          DB_USER: dbUser,
          DB_PASSWORD_length: dbPassword.length,
          NODE_ENV: process.env.NODE_ENV,
          DATABASE_URL_available: !!(process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0),
          connectionString: connectionString.replace(/:[^:@]*@/, ':***@'), // Mask password
        },
      })

      const isConnected = await testPostgresConnection(connectionConfig)

      if (isConnected) {
        return {
          connected: true,
          type: 'postgresql',
          lastChecked,
        }
      } else {
        throw new Error('Connection test failed')
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
      const { createPostgresConnection } = await import('./postgres-connection')

      const connectionConfig = {
        host: config.host,
        port: config.port,
        database: config.database,
        username: config.username,
        password: config.password,
        ssl: false, // Explicitly disable SSL
        connect_timeout: Math.floor((config.connectionTimeout || 30000) / 1000),
      }

      const sql = createPostgresConnection(connectionConfig)

      try {
        const result = await sql`
          SELECT version, name, applied_at, checksum
          FROM schema_migrations
          ORDER BY version
        `

        await sql.end()

        return result.map(row => ({
          version: row.version,
          name: row.name,
          applied: true,
          appliedAt: row.applied_at,
          checksum: row.checksum,
        }))
      } catch (error) {
        await sql.end()
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
      },
    ]
  }
}

// Export configuration function for use in other modules
export function getDbConfig() {
  return getDatabaseConfig()
}

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
