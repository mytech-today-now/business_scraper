/**
 * Centralized configuration management system
 * Handles environment variables, validation, and type-safe configuration
 */

import { logger } from '@/utils/logger'

// Configuration interfaces
export interface DatabaseConfig {
  url?: string
  host: string
  port: number
  name: string
  user: string
  password: string
  poolMin: number
  poolMax: number
  idleTimeout: number
  connectionTimeout: number
  ssl: boolean
}

export interface SecurityConfig {
  enableAuth: boolean
  sessionTimeout: number
  maxLoginAttempts: number
  lockoutDuration: number
  rateLimitWindow: number
  rateLimitMax: number
  scrapingRateLimit: number
  adminUsername: string
  adminPassword?: string
  adminPasswordHash?: string
  adminPasswordSalt?: string
}

export interface ScrapingConfig {
  timeout: number
  maxRetries: number
  delayMs: number
  searchEngineTimeout: number
  maxSearchResults: number
}

export interface ApiKeysConfig {
  googleMaps?: string
  googleSearch?: string
  googleSearchEngineId?: string
  openCage?: string
  bingSearch?: string
  yandexSearch?: string
}

export interface CacheConfig {
  type: 'memory' | 'redis'
  redis?: {
    host: string
    port: number
    password?: string
    db: number
    keyPrefix: string
  }
  memory: {
    maxSize: number
    ttl: number
  }
}

export interface LoggingConfig {
  level: 'error' | 'warn' | 'info' | 'debug'
  format: 'json' | 'text'
  enableConsole: boolean
  enableFile: boolean
  filePath?: string
  maxFileSize: number
  maxFiles: number
}

export interface FeatureFlags {
  enableAuth: boolean
  enableCaching: boolean
  enableRateLimiting: boolean
  enableMetrics: boolean
  enableDebugMode: boolean
  enableExperimentalFeatures: boolean
}

export interface AppConfig {
  app: {
    name: string
    version: string
    environment: 'development' | 'production' | 'test'
    debug: boolean
    port: number
  }
  database: DatabaseConfig
  security: SecurityConfig
  scraping: ScrapingConfig
  apiKeys: ApiKeysConfig
  cache: CacheConfig
  logging: LoggingConfig
  features: FeatureFlags
}

// Environment variable validation rules
interface ValidationRule {
  required?: boolean
  type: 'string' | 'number' | 'boolean' | 'url' | 'email' | 'port'
  min?: number
  max?: number
  pattern?: RegExp
  choices?: string[]
  default?: any
}

const configSchema: Record<string, ValidationRule> = {
  // Application
  'NEXT_PUBLIC_APP_NAME': { type: 'string', default: 'Business Scraper App' },
  'NEXT_PUBLIC_APP_VERSION': { type: 'string', default: '1.0.0' },
  'NODE_ENV': { type: 'string', choices: ['development', 'production', 'test'], default: 'development' },
  'NEXT_PUBLIC_DEBUG': { type: 'boolean', default: false },
  'PORT': { type: 'port', default: 3000 },

  // Database
  'DATABASE_URL': { type: 'url', required: false },
  'DB_HOST': { type: 'string', default: 'localhost' },
  'DB_PORT': { type: 'port', default: 5432 },
  'DB_NAME': { type: 'string', default: 'business_scraper_db' },
  'DB_USER': { type: 'string', default: 'postgres' },
  'DB_PASSWORD': { type: 'string', default: '' },
  'DB_POOL_MIN': { type: 'number', min: 1, default: 2 },
  'DB_POOL_MAX': { type: 'number', min: 1, default: 10 },
  'DB_POOL_IDLE_TIMEOUT': { type: 'number', min: 1000, default: 30000 },
  'DB_CONNECTION_TIMEOUT': { type: 'number', min: 1000, default: 5000 },
  'DB_SSL': { type: 'boolean', default: false },

  // Security
  'ENABLE_AUTH': { type: 'boolean', default: false },
  'SESSION_TIMEOUT': { type: 'number', min: 60000, default: 3600000 },
  'MAX_LOGIN_ATTEMPTS': { type: 'number', min: 1, max: 20, default: 5 },
  'LOCKOUT_DURATION': { type: 'number', min: 60000, default: 900000 },
  'RATE_LIMIT_WINDOW': { type: 'number', min: 1000, default: 60000 },
  'RATE_LIMIT_MAX': { type: 'number', min: 1, default: 100 },
  'SCRAPING_RATE_LIMIT': { type: 'number', min: 1, default: 10 },
  'ADMIN_USERNAME': { type: 'string', default: 'admin' },
  'ADMIN_PASSWORD': { type: 'string', required: false },
  'ADMIN_PASSWORD_HASH': { type: 'string', required: false },
  'ADMIN_PASSWORD_SALT': { type: 'string', required: false },

  // Scraping
  'SCRAPING_TIMEOUT': { type: 'number', min: 1000, default: 30000 },
  'SCRAPING_MAX_RETRIES': { type: 'number', min: 0, max: 10, default: 3 },
  'SCRAPING_DELAY_MS': { type: 'number', min: 0, default: 1000 },
  'SEARCH_ENGINE_TIMEOUT': { type: 'number', min: 1000, default: 10000 },
  'MAX_SEARCH_RESULTS': { type: 'number', min: 1, max: 1000, default: 50 },

  // API Keys (optional)
  'GOOGLE_MAPS_API_KEY': { type: 'string', required: false },
  'GOOGLE_SEARCH_API_KEY': { type: 'string', required: false },
  'GOOGLE_SEARCH_ENGINE_ID': { type: 'string', required: false },
  'OPENCAGE_API_KEY': { type: 'string', required: false },
  'BING_SEARCH_API_KEY': { type: 'string', required: false },
  'YANDEX_SEARCH_API_KEY': { type: 'string', required: false },

  // Cache
  'CACHE_TYPE': { type: 'string', choices: ['memory', 'redis'], default: 'memory' },
  'REDIS_HOST': { type: 'string', default: 'localhost' },
  'REDIS_PORT': { type: 'port', default: 6379 },
  'REDIS_PASSWORD': { type: 'string', required: false },
  'REDIS_DB': { type: 'number', min: 0, max: 15, default: 0 },
  'REDIS_KEY_PREFIX': { type: 'string', default: 'business_scraper:' },
  'CACHE_MAX_SIZE': { type: 'number', min: 1, default: 1000 },
  'CACHE_TTL': { type: 'number', min: 1000, default: 3600000 },

  // Logging
  'LOG_LEVEL': { type: 'string', choices: ['error', 'warn', 'info', 'debug'], default: 'info' },
  'LOG_FORMAT': { type: 'string', choices: ['json', 'text'], default: 'text' },
  'LOG_ENABLE_CONSOLE': { type: 'boolean', default: true },
  'LOG_ENABLE_FILE': { type: 'boolean', default: false },
  'LOG_FILE_PATH': { type: 'string', default: './logs/app.log' },
  'LOG_MAX_FILE_SIZE': { type: 'number', min: 1024, default: 10485760 }, // 10MB
  'LOG_MAX_FILES': { type: 'number', min: 1, default: 5 },

  // Feature Flags
  'FEATURE_ENABLE_CACHING': { type: 'boolean', default: true },
  'FEATURE_ENABLE_RATE_LIMITING': { type: 'boolean', default: true },
  'FEATURE_ENABLE_METRICS': { type: 'boolean', default: false },
  'FEATURE_ENABLE_EXPERIMENTAL': { type: 'boolean', default: false },
}

/**
 * Validate and parse environment variable value
 */
function validateEnvValue(key: string, value: string | undefined, rule: ValidationRule): any {
  // Handle missing values
  if (value === undefined || value === '') {
    if (rule.required) {
      throw new Error(`Required environment variable ${key} is missing`)
    }
    return rule.default
  }

  // Type validation and conversion
  switch (rule.type) {
    case 'string':
      if (rule.choices && !rule.choices.includes(value)) {
        throw new Error(`Environment variable ${key} must be one of: ${rule.choices.join(', ')}`)
      }
      if (rule.pattern && !rule.pattern.test(value)) {
        throw new Error(`Environment variable ${key} does not match required pattern`)
      }
      return value

    case 'number':
      const num = parseFloat(value)
      if (isNaN(num)) {
        throw new Error(`Environment variable ${key} must be a valid number`)
      }
      if (rule.min !== undefined && num < rule.min) {
        throw new Error(`Environment variable ${key} must be at least ${rule.min}`)
      }
      if (rule.max !== undefined && num > rule.max) {
        throw new Error(`Environment variable ${key} must be at most ${rule.max}`)
      }
      return num

    case 'boolean':
      const lower = value.toLowerCase()
      if (['true', '1', 'yes', 'on'].includes(lower)) return true
      if (['false', '0', 'no', 'off'].includes(lower)) return false
      throw new Error(`Environment variable ${key} must be a boolean value (true/false)`)

    case 'port':
      const port = parseInt(value)
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error(`Environment variable ${key} must be a valid port number (1-65535)`)
      }
      return port

    case 'url':
      try {
        new URL(value)
        return value
      } catch {
        throw new Error(`Environment variable ${key} must be a valid URL`)
      }

    case 'email':
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailPattern.test(value)) {
        throw new Error(`Environment variable ${key} must be a valid email address`)
      }
      return value

    default:
      return value
  }
}

/**
 * Load and validate configuration from environment variables
 */
export function loadConfig(): AppConfig {
  const errors: string[] = []
  const warnings: string[] = []
  const config: any = {}

  // Validate all environment variables
  for (const [key, rule] of Object.entries(configSchema)) {
    try {
      config[key] = validateEnvValue(key, process.env[key], rule)
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error))
    }
  }

  // Check for authentication configuration consistency
  if (config.ENABLE_AUTH) {
    const hasPlainPassword = config.ADMIN_PASSWORD
    const hasHashedPassword = config.ADMIN_PASSWORD_HASH && config.ADMIN_PASSWORD_SALT

    if (!hasPlainPassword && !hasHashedPassword) {
      errors.push('Authentication is enabled but no password is configured (ADMIN_PASSWORD or ADMIN_PASSWORD_HASH/ADMIN_PASSWORD_SALT)')
    }

    if (hasPlainPassword && process.env.NODE_ENV === 'production') {
      warnings.push('Using plain text password in production is not recommended. Use ADMIN_PASSWORD_HASH and ADMIN_PASSWORD_SALT instead.')
    }
  }

  // Check for Redis configuration if cache type is redis
  if (config.CACHE_TYPE === 'redis') {
    if (!config.REDIS_HOST) {
      errors.push('Redis cache is enabled but REDIS_HOST is not configured')
    }
  }

  // Report validation results
  if (warnings.length > 0) {
    warnings.forEach(warning => logger.warn('Config', warning))
  }

  if (errors.length > 0) {
    logger.error('Config', 'Configuration validation failed:', errors)
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`)
  }

  // Build structured configuration object
  const appConfig: AppConfig = {
    app: {
      name: config.NEXT_PUBLIC_APP_NAME,
      version: config.NEXT_PUBLIC_APP_VERSION,
      environment: config.NODE_ENV,
      debug: config.NEXT_PUBLIC_DEBUG,
      port: config.PORT,
    },
    database: {
      url: config.DATABASE_URL,
      host: config.DB_HOST,
      port: config.DB_PORT,
      name: config.DB_NAME,
      user: config.DB_USER,
      password: config.DB_PASSWORD,
      poolMin: config.DB_POOL_MIN,
      poolMax: config.DB_POOL_MAX,
      idleTimeout: config.DB_POOL_IDLE_TIMEOUT,
      connectionTimeout: config.DB_CONNECTION_TIMEOUT,
      ssl: config.DB_SSL,
    },
    security: {
      enableAuth: config.ENABLE_AUTH,
      sessionTimeout: config.SESSION_TIMEOUT,
      maxLoginAttempts: config.MAX_LOGIN_ATTEMPTS,
      lockoutDuration: config.LOCKOUT_DURATION,
      rateLimitWindow: config.RATE_LIMIT_WINDOW,
      rateLimitMax: config.RATE_LIMIT_MAX,
      scrapingRateLimit: config.SCRAPING_RATE_LIMIT,
      adminUsername: config.ADMIN_USERNAME,
      adminPassword: config.ADMIN_PASSWORD,
      adminPasswordHash: config.ADMIN_PASSWORD_HASH,
      adminPasswordSalt: config.ADMIN_PASSWORD_SALT,
    },
    scraping: {
      timeout: config.SCRAPING_TIMEOUT,
      maxRetries: config.SCRAPING_MAX_RETRIES,
      delayMs: config.SCRAPING_DELAY_MS,
      searchEngineTimeout: config.SEARCH_ENGINE_TIMEOUT,
      maxSearchResults: config.MAX_SEARCH_RESULTS,
    },
    apiKeys: {
      googleMaps: config.GOOGLE_MAPS_API_KEY,
      openCage: config.OPENCAGE_API_KEY,
      bingSearch: config.BING_SEARCH_API_KEY,
      yandexSearch: config.YANDEX_SEARCH_API_KEY,
    },
    cache: {
      type: config.CACHE_TYPE,
      redis: config.CACHE_TYPE === 'redis' ? {
        host: config.REDIS_HOST,
        port: config.REDIS_PORT,
        password: config.REDIS_PASSWORD,
        db: config.REDIS_DB,
        keyPrefix: config.REDIS_KEY_PREFIX,
      } : undefined,
      memory: {
        maxSize: config.CACHE_MAX_SIZE,
        ttl: config.CACHE_TTL,
      },
    },
    logging: {
      level: config.LOG_LEVEL,
      format: config.LOG_FORMAT,
      enableConsole: config.LOG_ENABLE_CONSOLE,
      enableFile: config.LOG_ENABLE_FILE,
      filePath: config.LOG_FILE_PATH,
      maxFileSize: config.LOG_MAX_FILE_SIZE,
      maxFiles: config.LOG_MAX_FILES,
    },
    features: {
      enableAuth: config.ENABLE_AUTH,
      enableCaching: config.FEATURE_ENABLE_CACHING,
      enableRateLimiting: config.FEATURE_ENABLE_RATE_LIMITING,
      enableMetrics: config.FEATURE_ENABLE_METRICS,
      enableDebugMode: config.NEXT_PUBLIC_DEBUG,
      enableExperimentalFeatures: config.FEATURE_ENABLE_EXPERIMENTAL,
    },
  }

  logger.info('Config', `Configuration loaded successfully for ${appConfig.app.environment} environment`)
  
  if (appConfig.app.debug) {
    logger.debug('Config', 'Configuration details:', {
      app: appConfig.app,
      features: appConfig.features,
      // Don't log sensitive information
    })
  }

  return appConfig
}

// Global configuration instance
let globalConfig: AppConfig | null = null

/**
 * Get the global configuration instance
 */
export function getConfig(): AppConfig {
  if (!globalConfig) {
    globalConfig = loadConfig()
  }
  return globalConfig
}

/**
 * Reload configuration (useful for testing or dynamic config updates)
 */
export function reloadConfig(): AppConfig {
  globalConfig = loadConfig()
  return globalConfig
}

/**
 * Get configuration for a specific section
 */
export function getDatabaseConfig(): DatabaseConfig {
  return getConfig().database
}

export function getSecurityConfig(): SecurityConfig {
  return getConfig().security
}

export function getScrapingConfig(): ScrapingConfig {
  return getConfig().scraping
}

export function getApiKeysConfig(): ApiKeysConfig {
  return getConfig().apiKeys
}

export function getCacheConfig(): CacheConfig {
  return getConfig().cache
}

export function getLoggingConfig(): LoggingConfig {
  return getConfig().logging
}

export function getFeatureFlags(): FeatureFlags {
  return getConfig().features
}
