/**
 * Centralized configuration management system
 * Handles environment variables, validation, and type-safe configuration
 */

import { logger } from '@/utils/logger'

// Configuration interfaces
export interface DatabaseConfig {
  url?: string
  type: 'postgresql' | 'indexeddb'
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
  enableNetworkSpoofing: boolean
  enableProxyRotation: boolean
  enableIPSpoofing: boolean
  enableMACAddressSpoofing: boolean
  enableFingerprintSpoofing: boolean
  requestDelayMin: number
  requestDelayMax: number
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
    maxMemory?: string
    evictionPolicy?: string
  }
  memory: {
    maxSize: number
    ttl: number
  }
  // Multi-level cache settings
  l1Cache?: {
    maxSize: number
    ttl: number
  }
  l2Cache?: {
    ttl: number
  }
  l3Cache?: {
    ttl: number
  }
  enableCacheWarming?: boolean
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

export interface FileUploadConfig {
  maxFileSize: number
  uploadDir: string
  tempDir: string
  quarantineDir: string
  enableQuarantine: boolean
  enableMalwareScanning: boolean
  enableMagicNumberValidation: boolean
  fileScanTimeout: number
  maxUploadFiles: number
  allowedTypes: string[]
  allowedExtensions: string[]
}

export interface PaymentsConfig {
  stripePublishableKey: string
  stripeSecretKey: string
  stripeWebhookSecret: string
  successUrl: string
  cancelUrl: string
}

export interface EmailConfig {
  smtpHost: string
  smtpPort: number
  smtpSecure: boolean
  smtpUser: string
  smtpPassword: string
  fromAddress: string
  supportEmail: string
  templatePath: string
}

export interface MonitoringConfig {
  enabled: boolean
  healthCheckInterval: number
  metricsRetention: number
  alertThresholds: {
    apiResponseTime: {
      warning: number
      critical: number
    }
    databaseQueryTime: {
      warning: number
      critical: number
    }
    memoryUsage: {
      warning: number
      critical: number
    }
    paymentProcessingTime: {
      warning: number
      critical: number
    }
  }
  notifications: {
    email: boolean
    slack: boolean
    webhook: boolean
  }
  prometheus: {
    enabled: boolean
    endpoint: string
  }
}

export interface AppConfig {
  app: {
    name: string
    version: string
    environment: 'development' | 'production' | 'test'
    debug: boolean
    port: number
    baseUrl: string
  }
  database: DatabaseConfig
  security: SecurityConfig
  scraping: ScrapingConfig
  apiKeys: ApiKeysConfig
  cache: CacheConfig
  logging: LoggingConfig
  features: FeatureFlags
  fileUpload: FileUploadConfig
  payments: PaymentsConfig
  email: EmailConfig
  monitoring: MonitoringConfig
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
  NEXT_PUBLIC_APP_NAME: { type: 'string', default: 'Business Scraper App' },
  NEXT_PUBLIC_APP_VERSION: { type: 'string', default: '3.0.1' },
  NODE_ENV: {
    type: 'string',
    choices: ['development', 'production', 'test'],
    default: 'development',
  },
  NEXT_PUBLIC_DEBUG: { type: 'boolean', default: false },
  PORT: { type: 'port', default: 3000 },

  // Database
  DATABASE_URL: { type: 'url', required: false },
  DB_TYPE: { type: 'string', choices: ['postgresql', 'indexeddb'], default: 'indexeddb' },
  DB_HOST: { type: 'string', default: 'postgres' },
  DB_PORT: { type: 'port', default: 5432 },
  DB_NAME: { type: 'string', default: 'business_scraper_db' },
  DB_USER: { type: 'string', default: 'postgres' },
  DB_PASSWORD: { type: 'string', default: '' },
  DB_POOL_MIN: { type: 'number', min: 1, default: 2 },
  DB_POOL_MAX: { type: 'number', min: 1, default: 10 },
  DB_POOL_IDLE_TIMEOUT: { type: 'number', min: 1000, default: 30000 },
  DB_CONNECTION_TIMEOUT: { type: 'number', min: 1000, default: 5000 },
  DB_SSL: { type: 'boolean', default: false },

  // Security
  ENABLE_AUTH: { type: 'boolean', default: false },
  SESSION_TIMEOUT: { type: 'number', min: 60000, default: 3600000 },
  MAX_LOGIN_ATTEMPTS: { type: 'number', min: 1, max: 20, default: 5 },
  LOCKOUT_DURATION: { type: 'number', min: 60000, default: 900000 },
  RATE_LIMIT_WINDOW: { type: 'number', min: 1000, default: 60000 },
  RATE_LIMIT_MAX: { type: 'number', min: 1, default: 100 },
  SCRAPING_RATE_LIMIT: { type: 'number', min: 1, default: 10 },
  ADMIN_USERNAME: { type: 'string', default: 'admin' },
  ADMIN_PASSWORD: { type: 'string', required: false },
  ADMIN_PASSWORD_HASH: { type: 'string', required: false },
  ADMIN_PASSWORD_SALT: { type: 'string', required: false },

  // Scraping
  SCRAPING_TIMEOUT: { type: 'number', min: 1000, default: 30000 },
  SCRAPING_MAX_RETRIES: { type: 'number', min: 0, max: 10, default: 3 },
  SCRAPING_DELAY_MS: { type: 'number', min: 0, default: 1000 },
  SEARCH_ENGINE_TIMEOUT: { type: 'number', min: 1000, default: 10000 },
  MAX_SEARCH_RESULTS: { type: 'number', min: 1, default: 10000 }, // No upper limit - gather as many as possible

  // Network Spoofing
  ENABLE_NETWORK_SPOOFING: { type: 'boolean', default: true },
  ENABLE_PROXY_ROTATION: { type: 'boolean', default: false }, // Disabled by default to avoid connection issues
  ENABLE_IP_SPOOFING: { type: 'boolean', default: true },
  ENABLE_MAC_ADDRESS_SPOOFING: { type: 'boolean', default: true },
  ENABLE_FINGERPRINT_SPOOFING: { type: 'boolean', default: true },
  REQUEST_DELAY_MIN: { type: 'number', min: 1000, default: 3000 },
  REQUEST_DELAY_MAX: { type: 'number', min: 2000, default: 8000 },

  // API Keys (optional)
  GOOGLE_MAPS_API_KEY: { type: 'string', required: false },
  GOOGLE_SEARCH_API_KEY: { type: 'string', required: false },
  GOOGLE_SEARCH_ENGINE_ID: { type: 'string', required: false },
  OPENCAGE_API_KEY: { type: 'string', required: false },
  BING_SEARCH_API_KEY: { type: 'string', required: false },
  YANDEX_SEARCH_API_KEY: { type: 'string', required: false },

  // Cache
  CACHE_TYPE: { type: 'string', choices: ['memory', 'redis'], default: 'memory' },
  REDIS_HOST: { type: 'string', default: 'localhost' },
  REDIS_PORT: { type: 'port', default: 6379 },
  REDIS_PASSWORD: { type: 'string', required: false },
  REDIS_DB: { type: 'number', min: 0, max: 15, default: 0 },
  REDIS_KEY_PREFIX: { type: 'string', default: 'business_scraper:' },
  REDIS_MAX_MEMORY: { type: 'string', default: '256mb' },
  REDIS_EVICTION_POLICY: { type: 'string', default: 'allkeys-lru' },
  CACHE_MAX_SIZE: { type: 'number', min: 1, default: 2000 },
  CACHE_TTL: { type: 'number', min: 1000, default: 1800000 },

  // Advanced Cache Settings
  CACHE_L1_MAX_SIZE: { type: 'number', min: 1, default: 1000 },
  CACHE_L1_TTL: { type: 'number', min: 1000, default: 1800000 },
  CACHE_L2_TTL: { type: 'number', min: 1000, default: 7200000 },
  CACHE_L3_TTL: { type: 'number', min: 1000, default: 86400000 },
  ENABLE_CACHE_WARMING: { type: 'boolean', default: false },

  // Logging
  LOG_LEVEL: { type: 'string', choices: ['error', 'warn', 'info', 'debug'], default: 'info' },
  LOG_FORMAT: { type: 'string', choices: ['json', 'text'], default: 'text' },
  LOG_ENABLE_CONSOLE: { type: 'boolean', default: true },
  LOG_ENABLE_FILE: { type: 'boolean', default: false },
  LOG_FILE_PATH: { type: 'string', default: './logs/app.log' },
  LOG_MAX_FILE_SIZE: { type: 'number', min: 1024, default: 10485760 }, // 10MB
  LOG_MAX_FILES: { type: 'number', min: 1, default: 5 },

  // Monitoring Configuration
  MONITORING_ENABLED: { type: 'boolean', default: true },
  MONITORING_HEALTH_CHECK_INTERVAL: { type: 'number', min: 5000, default: 30000 }, // 30 seconds
  MONITORING_METRICS_RETENTION: { type: 'number', min: 100, default: 1000 }, // Number of metrics to retain
  MONITORING_API_RESPONSE_WARNING: { type: 'number', min: 100, default: 1000 }, // 1 second
  MONITORING_API_RESPONSE_CRITICAL: { type: 'number', min: 500, default: 3000 }, // 3 seconds
  MONITORING_DB_QUERY_WARNING: { type: 'number', min: 100, default: 500 }, // 500ms
  MONITORING_DB_QUERY_CRITICAL: { type: 'number', min: 500, default: 2000 }, // 2 seconds
  MONITORING_MEMORY_WARNING: { type: 'number', min: 100, default: 524288000 }, // 500MB in bytes
  MONITORING_MEMORY_CRITICAL: { type: 'number', min: 500, default: 1073741824 }, // 1GB in bytes
  MONITORING_PAYMENT_WARNING: { type: 'number', min: 1000, default: 5000 }, // 5 seconds
  MONITORING_PAYMENT_CRITICAL: { type: 'number', min: 5000, default: 10000 }, // 10 seconds
  MONITORING_EMAIL_NOTIFICATIONS: { type: 'boolean', default: false },
  MONITORING_SLACK_NOTIFICATIONS: { type: 'boolean', default: false },
  MONITORING_WEBHOOK_NOTIFICATIONS: { type: 'boolean', default: false },
  MONITORING_PROMETHEUS_ENABLED: { type: 'boolean', default: true },
  MONITORING_PROMETHEUS_ENDPOINT: { type: 'string', default: '/api/metrics' },

  // Feature Flags
  FEATURE_ENABLE_CACHING: { type: 'boolean', default: true },
  FEATURE_ENABLE_RATE_LIMITING: { type: 'boolean', default: true },
  FEATURE_ENABLE_METRICS: { type: 'boolean', default: false },
  FEATURE_ENABLE_EXPERIMENTAL: { type: 'boolean', default: false },

  // File Upload Configuration
  MAX_FILE_SIZE: { type: 'number', min: 1024, default: 10485760 }, // 10MB
  UPLOAD_DIR: { type: 'string', default: './uploads' },
  TEMP_DIR: { type: 'string', default: './temp' },
  QUARANTINE_DIR: { type: 'string', default: './quarantine' },
  ENABLE_FILE_QUARANTINE: { type: 'boolean', default: true },
  ENABLE_MALWARE_SCANNING: { type: 'boolean', default: true },
  ENABLE_MAGIC_NUMBER_VALIDATION: { type: 'boolean', default: true },
  FILE_SCAN_TIMEOUT: { type: 'number', min: 1000, default: 30000 },
  MAX_UPLOAD_FILES: { type: 'number', min: 1, max: 100, default: 10 },

  // Stripe Configuration (conditionally required based on environment)
  STRIPE_PUBLISHABLE_KEY: {
    type: 'string',
    required: false,
    default: 'pk_test_development_placeholder',
  },
  STRIPE_SECRET_KEY: {
    type: 'string',
    required: false,
    default: 'sk_test_development_placeholder',
  },
  STRIPE_WEBHOOK_SECRET: {
    type: 'string',
    required: false,
    default: 'whsec_development_placeholder',
  },
  NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY: {
    type: 'string',
    required: false,
    default: 'pk_test_development_placeholder',
  },
  PAYMENT_SUCCESS_URL: {
    type: 'url',
    required: false,
    default: 'http://localhost:3000/payment/success',
  },
  PAYMENT_CANCEL_URL: {
    type: 'url',
    required: false,
    default: 'http://localhost:3000/payment/cancel',
  },

  // Email Configuration (conditionally required based on environment)
  SMTP_HOST: { type: 'string', required: false, default: 'localhost' },
  SMTP_PORT: { type: 'port', default: 587 },
  SMTP_SECURE: { type: 'boolean', default: false },
  SMTP_USER: { type: 'string', required: false, default: 'dev@example.com' },
  SMTP_PASSWORD: { type: 'string', required: false, default: 'development_password' },
  EMAIL_FROM_ADDRESS: { type: 'email', required: false, default: 'dev@example.com' },
  EMAIL_SUPPORT_ADDRESS: { type: 'email', required: false, default: 'support@example.com' },
  EMAIL_TEMPLATE_PATH: { type: 'string', default: './src/templates/email' },
  NEXT_PUBLIC_APP_BASE_URL: { type: 'url', required: false, default: 'http://localhost:3000' },
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

  // Debug: Log environment loading status
  const isClient = typeof window !== 'undefined'
  const nodeEnv = process.env.NODE_ENV || 'development'

  logger.debug('Config', `Loading configuration - Client: ${isClient}, Environment: ${nodeEnv}`)

  // Debug: Log some key environment variables
  const debugVars = [
    'STRIPE_PUBLISHABLE_KEY',
    'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    'SMTP_HOST',
    'EMAIL_FROM_ADDRESS',
    'NEXT_PUBLIC_APP_BASE_URL',
  ]

  debugVars.forEach(key => {
    const value = process.env[key]
    logger.debug(
      'Config',
      `Environment variable ${key}: ${value ? 'SET' : 'MISSING'} (length: ${value?.length || 0})`
    )
  })

  // Enhanced validation with environment-specific requirements
  const isDevelopment = nodeEnv === 'development'
  const isProduction = nodeEnv === 'production'

  // Define production-only required variables
  const productionRequiredVars = [
    'STRIPE_PUBLISHABLE_KEY',
    'STRIPE_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET',
    'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    'PAYMENT_SUCCESS_URL',
    'PAYMENT_CANCEL_URL',
    'SMTP_HOST',
    'SMTP_USER',
    'SMTP_PASSWORD',
    'EMAIL_FROM_ADDRESS',
    'EMAIL_SUPPORT_ADDRESS',
    'NEXT_PUBLIC_APP_BASE_URL',
  ]

  // Helper function to get safe development defaults
  const getDevDefault = (key: string): string => {
    switch (key) {
      case 'STRIPE_PUBLISHABLE_KEY':
      case 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY':
        return 'pk_test_development_placeholder'
      case 'STRIPE_SECRET_KEY':
        return 'sk_test_development_placeholder'
      case 'STRIPE_WEBHOOK_SECRET':
        return 'whsec_development_placeholder'
      case 'PAYMENT_SUCCESS_URL':
        return 'http://localhost:3000/payment/success'
      case 'PAYMENT_CANCEL_URL':
        return 'http://localhost:3000/payment/cancel'
      case 'SMTP_HOST':
        return 'localhost'
      case 'SMTP_USER':
        return 'dev@example.com'
      case 'SMTP_PASSWORD':
        return 'development_password'
      case 'EMAIL_FROM_ADDRESS':
      case 'EMAIL_SUPPORT_ADDRESS':
        return 'dev@example.com'
      case 'NEXT_PUBLIC_APP_BASE_URL':
        return 'http://localhost:3000'
      default:
        return ''
    }
  }

  // Validate all environment variables
  for (const [key, rule] of Object.entries(configSchema)) {
    try {
      // Safe object property assignment with validation
      if (typeof key === 'string' && key.length > 0 && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        // Modify rule requirements based on environment
        const modifiedRule = { ...rule }

        // In development, make production-required variables optional with defaults
        if (isDevelopment && productionRequiredVars.includes(key)) {
          modifiedRule.required = false
          if (!modifiedRule.default) {
            modifiedRule.default = getDevDefault(key)
          }
        }

        const validatedValue = validateEnvValue(key, process.env[key], modifiedRule)
        Object.defineProperty(config, key, {
          value: validatedValue,
          writable: true,
          enumerable: true,
          configurable: true,
        })

        // Log successful validation in debug mode
        if (isDevelopment && process.env[key] !== validatedValue) {
          logger.debug('Config', `Using default value for ${key}: ${validatedValue}`)
        }
      } else {
        errors.push(`Invalid configuration key: ${key}`)
      }
    } catch (error) {
      if (error instanceof Error) {
        // In development, convert some errors to warnings for non-critical vars
        if (isDevelopment && productionRequiredVars.includes(key)) {
          warnings.push(`Development warning for ${key}: ${error.message}`)
          // Try to use a safe default
          const defaultValue = getDevDefault(key)
          if (defaultValue) {
            config[key] = defaultValue
            logger.debug('Config', `Using fallback default for ${key}: ${defaultValue}`)
          }
        } else {
          errors.push(error.message)
        }
      } else {
        errors.push(`Unknown error validating ${key}`)
      }
    }
  }

  // Check for authentication configuration consistency
  if (config.ENABLE_AUTH) {
    const hasPlainPassword = config.ADMIN_PASSWORD
    const hasHashedPassword = config.ADMIN_PASSWORD_HASH && config.ADMIN_PASSWORD_SALT

    if (!hasPlainPassword && !hasHashedPassword) {
      errors.push(
        'Authentication is enabled but no password is configured (ADMIN_PASSWORD or ADMIN_PASSWORD_HASH/ADMIN_PASSWORD_SALT)'
      )
    }

    if (hasPlainPassword && process.env.NODE_ENV === 'production') {
      warnings.push(
        'Using plain text password in production is not recommended. Use ADMIN_PASSWORD_HASH and ADMIN_PASSWORD_SALT instead.'
      )
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
      baseUrl: config.NEXT_PUBLIC_APP_BASE_URL,
    },
    database: {
      url: config.DATABASE_URL,
      type: config.DB_TYPE,
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
      enableNetworkSpoofing: config.ENABLE_NETWORK_SPOOFING,
      enableProxyRotation: config.ENABLE_PROXY_ROTATION,
      enableIPSpoofing: config.ENABLE_IP_SPOOFING,
      enableMACAddressSpoofing: config.ENABLE_MAC_ADDRESS_SPOOFING,
      enableFingerprintSpoofing: config.ENABLE_FINGERPRINT_SPOOFING,
      requestDelayMin: config.REQUEST_DELAY_MIN,
      requestDelayMax: config.REQUEST_DELAY_MAX,
    },
    apiKeys: {
      googleMaps: config.GOOGLE_MAPS_API_KEY,
      googleSearch: config.GOOGLE_SEARCH_API_KEY,
      googleSearchEngineId: config.GOOGLE_SEARCH_ENGINE_ID,
      openCage: config.OPENCAGE_API_KEY,
      bingSearch: config.BING_SEARCH_API_KEY,
      yandexSearch: config.YANDEX_SEARCH_API_KEY,
    },
    cache: {
      type: config.CACHE_TYPE,
      redis:
        config.CACHE_TYPE === 'redis'
          ? {
              host: config.REDIS_HOST,
              port: config.REDIS_PORT,
              password: config.REDIS_PASSWORD,
              db: config.REDIS_DB,
              keyPrefix: config.REDIS_KEY_PREFIX,
              maxMemory: config.REDIS_MAX_MEMORY,
              evictionPolicy: config.REDIS_EVICTION_POLICY,
            }
          : undefined,
      memory: {
        maxSize: config.CACHE_MAX_SIZE,
        ttl: config.CACHE_TTL,
      },
      l1Cache: {
        maxSize: config.CACHE_L1_MAX_SIZE,
        ttl: config.CACHE_L1_TTL,
      },
      l2Cache: {
        ttl: config.CACHE_L2_TTL,
      },
      l3Cache: {
        ttl: config.CACHE_L3_TTL,
      },
      enableCacheWarming: config.ENABLE_CACHE_WARMING,
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
    fileUpload: {
      maxFileSize: config.MAX_FILE_SIZE,
      uploadDir: config.UPLOAD_DIR,
      tempDir: config.TEMP_DIR,
      quarantineDir: config.QUARANTINE_DIR,
      enableQuarantine: config.ENABLE_FILE_QUARANTINE,
      enableMalwareScanning: config.ENABLE_MALWARE_SCANNING,
      enableMagicNumberValidation: config.ENABLE_MAGIC_NUMBER_VALIDATION,
      fileScanTimeout: config.FILE_SCAN_TIMEOUT,
      maxUploadFiles: config.MAX_UPLOAD_FILES,
      allowedTypes: [
        'image/jpeg',
        'image/png',
        'image/gif',
        'text/plain',
        'application/pdf',
        'application/json',
        'text/csv',
        'application/vnd.ms-excel',
      ],
      allowedExtensions: [
        '.jpg',
        '.jpeg',
        '.png',
        '.gif',
        '.txt',
        '.pdf',
        '.json',
        '.csv',
        '.xlsx',
      ],
    },
    payments: {
      stripePublishableKey: config.STRIPE_PUBLISHABLE_KEY,
      stripeSecretKey: config.STRIPE_SECRET_KEY,
      stripeWebhookSecret: config.STRIPE_WEBHOOK_SECRET,
      successUrl: config.PAYMENT_SUCCESS_URL,
      cancelUrl: config.PAYMENT_CANCEL_URL,
    },
    email: {
      smtpHost: config.SMTP_HOST,
      smtpPort: config.SMTP_PORT,
      smtpSecure: config.SMTP_SECURE,
      smtpUser: config.SMTP_USER,
      smtpPassword: config.SMTP_PASSWORD,
      fromAddress: config.EMAIL_FROM_ADDRESS,
      supportEmail: config.EMAIL_SUPPORT_ADDRESS,
      templatePath: config.EMAIL_TEMPLATE_PATH,
    },
    monitoring: {
      enabled: config.MONITORING_ENABLED,
      healthCheckInterval: config.MONITORING_HEALTH_CHECK_INTERVAL,
      metricsRetention: config.MONITORING_METRICS_RETENTION,
      alertThresholds: {
        apiResponseTime: {
          warning: config.MONITORING_API_RESPONSE_WARNING,
          critical: config.MONITORING_API_RESPONSE_CRITICAL,
        },
        databaseQueryTime: {
          warning: config.MONITORING_DB_QUERY_WARNING,
          critical: config.MONITORING_DB_QUERY_CRITICAL,
        },
        memoryUsage: {
          warning: config.MONITORING_MEMORY_WARNING,
          critical: config.MONITORING_MEMORY_CRITICAL,
        },
        paymentProcessingTime: {
          warning: config.MONITORING_PAYMENT_WARNING,
          critical: config.MONITORING_PAYMENT_CRITICAL,
        },
      },
      notifications: {
        email: config.MONITORING_EMAIL_NOTIFICATIONS,
        slack: config.MONITORING_SLACK_NOTIFICATIONS,
        webhook: config.MONITORING_WEBHOOK_NOTIFICATIONS,
      },
      prometheus: {
        enabled: config.MONITORING_PROMETHEUS_ENABLED,
        endpoint: config.MONITORING_PROMETHEUS_ENDPOINT,
      },
    },
  }

  logger.info(
    'Config',
    `Configuration loaded successfully for ${appConfig.app.environment} environment`
  )

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

export function getPaymentsConfig(): PaymentsConfig {
  return getConfig().payments
}
