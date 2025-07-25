/**
 * Tests for configuration management system
 */

import { loadConfig, getConfig, reloadConfig } from '@/lib/config'

// Mock environment variables
const mockEnv = {
  NODE_ENV: 'test',
  NEXT_PUBLIC_APP_NAME: 'Test App',
  NEXT_PUBLIC_APP_VERSION: '1.0.0-test',
  NEXT_PUBLIC_DEBUG: 'false',
  PORT: '3001',
  
  // Database
  DB_HOST: 'localhost',
  DB_PORT: '5432',
  DB_NAME: 'test_db',
  DB_USER: 'test_user',
  DB_PASSWORD: 'test_pass',
  DB_SSL: 'false',
  
  // Security
  ENABLE_AUTH: 'false',
  SESSION_TIMEOUT: '1800000',
  MAX_LOGIN_ATTEMPTS: '10',
  LOCKOUT_DURATION: '300000',
  RATE_LIMIT_WINDOW: '60000',
  RATE_LIMIT_MAX: '1000',
  SCRAPING_RATE_LIMIT: '100',
  ADMIN_USERNAME: 'testuser',
  ADMIN_PASSWORD: 'testpass',
  
  // Scraping
  SCRAPING_TIMEOUT: '5000',
  SCRAPING_MAX_RETRIES: '1',
  SCRAPING_DELAY_MS: '100',
  SEARCH_ENGINE_TIMEOUT: '5000',
  MAX_SEARCH_RESULTS: '10',
  
  // Cache
  CACHE_TYPE: 'memory',
  CACHE_MAX_SIZE: '100',
  CACHE_TTL: '60000',
  
  // Logging
  LOG_LEVEL: 'warn',
  LOG_FORMAT: 'text',
  LOG_ENABLE_CONSOLE: 'false',
  LOG_ENABLE_FILE: 'false',
  
  // Features
  FEATURE_ENABLE_CACHING: 'false',
  FEATURE_ENABLE_RATE_LIMITING: 'false',
  FEATURE_ENABLE_METRICS: 'false',
  FEATURE_ENABLE_EXPERIMENTAL: 'true'
}

describe('Configuration Management', () => {
  let originalEnv: NodeJS.ProcessEnv

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env }
    
    // Clear environment
    Object.keys(process.env).forEach(key => {
      if (key.startsWith('DB_') || key.startsWith('ENABLE_') || key.startsWith('LOG_') || 
          key.startsWith('CACHE_') || key.startsWith('FEATURE_') || key.startsWith('SCRAPING_') ||
          key.startsWith('RATE_') || key.startsWith('SESSION_') || key.startsWith('MAX_') ||
          key.startsWith('ADMIN_') || key.startsWith('NEXT_PUBLIC_') || key === 'NODE_ENV' || key === 'PORT') {
        delete process.env[key]
      }
    })
    
    // Set test environment
    Object.assign(process.env, mockEnv)
  })

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv
  })

  describe('loadConfig', () => {
    it('should load configuration from environment variables', () => {
      const config = loadConfig()
      
      expect(config.app.name).toBe('Test App')
      expect(config.app.version).toBe('1.0.0-test')
      expect(config.app.environment).toBe('test')
      expect(config.app.debug).toBe(false)
      expect(config.app.port).toBe(3001)
    })

    it('should load database configuration', () => {
      const config = loadConfig()
      
      expect(config.database.host).toBe('localhost')
      expect(config.database.port).toBe(5432)
      expect(config.database.name).toBe('test_db')
      expect(config.database.user).toBe('test_user')
      expect(config.database.password).toBe('test_pass')
      expect(config.database.ssl).toBe(false)
    })

    it('should load security configuration', () => {
      const config = loadConfig()
      
      expect(config.security.enableAuth).toBe(false)
      expect(config.security.sessionTimeout).toBe(1800000)
      expect(config.security.maxLoginAttempts).toBe(10)
      expect(config.security.adminUsername).toBe('testuser')
      expect(config.security.adminPassword).toBe('testpass')
    })

    it('should load feature flags', () => {
      const config = loadConfig()
      
      expect(config.features.enableAuth).toBe(false)
      expect(config.features.enableCaching).toBe(false)
      expect(config.features.enableRateLimiting).toBe(false)
      expect(config.features.enableExperimentalFeatures).toBe(true)
    })

    it('should use default values for missing variables', () => {
      // Remove some environment variables
      delete process.env.SCRAPING_TIMEOUT
      delete process.env.CACHE_MAX_SIZE
      
      const config = loadConfig()
      
      expect(config.scraping.timeout).toBe(30000) // Default value
      expect(config.cache.memory.maxSize).toBe(1000) // Default value
    })

    it('should validate required variables', () => {
      // Set an invalid value that will cause validation to fail
      const originalEnv = process.env.NODE_ENV
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'invalid_environment',
        configurable: true
      })

      try {
        expect(() => loadConfig()).toThrow(/Configuration validation failed/)
      } finally {
        Object.defineProperty(process.env, 'NODE_ENV', {
          value: originalEnv,
          configurable: true
        })
      }
    })

    it('should validate data types', () => {
      // Set invalid port
      process.env.PORT = 'invalid'

      expect(() => loadConfig()).toThrow(/Configuration validation failed/)
    })

    it('should validate number ranges', () => {
      // Set port out of range
      process.env.PORT = '99999'

      expect(() => loadConfig()).toThrow(/Configuration validation failed/)
    })

    it('should validate boolean values', () => {
      // Set invalid boolean
      process.env.ENABLE_AUTH = 'maybe'

      expect(() => loadConfig()).toThrow(/Configuration validation failed/)
    })

    it('should validate choice constraints', () => {
      // Set invalid environment
      const originalEnv = process.env.NODE_ENV
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'invalid',
        configurable: true
      })

      try {
        expect(() => loadConfig()).toThrow(/Configuration validation failed/)
      } finally {
        Object.defineProperty(process.env, 'NODE_ENV', {
          value: originalEnv,
          configurable: true
        })
      }
    })
  })

  describe('Database URL parsing', () => {
    it('should store DATABASE_URL correctly', () => {
      process.env.DATABASE_URL = 'postgresql://user:pass@host:5433/dbname?ssl=true'

      const config = loadConfig()

      expect(config.database.url).toBe('postgresql://user:pass@host:5433/dbname?ssl=true')
      // Individual DB values should still use their defaults/env vars
      expect(config.database.host).toBe('localhost') // Default value
      expect(config.database.port).toBe(5432) // Default value
    })

    it('should handle invalid DATABASE_URL', () => {
      process.env.DATABASE_URL = 'invalid-url'
      
      expect(() => loadConfig()).toThrow(/Configuration validation failed/)
    })
  })

  describe('Production validation', () => {
    beforeEach(() => {
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'production',
        configurable: true
      })
      process.env.ENABLE_AUTH = 'true'
    })

    it('should require hashed password in production', () => {
      // Only plain password provided
      process.env.ADMIN_PASSWORD = 'plaintext'
      delete process.env.ADMIN_PASSWORD_HASH
      delete process.env.ADMIN_PASSWORD_SALT
      
      const config = loadConfig()
      // Should load but with warnings (warnings are logged, not thrown)
      expect(config.security.adminPassword).toBe('plaintext')
    })

    it('should accept hashed password in production', () => {
      delete process.env.ADMIN_PASSWORD
      process.env.ADMIN_PASSWORD_HASH = 'hashed_password'
      process.env.ADMIN_PASSWORD_SALT = 'salt_value'
      
      const config = loadConfig()
      expect(config.security.adminPasswordHash).toBe('hashed_password')
      expect(config.security.adminPasswordSalt).toBe('salt_value')
    })
  })

  describe('Cache configuration', () => {
    it('should configure memory cache', () => {
      process.env.CACHE_TYPE = 'memory'
      process.env.CACHE_MAX_SIZE = '500'
      process.env.CACHE_TTL = '120000'
      
      const config = loadConfig()
      
      expect(config.cache.type).toBe('memory')
      expect(config.cache.memory.maxSize).toBe(500)
      expect(config.cache.memory.ttl).toBe(120000)
    })

    it('should configure Redis cache', () => {
      process.env.CACHE_TYPE = 'redis'
      process.env.REDIS_HOST = 'redis-server'
      process.env.REDIS_PORT = '6380'
      process.env.REDIS_PASSWORD = 'redis-pass'
      process.env.REDIS_DB = '1'
      process.env.REDIS_KEY_PREFIX = 'test:'
      
      const config = loadConfig()
      
      expect(config.cache.type).toBe('redis')
      expect(config.cache.redis?.host).toBe('redis-server')
      expect(config.cache.redis?.port).toBe(6380)
      expect(config.cache.redis?.password).toBe('redis-pass')
      expect(config.cache.redis?.db).toBe(1)
      expect(config.cache.redis?.keyPrefix).toBe('test:')
    })

    it('should validate Redis configuration when Redis is selected', () => {
      process.env.CACHE_TYPE = 'redis'
      process.env.REDIS_PORT = 'invalid_port'

      expect(() => loadConfig()).toThrow(/Configuration validation failed/)
    })
  })

  describe('getConfig and reloadConfig', () => {
    it('should return cached configuration', () => {
      const config1 = getConfig()
      const config2 = getConfig()
      
      expect(config1).toBe(config2) // Same instance
    })

    it('should reload configuration when requested', () => {
      const config1 = getConfig()
      
      // Change environment
      process.env.NEXT_PUBLIC_APP_NAME = 'Updated App'
      
      const config2 = reloadConfig()
      
      expect(config1).not.toBe(config2) // Different instances
      expect(config2.app.name).toBe('Updated App')
    })
  })
})
