/**
 * Tests for configuration validator
 */

import {
  validateConfiguration,
  performConfigHealthCheck,
  generateConfigReport,
} from '@/lib/config-validator'
import { jest } from '@jest/globals'
import { mockConfigData } from '../fixtures/testData'
import { setupTest, cleanupTest } from '../setup/testSetup'

// Use safe mock configuration from fixtures
const mockConfig = mockConfigData

// Mock the config module properly
const mockGetConfig = jest.fn(() => mockConfig)
jest.mock('@/lib/config', () => ({
  getConfig: mockGetConfig,
}))

// Additional mock config for testing variations
const testMockConfig = {
  app: {
    name: 'Test App',
    version: '1.0.0',
    environment: 'test',
    debug: false,
    port: 3000,
  },
  database: {
    host: 'localhost',
    port: 5432,
    name: 'test_db',
    user: 'test_user',
    password: 'test_pass',
    poolMin: 2,
    poolMax: 10,
    idleTimeout: 30000,
    connectionTimeout: 5000,
    ssl: false,
  },
  security: {
    enableAuth: false,
    sessionTimeout: 3600000,
    maxLoginAttempts: 5,
    lockoutDuration: 900000,
    rateLimitWindow: 60000,
    rateLimitMax: 100,
    scrapingRateLimit: 10,
    adminUsername: 'admin',
    adminPassword: 'test123',
  },
  scraping: {
    timeout: 30000,
    maxRetries: 3,
    delayMs: 1000,
    searchEngineTimeout: 10000,
    maxSearchResults: 50,
  },
  apiKeys: {
    googleMaps: undefined,
    openCage: undefined,
    bingSearch: undefined,
    yandexSearch: undefined,
  },
  cache: {
    type: 'memory',
    memory: {
      maxSize: 1000,
      ttl: 3600000,
    },
  },
  logging: {
    level: 'info',
    format: 'text',
    enableConsole: true,
    enableFile: false,
    filePath: './logs/app.log',
    maxFileSize: 10485760,
    maxFiles: 5,
  },
  features: {
    enableAuth: false,
    enableCaching: true,
    enableRateLimiting: true,
    enableMetrics: false,
    enableDebugMode: false,
    enableExperimentalFeatures: false,
  },
}

describe('Configuration Validator', () => {
  beforeEach(() => {
    setupTest()
    // Reset mock to default config
    mockGetConfig.mockReturnValue(mockConfig)
  })

  afterEach(() => {
    cleanupTest()
  })

  describe('validateConfiguration', () => {
    it('should pass validation for valid configuration', () => {
      const result = validateConfiguration()

      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should detect empty app name', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, name: '' },
      })

      const result = validateConfiguration()

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Application name cannot be empty')
    })

    it('should warn about debug mode in production', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, environment: 'production', debug: true },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain('Debug mode is enabled in production environment')
    })

    it('should validate database pool configuration', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        database: { ...mockConfig.database, poolMin: 10, poolMax: 5 },
      })

      const result = validateConfiguration()

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain(
        'Database pool minimum size cannot be greater than maximum size'
      )
    })

    it('should warn about high database pool size', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        database: { ...mockConfig.database, poolMax: 100 },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Database pool maximum size is very high, consider reducing for better resource management'
      )
    })

    it('should warn about SSL disabled in production', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, environment: 'production' },
        database: { ...mockConfig.database, ssl: false },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain('SSL is not enabled for database connection in production')
    })

    it('should validate authentication configuration', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        security: {
          ...mockConfig.security,
          enableAuth: true,
          adminPassword: undefined,
          adminPasswordHash: undefined,
          adminPasswordSalt: undefined,
        },
      })

      const result = validateConfiguration()

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Authentication is enabled but no password is configured')
    })

    it('should warn about plain text password in production', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, environment: 'production' },
        security: { ...mockConfig.security, enableAuth: true, adminPassword: 'plaintext' },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Plain text password is used in production, consider using hashed password'
      )
    })

    it('should validate scraping configuration', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        scraping: { ...mockConfig.scraping, timeout: 1000 },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Scraping timeout is very low, may cause premature timeouts'
      )
    })

    it('should warn about high scraping rate limit', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        security: { ...mockConfig.security, scrapingRateLimit: 200 },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Scraping rate limit is high, may cause issues with target websites'
      )
    })

    it('should recommend API key configuration', () => {
      const result = validateConfiguration()

      expect(result.recommendations).toContain(
        'No API keys configured, some features may have limited functionality'
      )
    })

    it('should detect placeholder API keys', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        apiKeys: { ...mockConfig.apiKeys, googleMaps: 'your_api_key_here' },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain('googleMaps API key appears to be a placeholder value')
    })

    it('should validate cache configuration', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        cache: {
          type: 'redis',
          redis: undefined,
          memory: mockConfig.cache.memory,
        },
      })

      const result = validateConfiguration()

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Redis cache is enabled but Redis configuration is missing')
    })

    it('should validate logging configuration', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        logging: {
          ...mockConfig.logging,
          enableConsole: false,
          enableFile: false,
        },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Both console and file logging are disabled, no logs will be output'
      )
    })

    it('should warn about debug logging in production', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, environment: 'production' },
        logging: { ...mockConfig.logging, level: 'debug' },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain(
        'Debug logging is enabled in production, may impact performance'
      )
    })

    it('should validate feature flags', () => {
      mockGetConfig.mockReturnValue({
        ...mockConfig,
        app: { ...mockConfig.app, environment: 'production' },
        features: { ...mockConfig.features, enableExperimentalFeatures: true },
      })

      const result = validateConfiguration()

      expect(result.warnings).toContain('Experimental features are enabled in production')
    })

    it('should handle configuration loading errors', () => {
      mockGetConfig.mockImplementation(() => {
        throw new Error('Config loading failed')
      })

      const result = validateConfiguration()

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Configuration loading failed: Config loading failed')
    })
  })

  describe('performConfigHealthCheck', () => {
    it('should perform comprehensive health check', async () => {
      const result = await performConfigHealthCheck()

      expect(result.status).toBeDefined()
      expect(result.checks).toBeDefined()
      expect(result.summary).toBeDefined()
      expect(result.summary.total).toBeGreaterThan(0)
    })

    it('should check configuration validation', async () => {
      const result = await performConfigHealthCheck()

      expect(result.checks.configValidation).toBeDefined()
      expect(result.checks.configValidation?.status).toBe('pass')
    })

    it('should check environment variables', async () => {
      const result = await performConfigHealthCheck()

      expect(result.checks.environmentVariables).toBeDefined()
    })

    it('should check security configuration', async () => {
      const result = await performConfigHealthCheck()

      expect(result.checks.securityConfig).toBeDefined()
    })

    it('should check feature flag consistency', async () => {
      const result = await performConfigHealthCheck()

      expect(result.checks.featureConsistency).toBeDefined()
    })

    it('should handle validation errors', async () => {
      mockGetConfig.mockImplementation(() => {
        throw new Error('Config error')
      })

      const result = await performConfigHealthCheck()

      expect(result.checks.configValidation?.status).toBe('fail')
    })

    it('should calculate correct summary', async () => {
      const result = await performConfigHealthCheck()

      const { passed, warnings, failed, total } = result.summary
      expect(passed + warnings + failed).toBe(total)
    })

    it('should determine overall status correctly', async () => {
      const result = await performConfigHealthCheck()

      if (result.summary.failed > 0) {
        expect(result.status).toBe('error')
      } else if (result.summary.warnings > 0) {
        expect(result.status).toBe('warning')
      } else {
        expect(result.status).toBe('healthy')
      }
    })
  })

  describe('generateConfigReport', () => {
    it('should generate markdown report', () => {
      const report = generateConfigReport()

      expect(report).toContain('# Configuration Report')
      expect(report).toContain('## Validation Results')
      expect(report).toContain('## Feature Status')
      expect(typeof report).toBe('string')
    })

    it('should include validation results', () => {
      const report = generateConfigReport()

      expect(report).toContain('**Status:**')
      expect(report).toContain('**Errors:**')
      expect(report).toContain('**Warnings:**')
    })

    it('should include feature status', () => {
      const report = generateConfigReport()

      expect(report).toContain('**Authentication:**')
      expect(report).toContain('**Caching:**')
      expect(report).toContain('**Rate Limiting:**')
    })

    it('should include environment information', () => {
      const report = generateConfigReport()

      expect(report).toContain('**Environment:** test')
      expect(report).toContain('**Application:** Test App')
    })
  })
})
