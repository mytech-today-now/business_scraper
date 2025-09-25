/**
 * Build-time Guard Tests
 * Tests for build-time database connection protection
 */

import {
  isBuildTime,
  isDatabaseConnectionAllowed,
  guardDatabaseOperation,
  guardDatabaseOperationSync,
  createProtectedDatabaseConnection,
  getBuildTimeConfig,
  logBuildTimeEnvironment
} from '../lib/build-time-guard'

// Mock logger
jest.mock('../utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }
}))

describe('Build-time Guard', () => {
  const originalEnv = process.env

  beforeEach(() => {
    jest.resetAllMocks()
    process.env = { ...originalEnv }
  })

  afterAll(() => {
    process.env = originalEnv
  })

  describe('isBuildTime', () => {
    it('should detect Next.js build phase', () => {
      process.env.NEXT_PHASE = 'phase-production-build'
      expect(isBuildTime()).toBe(true)
    })

    it('should detect explicit build flag', () => {
      process.env.IS_BUILD_TIME = 'true'
      expect(isBuildTime()).toBe(true)
    })

    it('should detect CI build environment', () => {
      process.env.CI = 'true'
      process.env.GITHUB_ACTIONS = 'true'
      expect(isBuildTime()).toBe(true)
    })

    it('should detect webpack build', () => {
      process.env.WEBPACK_BUILD = '1'
      expect(isBuildTime()).toBe(true)
    })

    it('should return false for runtime environment', () => {
      delete process.env.NEXT_PHASE
      delete process.env.IS_BUILD_TIME
      delete process.env.CI
      delete process.env.WEBPACK_BUILD
      expect(isBuildTime()).toBe(false)
    })
  })

  describe('isDatabaseConnectionAllowed', () => {
    it('should disallow database connections during build time', () => {
      process.env.IS_BUILD_TIME = 'true'
      expect(isDatabaseConnectionAllowed()).toBe(false)
    })

    it('should disallow database connections when explicitly disabled', () => {
      process.env.DISABLE_DATABASE = 'true'
      expect(isDatabaseConnectionAllowed()).toBe(false)
    })

    it('should allow database connections in runtime', () => {
      delete process.env.IS_BUILD_TIME
      delete process.env.DISABLE_DATABASE
      expect(isDatabaseConnectionAllowed()).toBe(true)
    })
  })

  describe('guardDatabaseOperation', () => {
    it('should execute operation when database is allowed', async () => {
      delete process.env.IS_BUILD_TIME
      const mockOperation = jest.fn().mockResolvedValue('success')
      
      const result = await guardDatabaseOperation(
        mockOperation,
        'fallback',
        'test operation'
      )

      expect(mockOperation).toHaveBeenCalled()
      expect(result).toBe('success')
    })

    it('should return fallback value during build time', async () => {
      process.env.IS_BUILD_TIME = 'true'
      const mockOperation = jest.fn()
      
      const result = await guardDatabaseOperation(
        mockOperation,
        'fallback',
        'test operation'
      )

      expect(mockOperation).not.toHaveBeenCalled()
      expect(result).toBe('fallback')
    })
  })

  describe('guardDatabaseOperationSync', () => {
    it('should execute sync operation when database is allowed', () => {
      delete process.env.IS_BUILD_TIME
      const mockOperation = jest.fn().mockReturnValue('success')
      
      const result = guardDatabaseOperationSync(
        mockOperation,
        'fallback',
        'test operation'
      )

      expect(mockOperation).toHaveBeenCalled()
      expect(result).toBe('success')
    })

    it('should return fallback value during build time', () => {
      process.env.IS_BUILD_TIME = 'true'
      const mockOperation = jest.fn()
      
      const result = guardDatabaseOperationSync(
        mockOperation,
        'fallback',
        'test operation'
      )

      expect(mockOperation).not.toHaveBeenCalled()
      expect(result).toBe('fallback')
    })
  })

  describe('createProtectedDatabaseConnection', () => {
    it('should create connection when database is allowed', async () => {
      delete process.env.IS_BUILD_TIME
      const mockConnection = { connected: true }
      const mockFactory = jest.fn().mockResolvedValue(mockConnection)
      
      const result = await createProtectedDatabaseConnection(
        mockFactory,
        'test connection'
      )

      expect(mockFactory).toHaveBeenCalled()
      expect(result).toBe(mockConnection)
    })

    it('should return null during build time', async () => {
      process.env.IS_BUILD_TIME = 'true'
      const mockFactory = jest.fn()
      
      const result = await createProtectedDatabaseConnection(
        mockFactory,
        'test connection'
      )

      expect(mockFactory).not.toHaveBeenCalled()
      expect(result).toBeNull()
    })

    it('should handle connection factory errors', async () => {
      delete process.env.IS_BUILD_TIME
      const mockError = new Error('Connection failed')
      const mockFactory = jest.fn().mockRejectedValue(mockError)
      
      await expect(createProtectedDatabaseConnection(
        mockFactory,
        'test connection'
      )).rejects.toThrow('Connection failed')
    })
  })

  describe('getBuildTimeConfig', () => {
    it('should return build-time configuration during build', () => {
      process.env.IS_BUILD_TIME = 'true'
      
      const config = getBuildTimeConfig()
      
      expect(config.allowDatabaseConnections).toBe(false)
      expect(config.skipRetentionPolicies).toBe(true)
      expect(config.skipBackgroundJobs).toBe(true)
      expect(config.skipDataMigrations).toBe(true)
    })

    it('should return runtime configuration during runtime', () => {
      delete process.env.IS_BUILD_TIME
      delete process.env.DISABLE_DATABASE
      
      const config = getBuildTimeConfig()
      
      expect(config.allowDatabaseConnections).toBe(true)
      expect(config.skipRetentionPolicies).toBe(false)
      expect(config.skipBackgroundJobs).toBe(false)
      expect(config.skipDataMigrations).toBe(false)
    })

    it('should respect explicit skip flags', () => {
      delete process.env.IS_BUILD_TIME
      process.env.SKIP_RETENTION_POLICIES = 'true'
      process.env.SKIP_BACKGROUND_JOBS = 'true'
      
      const config = getBuildTimeConfig()
      
      expect(config.skipRetentionPolicies).toBe(true)
      expect(config.skipBackgroundJobs).toBe(true)
    })
  })

  describe('logBuildTimeEnvironment', () => {
    it('should log environment information', () => {
      const { logger } = require('../utils/logger')
      
      logBuildTimeEnvironment()
      
      expect(logger.info).toHaveBeenCalledWith(
        'BuildTimeGuard',
        'Build-time environment configuration',
        expect.objectContaining({
          isBuildTime: expect.any(Boolean),
          isDatabaseConnectionAllowed: expect.any(Boolean),
          config: expect.any(Object),
          environment: expect.any(Object)
        })
      )
    })
  })
})
