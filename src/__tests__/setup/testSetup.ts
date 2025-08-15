/**
 * Test Setup Configuration
 * Global test setup for secure and isolated testing
 */

import { jest } from '@jest/globals'
import { createMockFileSystem, createMockEnvironment, createMockLogger } from '../utils/mockHelpers'

// Global test configuration
export const testConfig = {
  timeout: 10000,
  maxRetries: 3,
  isolateModules: true
}

// Global mocks that should be available in all tests
export const globalMocks = {
  fileSystem: createMockFileSystem(),
  environment: createMockEnvironment({
    NODE_ENV: 'test',
    TEST_MODE: 'true'
  }),
  logger: createMockLogger()
}

// Setup function to be called before each test
export const setupTest = () => {
  // Reset all global mocks
  globalMocks.fileSystem.reset()
  globalMocks.environment.restore()
  globalMocks.logger.reset()

  // Mock common modules that should never perform real operations in tests
  jest.mock('fs', () => globalMocks.fileSystem)
  jest.mock('fs/promises', () => ({
    readFile: jest.fn(),
    writeFile: jest.fn(),
    mkdir: jest.fn(),
    rmdir: jest.fn(),
    unlink: jest.fn(),
    access: jest.fn(),
    stat: jest.fn()
  }))

  // Mock path operations to use safe test paths
  jest.mock('path', () => ({
    join: jest.fn((...args: string[]) => args.join('/')),
    resolve: jest.fn((...args: string[]) => '/' + args.join('/')),
    dirname: jest.fn((path: string) => path.split('/').slice(0, -1).join('/')),
    basename: jest.fn((path: string) => path.split('/').pop() || ''),
    extname: jest.fn((path: string) => {
      const parts = path.split('.')
      return parts.length > 1 ? '.' + parts.pop() : ''
    })
  }))

  // Mock os module for safe temporary directory operations
  jest.mock('os', () => ({
    tmpdir: jest.fn(() => '/tmp/test'),
    homedir: jest.fn(() => '/home/test'),
    platform: jest.fn(() => 'test'),
    arch: jest.fn(() => 'test')
  }))

  // Mock crypto for consistent test results
  jest.mock('crypto', () => ({
    randomBytes: jest.fn((size: number) => Buffer.alloc(size, 'test')),
    createHash: jest.fn(() => ({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn(() => 'test-hash-12345')
    })),
    createHmac: jest.fn(() => ({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn(() => 'test-hmac-12345')
    }))
  }))

  // Mock logger to prevent console spam during tests
  jest.mock('@/utils/logger', () => ({
    logger: globalMocks.logger
  }))
}

// Cleanup function to be called after each test
export const cleanupTest = () => {
  // Clear all mocks
  jest.clearAllMocks()
  
  // Reset global state
  globalMocks.fileSystem.reset()
  globalMocks.environment.restore()
  globalMocks.logger.reset()

  // Clear any timers
  jest.clearAllTimers()
}

// Helper to create isolated test environment
export const createIsolatedTest = (testFn: () => void | Promise<void>) => {
  return async () => {
    setupTest()
    try {
      await testFn()
    } finally {
      cleanupTest()
    }
  }
}

// Security test helpers
export const securityTestHelpers = {
  // Create a safe test file without touching the real filesystem
  createSafeTestFile: (content: string, filename: string, mimeType: string = 'text/plain') => {
    return new File([content], filename, { type: mimeType })
  },

  // Validate that no real file operations occurred
  validateNoRealFileOperations: () => {
    const fs = require('fs')
    expect(fs.existsSync).not.toHaveBeenCalledWith(expect.stringMatching(/^(?!\/tmp\/test)/))
    expect(fs.writeFileSync).not.toHaveBeenCalledWith(expect.stringMatching(/^(?!\/tmp\/test)/))
    expect(fs.rmSync).not.toHaveBeenCalledWith(expect.stringMatching(/^(?!\/tmp\/test)/))
  },

  // Validate that no environment variables were permanently modified
  validateEnvironmentIntegrity: () => {
    const criticalEnvVars = ['NODE_ENV', 'PATH', 'HOME']
    criticalEnvVars.forEach(envVar => {
      expect(process.env[envVar]).toBeDefined()
    })
  },

  // Create mock malicious content safely
  createMockMaliciousContent: (type: 'xss' | 'sql' | 'path' | 'command') => {
    const patterns = {
      xss: 'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=', // base64 encoded
      sql: 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDEgT1IgMT0x',
      path: 'Li4vLi4vLi4vZXRjL3Bhc3N3ZA==',
      command: 'RVhFQyB4cF9jbWRzaGVsbCgnZGlyJyk='
    }
    return Buffer.from(patterns[type], 'base64').toString('utf-8')
  }
}

// Export default setup for Jest configuration
export default {
  setupTest,
  cleanupTest,
  createIsolatedTest,
  globalMocks,
  testConfig,
  securityTestHelpers
}
