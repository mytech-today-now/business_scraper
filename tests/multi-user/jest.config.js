/**
 * Jest Configuration for Multi-User Tests
 * Specialized configuration for testing multi-user collaboration features
 */

const nextJest = require('next/jest')

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files
  dir: './',
})

// Add any custom config to be passed to Jest
const customJestConfig = {
  // Test environment
  testEnvironment: 'jsdom',

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/tests/multi-user/setup.ts'],

  // Test patterns
  testMatch: ['<rootDir>/tests/multi-user/**/*.test.{js,jsx,ts,tsx}'],

  // Module name mapping
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@/components/(.*)$': '<rootDir>/src/components/$1',
    '^@/lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@/types/(.*)$': '<rootDir>/src/types/$1',
    '^@/utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@/app/(.*)$': '<rootDir>/src/app/$1',
  },

  // Coverage configuration
  collectCoverageFrom: [
    'src/lib/user-management.ts',
    'src/lib/rbac.ts',
    'src/lib/rbac-middleware.ts',
    'src/lib/team-management.ts',
    'src/lib/workspace-management.ts',
    'src/lib/collaboration-websocket.ts',
    'src/lib/audit-service.ts',
    'src/lib/analytics-service.ts',
    'src/lib/roi-tracking.ts',
    'src/app/api/users/**/*.ts',
    'src/app/api/auth/multi-user/**/*.ts',
    'src/app/api/teams/**/*.ts',
    'src/app/api/workspaces/**/*.ts',
    'src/app/api/analytics/**/*.ts',
    'src/app/api/campaigns/**/*.ts',
    'src/app/api/scraping/**/*.ts',
    'src/components/multi-user/**/*.{ts,tsx}',
    '!**/*.d.ts',
    '!**/node_modules/**',
    '!**/.next/**',
  ],

  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
    },
    './src/lib/user-management.ts': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/lib/rbac.ts': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
  },

  // Coverage reporters
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],

  // Test timeout
  testTimeout: 30000,

  // Transform configuration
  transform: {
    '^.+\\.(js|jsx|ts|tsx)$': ['babel-jest', { presets: ['next/babel'] }],
  },

  // Module file extensions
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],

  // Global setup and teardown
  globalSetup: '<rootDir>/tests/multi-user/global-setup.ts',
  globalTeardown: '<rootDir>/tests/multi-user/global-teardown.ts',

  // Test environment options
  testEnvironmentOptions: {
    url: 'http://localhost:3000',
  },

  // Clear mocks between tests
  clearMocks: true,

  // Restore mocks after each test
  restoreMocks: true,

  // Verbose output
  verbose: true,

  // Fail fast on first test failure
  bail: false,

  // Maximum worker processes
  maxWorkers: '50%',

  // Cache directory
  cacheDirectory: '<rootDir>/.jest-cache',

  // Error on deprecated features
  errorOnDeprecated: true,

  // Notify mode
  notify: false,

  // Watch plugins
  watchPlugins: ['jest-watch-typeahead/filename', 'jest-watch-typeahead/testname'],

  // Reporters
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: '<rootDir>/test-results/multi-user',
        outputName: 'junit.xml',
        suiteName: 'Multi-User Tests',
      },
    ],
    [
      'jest-html-reporters',
      {
        publicPath: '<rootDir>/test-results/multi-user',
        filename: 'report.html',
        expand: true,
        hideIcon: false,
        pageTitle: 'Multi-User Test Report',
      },
    ],
  ],
}

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig)
