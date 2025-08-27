const nextJest = require('next/jest')

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files
  dir: './',
})

// Add any custom config to be passed to Jest
const customJestConfig = {
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testEnvironment: 'jsdom',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@/components/(.*)$': '<rootDir>/src/view/components/$1',
    '^@/model/(.*)$': '<rootDir>/src/model/$1',
    '^@/controller/(.*)$': '<rootDir>/src/controller/$1',
    '^@/utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@/types/(.*)$': '<rootDir>/src/types/$1',
    '^@/lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@/view/(.*)$': '<rootDir>/src/view/$1',
    '^@/app/(.*)$': '<rootDir>/src/app/$1',
    '^@/hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^clsx$': '<rootDir>/src/__tests__/mocks/clsx.js',
  },
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/index.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/tests/**',
  ],
  coverageThreshold: {
    global: {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    // Per-directory thresholds for granular control
    './src/model/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    './src/controller/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    './src/view/': {
      branches: 90, // Slightly lower for UI components
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/utils/': {
      branches: 98,
      functions: 98,
      lines: 98,
      statements: 98,
    },
    './src/lib/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
  },
  testTimeout: 60000,
  verbose: true,
  // Enhanced error handling and retry configuration
  maxWorkers: '50%',
  detectOpenHandles: true,
  forceExit: true,
  // Improved test isolation
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  // Better error reporting
  errorOnDeprecated: false, // Set to false to avoid issues with legacy dependencies
  // Coverage reporting
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  coverageDirectory: 'coverage',
  // Test result processing with retry support
  testRunner: 'jest-circus/runner',
  // Global test configuration
  globals: {
    'ts-jest': {
      useESM: true,
    },
  },
  // Global setup and teardown
  globalSetup: '<rootDir>/src/__tests__/setup/globalSetup.js',
  globalTeardown: '<rootDir>/src/__tests__/setup/globalTeardown.js',
}

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig)
