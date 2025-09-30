const nextJest = require('next/jest')

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files
  dir: './',
})

// Add any custom config to be passed to Jest
const customJestConfig = {
  setupFilesAfterEnv: [
    '<rootDir>/jest.setup.js',
    '<rootDir>/src/__tests__/setup/jestTypeScriptSetup.ts'
  ],
  testEnvironment: 'jsdom',
  // Enhanced TypeScript support (compatible with Next.js)
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      tsconfig: {
        jsx: 'react-jsx',
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        strict: true,
        noImplicitReturns: true,
        noFallthroughCasesInSwitch: true,
        noUncheckedIndexedAccess: true,
        strictNullChecks: true,
      },
      isolatedModules: true,
    }],
  },
  // Configure ESM module handling for lucide-react and other ESM packages
  transformIgnorePatterns: [
    'node_modules/(?!(lucide-react|@testing-library|@babel|@jest|uuid|nanoid)/)'
  ],
  // Enable ESM support
  extensionsToTreatAsEsm: ['.ts', '.tsx'],
  moduleNameMapper: {
    // TypeScript path mapping (matches tsconfig.json)
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
    '^@/test-utils$': '<rootDir>/src/__tests__/utils/testUtils',
    '^@/mock-helpers$': '<rootDir>/src/__tests__/utils/mockTypeHelpers',
    '^@/common-mocks$': '<rootDir>/src/__tests__/utils/commonMocks',
    // Mock specific modules
    '^clsx$': '<rootDir>/src/__tests__/mocks/clsx.js',
    // ESM module mappings for proper handling
    '^lucide-react$': '<rootDir>/src/__tests__/mocks/lucide-react.js',
    '^uuid$': '<rootDir>/src/__tests__/mocks/uuid.js',
  },
  testMatch: [
    '<rootDir>/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/src/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],
  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/.next/',
    '<rootDir>/src/tests/unit/disabled/',
    '<rootDir>/src/tests/integration/disabled/',
    '<rootDir>/src/tests/e2e/disabled/',
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
  testRunner: 'jest-circus',
  // Enhanced custom reporters for professional test tracking
  reporters: [
    'default',
    '<rootDir>/src/utils/JestTestReporter.js'
  ],
  // Enhanced TypeScript and global configuration
  globals: {
    'ts-jest': {
      tsconfig: {
        jsx: 'react-jsx',
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        strict: true,
      },
      isolatedModules: true,
    },
    // Global test utilities
    __TEST_ENV__: 'jest',
    __MOCK_ENABLED__: true,
  },
  // TypeScript file extensions
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  // Improved module resolution for TypeScript
  resolver: undefined,
  // Global setup and teardown
  globalSetup: '<rootDir>/src/__tests__/setup/globalSetup.js',
  globalTeardown: '<rootDir>/src/__tests__/setup/globalTeardown.js',
}

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig)
