const nextJest = require('next/jest')

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files
  dir: './',
})

// Add any custom config to be passed to Jest
const customJestConfig = {
  // setupFilesAfterEnv: ['./jest.setup.js'],
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
  testTimeout: 30000,
  verbose: true,
}

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig)
