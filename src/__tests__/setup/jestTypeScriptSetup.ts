/**
 * Jest TypeScript Setup File
 * 
 * Configures global mock utilities, type helpers, and consistent mock patterns
 * for better TypeScript integration in Jest tests.
 */

import { jest } from '@jest/globals'
import '@testing-library/jest-dom'

// Import our enhanced mock utilities
import {
  MockedFunction,
  MockedObject,
  createMockFunction,
  createMockResolvedFunction,
  createMockRejectedFunction,
  createMockObject,
  createMockResponse,
  createFetchMock,
  mockHelpers,
  asMockedFunction,
  asMockedObject,
} from '../utils/mockTypeHelpers'

import {
  commonServiceMocks,
  createMockBusinessRecord,
  createMockUser,
  createMockSearchResult,
  mockFetchResponses,
  createTypedMocks,
  resetAllCommonMocks,
  clearAllCommonMocks,
} from '../utils/commonMocks'

// Extend global namespace with our mock utilities
declare global {
  // Global mock factory functions
  const createMockFunction: typeof createMockFunction
  const createMockResolvedFunction: typeof createMockResolvedFunction
  const createMockRejectedFunction: typeof createMockRejectedFunction
  const createMockObject: typeof createMockObject
  const createMockResponse: typeof createMockResponse
  const createFetchMock: typeof createFetchMock

  // Mock type helpers
  const asMockedFunction: typeof asMockedFunction
  const asMockedObject: typeof asMockedObject

  // Test data factories
  const createMockBusinessRecord: typeof createMockBusinessRecord
  const createMockUser: typeof createMockUser
  const createMockSearchResult: typeof createMockSearchResult

  // Common mock services
  const mockStorageService: typeof commonServiceMocks.storage
  const mockSearchService: typeof commonServiceMocks.search
  const mockEmailService: typeof commonServiceMocks.email
  const mockPaymentService: typeof commonServiceMocks.payment

  // Mock response helpers
  const mockFetchResponses: typeof mockFetchResponses
  const createTypedMocks: typeof createTypedMocks

  // Mock management utilities
  const resetAllCommonMocks: typeof resetAllCommonMocks
  const clearAllCommonMocks: typeof clearAllCommonMocks

  // Enhanced mock helpers
  const mockHelpers: typeof mockHelpers

  // CSRF and Security mock variables
  const mockCSRFToken: string
  const mockSessionId: string
}

// Set up global mock utilities
global.createMockFunction = createMockFunction
global.createMockResolvedFunction = createMockResolvedFunction
global.createMockRejectedFunction = createMockRejectedFunction
global.createMockObject = createMockObject
global.createMockResponse = createMockResponse
global.createFetchMock = createFetchMock

// Type helpers
global.asMockedFunction = asMockedFunction
global.asMockedObject = asMockedObject

// Test data factories
global.createMockBusinessRecord = createMockBusinessRecord
global.createMockUser = createMockUser
global.createMockSearchResult = createMockSearchResult

// Common mock services
global.mockStorageService = commonServiceMocks.storage
global.mockSearchService = commonServiceMocks.search
global.mockEmailService = commonServiceMocks.email
global.mockPaymentService = commonServiceMocks.payment

// Mock response helpers
global.mockFetchResponses = mockFetchResponses
global.createTypedMocks = createTypedMocks

// Mock management utilities
global.resetAllCommonMocks = resetAllCommonMocks
global.clearAllCommonMocks = clearAllCommonMocks

// Enhanced mock helpers
global.mockHelpers = mockHelpers

// Custom Jest matchers for business scraper specific assertions
expect.extend({
  toBeValidBusinessRecord(received: any) {
    const pass = (
      received &&
      typeof received === 'object' &&
      typeof received.id === 'string' &&
      typeof received.businessName === 'string' &&
      Array.isArray(received.email) &&
      typeof received.phone === 'string' &&
      typeof received.websiteUrl === 'string' &&
      received.address &&
      typeof received.address.street === 'string' &&
      typeof received.address.city === 'string' &&
      typeof received.address.state === 'string' &&
      typeof received.address.zipCode === 'string' &&
      typeof received.industry === 'string' &&
      received.scrapedAt instanceof Date
    )

    return {
      message: () =>
        pass
          ? `Expected ${received} not to be a valid business record`
          : `Expected ${received} to be a valid business record`,
      pass,
    }
  },

  toBeValidEmailAddress(received: string) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    const pass = typeof received === 'string' && emailRegex.test(received)

    return {
      message: () =>
        pass
          ? `Expected ${received} not to be a valid email address`
          : `Expected ${received} to be a valid email address`,
      pass,
    }
  },

  toBeValidPhoneNumber(received: string) {
    const phoneRegex = /^\+?[\d\s\-\(\)]+$/
    const pass = typeof received === 'string' && phoneRegex.test(received) && received.length >= 10

    return {
      message: () =>
        pass
          ? `Expected ${received} not to be a valid phone number`
          : `Expected ${received} to be a valid phone number`,
      pass,
    }
  },

  toBeValidUrl(received: string) {
    try {
      new URL(received)
      return {
        message: () => `Expected ${received} not to be a valid URL`,
        pass: true,
      }
    } catch {
      return {
        message: () => `Expected ${received} to be a valid URL`,
        pass: false,
      }
    }
  },

  toHaveValidAddress(received: any) {
    const pass = (
      received &&
      received.address &&
      typeof received.address.street === 'string' &&
      typeof received.address.city === 'string' &&
      typeof received.address.state === 'string' &&
      typeof received.address.zipCode === 'string' &&
      received.address.street.length > 0 &&
      received.address.city.length > 0 &&
      received.address.state.length > 0 &&
      received.address.zipCode.length > 0
    )

    return {
      message: () =>
        pass
          ? `Expected ${received} not to have a valid address`
          : `Expected ${received} to have a valid address`,
      pass,
    }
  },

  toBeWithinTimeRange(received: Date, start: Date, end: Date) {
    const pass = received instanceof Date && received >= start && received <= end

    return {
      message: () =>
        pass
          ? `Expected ${received} not to be within time range ${start} - ${end}`
          : `Expected ${received} to be within time range ${start} - ${end}`,
      pass,
    }
  },

  toMatchBusinessSchema(received: any) {
    const requiredFields = ['id', 'businessName', 'email', 'phone', 'websiteUrl', 'address', 'industry', 'scrapedAt']
    const pass = requiredFields.every(field => received && received.hasOwnProperty(field))

    return {
      message: () =>
        pass
          ? `Expected ${received} not to match business schema`
          : `Expected ${received} to match business schema`,
      pass,
    }
  },

  toHaveValidIndustryCategory(received: any) {
    const validIndustries = [
      'Technology', 'Healthcare', 'Finance', 'Education', 'Retail',
      'Manufacturing', 'Construction', 'Real Estate', 'Legal', 'Consulting'
    ]
    const pass = received && validIndustries.includes(received.industry)

    return {
      message: () =>
        pass
          ? `Expected ${received} not to have a valid industry category`
          : `Expected ${received} to have a valid industry category`,
      pass,
    }
  },

  toBeValidSearchResult(received: any) {
    const pass = (
      received &&
      typeof received === 'object' &&
      typeof received.title === 'string' &&
      typeof received.url === 'string' &&
      typeof received.snippet === 'string' &&
      typeof received.domain === 'string' &&
      typeof received.location === 'string' &&
      typeof received.source === 'string'
    )

    return {
      message: () =>
        pass
          ? `Expected ${received} not to be a valid search result`
          : `Expected ${received} to be a valid search result`,
      pass,
    }
  },

  toHaveValidContactInfo(received: any) {
    const hasValidEmail = received.email && Array.isArray(received.email) && received.email.length > 0
    const hasValidPhone = received.phone && typeof received.phone === 'string' && received.phone.length > 0
    const pass = hasValidEmail || hasValidPhone

    return {
      message: () =>
        pass
          ? `Expected ${received} not to have valid contact info`
          : `Expected ${received} to have valid contact info (email or phone)`,
      pass: Boolean(pass),
    }
  },
})

// Enhanced console setup for test environment
const originalConsole = { ...console }

// Set up test-specific console behavior
global.console = {
  ...originalConsole,
  // Suppress info and log in tests unless explicitly needed
  info: jest.fn(),
  log: jest.fn(),
  // Keep warn and error for important test feedback
  warn: originalConsole.warn,
  error: originalConsole.error,
  // Add debug method for test debugging
  debug: jest.fn(),
}

// Enhanced environment variable setup for tests
const originalEnv = { ...process.env }

// Set up comprehensive test environment variables
process.env = {
  ...originalEnv,
  NODE_ENV: 'test',
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db',
  REDIS_URL: 'redis://localhost:6379',
  ENCRYPTION_KEY: 'test-encryption-key-32-characters',
  ENCRYPTION_MASTER_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  JWT_SECRET: 'test-jwt-secret',
  CSRF_SECRET: 'test-csrf-secret-key-for-testing',
  SESSION_SECRET: 'test-session-secret-key',
  NEXTAUTH_SECRET: 'test-nextauth-secret',
  NEXTAUTH_URL: 'http://localhost:3000',
  // Disable external services in tests
  DISABLE_DATABASE: 'true',
  DISABLE_REDIS: 'true',
  DISABLE_EMAIL: 'true',
  DISABLE_ANALYTICS: 'true',
  // Test-specific configurations
  TEST_MODE: 'true',
  JEST_WORKER_ID: '1',
}

// CSRF Token Mock Setup
global.mockCSRFToken = 'test-csrf-token-' + Math.random().toString(36).substr(2, 9)
global.mockSessionId = 'test-session-' + Math.random().toString(36).substr(2, 9)

// Mock CSRF Protection Service
jest.mock('@/lib/csrfProtection', () => ({
  csrfProtectionService: {
    generateCSRFToken: jest.fn(() => ({
      token: global.mockCSRFToken,
      expiresAt: Date.now() + 3600000, // 1 hour
      sessionId: global.mockSessionId
    })),
    validateCSRFToken: jest.fn(() => ({ isValid: true })),
    invalidateCSRFToken: jest.fn(() => true),
    cleanupExpiredTokens: jest.fn(() => 0)
  },
  validateCSRFMiddleware: jest.fn(() => Promise.resolve({ isValid: true })),
  validateTemporaryCSRFToken: jest.fn(() => true),
  invalidateTemporaryCSRFToken: jest.fn(() => true)
}))

// Mock Security Service
jest.mock('@/lib/security', () => ({
  hashPassword: jest.fn(() => Promise.resolve('hashed-password')),
  verifyPassword: jest.fn(() => Promise.resolve(true)),
  createSession: jest.fn(() => Promise.resolve({
    sessionId: global.mockSessionId,
    userId: 'test-user-id',
    expiresAt: new Date(Date.now() + 3600000)
  })),
  getSession: jest.fn(() => Promise.resolve({
    sessionId: global.mockSessionId,
    userId: 'test-user-id',
    isValid: true
  })),
  getClientIP: jest.fn(() => '127.0.0.1'),
  sanitizeInput: jest.fn((input) => input?.trim()),
  validateInput: jest.fn(() => ({ isValid: true, errors: [] })),
  validateCSRFToken: jest.fn(() => true),
  generateSecureToken: jest.fn(() => 'secure-token-123'),
  checkRateLimit: jest.fn(() => true),
  trackLoginAttempt: jest.fn(() => true),
  isLockedOut: jest.fn(() => false),
  logSuspiciousActivity: jest.fn(() => Promise.resolve()),
  encryptData: jest.fn(() => Promise.resolve('encrypted-data')),
  decryptData: jest.fn(() => Promise.resolve('decrypted-data')),
  invalidateSession: jest.fn(() => Promise.resolve()),
  validateSecureSession: jest.fn(() => Promise.resolve({ valid: true })),
  isIpLockedOut: jest.fn(() => false),
  recordFailedLogin: jest.fn(() => undefined),
  defaultSecurityConfig: {
    sessionTimeout: 3600000,
    maxLoginAttempts: 5,
    lockoutDuration: 900000
  }
}))

// Mock Storage Service
jest.mock('@/model/storage', () => ({
  storage: {
    getAllBusinesses: jest.fn(() => Promise.resolve([])),
    saveBusiness: jest.fn(() => Promise.resolve()),
    saveBusinesses: jest.fn(() => Promise.resolve()),
    getBusinessById: jest.fn(() => Promise.resolve(null)),
    deleteBusinessById: jest.fn(() => Promise.resolve()),
    clearAllBusinesses: jest.fn(() => Promise.resolve()),
    getBusinessCount: jest.fn(() => Promise.resolve(0)),
    searchBusinesses: jest.fn(() => Promise.resolve([])),
  },
  StorageService: jest.fn().mockImplementation(() => ({
    getAllBusinesses: jest.fn(() => Promise.resolve([])),
    saveBusiness: jest.fn(() => Promise.resolve()),
    saveBusinesses: jest.fn(() => Promise.resolve()),
  })),
}))

// Mock Advanced Rate Limit Service
jest.mock('@/lib/advancedRateLimit', () => ({
  advancedRateLimitService: {
    checkApiRateLimit: jest.fn(() => ({ allowed: true, remaining: 100, resetTime: Date.now() + 3600000 })),
    recordApiCall: jest.fn(() => Promise.resolve()),
    getRateLimitStatus: jest.fn(() => ({ allowed: true, remaining: 100 })),
    clearRateLimit: jest.fn(() => Promise.resolve()),
  },
}))

// Mock Logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    trace: jest.fn(),
  },
}))

// Mock Next-Auth and Jose modules
jest.mock('next-auth', () => ({
  default: jest.fn(),
  getServerSession: jest.fn(),
}))

jest.mock('jose', () => ({
  SignJWT: jest.fn().mockImplementation(() => ({
    setProtectedHeader: jest.fn().mockReturnThis(),
    setIssuedAt: jest.fn().mockReturnThis(),
    setExpirationTime: jest.fn().mockReturnThis(),
    sign: jest.fn(() => Promise.resolve('mock-jwt-token')),
  })),
  jwtVerify: jest.fn(() => Promise.resolve({ payload: { sub: 'test-user' } })),
}))

// Mock TensorFlow.js to avoid WebGL/Canvas issues in Jest
jest.mock('@tensorflow/tfjs', () => ({
  sequential: jest.fn(() => ({
    add: jest.fn(),
    compile: jest.fn(),
    fit: jest.fn(() => Promise.resolve()),
    predict: jest.fn(() => ({
      data: jest.fn(() => Promise.resolve([0.75])),
      dispose: jest.fn(),
    })),
  })),
  layers: {
    dense: jest.fn(() => ({})),
  },
  tensor2d: jest.fn(() => ({
    dispose: jest.fn(),
  })),
  setBackend: jest.fn(() => Promise.resolve()),
  ready: jest.fn(() => Promise.resolve()),
}))

jest.mock('@tensorflow/tfjs-layers', () => ({
  sequential: jest.fn(() => ({
    add: jest.fn(),
    compile: jest.fn(),
    fit: jest.fn(() => Promise.resolve()),
    predict: jest.fn(() => ({
      data: jest.fn(() => Promise.resolve([0.75])),
      dispose: jest.fn(),
    })),
  })),
  layers: {
    dense: jest.fn(() => ({})),
  },
}))

// Mock Enhanced Filtering Service
jest.mock('@/lib/enhancedFilteringService', () => ({
  EnhancedFilteringService: jest.fn().mockImplementation(() => ({
    filterBusinesses: jest.fn(() => Promise.resolve({
      businesses: [],
      totalCount: 0,
      hasMore: false,
    })),
  })),
}))

// Mock data processing services
jest.mock('@/lib/enhancedDataManager', () => ({
  enhancedDataManager: {
    initialize: jest.fn(() => Promise.resolve()),
    processSingle: jest.fn(() => Promise.resolve({
      processed: {},
      score: { score: 75, confidence: 0.8, factors: {}, recommendations: [] },
      validation: { isValid: true, confidence: 0.9, errors: [], warnings: [], suggestions: [] },
      duplicates: [],
    })),
    processBatch: jest.fn(() => Promise.resolve({
      processed: [],
      scores: new Map(),
      duplicates: [],
      errors: [],
      stats: { total: 0, processed: 0, scored: 0, duplicates: 0, errors: 0 },
    })),
  },
}))

jest.mock('@/lib/aiLeadScoring', () => ({
  aiLeadScoringService: {
    initialize: jest.fn(() => Promise.resolve()),
    getLeadScore: jest.fn(() => Promise.resolve({
      score: 75,
      confidence: 0.8,
      factors: {
        contactability: { score: 80, weight: 0.3, details: 'Good contact info' },
        businessMaturity: { score: 70, weight: 0.25, details: 'Established business' },
        marketPotential: { score: 75, weight: 0.25, details: 'Good market potential' },
        engagementLikelihood: { score: 80, weight: 0.2, details: 'High engagement likelihood' },
      },
      recommendations: ['Contact via email', 'Follow up within 24 hours'],
    })),
  },
}))

jest.mock('@/lib/duplicateDetection', () => ({
  duplicateDetectionSystem: {
    findDuplicates: jest.fn(() => Promise.resolve([])),
  },
}))

jest.mock('@/lib/smartCacheManager', () => ({
  smartCacheManager: {
    get: jest.fn(() => Promise.resolve(null)),
    set: jest.fn(() => Promise.resolve()),
  },
}))

jest.mock('@/lib/emailValidationService', () => ({
  EmailValidationService: jest.fn().mockImplementation(() => ({
    validateEmail: jest.fn(() => Promise.resolve({
      isValid: true,
      confidence: 0.9,
      metadata: {
        provider: 'gmail',
        disposable: false,
        role: false,
        deliverable: true,
      },
    })),
  })),
}))

jest.mock('@/lib/phoneValidationService', () => ({
  PhoneValidationService: jest.fn().mockImplementation(() => ({
    validatePhone: jest.fn(() => Promise.resolve({
      isValid: true,
      formatted: '+15551234567',
      type: 'mobile',
      carrier: 'Verizon',
      location: 'Los Angeles, CA',
    })),
  })),
}))

jest.mock('@/lib/businessIntelligenceService', () => ({
  BusinessIntelligenceService: jest.fn().mockImplementation(() => ({
    analyzeBusinessIntelligence: jest.fn(() => Promise.resolve({
      industryMatch: 0.95,
      businessSize: 'medium',
      marketPresence: 'strong',
      digitalFootprint: 'excellent',
      trustScore: 0.85,
      riskFactors: [],
      opportunities: ['digital_marketing', 'expansion'],
    })),
  })),
}))

jest.mock('@/model/geocoder', () => ({
  geocoder: {
    geocodeAddress: jest.fn(() => Promise.resolve({
      latitude: 34.0522,
      longitude: -118.2437,
      formattedAddress: '123 Main Street, Los Angeles, CA 90210',
      confidence: 0.95,
    })),
  },
}))

// Global test setup
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks()

  // Reset common service mocks
  resetAllCommonMocks()

  // Reset fetch mock if it exists
  if (global.fetch && jest.isMockFunction(global.fetch)) {
    global.fetch.mockClear()
  }

  // Reset CSRF token mocks
  global.mockCSRFToken = 'test-csrf-token-' + Math.random().toString(36).substr(2, 9)
  global.mockSessionId = 'test-session-' + Math.random().toString(36).substr(2, 9)

  // Ensure crypto polyfills are available
  if (typeof globalThis.crypto === 'undefined') {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        randomUUID: () => 'test-uuid-' + Math.random().toString(36).substr(2, 9),
        getRandomValues: (arr) => {
          for (let i = 0; i < arr.length; i++) {
            arr[i] = Math.floor(Math.random() * 256)
          }
          return arr
        },
        createHash: (algorithm) => ({
          update: (data) => ({
            digest: (encoding) => {
              const str = typeof data === 'string' ? data : data.toString()
              let hash = 0
              for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i)
                hash = ((hash << 5) - hash) + char
                hash = hash & hash
              }
              return encoding === 'hex' ? Math.abs(hash).toString(16).padStart(8, '0') : Math.abs(hash).toString()
            }
          })
        }),
        subtle: {
          importKey: jest.fn().mockResolvedValue({}),
          deriveBits: jest.fn().mockResolvedValue(new ArrayBuffer(32)),
          generateKey: jest.fn().mockResolvedValue({}),
          encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
          decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16))
        }
      },
      writable: true,
      configurable: true
    })
  }
})

afterEach(() => {
  // Clean up after each test
  jest.restoreAllMocks()

  // Clear all common mocks
  clearAllCommonMocks()
})

// Global test teardown
afterAll(() => {
  // Restore original console
  global.console = originalConsole

  // Restore original environment variables
  process.env = originalEnv
})

// Export types for use in test files
export type {
  MockedFunction,
  MockedObject,
} from '../utils/mockTypeHelpers'

export type {
  BusinessRecord,
  SearchResult,
  User,
  ApiResponse,
} from '../../types/jest'
