/**
 * Common Mock Utilities
 * 
 * Centralized mock utilities for consistent mocking patterns across all test files.
 * This addresses the systematic mock function type resolution enhancement.
 */

import { jest } from '@jest/globals'
import { 
  MockedFunction, 
  MockedObject, 
  createMockFunction, 
  createMockResolvedFunction,
  createMockResponse,
  mockHelpers
} from './mockTypeHelpers'

/**
 * Common service mocks used across multiple test files
 */
export const commonServiceMocks = {
  /**
   * Mock for database/storage services
   */
  storage: {
    initialize: createMockResolvedFunction<() => Promise<void>>(undefined),
    saveBusiness: createMockResolvedFunction<(business: any) => Promise<void>>(undefined),
    saveBusinesses: createMockResolvedFunction<(businesses: any[]) => Promise<void>>(undefined),
    getAllBusinesses: createMockResolvedFunction<() => Promise<any[]>>([]),
    getBusiness: createMockResolvedFunction<(id: string) => Promise<any | null>>(null),
    deleteBusiness: createMockResolvedFunction<(id: string) => Promise<void>>(undefined),
    clearBusinesses: createMockResolvedFunction<() => Promise<void>>(undefined),
    close: createMockResolvedFunction<() => Promise<void>>(undefined),
  },

  /**
   * Mock for API services
   */
  api: {
    get: createMockResolvedFunction<(url: string) => Promise<any>>({}),
    post: createMockResolvedFunction<(url: string, data?: any) => Promise<any>>({}),
    put: createMockResolvedFunction<(url: string, data?: any) => Promise<any>>({}),
    delete: createMockResolvedFunction<(url: string) => Promise<any>>({}),
  },

  /**
   * Mock for authentication services
   */
  auth: {
    login: createMockResolvedFunction<(credentials: any) => Promise<any>>({ success: true }),
    logout: createMockResolvedFunction<() => Promise<void>>(undefined),
    getUser: createMockResolvedFunction<() => Promise<any | null>>(null),
    isAuthenticated: createMockFunction<() => boolean>(),
  },

  /**
   * Mock for logger services
   */
  logger: {
    info: createMockFunction<(message: string, ...args: any[]) => void>(),
    warn: createMockFunction<(message: string, ...args: any[]) => void>(),
    error: createMockFunction<(message: string, ...args: any[]) => void>(),
    debug: createMockFunction<(message: string, ...args: any[]) => void>(),
  },
}

/**
 * Mock business record factory with proper typing
 */
export function createMockBusinessRecord(overrides: Partial<any> = {}): any {
  return {
    id: 'test-business-id',
    businessName: 'Test Business',
    email: ['test@example.com'],
    phone: '+1-555-0123',
    websiteUrl: 'https://testbusiness.com',
    address: {
      street: '123 Main St',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345',
    },
    industry: 'Technology',
    scrapedAt: new Date(),
    website: 'https://testbusiness.com',
    ...overrides,
  }
}

/**
 * Mock user record factory
 */
export function createMockUser(overrides: Partial<any> = {}): any {
  return {
    id: 'test-user-id',
    username: 'testuser',
    email: 'test@example.com',
    roles: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  }
}

/**
 * Mock search result factory
 */
export function createMockSearchResult(overrides: Partial<any> = {}): any {
  return {
    title: 'Test Business Result',
    url: 'https://testbusiness.com',
    snippet: 'Test business description',
    domain: 'testbusiness.com',
    location: 'Test City, TS',
    phone: '555-123-4567',
    rating: 4.5,
    reviewCount: 100,
    category: 'Technology',
    source: 'TestSearchEngine',
    ...overrides,
  }
}

/**
 * Mock audit log factory
 */
export function createMockAuditLog(overrides: Partial<any> = {}): any {
  return {
    id: 'test-audit-id',
    action: 'test_action',
    resource: 'test_resource',
    userId: 'test-user-id',
    timestamp: new Date(),
    category: 'test',
    severity: 'info',
    complianceFlags: [],
    ...overrides,
  }
}

/**
 * Mock fetch responses for common patterns
 */
export const mockFetchResponses = {
  success: (data?: any) => createMockResponse(data, { status: 200 }),
  created: (data?: any) => createMockResponse(data, { status: 201 }),
  noContent: () => createMockResponse(null, { status: 204 }),
  badRequest: (error?: any) => createMockResponse(error || { error: 'Bad Request' }, { status: 400 }),
  unauthorized: () => createMockResponse({ error: 'Unauthorized' }, { status: 401 }),
  forbidden: () => createMockResponse({ error: 'Forbidden' }, { status: 403 }),
  notFound: () => createMockResponse({ error: 'Not Found' }, { status: 404 }),
  serverError: (error?: any) => createMockResponse(error || { error: 'Internal Server Error' }, { status: 500 }),

  // CSRF-specific responses
  csrfToken: (token: string = 'test-csrf-token', expiresIn: number = 600000) => createMockResponse({
    csrfToken: token,
    tokenId: 'test-token-id',
    temporary: true,
    expiresAt: new Date(Date.now() + expiresIn).toISOString(),
  }, {
    status: 200,
    headers: {
      'X-CSRF-Token': token,
      'X-CSRF-Token-ID': 'test-token-id',
      'X-CSRF-Expires': String(Date.now() + expiresIn),
    }
  }),

  csrfFailure: () => createMockResponse({ error: 'CSRF token generation failed' }, { status: 500 }),
}

/**
 * Mock environment setup utilities
 */
export function setupMockEnvironment(envVars: Record<string, string> = {}) {
  const originalEnv = { ...process.env }
  
  beforeEach(() => {
    Object.entries(envVars).forEach(([key, value]) => {
      Object.defineProperty(process.env, key, {
        value,
        writable: true,
        configurable: true,
      })
    })
  })

  afterEach(() => {
    // Restore original environment
    Object.keys(envVars).forEach(key => {
      if (originalEnv[key] !== undefined) {
        Object.defineProperty(process.env, key, {
          value: originalEnv[key],
          writable: true,
          configurable: true,
        })
      } else {
        delete process.env[key]
      }
    })
  })
}

/**
 * Mock browser APIs setup
 */
export function setupMockBrowserAPIs() {
  beforeEach(() => {
    // Mock navigator.onLine
    Object.defineProperty(navigator, 'onLine', {
      value: true,
      writable: true,
      configurable: true,
    })

    // Mock URL methods
    global.URL.createObjectURL = jest.fn(() => 'mocked-url')
    global.URL.revokeObjectURL = jest.fn()
  })

  afterEach(() => {
    jest.clearAllMocks()
  })
}

/**
 * Utility to create properly typed mock functions for specific patterns
 */
export const createTypedMocks = {
  /**
   * Create a mock for async database operations
   */
  databaseQuery: <T = any>(mockResult?: T) => 
    createMockResolvedFunction<(query: string, params?: any[]) => Promise<{ rows: T[]; rowCount: number }>>(
      { rows: mockResult ? [mockResult] : [], rowCount: mockResult ? 1 : 0 }
    ),

  /**
   * Create a mock for HTTP client methods
   */
  httpClient: <T = any>(mockResponse?: T) => ({
    get: createMockResolvedFunction<(url: string, config?: any) => Promise<{ data: T }>>(
      { data: mockResponse || {} }
    ),
    post: createMockResolvedFunction<(url: string, data?: any, config?: any) => Promise<{ data: T }>>(
      { data: mockResponse || {} }
    ),
    put: createMockResolvedFunction<(url: string, data?: any, config?: any) => Promise<{ data: T }>>(
      { data: mockResponse || {} }
    ),
    delete: createMockResolvedFunction<(url: string, config?: any) => Promise<{ data: T }>>(
      { data: mockResponse || {} }
    ),
  }),

  /**
   * Create a mock for event handlers
   */
  eventHandler: <T extends Event = Event>() => createMockFunction<(event: T) => void>(),

  /**
   * Create a mock for React component props
   */
  componentProps: <T extends Record<string, any>>(props: Partial<T> = {}) => props as T,
}

/**
 * Reset all common mocks
 */
export function resetAllCommonMocks() {
  Object.values(commonServiceMocks).forEach(service => {
    Object.values(service).forEach(method => {
      if (jest.isMockFunction(method)) {
        method.mockReset()
      }
    })
  })
}

/**
 * Clear all common mocks
 */
export function clearAllCommonMocks() {
  Object.values(commonServiceMocks).forEach(service => {
    Object.values(service).forEach(method => {
      if (jest.isMockFunction(method)) {
        method.mockClear()
      }
    })
  })
}
