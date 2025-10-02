/**
 * Enhanced Mock Type Helpers for Jest
 *
 * This module provides comprehensive mock helper functions to resolve
 * Jest mock function type issues across the business scraper application.
 *
 * Addresses GitHub Issue: Systematic Mock Function Type Resolution (CRITICAL PRIORITY)
 * Enhanced version with improved type safety and broader compatibility
 */

import { jest } from '@jest/globals'

// Type definitions for Jest mocks with improved constraints
export type MockedFunction<T extends (...args: any[]) => any> = jest.MockedFunction<T>
export type MockedClass<T extends new (...args: any[]) => any> = jest.MockedClass<T>
export type MockedObject<T> = jest.Mocked<T>

// Enhanced type for proper Response mocking
export interface MockResponse extends Response {
  json: jest.MockedFunction<() => Promise<any>>
  text: jest.MockedFunction<() => Promise<string>>
  blob: jest.MockedFunction<() => Promise<Blob>>
  arrayBuffer: jest.MockedFunction<() => Promise<ArrayBuffer>>
  formData: jest.MockedFunction<() => Promise<FormData>>
  clone: jest.MockedFunction<() => Response>
}

// Helper type for extracting function types
export type AnyFunction = (...args: any[]) => any
export type AsyncFunction = (...args: any[]) => Promise<any>

/**
 * Creates a properly typed Jest mock function
 */
export function createMockFunction<T extends AnyFunction = AnyFunction>(): MockedFunction<T> {
  return jest.fn() as MockedFunction<T>
}

/**
 * Creates a mock function with a resolved value
 * Fixed type constraints to handle generic return types properly
 */
export function createMockResolvedFunction<T extends AsyncFunction>(
  resolvedValue?: any
): MockedFunction<T> {
  const mockFn = jest.fn() as MockedFunction<T>
  if (resolvedValue !== undefined) {
    mockFn.mockResolvedValue(resolvedValue)
  }
  return mockFn
}

/**
 * Creates a mock function with a rejected value
 * Fixed type constraints to handle error types properly
 */
export function createMockRejectedFunction<T extends AsyncFunction>(
  rejectedValue?: any
): MockedFunction<T> {
  const mockFn = jest.fn() as MockedFunction<T>
  if (rejectedValue !== undefined) {
    mockFn.mockRejectedValue(rejectedValue)
  }
  return mockFn
}

/**
 * Creates a mock function with an implementation
 */
export function createMockImplementation<T extends AnyFunction>(
  implementation: T
): MockedFunction<T> {
  return jest.fn(implementation) as MockedFunction<T>
}

/**
 * Creates a properly typed mock object for a service/class
 * Enhanced with better type inference and optional properties
 */
export function createMockObject<T extends Record<string, any>>(
  mockImplementation?: Partial<{
    [K in keyof T]: T[K] extends (...args: any[]) => any ? MockedFunction<T[K]> : T[K]
  }>
): MockedObject<T> {
  return (mockImplementation || {}) as MockedObject<T>
}

/**
 * Helper to properly type an existing Jest mock
 * Useful for converting jest.fn() to properly typed mocks
 */
export function asMockedFunction<T extends AnyFunction>(mock: any): MockedFunction<T> {
  return mock as MockedFunction<T>
}

/**
 * Helper to properly type an existing mock object
 * Useful for converting mock objects to properly typed mocks
 */
export function asMockedObject<T>(mock: any): MockedObject<T> {
  return mock as MockedObject<T>
}

/**
 * Creates a mock function that returns different values on subsequent calls
 */
export function createMockWithReturnValues<T extends AnyFunction>(
  ...returnValues: ReturnType<T>[]
): MockedFunction<T> {
  const mockFn = jest.fn() as MockedFunction<T>
  returnValues.forEach(value => mockFn.mockReturnValueOnce(value))
  return mockFn
}

/**
 * Creates a mock for Stripe service methods
 */
export function createStripeMock() {
  return {
    customers: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      update: createMockFunction<(id: string, params: any) => Promise<any>>(),
      del: createMockFunction<(id: string) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
    subscriptions: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      update: createMockFunction<(id: string, params: any) => Promise<any>>(),
      cancel: createMockFunction<(id: string) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
    paymentMethods: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      attach: createMockFunction<(id: string, params: any) => Promise<any>>(),
      detach: createMockFunction<(id: string) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
    invoices: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      pay: createMockFunction<(id: string, params?: any) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
    prices: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
    products: {
      create: createMockFunction<(params: any) => Promise<any>>(),
      retrieve: createMockFunction<(id: string) => Promise<any>>(),
      update: createMockFunction<(id: string, params: any) => Promise<any>>(),
      list: createMockFunction<(params?: any) => Promise<any>>(),
    },
  }
}

/**
 * Creates a mock for storage service methods
 */
export function createStorageMock() {
  return createMockObject({
    initialize: createMockResolvedFunction<() => Promise<void>>(undefined),
    saveBusiness: createMockResolvedFunction<(business: any) => Promise<void>>(undefined),
    saveBusinesses: createMockResolvedFunction<(businesses: any[]) => Promise<void>>(undefined),
    getAllBusinesses: createMockResolvedFunction<() => Promise<any[]>>([]),
    getBusiness: createMockResolvedFunction<(id: string) => Promise<any | null>>(null),
    deleteBusiness: createMockResolvedFunction<(id: string) => Promise<void>>(undefined),
    clearBusinesses: createMockResolvedFunction<() => Promise<void>>(undefined),
    saveIndustry: createMockResolvedFunction<(industry: any) => Promise<void>>(undefined),
    getAllIndustries: createMockResolvedFunction<() => Promise<any[]>>([]),
    deleteIndustry: createMockResolvedFunction<(id: string) => Promise<void>>(undefined),
    clearIndustries: createMockResolvedFunction<() => Promise<void>>(undefined),
    saveConfig: createMockResolvedFunction<(config: any) => Promise<void>>(undefined),
    getConfig: createMockResolvedFunction<() => Promise<any | null>>(null),
    clearAll: createMockResolvedFunction<() => Promise<void>>(undefined),
    close: createMockResolvedFunction<() => Promise<void>>(undefined),
    getUserPaymentProfile: createMockResolvedFunction<(userId: string) => Promise<any | null>>(null),
    saveUserPaymentProfile: createMockResolvedFunction<(profile: any) => Promise<void>>(undefined),
    deleteUserPaymentProfile: createMockResolvedFunction<(userId: string) => Promise<void>>(undefined),
  })
}

/**
 * Creates a mock for API response patterns
 */
export function createApiResponseMock<T>(data: T, success = true) {
  return {
    success,
    data,
    message: success ? 'Operation successful' : 'Operation failed',
    timestamp: new Date().toISOString(),
    ...(success ? {} : { error: 'Test error message' }),
  }
}

/**
 * Creates a mock for Next.js API request
 */
export function createNextRequestMock(
  url: string,
  options: {
    method?: string
    body?: any
    headers?: Record<string, string>
  } = {}
) {
  return {
    url,
    method: options.method || 'GET',
    headers: new Headers(options.headers || {}),
    json: createMockResolvedFunction<() => Promise<any>>(options.body || {}),
    text: createMockResolvedFunction<() => Promise<string>>(JSON.stringify(options.body || {})),
    formData: createMockResolvedFunction<() => Promise<FormData>>(new FormData()),
  }
}

/**
 * Creates a mock for Next.js API response
 */
export function createNextResponseMock(data: any, status = 200) {
  return {
    status,
    headers: new Headers(),
    json: createMockResolvedFunction<() => Promise<any>>(data),
    text: createMockResolvedFunction<() => Promise<string>>(JSON.stringify(data)),
    ok: status >= 200 && status < 300,
  }
}

/**
 * Helper to properly type an existing mock
 */
export function typeMock<T>(mock: any): MockedObject<T> {
  return mock as MockedObject<T>
}

/**
 * Helper to create a mock with specific return values for different calls
 * Enhanced with better type handling for promises
 */
export function createMockWithSequentialReturns<T extends AnyFunction>(
  returns: Array<ReturnType<T>>
): MockedFunction<T> {
  const mock = jest.fn() as MockedFunction<T>
  returns.forEach((returnValue) => {
    if (returnValue && typeof returnValue === 'object' && 'then' in returnValue) {
      // Handle promise-like objects
      mock.mockResolvedValueOnce(returnValue)
    } else {
      mock.mockReturnValueOnce(returnValue)
    }
  })
  return mock
}

/**
 * Helper to reset all mocks in an object
 */
export function resetMockObject<T extends Record<string, any>>(mockObject: MockedObject<T>): void {
  Object.values(mockObject).forEach((value) => {
    if (jest.isMockFunction(value)) {
      value.mockReset()
    }
  })
}

/**
 * Helper to clear all mocks in an object
 */
export function clearMockObject<T extends Record<string, any>>(mockObject: MockedObject<T>): void {
  Object.values(mockObject).forEach((value) => {
    if (jest.isMockFunction(value)) {
      value.mockClear()
    }
  })
}

/**
 * Creates a mock for SQL/database operations
 * Enhanced with proper typing for database operations
 */
export function createSqlMock() {
  return {
    unsafe: createMockFunction<(query: string, ...params: any[]) => Promise<any>>(),
    begin: createMockFunction<(callback: (sql: any) => Promise<any>) => Promise<any>>(),
    end: createMockFunction<() => Promise<void>>(),
    query: createMockFunction<(query: string, params?: any[]) => Promise<any>>(),
    connect: createMockFunction<() => Promise<any>>(),
    release: createMockFunction<() => Promise<void>>(),
  }
}

/**
 * Creates a properly typed fetch mock
 * Addresses common fetch mocking issues with complete Response interface
 */
export function createFetchMock(defaultResponse?: any): MockedFunction<typeof fetch> {
  const mockFetch = jest.fn() as MockedFunction<typeof fetch>

  if (defaultResponse) {
    mockFetch.mockResolvedValue(createMockResponse(defaultResponse))
  }

  return mockFetch
}

/**
 * Creates a complete mock Response object with all required properties
 */
export function createMockResponse(data?: any, init: ResponseInit = {}): MockResponse {
  const status = init.status || 200
  const statusText = init.statusText || 'OK'
  const headers = new Headers(init.headers)

  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    headers,
    redirected: false,
    type: 'basic' as ResponseType,
    url: 'https://test.example.com',
    body: null,
    bodyUsed: false,
    json: jest.fn().mockResolvedValue(data || {}),
    text: jest.fn().mockResolvedValue(typeof data === 'string' ? data : JSON.stringify(data || {})),
    blob: jest.fn().mockResolvedValue(new Blob()),
    arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(0)),
    formData: jest.fn().mockResolvedValue(new FormData()),
    clone: jest.fn().mockReturnValue({} as Response),
  } as MockResponse
}

/**
 * Creates a mock for React component props with proper typing
 */
export function createComponentPropsMock<T extends Record<string, any>>(
  props: Partial<T> = {}
): T {
  return props as T
}

/**
 * Creates a mock for context providers
 */
export function createContextMock<T>(value: Partial<T>): T {
  return value as T
}

/**
 * Creates a mock for bcrypt operations
 */
export function createBcryptMock() {
  return {
    hash: createMockFunction<(data: string, saltOrRounds: string | number) => Promise<string>>(),
    compare: createMockFunction<(data: string, encrypted: string) => Promise<boolean>>(),
    genSalt: createMockFunction<(rounds?: number) => Promise<string>>(),
    hashSync: createMockFunction<(data: string, saltOrRounds: string | number) => string>(),
    compareSync: createMockFunction<(data: string, encrypted: string) => boolean>(),
    genSaltSync: createMockFunction<(rounds?: number) => string>(),
  }
}

/**
 * Creates a mock for environment variables that handles read-only properties
 */
export function createEnvMock(envVars: Record<string, string>) {
  const originalEnv = process.env

  beforeEach(() => {
    // Use Object.defineProperty to handle read-only properties
    Object.keys(envVars).forEach(key => {
      Object.defineProperty(process.env, key, {
        value: envVars[key],
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

  return {
    setEnv: (key: string, value: string) => {
      Object.defineProperty(process.env, key, {
        value,
        writable: true,
        configurable: true,
      })
    },
    getEnv: (key: string) => process.env[key],
    resetEnv: () => {
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
    },
  }
}

/**
 * Helper to safely mock NODE_ENV and other read-only environment variables
 */
export function mockNodeEnv(env: string): () => void {
  const originalEnv = process.env.NODE_ENV

  // Set the environment immediately
  Object.defineProperty(process.env, 'NODE_ENV', {
    value: env,
    writable: true,
    configurable: true,
  })

  // Return a restore function
  return () => {
    Object.defineProperty(process.env, 'NODE_ENV', {
      value: originalEnv,
      writable: true,
      configurable: true,
    })
  }
}

/**
 * Helper to safely mock navigator.onLine property
 */
export function mockNavigatorOnline(isOnline: boolean = true) {
  const originalOnline = navigator.onLine

  beforeEach(() => {
    Object.defineProperty(navigator, 'onLine', {
      value: isOnline,
      writable: true,
      configurable: true,
    })
  })

  afterEach(() => {
    Object.defineProperty(navigator, 'onLine', {
      value: originalOnline,
      writable: false,
      configurable: true,
    })
  })

  return {
    setOnline: (online: boolean) => {
      Object.defineProperty(navigator, 'onLine', {
        value: online,
        writable: true,
        configurable: true,
      })
    }
  }
}

/**
 * Helper to safely access array elements with null checks
 */
export function safeArrayAccess<T>(array: T[] | undefined | null, index: number): T | undefined {
  return array && array.length > index ? array[index] : undefined
}

/**
 * Helper to create type-safe array access expectations
 */
export function expectArrayElement<T>(array: T[] | undefined | null, index: number): T {
  expect(array).toBeDefined()
  expect(array).not.toBeNull()
  expect(array!.length).toBeGreaterThan(index)
  return array![index]
}

/**
 * Creates a mock for browser APIs (IntersectionObserver, ResizeObserver, etc.)
 */
export function createBrowserApiMock<T extends new (...args: any[]) => any>(
  ApiConstructor: T,
  mockImplementation: Partial<InstanceType<T>> = {}
): MockedClass<T> {
  return jest.fn().mockImplementation(() => mockImplementation) as MockedClass<T>
}

/**
 * Helper to create properly typed mocks for common patterns
 */
export const mockHelpers = {
  // Common function types
  asyncFunction: <T = any>() => createMockResolvedFunction<() => Promise<T>>(),
  syncFunction: <T = any>() => createMockFunction<() => T>(),

  // Common object patterns
  eventHandler: () => createMockFunction<(event: Event) => void>(),
  callback: <T = any>() => createMockFunction<(value: T) => void>(),

  // API patterns
  apiResponse: <T = any>(data?: T) => createMockResponse(data),

  // Error patterns
  rejectedPromise: (error: any = new Error('Mock error')) =>
    createMockRejectedFunction<() => Promise<never>>(error),

  // Safe array access
  safeGet: <T>(array: T[] | undefined | null, index: number) => safeArrayAccess(array, index),
  expectGet: <T>(array: T[] | undefined | null, index: number) => expectArrayElement(array, index),

  // Mock Response patterns
  successResponse: (data?: any) => createMockResponse(data, { status: 200 }),
  errorResponse: (error?: any, status: number = 500) => createMockResponse(error, { status }),

  // Mock Headers
  headers: (init?: HeadersInit) => new Headers(init),
}

/**
 * Export all types and helpers for easy importing
 */
export {
  jest,
  type AnyFunction,
  type AsyncFunction,
}
