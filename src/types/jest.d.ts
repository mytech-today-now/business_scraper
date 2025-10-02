/**
 * Jest TypeScript Declaration File
 * 
 * Comprehensive TypeScript declarations for Jest globals, custom matchers,
 * and mock types to improve IntelliSense and type safety in test files.
 */

/// <reference types="jest" />
/// <reference types="@testing-library/jest-dom" />

import { jest } from '@jest/globals'

declare global {
  // Extend Jest namespace with custom matchers and utilities
  namespace jest {
    interface Matchers<R> {
      // Custom matchers for business scraper specific assertions
      toBeValidBusinessRecord(): R
      toBeValidEmailAddress(): R
      toBeValidPhoneNumber(): R
      toBeValidUrl(): R
      toHaveValidAddress(): R
      toBeWithinTimeRange(start: Date, end: Date): R
      toMatchBusinessSchema(): R
      toHaveValidIndustryCategory(): R
      toBeValidSearchResult(): R
      toHaveValidContactInfo(): R
    }

    interface Expect {
      // Enhanced expect utilities
      objectContaining<T = any>(sample: Partial<T>): any
      arrayContaining<T = any>(sample: Array<T>): any
      stringMatching(regexp: string | RegExp): any
      stringContaining(str: string): any
      any(constructor: any): any
      anything(): any
    }

    // Enhanced mock function types with better constraints
    interface MockedFunction<T extends (...args: any[]) => any> {
      (...args: Parameters<T>): ReturnType<T>
      mockReturnValue(value: ReturnType<T>): this
      mockReturnValueOnce(value: ReturnType<T>): this
      mockResolvedValue(value: Awaited<ReturnType<T>>): this
      mockResolvedValueOnce(value: Awaited<ReturnType<T>>): this
      mockRejectedValue(value: any): this
      mockRejectedValueOnce(value: any): this
      mockImplementation(fn?: T): this
      mockImplementationOnce(fn: T): this
      mockName(name: string): this
      mockClear(): this
      mockReset(): this
      mockRestore(): this
      getMockName(): string
      mock: MockContext<T>
    }

    interface MockContext<T extends (...args: any[]) => any> {
      calls: Array<Parameters<T>>
      instances: Array<ReturnType<T>>
      invocationCallOrder: number[]
      results: Array<{
        type: 'return' | 'throw' | 'incomplete'
        value: ReturnType<T>
      }>
      lastCall?: Parameters<T>
    }

    // Enhanced Mocked type for better object mocking
    type Mocked<T> = {
      [K in keyof T]: T[K] extends (...args: any[]) => any
        ? MockedFunction<T[K]>
        : T[K] extends object
        ? Mocked<T[K]>
        : T[K]
    } & T

    // Mock class type
    interface MockedClass<T extends new (...args: any[]) => any> {
      new (...args: ConstructorParameters<T>): Mocked<InstanceType<T>>
      (...args: ConstructorParameters<T>): Mocked<InstanceType<T>>
      prototype: Mocked<InstanceType<T>>
      mock: MockContext<T>
      mockClear(): this
      mockReset(): this
      mockRestore(): this
      mockImplementation(fn?: T): this
      mockImplementationOnce(fn: T): this
      mockName(name: string): this
      getMockName(): string
    }
  }

  // Global test utilities and types
  namespace NodeJS {
    interface Global {
      // Mock utilities
      createMockFunction: <T extends (...args: any[]) => any>() => jest.MockedFunction<T>
      createMockObject: <T extends Record<string, any>>(
        mockImplementation?: Partial<T>
      ) => jest.Mocked<T>
      createMockResponse: (data?: any, init?: ResponseInit) => Response
      
      // Test data factories
      createMockBusinessRecord: (overrides?: Partial<any>) => any
      createMockUser: (overrides?: Partial<any>) => any
      createMockSearchResult: (overrides?: Partial<any>) => any
      
      // Common mock services
      mockStorageService: jest.Mocked<any>
      mockSearchService: jest.Mocked<any>
      mockEmailService: jest.Mocked<any>
      mockPaymentService: jest.Mocked<any>
    }
  }

  // Enhanced fetch mock type
  interface MockFetch extends jest.MockedFunction<typeof fetch> {
    mockResponseOnce(data: any, init?: ResponseInit): this
    mockRejectOnce(error: any): this
    mockResponse(data: any, init?: ResponseInit): this
    mockReject(error: any): this
  }

  // Mock Response interface with proper typing
  interface MockResponse extends Response {
    json: jest.MockedFunction<() => Promise<any>>
    text: jest.MockedFunction<() => Promise<string>>
    blob: jest.MockedFunction<() => Promise<Blob>>
    arrayBuffer: jest.MockedFunction<() => Promise<ArrayBuffer>>
    formData: jest.MockedFunction<() => Promise<FormData>>
    clone: jest.MockedFunction<() => Response>
  }

  // Mock NextRequest and NextResponse types
  interface MockNextRequest {
    url: string
    method: string
    headers: Headers
    body?: any
    cookies: {
      get: jest.MockedFunction<(name: string) => { value: string } | undefined>
      set: jest.MockedFunction<(name: string, value: string) => void>
      delete: jest.MockedFunction<(name: string) => void>
      has: jest.MockedFunction<(name: string) => boolean>
      getAll: jest.MockedFunction<() => Array<{ name: string; value: string }>>
    }
    json: jest.MockedFunction<() => Promise<any>>
    text: jest.MockedFunction<() => Promise<string>>
    formData: jest.MockedFunction<() => Promise<FormData>>
    clone: jest.MockedFunction<() => MockNextRequest>
  }

  interface MockNextResponse {
    status: number
    headers: Headers
    json: jest.MockedFunction<() => Promise<any>>
    text: jest.MockedFunction<() => Promise<string>>
    ok: boolean
  }

  // Global variables for test environment
  const fetch: MockFetch
  const NextRequest: new (url: string, init?: any) => MockNextRequest
  const NextResponse: {
    json: jest.MockedFunction<(data: any, init?: any) => MockNextResponse>
    redirect: jest.MockedFunction<(url: string, status?: number) => MockNextResponse>
  }

  // Test environment configuration
  interface TestEnvironment {
    NODE_ENV: 'test'
    DATABASE_URL: string
    REDIS_URL: string
    ENCRYPTION_KEY: string
    JWT_SECRET: string
  }

  // Business scraper specific types for testing
  interface BusinessRecord {
    id: string
    businessName: string
    email: string[]
    phone: string
    websiteUrl: string
    address: {
      street: string
      city: string
      state: string
      zipCode: string
    }
    industry: string
    scrapedAt: Date
    website: string
  }

  interface SearchResult {
    title: string
    url: string
    snippet: string
    domain: string
    location: string
    phone?: string
    rating?: number
    reviewCount?: number
    category?: string
    source: string
  }

  interface User {
    id: string
    username: string
    email: string
    roles: string[]
    createdAt: Date
    updatedAt: Date
  }

  // API Response types for testing
  interface ApiResponse<T = any> {
    success: boolean
    data: T
    message: string
    timestamp: string
    error?: string
  }

  // Mock service interfaces
  interface MockStorageService {
    initialize: jest.MockedFunction<() => Promise<void>>
    saveBusiness: jest.MockedFunction<(business: BusinessRecord) => Promise<void>>
    saveBusinesses: jest.MockedFunction<(businesses: BusinessRecord[]) => Promise<void>>
    getAllBusinesses: jest.MockedFunction<() => Promise<BusinessRecord[]>>
    getBusiness: jest.MockedFunction<(id: string) => Promise<BusinessRecord | null>>
    deleteBusiness: jest.MockedFunction<(id: string) => Promise<void>>
    clearBusinesses: jest.MockedFunction<() => Promise<void>>
  }

  interface MockSearchService {
    search: jest.MockedFunction<(query: string, options?: any) => Promise<SearchResult[]>>
    searchByLocation: jest.MockedFunction<(location: string, industry?: string) => Promise<SearchResult[]>>
    validateResult: jest.MockedFunction<(result: SearchResult) => boolean>
  }

  interface MockEmailService {
    sendEmail: jest.MockedFunction<(to: string, subject: string, body: string) => Promise<void>>
    validateEmail: jest.MockedFunction<(email: string) => boolean>
    extractEmails: jest.MockedFunction<(text: string) => string[]>
  }

  interface MockPaymentService {
    processPayment: jest.MockedFunction<(amount: number, token: string) => Promise<any>>
    createCustomer: jest.MockedFunction<(email: string) => Promise<any>>
    createSubscription: jest.MockedFunction<(customerId: string, priceId: string) => Promise<any>>
  }
}

// Export types for use in test files
export type {
  BusinessRecord,
  SearchResult,
  User,
  ApiResponse,
  MockStorageService,
  MockSearchService,
  MockEmailService,
  MockPaymentService,
  MockResponse,
  MockNextRequest,
  MockNextResponse,
  TestEnvironment
}
