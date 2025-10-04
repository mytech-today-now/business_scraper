/**
 * Mock Setup Utilities
 * 
 * Centralized mock setup and configuration for Jest tests.
 * Provides consistent mock patterns and cleanup procedures.
 */

import { jest } from '@jest/globals'
import {
  mockFactory,
  mockCleanup,
  setupStandardizedMocks,
  cleanupStandardizedMocks,
  StandardizedWebSocketMock,
  StandardizedEventSourceMock
} from './standardizedMocks'
import {
  setupExternalServiceMocks,
  cleanupExternalServiceMocks,
  externalServiceMockFactory
} from './externalServiceMocks'
import {
  setupComprehensiveCleanup,
  performComprehensiveCleanup,
  testIsolation,
  mockValidator,
  memoryDetector
} from './mockCleanup'

/**
 * Global Mock Setup
 * Sets up all standardized mocks for the test environment
 */
export function setupGlobalMocks(): void {
  // Setup standardized mocks
  setupStandardizedMocks()
  
  // Setup additional browser APIs
  setupBrowserAPIMocks()
  
  // Setup Node.js specific mocks
  setupNodeMocks()
  
  // Setup external service mocks
  setupExternalServiceMocksInternal()
}

/**
 * Browser API Mocks
 * Comprehensive browser API mocking for consistent test environment
 */
export function setupBrowserAPIMocks(): void {
  // Navigator mocks
  Object.defineProperty(navigator, 'onLine', {
    value: true,
    writable: true,
    configurable: true,
  })

  Object.defineProperty(navigator, 'userAgent', {
    value: 'Mozilla/5.0 (Test Environment)',
    writable: true,
    configurable: true,
  })

  // Location mock
  Object.defineProperty(window, 'location', {
    value: {
      href: 'http://localhost:3000',
      origin: 'http://localhost:3000',
      protocol: 'http:',
      host: 'localhost:3000',
      hostname: 'localhost',
      port: '3000',
      pathname: '/',
      search: '',
      hash: '',
      assign: jest.fn(),
      replace: jest.fn(),
      reload: jest.fn(),
    },
    writable: true,
    configurable: true,
  })

  // Storage mocks
  const createStorageMock = () => {
    const storage: Record<string, string> = {}
    return {
      getItem: jest.fn((key: string) => storage[key] || null),
      setItem: jest.fn((key: string, value: string) => {
        storage[key] = value
      }),
      removeItem: jest.fn((key: string) => {
        delete storage[key]
      }),
      clear: jest.fn(() => {
        Object.keys(storage).forEach(key => delete storage[key])
      }),
      get length() {
        return Object.keys(storage).length
      },
      key: jest.fn((index: number) => Object.keys(storage)[index] || null),
    }
  }

  Object.defineProperty(window, 'localStorage', {
    value: createStorageMock(),
    writable: true,
    configurable: true,
  })

  Object.defineProperty(window, 'sessionStorage', {
    value: createStorageMock(),
    writable: true,
    configurable: true,
  })

  // URL mocks
  global.URL.createObjectURL = jest.fn(() => 'mocked-object-url')
  global.URL.revokeObjectURL = jest.fn()

  // Blob mock
  global.Blob = jest.fn().mockImplementation((content, options) => ({
    size: content ? content.reduce((acc: number, item: any) => acc + item.length, 0) : 0,
    type: options?.type || '',
    slice: jest.fn(),
    stream: jest.fn(),
    text: jest.fn().mockResolvedValue(content ? content.join('') : ''),
    arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(0)),
  })) as any

  // File mock
  global.File = jest.fn().mockImplementation((content, name, options) => ({
    ...new (global.Blob as any)(content, options),
    name,
    lastModified: Date.now(),
    webkitRelativePath: '',
  })) as any

  // FileReader mock
  global.FileReader = jest.fn().mockImplementation(() => ({
    readAsText: jest.fn(function(this: any, file: any) {
      setTimeout(() => {
        this.result = 'mocked file content'
        if (this.onload) this.onload({ target: this })
      }, 0)
    }),
    readAsDataURL: jest.fn(function(this: any, file: any) {
      setTimeout(() => {
        this.result = 'data:text/plain;base64,bW9ja2VkIGZpbGUgY29udGVudA=='
        if (this.onload) this.onload({ target: this })
      }, 0)
    }),
    readAsArrayBuffer: jest.fn(function(this: any, file: any) {
      setTimeout(() => {
        this.result = new ArrayBuffer(0)
        if (this.onload) this.onload({ target: this })
      }, 0)
    }),
    abort: jest.fn(),
    result: null,
    error: null,
    readyState: 0,
    onload: null,
    onerror: null,
    onabort: null,
    onloadstart: null,
    onloadend: null,
    onprogress: null,
  })) as any

  // Notification mock
  global.Notification = jest.fn().mockImplementation((title: string, options?: any) => ({
    title,
    body: options?.body || '',
    icon: options?.icon || '',
    tag: options?.tag || '',
    close: jest.fn(),
    onclick: null,
    onclose: null,
    onerror: null,
    onshow: null,
  })) as any

  Object.defineProperty(global.Notification, 'permission', {
    value: 'granted',
    writable: true,
  })

  Object.defineProperty(global.Notification, 'requestPermission', {
    value: jest.fn().mockResolvedValue('granted'),
    writable: true,
  })

  // Observer mocks
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }))

  global.IntersectionObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
    root: null,
    rootMargin: '',
    thresholds: [],
  }))

  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn(),
    takeRecords: jest.fn(() => []),
  }))

  // Media query mock
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation(query => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  })

  // Animation frame mocks
  global.requestAnimationFrame = jest.fn(cb => setTimeout(cb, 0))
  global.cancelAnimationFrame = jest.fn(id => clearTimeout(id))

  // Performance mock
  Object.defineProperty(window, 'performance', {
    value: {
      now: jest.fn(() => Date.now()),
      mark: jest.fn(),
      measure: jest.fn(),
      getEntriesByType: jest.fn(() => []),
      getEntriesByName: jest.fn(() => []),
      clearMarks: jest.fn(),
      clearMeasures: jest.fn(),
    },
    writable: true,
    configurable: true,
  })
}

/**
 * Node.js Specific Mocks
 * Mocks for Node.js APIs used in the application
 */
export function setupNodeMocks(): void {
  // Process mock enhancements
  if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'test'
  }

  // Console mock to reduce noise
  const originalConsole = { ...console }
  global.console = {
    ...originalConsole,
    log: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }

  // Crypto mock for Node.js
  if (typeof global.crypto === 'undefined') {
    global.crypto = {
      getRandomValues: jest.fn((arr: any) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256)
        }
        return arr
      }),
      randomUUID: jest.fn(() => 'mocked-uuid-' + Date.now()),
    } as any
  }
}

/**
 * External Service Mocks Setup
 * Configure mocks for external services
 */
export function setupExternalServiceMocksInternal(): void {
  // Setup external service mocks
  setupExternalServiceMocks()

  // Create and register service mocks
  const stripeMock = externalServiceMockFactory.createStripeMock()
  const geocodingMock = externalServiceMockFactory.createGeocodingMock()
  const databaseMock = externalServiceMockFactory.createDatabaseMock()

  // Register service mocks globally for access in tests
  mockCleanup.setGlobalMockState('stripe', stripeMock)
  mockCleanup.setGlobalMockState('geocoding', geocodingMock)
  mockCleanup.setGlobalMockState('database', databaseMock)
}

/**
 * Test Cleanup Utilities
 * Comprehensive cleanup for test isolation
 */
export function setupTestCleanup(): void {
  // Use comprehensive cleanup system
  setupComprehensiveCleanup()
}

/**
 * Mock Verification Utilities
 * Helper functions for verifying mock behavior
 */
export const mockVerification = {
  // Verify WebSocket mock behavior
  verifyWebSocketMock: (mockInstance: StandardizedWebSocketMock) => ({
    wasConnected: () => mockInstance.readyState === StandardizedWebSocketMock.OPEN,
    wasClosed: () => mockInstance.readyState === StandardizedWebSocketMock.CLOSED,
    messagesSent: () => jest.mocked(mockInstance.send).mock.calls.length,
    eventsTriggered: (eventType: string) => {
      // This would need to be enhanced based on actual implementation
      return true
    },
  }),

  // Verify HTTP mock behavior
  verifyHttpMock: () => {
    const httpMock = mockFactory.createHttpMock()
    return {
      requestCount: () => httpMock.getRequestHistory().length,
      lastRequest: () => {
        const history = httpMock.getRequestHistory()
        return history[history.length - 1]
      },
      requestsForUrl: (url: string) => 
        httpMock.getRequestHistory().filter(req => req.url === url),
    }
  },

  // Verify database mock behavior
  verifyDatabaseMock: () => {
    const dbMock = mockFactory.createDatabaseMock()
    return {
      queryCount: () => dbMock.getQueryHistory().length,
      lastQuery: () => {
        const history = dbMock.getQueryHistory()
        return history[history.length - 1]
      },
      queriesForTable: (tableName: string) =>
        dbMock.getQueryHistory().filter(query => 
          query.sql.toLowerCase().includes(tableName.toLowerCase())
        ),
    }
  },
}

// Export main setup function
export const setupMockEnvironment = () => {
  setupGlobalMocks()
  setupTestCleanup()
}

// Export external service mock creation functions
export const createStripeMock = () => externalServiceMockFactory.createStripeMock()
export const createGeocodingMock = () => externalServiceMockFactory.createGeocodingMock()
export const createDatabaseMock = (maxConnections?: number) =>
  externalServiceMockFactory.createDatabaseMock(maxConnections)

// Export standardized mock creation functions
export const createStandardizedHttpMock = () => mockFactory.createHttpMock()
export const createStandardizedWebSocketMock = () => mockFactory.createWebSocketMock()
export const createStandardizedEventSourceMock = () => mockFactory.createEventSourceMock()

// Export verification utilities
export const verifyExternalServiceMocks = {
  stripe: () => {
    const stripeMock = externalServiceMockFactory.getStripeMock()
    return {
      paymentIntentCreated: (id: string) => stripeMock?.getPaymentIntent(id) !== undefined,
      customerCreated: (id: string) => stripeMock?.getCustomer(id) !== undefined,
      webhookEventsCount: () => stripeMock?.getWebhookEvents().length || 0,
    }
  },

  geocoding: () => {
    const geocodingMock = externalServiceMockFactory.getGeocodingMock()
    return {
      geocodeCallCount: () => geocodingMock?.getGeocodeHistory().length || 0,
      lastGeocodedAddress: () => {
        const history = geocodingMock?.getGeocodeHistory() || []
        return history[history.length - 1]?.address
      },
    }
  },

  database: () => {
    const databaseMock = externalServiceMockFactory.getDatabaseMock()
    return {
      queryCount: () => databaseMock?.getQueryHistory().length || 0,
      connectionStats: () => databaseMock?.getConnectionStats(),
      lastQuery: () => {
        const history = databaseMock?.getQueryHistory() || []
        return history[history.length - 1]
      },
    }
  },
}

// Export cleanup utilities
export { cleanupUtils } from './mockCleanup'
