/**
 * Standardized Mock Utilities
 * 
 * Comprehensive mock utilities for consistent mocking patterns across all test files.
 * This addresses mock reliability enhancement requirements.
 */

import { jest } from '@jest/globals'
import { 
  MockedFunction, 
  createMockFunction, 
  createMockResolvedFunction,
  createMockResponse
} from './mockTypeHelpers'

/**
 * WebSocket Mock Implementation
 * Standardized WebSocket mock for streaming functionality tests
 */
export class StandardizedWebSocketMock {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  readyState = StandardizedWebSocketMock.CONNECTING
  url: string
  protocol?: string
  
  // Event handlers
  onopen: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  // Event listener management
  private eventListeners: Map<string, Set<EventListener>> = new Map()

  constructor(url: string, protocols?: string | string[]) {
    this.url = url
    this.protocol = Array.isArray(protocols) ? protocols[0] : protocols
    
    // Initialize event listener sets
    this.eventListeners.set('open', new Set())
    this.eventListeners.set('close', new Set())
    this.eventListeners.set('message', new Set())
    this.eventListeners.set('error', new Set())
    
    // Simulate connection opening after a short delay
    setTimeout(() => {
      this.readyState = StandardizedWebSocketMock.OPEN
      this.triggerEvent('open', new Event('open'))
    }, 10)
  }

  send(data: string | ArrayBuffer | Blob | ArrayBufferView): void {
    if (this.readyState !== StandardizedWebSocketMock.OPEN) {
      throw new Error('WebSocket is not open')
    }
    // Mock send implementation - can be extended for testing
  }

  close(code?: number, reason?: string): void {
    this.readyState = StandardizedWebSocketMock.CLOSING
    setTimeout(() => {
      this.readyState = StandardizedWebSocketMock.CLOSED
      const closeEvent = new CloseEvent('close', { 
        code: code || 1000, 
        reason: reason || 'Normal closure' 
      })
      this.triggerEvent('close', closeEvent)
    }, 5)
  }

  addEventListener(type: string, listener: EventListener): void {
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.add(listener)
    }
  }

  removeEventListener(type: string, listener: EventListener): void {
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.delete(listener)
    }
  }

  dispatchEvent(event: Event): boolean {
    this.triggerEvent(event.type, event)
    return true
  }

  // Helper methods for testing
  simulateMessage(data: any): void {
    if (this.readyState === StandardizedWebSocketMock.OPEN) {
      const messageEvent = new MessageEvent('message', { 
        data: typeof data === 'string' ? data : JSON.stringify(data) 
      })
      this.triggerEvent('message', messageEvent)
    }
  }

  simulateError(error?: string): void {
    const errorEvent = new Event('error')
    this.triggerEvent('error', errorEvent)
  }

  simulateClose(code: number = 1000, reason: string = 'Test closure'): void {
    this.close(code, reason)
  }

  private triggerEvent(type: string, event: Event): void {
    // Trigger direct event handler
    switch (type) {
      case 'open':
        if (this.onopen) this.onopen(event)
        break
      case 'close':
        if (this.onclose) this.onclose(event as CloseEvent)
        break
      case 'message':
        if (this.onmessage) this.onmessage(event as MessageEvent)
        break
      case 'error':
        if (this.onerror) this.onerror(event)
        break
    }

    // Trigger event listeners
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.forEach(listener => listener(event))
    }
  }

  // Reset method for test cleanup
  reset(): void {
    this.readyState = StandardizedWebSocketMock.CONNECTING
    this.onopen = null
    this.onclose = null
    this.onmessage = null
    this.onerror = null
    this.eventListeners.forEach(listeners => listeners.clear())
  }
}

/**
 * EventSource Mock Implementation
 * Standardized EventSource mock for real-time updates
 */
export class StandardizedEventSourceMock {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSED = 2

  readyState = StandardizedEventSourceMock.CONNECTING
  url: string
  withCredentials: boolean

  // Event handlers
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  // Event listener management
  private eventListeners: Map<string, Set<EventListener>> = new Map()

  constructor(url: string, eventSourceInitDict?: EventSourceInit) {
    this.url = url
    this.withCredentials = eventSourceInitDict?.withCredentials || false
    
    // Initialize event listener sets
    this.eventListeners.set('open', new Set())
    this.eventListeners.set('message', new Set())
    this.eventListeners.set('error', new Set())
    
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = StandardizedEventSourceMock.OPEN
      this.triggerEvent('open', new Event('open'))
    }, 10)
  }

  close(): void {
    this.readyState = StandardizedEventSourceMock.CLOSED
  }

  addEventListener(type: string, listener: EventListener): void {
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.add(listener)
    }
  }

  removeEventListener(type: string, listener: EventListener): void {
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.delete(listener)
    }
  }

  dispatchEvent(event: Event): boolean {
    this.triggerEvent(event.type, event)
    return true
  }

  // Helper methods for testing
  simulateMessage(data: any, eventType?: string): void {
    if (this.readyState === StandardizedEventSourceMock.OPEN) {
      const messageEvent = new MessageEvent(eventType || 'message', { 
        data: typeof data === 'string' ? data : JSON.stringify(data) 
      })
      this.triggerEvent('message', messageEvent)
    }
  }

  simulateError(): void {
    const errorEvent = new Event('error')
    this.triggerEvent('error', errorEvent)
  }

  private triggerEvent(type: string, event: Event): void {
    // Trigger direct event handler
    switch (type) {
      case 'open':
        if (this.onopen) this.onopen(event)
        break
      case 'message':
        if (this.onmessage) this.onmessage(event as MessageEvent)
        break
      case 'error':
        if (this.onerror) this.onerror(event)
        break
    }

    // Trigger event listeners
    const listeners = this.eventListeners.get(type)
    if (listeners) {
      listeners.forEach(listener => listener(event))
    }
  }

  // Reset method for test cleanup
  reset(): void {
    this.readyState = StandardizedEventSourceMock.CONNECTING
    this.onopen = null
    this.onmessage = null
    this.onerror = null
    this.eventListeners.forEach(listeners => listeners.clear())
  }
}

/**
 * HTTP Client Mock Factory
 * Standardized HTTP request/response mocking
 */
export class StandardizedHttpMock {
  private static instance: StandardizedHttpMock
  private mockResponses: Map<string, any> = new Map()
  private requestHistory: Array<{ method: string; url: string; data?: any; config?: any }> = []

  static getInstance(): StandardizedHttpMock {
    if (!StandardizedHttpMock.instance) {
      StandardizedHttpMock.instance = new StandardizedHttpMock()
    }
    return StandardizedHttpMock.instance
  }

  // Configure mock responses
  mockResponse(method: string, url: string, response: any): void {
    const key = `${method.toUpperCase()}:${url}`
    this.mockResponses.set(key, response)
  }

  // Create mock HTTP client
  createMockClient() {
    return {
      get: this.createMethodMock('GET'),
      post: this.createMethodMock('POST'),
      put: this.createMethodMock('PUT'),
      delete: this.createMethodMock('DELETE'),
      patch: this.createMethodMock('PATCH'),
      head: this.createMethodMock('HEAD'),
      options: this.createMethodMock('OPTIONS'),
    }
  }

  private createMethodMock(method: string) {
    return jest.fn(async (url: string, data?: any, config?: any) => {
      // Record request
      this.requestHistory.push({ method, url, data, config })
      
      // Find mock response
      const key = `${method}:${url}`
      const response = this.mockResponses.get(key)
      
      if (response) {
        if (response instanceof Error) {
          throw response
        }
        return response
      }
      
      // Default response
      return { data: {}, status: 200, statusText: 'OK' }
    })
  }

  // Get request history for verification
  getRequestHistory(): Array<{ method: string; url: string; data?: any; config?: any }> {
    return [...this.requestHistory]
  }

  // Reset all mocks
  reset(): void {
    this.mockResponses.clear()
    this.requestHistory.length = 0
  }
}

/**
 * Database Mock Factory
 * Standardized database operation mocking
 */
export class StandardizedDatabaseMock {
  private mockData: Map<string, any[]> = new Map()
  private queryHistory: Array<{ sql: string; params?: any[]; timestamp: Date }> = []
  private connectionPool: Array<{ id: string; connected: boolean }> = []

  constructor() {
    // Initialize connection pool
    for (let i = 0; i < 5; i++) {
      this.connectionPool.push({ id: `conn_${i}`, connected: true })
    }
  }

  // Mock query method
  query = jest.fn(async (sql: string, params?: any[]) => {
    // Record query
    this.queryHistory.push({ sql, params, timestamp: new Date() })

    // Simulate query execution time
    await new Promise(resolve => setTimeout(resolve, Math.random() * 10))

    // Parse SQL to determine operation
    const operation = sql.trim().split(' ')[0].toUpperCase()
    const tableName = this.extractTableName(sql)

    switch (operation) {
      case 'SELECT':
        return {
          rows: this.mockData.get(tableName) || [],
          rowCount: this.mockData.get(tableName)?.length || 0,
          command: 'SELECT',
          executionTime: Math.random() * 100,
        }

      case 'INSERT':
        const insertData = this.mockData.get(tableName) || []
        const newRow = { id: Date.now(), ...params }
        insertData.push(newRow)
        this.mockData.set(tableName, insertData)
        return {
          rows: [newRow],
          rowCount: 1,
          command: 'INSERT',
          executionTime: Math.random() * 50,
        }

      case 'UPDATE':
        const updateData = this.mockData.get(tableName) || []
        const updatedRows = updateData.map(row => ({ ...row, ...params }))
        this.mockData.set(tableName, updatedRows)
        return {
          rows: updatedRows,
          rowCount: updatedRows.length,
          command: 'UPDATE',
          executionTime: Math.random() * 75,
        }

      case 'DELETE':
        this.mockData.delete(tableName)
        return {
          rows: [],
          rowCount: 0,
          command: 'DELETE',
          executionTime: Math.random() * 25,
        }

      default:
        return {
          rows: [],
          rowCount: 0,
          command: operation,
          executionTime: Math.random() * 10,
        }
    }
  })

  // Mock connection method
  connect = jest.fn(async () => {
    const availableConnection = this.connectionPool.find(conn => conn.connected)
    if (!availableConnection) {
      throw new Error('No available database connections')
    }

    return {
      query: this.query,
      release: jest.fn(() => {
        availableConnection.connected = true
      }),
      end: jest.fn(),
    }
  })

  // Helper methods
  addMockData(tableName: string, data: any[]): void {
    this.mockData.set(tableName, data)
  }

  getMockData(tableName: string): any[] {
    return this.mockData.get(tableName) || []
  }

  getQueryHistory(): Array<{ sql: string; params?: any[]; timestamp: Date }> {
    return [...this.queryHistory]
  }

  private extractTableName(sql: string): string {
    // Simple table name extraction - can be enhanced
    const match = sql.match(/(?:FROM|INTO|UPDATE)\s+(\w+)/i)
    return match ? match[1].toLowerCase() : 'unknown'
  }

  // Reset method
  reset(): void {
    this.mockData.clear()
    this.queryHistory.length = 0
    this.connectionPool.forEach(conn => conn.connected = true)
    jest.clearAllMocks()
  }
}

/**
 * External Service Mock Factory
 * Standardized external service mocking (Stripe, geocoding, etc.)
 */
export class StandardizedExternalServiceMock {
  private serviceMocks: Map<string, any> = new Map()

  // Stripe Payment Mock
  createStripeMock() {
    const stripeMock = {
      paymentIntents: {
        create: jest.fn(async (params: any) => ({
          id: `pi_test_${Date.now()}`,
          amount: params.amount,
          currency: params.currency || 'usd',
          status: 'requires_payment_method',
          client_secret: `pi_test_${Date.now()}_secret_test`,
          created: Math.floor(Date.now() / 1000),
        })),

        confirm: jest.fn(async (id: string) => ({
          id,
          status: 'succeeded',
          charges: {
            data: [{
              id: `ch_test_${Date.now()}`,
              amount: 2000,
              currency: 'usd',
              status: 'succeeded',
            }]
          }
        })),

        retrieve: jest.fn(async (id: string) => ({
          id,
          status: 'succeeded',
          amount: 2000,
          currency: 'usd',
        })),
      },

      customers: {
        create: jest.fn(async (params: any) => ({
          id: `cus_test_${Date.now()}`,
          email: params.email,
          created: Math.floor(Date.now() / 1000),
        })),

        retrieve: jest.fn(async (id: string) => ({
          id,
          email: 'test@example.com',
          created: Math.floor(Date.now() / 1000),
        })),
      },

      webhooks: {
        constructEvent: jest.fn((payload: any, signature: string, secret: string) => ({
          id: `evt_test_${Date.now()}`,
          type: 'payment_intent.succeeded',
          data: {
            object: {
              id: 'pi_test_123',
              status: 'succeeded',
            }
          }
        })),
      },
    }

    this.serviceMocks.set('stripe', stripeMock)
    return stripeMock
  }

  // Geocoding Service Mock
  createGeocodingMock() {
    const geocodingMock = {
      geocode: jest.fn(async (address: string) => ({
        results: [{
          formatted_address: address,
          geometry: {
            location: {
              lat: 40.7128,
              lng: -74.0060,
            }
          },
          place_id: `place_test_${Date.now()}`,
        }],
        status: 'OK',
      })),

      reverseGeocode: jest.fn(async (lat: number, lng: number) => ({
        results: [{
          formatted_address: '123 Test St, Test City, TS 12345',
          geometry: {
            location: { lat, lng }
          },
          place_id: `place_test_${Date.now()}`,
        }],
        status: 'OK',
      })),
    }

    this.serviceMocks.set('geocoding', geocodingMock)
    return geocodingMock
  }

  // File System Mock
  createFileSystemMock() {
    const fileSystemMock = {
      readFile: jest.fn(async (path: string) => {
        if (path.includes('test')) {
          return Buffer.from('test file content')
        }
        throw new Error('File not found')
      }),

      writeFile: jest.fn(async (path: string, data: any) => {
        // Mock successful write
        return true
      }),

      unlink: jest.fn(async (path: string) => {
        // Mock successful delete
        return true
      }),

      mkdir: jest.fn(async (path: string) => {
        // Mock successful directory creation
        return true
      }),

      stat: jest.fn(async (path: string) => ({
        isFile: () => true,
        isDirectory: () => false,
        size: 1024,
        mtime: new Date(),
      })),
    }

    this.serviceMocks.set('filesystem', fileSystemMock)
    return fileSystemMock
  }

  // Get specific service mock
  getServiceMock(serviceName: string): any {
    return this.serviceMocks.get(serviceName)
  }

  // Reset all service mocks
  reset(): void {
    this.serviceMocks.forEach(mock => {
      if (typeof mock === 'object' && mock !== null) {
        Object.values(mock).forEach(service => {
          if (typeof service === 'object' && service !== null) {
            Object.values(service).forEach(method => {
              if (jest.isMockFunction(method)) {
                method.mockReset()
              }
            })
          }
        })
      }
    })
  }
}

/**
 * Mock Cleanup Manager
 * Centralized mock cleanup and state management
 */
export class MockCleanupManager {
  private static instance: MockCleanupManager
  private registeredMocks: Array<{ name: string; resetFn: () => void }> = []
  private globalMockState: Map<string, any> = new Map()

  static getInstance(): MockCleanupManager {
    if (!MockCleanupManager.instance) {
      MockCleanupManager.instance = new MockCleanupManager()
    }
    return MockCleanupManager.instance
  }

  // Register a mock for cleanup
  registerMock(name: string, resetFn: () => void): void {
    this.registeredMocks.push({ name, resetFn })
  }

  // Clean up all registered mocks
  cleanupAllMocks(): void {
    this.registeredMocks.forEach(({ name, resetFn }) => {
      try {
        resetFn()
      } catch (error) {
        console.warn(`Failed to reset mock ${name}:`, error)
      }
    })

    // Clear Jest mocks
    jest.clearAllMocks()
    jest.resetAllMocks()

    // Clear global state
    this.globalMockState.clear()
  }

  // Store global mock state
  setGlobalMockState(key: string, value: any): void {
    this.globalMockState.set(key, value)
  }

  // Get global mock state
  getGlobalMockState(key: string): any {
    return this.globalMockState.get(key)
  }

  // Reset specific mock by name
  resetMock(name: string): void {
    const mock = this.registeredMocks.find(m => m.name === name)
    if (mock) {
      mock.resetFn()
    }
  }

  // Get list of registered mocks
  getRegisteredMocks(): string[] {
    return this.registeredMocks.map(m => m.name)
  }
}

/**
 * Standardized Mock Factory
 * Main factory for creating all types of mocks
 */
export class StandardizedMockFactory {
  private static instance: StandardizedMockFactory
  private webSocketMock: StandardizedWebSocketMock | null = null
  private eventSourceMock: StandardizedEventSourceMock | null = null
  private httpMock: StandardizedHttpMock | null = null
  private databaseMock: StandardizedDatabaseMock | null = null
  private externalServiceMock: StandardizedExternalServiceMock | null = null
  private cleanupManager: MockCleanupManager

  constructor() {
    this.cleanupManager = MockCleanupManager.getInstance()
  }

  static getInstance(): StandardizedMockFactory {
    if (!StandardizedMockFactory.instance) {
      StandardizedMockFactory.instance = new StandardizedMockFactory()
    }
    return StandardizedMockFactory.instance
  }

  // Create WebSocket mock
  createWebSocketMock(): typeof StandardizedWebSocketMock {
    if (!this.webSocketMock) {
      this.cleanupManager.registerMock('websocket', () => {
        if (this.webSocketMock) {
          this.webSocketMock.reset()
        }
      })
    }
    return StandardizedWebSocketMock
  }

  // Create EventSource mock
  createEventSourceMock(): typeof StandardizedEventSourceMock {
    if (!this.eventSourceMock) {
      this.cleanupManager.registerMock('eventsource', () => {
        if (this.eventSourceMock) {
          this.eventSourceMock.reset()
        }
      })
    }
    return StandardizedEventSourceMock
  }

  // Create HTTP mock
  createHttpMock(): StandardizedHttpMock {
    if (!this.httpMock) {
      this.httpMock = StandardizedHttpMock.getInstance()
      this.cleanupManager.registerMock('http', () => {
        if (this.httpMock) {
          this.httpMock.reset()
        }
      })
    }
    return this.httpMock
  }

  // Create Database mock
  createDatabaseMock(): StandardizedDatabaseMock {
    if (!this.databaseMock) {
      this.databaseMock = new StandardizedDatabaseMock()
      this.cleanupManager.registerMock('database', () => {
        if (this.databaseMock) {
          this.databaseMock.reset()
        }
      })
    }
    return this.databaseMock
  }

  // Create External Service mock
  createExternalServiceMock(): StandardizedExternalServiceMock {
    if (!this.externalServiceMock) {
      this.externalServiceMock = new StandardizedExternalServiceMock()
      this.cleanupManager.registerMock('external-services', () => {
        if (this.externalServiceMock) {
          this.externalServiceMock.reset()
        }
      })
    }
    return this.externalServiceMock
  }

  // Reset all mocks
  resetAllMocks(): void {
    this.cleanupManager.cleanupAllMocks()
  }

  // Setup global mocks for Jest
  setupGlobalMocks(): void {
    // Setup WebSocket mock globally
    global.WebSocket = this.createWebSocketMock() as any

    // Setup EventSource mock globally
    global.EventSource = this.createEventSourceMock() as any

    // Setup fetch mock if not already mocked
    if (!global.fetch || !jest.isMockFunction(global.fetch)) {
      global.fetch = jest.fn()
    }
  }
}

// Export singleton instances for easy access
export const mockFactory = StandardizedMockFactory.getInstance()
export const mockCleanup = MockCleanupManager.getInstance()

// Export convenience functions
export const setupStandardizedMocks = () => mockFactory.setupGlobalMocks()
export const cleanupStandardizedMocks = () => mockFactory.resetAllMocks()
