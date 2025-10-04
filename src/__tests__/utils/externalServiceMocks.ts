/**
 * External Service Mocks
 * 
 * Comprehensive mocks for external services including Stripe, geocoding APIs,
 * database connections, and other third-party integrations.
 */

import { jest } from '@jest/globals'
import { mockCleanup } from './standardizedMocks'

/**
 * Stripe Service Mock
 * Comprehensive Stripe API mocking for payment processing tests
 */
export class StripeServiceMock {
  private paymentIntentsData: Map<string, any> = new Map()
  private customersData: Map<string, any> = new Map()
  private subscriptionsData: Map<string, any> = new Map()
  private webhookEvents: Array<any> = []

  // Payment Intents
  paymentIntents = {
    create: jest.fn(async (params: any) => {
      const id = `pi_test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      const paymentIntent = {
        id,
        object: 'payment_intent',
        amount: params.amount,
        currency: params.currency || 'usd',
        status: 'requires_payment_method',
        client_secret: `${id}_secret_test`,
        created: Math.floor(Date.now() / 1000),
        customer: params.customer || null,
        description: params.description || null,
        metadata: params.metadata || {},
        automatic_payment_methods: params.automatic_payment_methods || null,
        setup_future_usage: params.setup_future_usage || null,
        payment_method: null,
        last_payment_error: null,
        next_action: null,
        receipt_email: null,
        shipping: null,
      }
      
      this.paymentIntentsData.set(id, paymentIntent)
      return paymentIntent
    }),

    retrieve: jest.fn(async (id: string) => {
      const paymentIntent = this.paymentIntentsData.get(id)
      if (!paymentIntent) {
        throw new Error(`No such payment_intent: ${id}`)
      }
      return paymentIntent
    }),

    update: jest.fn(async (id: string, params: any) => {
      const paymentIntent = this.paymentIntentsData.get(id)
      if (!paymentIntent) {
        throw new Error(`No such payment_intent: ${id}`)
      }

      const updated = { ...paymentIntent, ...params }
      this.paymentIntentsData.set(id, updated)
      return updated
    }),

    confirm: jest.fn(async (id: string, params?: any) => {
      const paymentIntent = this.paymentIntentsData.get(id)
      if (!paymentIntent) {
        throw new Error(`No such payment_intent: ${id}`)
      }

      const confirmed = {
        ...paymentIntent,
        status: 'succeeded',
        charges: {
          object: 'list',
          data: [{
            id: `ch_test_${Date.now()}`,
            object: 'charge',
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: 'succeeded',
            created: Math.floor(Date.now() / 1000),
          }]
        }
      }

      this.paymentIntentsData.set(id, confirmed)
      return confirmed
    }),

    cancel: jest.fn(async (id: string) => {
      const paymentIntent = this.paymentIntentsData.get(id)
      if (!paymentIntent) {
        throw new Error(`No such payment_intent: ${id}`)
      }

      const cancelled = { ...paymentIntent, status: 'canceled' }
      this.paymentIntentsData.set(id, cancelled)
      return cancelled
    }),
  }

  // Customers
  customers = {
    create: jest.fn(async (params: any) => {
      const id = `cus_test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      const customer = {
        id,
        object: 'customer',
        email: params.email || null,
        name: params.name || null,
        phone: params.phone || null,
        description: params.description || null,
        metadata: params.metadata || {},
        created: Math.floor(Date.now() / 1000),
        default_source: null,
        invoice_prefix: id.substr(4, 8).toUpperCase(),
        livemode: false,
      }
      
      this.customersData.set(id, customer)
      return customer
    }),

    retrieve: jest.fn(async (id: string) => {
      const customer = this.customersData.get(id)
      if (!customer) {
        throw new Error(`No such customer: ${id}`)
      }
      return customer
    }),

    update: jest.fn(async (id: string, params: any) => {
      const customer = this.customersData.get(id)
      if (!customer) {
        throw new Error(`No such customer: ${id}`)
      }

      const updated = { ...customer, ...params }
      this.customersData.set(id, updated)
      return updated
    }),

    delete: jest.fn(async (id: string) => {
      const customer = this.customersData.get(id)
      if (!customer) {
        throw new Error(`No such customer: ${id}`)
      }

      this.customersData.delete(id)
      return { id, object: 'customer', deleted: true }
    }),
  }

  // Subscriptions
  subscriptions = {
    create: jest.fn(async (params: any) => {
      const id = `sub_test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      const subscription = {
        id,
        object: 'subscription',
        customer: params.customer,
        status: 'active',
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 2592000, // 30 days
        created: Math.floor(Date.now() / 1000),
        items: {
          object: 'list',
          data: params.items || []
        },
        metadata: params.metadata || {},
      }
      
      this.subscriptionsData.set(id, subscription)
      return subscription
    }),

    retrieve: jest.fn(async (id: string) => {
      const subscription = this.subscriptionsData.get(id)
      if (!subscription) {
        throw new Error(`No such subscription: ${id}`)
      }
      return subscription
    }),

    update: jest.fn(async (id: string, params: any) => {
      const subscription = this.subscriptionsData.get(id)
      if (!subscription) {
        throw new Error(`No such subscription: ${id}`)
      }

      const updated = { ...subscription, ...params }
      this.subscriptionsData.set(id, updated)
      return updated
    }),

    cancel: jest.fn(async (id: string) => {
      const subscription = this.subscriptionsData.get(id)
      if (!subscription) {
        throw new Error(`No such subscription: ${id}`)
      }

      const cancelled = { ...subscription, status: 'canceled' }
      this.subscriptionsData.set(id, cancelled)
      return cancelled
    }),
  }

  // Webhooks
  webhooks = {
    constructEvent: jest.fn((payload: string | Buffer, signature: string, secret: string) => {
      const event = {
        id: `evt_test_${Date.now()}`,
        object: 'event',
        type: 'payment_intent.succeeded',
        created: Math.floor(Date.now() / 1000),
        data: {
          object: {
            id: 'pi_test_123',
            object: 'payment_intent',
            status: 'succeeded',
          }
        },
        livemode: false,
        pending_webhooks: 1,
        request: {
          id: `req_test_${Date.now()}`,
          idempotency_key: null,
        }
      }
      
      this.webhookEvents.push(event)
      return event
    }),
  }

  // Helper methods for testing
  getPaymentIntent(id: string) {
    return this.paymentIntentsData.get(id)
  }

  getCustomer(id: string) {
    return this.customersData.get(id)
  }

  getSubscription(id: string) {
    return this.subscriptionsData.get(id)
  }

  getWebhookEvents() {
    return [...this.webhookEvents]
  }

  // Simulate errors for testing
  simulateError(method: string, errorType: string = 'card_declined') {
    const errorMap: Record<string, any> = {
      card_declined: {
        type: 'card_error',
        code: 'card_declined',
        message: 'Your card was declined.',
        decline_code: 'generic_decline'
      },
      insufficient_funds: {
        type: 'card_error',
        code: 'card_declined',
        message: 'Your card has insufficient funds.',
        decline_code: 'insufficient_funds'
      },
      invalid_request: {
        type: 'invalid_request_error',
        message: 'Invalid request parameters.',
      },
      api_error: {
        type: 'api_error',
        message: 'An error occurred with our API.',
      }
    }

    const error = errorMap[errorType] || errorMap.api_error
    
    // Mock the specific method to throw this error
    if (method.includes('.')) {
      const [service, methodName] = method.split('.')
      if (this[service as keyof this] && typeof this[service as keyof this] === 'object') {
        const serviceObj = this[service as keyof this] as any
        if (serviceObj[methodName]) {
          serviceObj[methodName].mockRejectedValueOnce(error)
        }
      }
    }
  }

  // Reset all mocks
  reset() {
    // Clear data maps
    this.paymentIntentsData.clear()
    this.customersData.clear()
    this.subscriptionsData.clear()
    this.webhookEvents.length = 0

    // Reset Jest mocks for payment intents
    Object.values(this.paymentIntents).forEach(method => {
      if (jest.isMockFunction(method)) method.mockReset()
    })

    // Reset Jest mocks for customers
    Object.values(this.customers).forEach(method => {
      if (jest.isMockFunction(method)) method.mockReset()
    })

    // Reset Jest mocks for subscriptions
    Object.values(this.subscriptions).forEach(method => {
      if (jest.isMockFunction(method)) method.mockReset()
    })

    // Reset Jest mocks for webhooks
    Object.values(this.webhooks).forEach(method => {
      if (jest.isMockFunction(method)) method.mockReset()
    })
  }
}

/**
 * Geocoding Service Mock
 * Mock for various geocoding APIs (Google Maps, OpenCage, Nominatim)
 */
export class GeocodingServiceMock {
  private geocodeHistory: Array<{ address: string; result: any; timestamp: Date }> = []
  private mockResults: Map<string, any> = new Map()

  // Google Maps Geocoding API Mock
  googleMapsGeocode = jest.fn(async (address: string) => {
    const result = this.mockResults.get(address) || this.getDefaultGeocodingResult(address)
    this.geocodeHistory.push({ address, result, timestamp: new Date() })

    return {
      status: 'OK',
      results: [result]
    }
  })

  // OpenCage Geocoding API Mock
  openCageGeocode = jest.fn(async (address: string) => {
    const result = this.mockResults.get(address) || this.getDefaultGeocodingResult(address)
    this.geocodeHistory.push({ address, result, timestamp: new Date() })

    return {
      status: { code: 200, message: 'OK' },
      results: [{
        ...result,
        confidence: Math.floor(result.confidence * 10), // OpenCage uses 1-10 scale
        formatted: result.formatted_address,
      }]
    }
  })

  // Nominatim (OpenStreetMap) Geocoding Mock
  nominatimGeocode = jest.fn(async (address: string) => {
    const result = this.mockResults.get(address) || this.getDefaultGeocodingResult(address)
    this.geocodeHistory.push({ address, result, timestamp: new Date() })

    return [{
      lat: result.geometry.location.lat.toString(),
      lon: result.geometry.location.lng.toString(),
      display_name: result.formatted_address,
      importance: result.confidence,
      place_id: result.place_id,
    }]
  })

  // Reverse geocoding mock
  reverseGeocode = jest.fn(async (lat: number, lng: number) => {
    const result = {
      formatted_address: `${Math.abs(lat).toFixed(4)}°${lat >= 0 ? 'N' : 'S'}, ${Math.abs(lng).toFixed(4)}°${lng >= 0 ? 'E' : 'W'}`,
      geometry: {
        location: { lat, lng }
      },
      place_id: `place_${Date.now()}`,
      confidence: 0.9,
    }

    this.geocodeHistory.push({
      address: `${lat},${lng}`,
      result,
      timestamp: new Date()
    })

    return {
      status: 'OK',
      results: [result]
    }
  })

  // Helper methods
  private getDefaultGeocodingResult(address: string) {
    return {
      formatted_address: address,
      geometry: {
        location: {
          lat: 40.7128 + (Math.random() - 0.5) * 0.1, // NYC area with some variance
          lng: -74.0060 + (Math.random() - 0.5) * 0.1
        },
        location_type: 'APPROXIMATE',
        viewport: {
          northeast: { lat: 40.7628, lng: -73.9560 },
          southwest: { lat: 40.6628, lng: -74.0560 }
        }
      },
      place_id: `place_test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      types: ['establishment', 'point_of_interest'],
      confidence: 0.8 + Math.random() * 0.2, // 0.8-1.0
    }
  }

  // Configure mock result for specific address
  setMockResult(address: string, result: any) {
    this.mockResults.set(address, result)
  }

  // Get geocoding history for verification
  getGeocodeHistory() {
    return [...this.geocodeHistory]
  }

  // Simulate API errors
  simulateError(service: 'google' | 'opencage' | 'nominatim', errorType: string = 'OVER_QUERY_LIMIT') {
    const errorMap: Record<string, any> = {
      OVER_QUERY_LIMIT: {
        status: 'OVER_QUERY_LIMIT',
        error_message: 'You have exceeded your daily request quota for this API.'
      },
      REQUEST_DENIED: {
        status: 'REQUEST_DENIED',
        error_message: 'The provided API key is invalid.'
      },
      INVALID_REQUEST: {
        status: 'INVALID_REQUEST',
        error_message: 'This request was invalid.'
      },
      ZERO_RESULTS: {
        status: 'ZERO_RESULTS',
        results: []
      }
    }

    const error = errorMap[errorType] || errorMap.INVALID_REQUEST

    switch (service) {
      case 'google':
        this.googleMapsGeocode.mockRejectedValueOnce(error)
        break
      case 'opencage':
        this.openCageGeocode.mockRejectedValueOnce(error)
        break
      case 'nominatim':
        this.nominatimGeocode.mockRejectedValueOnce(error)
        break
    }
  }

  // Reset all mocks
  reset() {
    this.geocodeHistory.length = 0
    this.mockResults.clear()

    this.googleMapsGeocode.mockReset()
    this.openCageGeocode.mockReset()
    this.nominatimGeocode.mockReset()
    this.reverseGeocode.mockReset()
  }
}

/**
 * Database Connection Mock
 * Mock for database operations with connection pooling simulation
 */
export class DatabaseConnectionMock {
  private connections: Array<{ id: string; inUse: boolean; created: Date }> = []
  private queryHistory: Array<{ sql: string; params?: any[]; duration: number; timestamp: Date }> = []
  private mockData: Map<string, any[]> = new Map()
  private maxConnections = 10
  private currentConnections = 0

  constructor(maxConnections: number = 10) {
    this.maxConnections = maxConnections
    // Initialize connection pool
    for (let i = 0; i < Math.min(3, maxConnections); i++) {
      this.connections.push({
        id: `conn_${i}`,
        inUse: false,
        created: new Date()
      })
    }
  }

  // Connection management
  connect = jest.fn(async () => {
    if (this.currentConnections >= this.maxConnections) {
      throw new Error('Connection pool exhausted')
    }

    const availableConnection = this.connections.find(conn => !conn.inUse)
    if (availableConnection) {
      availableConnection.inUse = true
      this.currentConnections++
      return this.createConnectionObject(availableConnection.id)
    }

    // Create new connection if under limit
    if (this.connections.length < this.maxConnections) {
      const newConnection = {
        id: `conn_${this.connections.length}`,
        inUse: true,
        created: new Date()
      }
      this.connections.push(newConnection)
      this.currentConnections++
      return this.createConnectionObject(newConnection.id)
    }

    throw new Error('No available connections')
  })

  private createConnectionObject(connectionId: string) {
    return {
      id: connectionId,
      query: this.query,
      release: jest.fn(() => {
        const connection = this.connections.find(conn => conn.id === connectionId)
        if (connection) {
          connection.inUse = false
          this.currentConnections--
        }
      }),
      end: jest.fn(() => {
        const connectionIndex = this.connections.findIndex(conn => conn.id === connectionId)
        if (connectionIndex !== -1) {
          this.connections.splice(connectionIndex, 1)
          this.currentConnections--
        }
      })
    }
  }

  // Query execution
  query = jest.fn(async (sql: string, params?: any[]) => {
    const startTime = Date.now()

    // Simulate query execution time
    await new Promise(resolve => setTimeout(resolve, Math.random() * 50))

    const duration = Date.now() - startTime
    this.queryHistory.push({ sql, params, duration, timestamp: new Date() })

    // Parse SQL to determine operation and table
    const operation = sql.trim().split(' ')[0].toUpperCase()
    const tableName = this.extractTableName(sql)

    switch (operation) {
      case 'SELECT':
        return {
          rows: this.mockData.get(tableName) || [],
          rowCount: this.mockData.get(tableName)?.length || 0,
          command: 'SELECT',
          fields: [],
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
          fields: [],
        }

      case 'UPDATE':
        const updateData = this.mockData.get(tableName) || []
        const updatedRows = updateData.map(row => ({ ...row, ...params }))
        this.mockData.set(tableName, updatedRows)
        return {
          rows: updatedRows,
          rowCount: updatedRows.length,
          command: 'UPDATE',
          fields: [],
        }

      case 'DELETE':
        const deleteData = this.mockData.get(tableName) || []
        this.mockData.set(tableName, [])
        return {
          rows: [],
          rowCount: deleteData.length,
          command: 'DELETE',
          fields: [],
        }

      default:
        return {
          rows: [],
          rowCount: 0,
          command: operation,
          fields: [],
        }
    }
  })

  private extractTableName(sql: string): string {
    const match = sql.match(/(?:FROM|INTO|UPDATE|JOIN)\s+(\w+)/i)
    return match ? match[1].toLowerCase() : 'unknown'
  }

  // Helper methods
  addMockData(tableName: string, data: any[]) {
    this.mockData.set(tableName, data)
  }

  getMockData(tableName: string) {
    return this.mockData.get(tableName) || []
  }

  getQueryHistory() {
    return [...this.queryHistory]
  }

  getConnectionStats() {
    return {
      total: this.connections.length,
      inUse: this.currentConnections,
      available: this.connections.length - this.currentConnections,
      maxConnections: this.maxConnections
    }
  }

  // Simulate database errors
  simulateError(errorType: string = 'connection_error') {
    const errorMap: Record<string, any> = {
      connection_error: new Error('Connection to database failed'),
      timeout_error: new Error('Query timeout'),
      syntax_error: new Error('Syntax error in SQL statement'),
      constraint_violation: new Error('Constraint violation'),
    }

    const error = errorMap[errorType] || errorMap.connection_error
    this.query.mockRejectedValueOnce(error)
  }

  // Reset all mocks
  reset() {
    this.connections.forEach(conn => conn.inUse = false)
    this.currentConnections = 0
    this.queryHistory.length = 0
    this.mockData.clear()

    this.connect.mockReset()
    this.query.mockReset()
  }
}

/**
 * External Service Mock Factory
 * Centralized factory for creating and managing external service mocks
 */
export class ExternalServiceMockFactory {
  private static instance: ExternalServiceMockFactory
  private stripeMock: StripeServiceMock | null = null
  private geocodingMock: GeocodingServiceMock | null = null
  private databaseMock: DatabaseConnectionMock | null = null

  static getInstance(): ExternalServiceMockFactory {
    if (!ExternalServiceMockFactory.instance) {
      ExternalServiceMockFactory.instance = new ExternalServiceMockFactory()
    }
    return ExternalServiceMockFactory.instance
  }

  // Create Stripe mock
  createStripeMock(): StripeServiceMock {
    if (!this.stripeMock) {
      this.stripeMock = new StripeServiceMock()
      mockCleanup.registerMock('stripe', () => this.stripeMock?.reset())
    }
    return this.stripeMock
  }

  // Create Geocoding mock
  createGeocodingMock(): GeocodingServiceMock {
    if (!this.geocodingMock) {
      this.geocodingMock = new GeocodingServiceMock()
      mockCleanup.registerMock('geocoding', () => this.geocodingMock?.reset())
    }
    return this.geocodingMock
  }

  // Create Database mock
  createDatabaseMock(maxConnections: number = 10): DatabaseConnectionMock {
    if (!this.databaseMock) {
      this.databaseMock = new DatabaseConnectionMock(maxConnections)
      mockCleanup.registerMock('database', () => this.databaseMock?.reset())
    }
    return this.databaseMock
  }

  // Get existing mocks
  getStripeMock(): StripeServiceMock | null {
    return this.stripeMock
  }

  getGeocodingMock(): GeocodingServiceMock | null {
    return this.geocodingMock
  }

  getDatabaseMock(): DatabaseConnectionMock | null {
    return this.databaseMock
  }

  // Reset all external service mocks
  resetAllMocks(): void {
    this.stripeMock?.reset()
    this.geocodingMock?.reset()
    this.databaseMock?.reset()
  }

  // Setup global mocks for Jest
  setupGlobalExternalServiceMocks(): void {
    // Mock Stripe globally
    jest.mock('stripe', () => {
      return jest.fn().mockImplementation(() => this.createStripeMock())
    })

    // Mock axios for geocoding services
    jest.mock('axios', () => ({
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      create: jest.fn(() => ({
        get: jest.fn(),
        post: jest.fn(),
        put: jest.fn(),
        delete: jest.fn(),
      })),
    }))

    // Mock database modules
    jest.mock('@/lib/database', () => ({
      createDatabase: jest.fn(() => this.createDatabaseMock()),
      checkDatabaseConnection: jest.fn(() => Promise.resolve(true)),
    }))
  }
}

// Export singleton instance
export const externalServiceMockFactory = ExternalServiceMockFactory.getInstance()

// Export convenience functions
export const createStripeMock = () => externalServiceMockFactory.createStripeMock()
export const createGeocodingMock = () => externalServiceMockFactory.createGeocodingMock()
export const createDatabaseMock = (maxConnections?: number) =>
  externalServiceMockFactory.createDatabaseMock(maxConnections)

// Setup function for Jest
export const setupExternalServiceMocks = () => {
  externalServiceMockFactory.setupGlobalExternalServiceMocks()
}

// Cleanup function
export const cleanupExternalServiceMocks = () => {
  externalServiceMockFactory.resetAllMocks()
}

// Mock verification utilities
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
