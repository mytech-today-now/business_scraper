import '@testing-library/jest-dom'

// Mock environment variables for testing
process.env.NODE_ENV = 'test'
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db'
process.env.REDIS_URL = 'redis://localhost:6379'
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters'
process.env.ENCRYPTION_MASTER_KEY =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
process.env.JWT_SECRET = 'test-jwt-secret'

// Add TextEncoder and TextDecoder polyfills for Node.js
const { TextEncoder, TextDecoder } = require('util')
global.TextEncoder = TextEncoder
global.TextDecoder = TextDecoder

// Add Node.js timer polyfills for test environment
global.setImmediate = global.setImmediate || ((fn, ...args) => setTimeout(fn, 0, ...args))
global.clearImmediate = global.clearImmediate || ((id) => clearTimeout(id))

// Add comprehensive crypto polyfills for test environment
const crypto = require('crypto')

if (typeof globalThis.crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: {
      randomUUID: () => {
        // Generate a proper UUID v4 format
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0
          const v = c === 'x' ? r : (r & 0x3 | 0x8)
          return v.toString(16)
        })
      },
      getRandomValues: (arr) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256)
        }
        return arr
      },
      // Add createHash function for Node.js crypto compatibility
      createHash: (algorithm) => {
        try {
          return crypto.createHash(algorithm)
        } catch (error) {
          // Fallback implementation for test environment
          return {
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
          }
        }
      },
      subtle: {
        importKey: jest.fn().mockResolvedValue({}),
        deriveBits: jest.fn().mockResolvedValue(new ArrayBuffer(32)),
        generateKey: jest.fn().mockResolvedValue({}),
        encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
        decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
        digest: jest.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    },
    writable: true,
    configurable: true
  })
}

// Also ensure Node.js crypto is available globally for compatibility
if (typeof global.crypto === 'undefined') {
  global.crypto = globalThis.crypto
}

// Mock IndexedDB
global.indexedDB = require('fake-indexeddb')
global.IDBKeyRange = require('fake-indexeddb/lib/FDBKeyRange')

// Enhanced XMLHttpRequest mock with CORS support
class MockXMLHttpRequest {
  constructor() {
    this.readyState = 0
    this.status = 0
    this.statusText = ''
    this.responseText = ''
    this.responseXML = null
    this.response = ''
    this.responseType = ''
    this.timeout = 0
    this.withCredentials = false
    this.upload = {}
    this._headers = {}
    this._requestHeaders = {}
    this._listeners = {}
  }

  open(method, url, async = true, user = null, password = null) {
    this.method = method
    this.url = url
    this.async = async
    this.readyState = 1
    this._fireEvent('readystatechange')
  }

  setRequestHeader(name, value) {
    this._requestHeaders[name.toLowerCase()] = value
  }

  send(data = null) {
    this.readyState = 2
    this._fireEvent('readystatechange')

    // Simulate CORS-enabled response
    setTimeout(() => {
      this.readyState = 3
      this._fireEvent('readystatechange')

      // Set CORS headers
      this._headers = {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization, X-CSRF-Token',
        'access-control-allow-credentials': 'true',
        'content-type': 'application/json'
      }

      this.status = this.method === 'OPTIONS' ? 200 : 200
      this.statusText = 'OK'
      this.responseText = JSON.stringify({})
      this.response = this.responseText
      this.readyState = 4

      this._fireEvent('load')
      this._fireEvent('readystatechange')
    }, 0)
  }

  abort() {
    this.readyState = 0
    this._fireEvent('abort')
  }

  getResponseHeader(name) {
    return this._headers[name.toLowerCase()] || null
  }

  getAllResponseHeaders() {
    return Object.entries(this._headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\r\n')
  }

  addEventListener(type, listener) {
    if (!this._listeners[type]) {
      this._listeners[type] = []
    }
    this._listeners[type].push(listener)
  }

  removeEventListener(type, listener) {
    if (this._listeners[type]) {
      const index = this._listeners[type].indexOf(listener)
      if (index > -1) {
        this._listeners[type].splice(index, 1)
      }
    }
  }

  _fireEvent(type) {
    if (this._listeners[type]) {
      this._listeners[type].forEach(listener => {
        listener.call(this, { type, target: this })
      })
    }

    // Also call on* properties
    const handler = this[`on${type}`]
    if (typeof handler === 'function') {
      handler.call(this, { type, target: this })
    }
  }
}

// Set up XMLHttpRequest mock
global.XMLHttpRequest = MockXMLHttpRequest

// Mock Next.js router
jest.mock('next/router', () => ({
  useRouter() {
    return {
      route: '/',
      pathname: '/',
      query: {},
      asPath: '/',
      push: jest.fn(),
      pop: jest.fn(),
      reload: jest.fn(),
      back: jest.fn(),
      prefetch: jest.fn().mockResolvedValue(undefined),
      beforePopState: jest.fn(),
      events: {
        on: jest.fn(),
        off: jest.fn(),
        emit: jest.fn(),
      },
      isFallback: false,
    }
  },
}))

// Mock Next.js navigation
jest.mock('next/navigation', () => ({
  useRouter() {
    return {
      push: jest.fn(),
      replace: jest.fn(),
      prefetch: jest.fn(),
      back: jest.fn(),
      forward: jest.fn(),
      refresh: jest.fn(),
    }
  },
  useSearchParams() {
    return new URLSearchParams()
  },
  usePathname() {
    return '/'
  },
}))

// Enhanced fetch mock with CORS support
global.fetch = jest.fn((input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url
  const method = init.method || 'GET'

  // Create proper CORS headers for localhost requests
  const corsHeaders = new Headers({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json',
    ...(init.headers || {})
  })

  // Handle OPTIONS preflight requests
  if (method === 'OPTIONS') {
    return Promise.resolve({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: corsHeaders,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(''),
      blob: () => Promise.resolve(new Blob()),
      clone: () => global.fetch(input, init)
    })
  }

  // Handle regular requests with CORS headers
  return Promise.resolve({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: corsHeaders,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
    clone: () => global.fetch(input, init)
  })
})

// Mock NextRequest with proper read-only property handling for Next.js 14 compatibility
class MockNextRequest {
  constructor(input, init = {}) {
    const url = typeof input === 'string' ? input : input.url
    const parsedUrl = new URL(url)

    // Define read-only properties using Object.defineProperty
    Object.defineProperty(this, 'url', {
      value: url,
      writable: false,
      enumerable: true,
      configurable: false
    })

    Object.defineProperty(this, 'nextUrl', {
      value: parsedUrl,
      writable: false,
      enumerable: true,
      configurable: false
    })

    // Define other properties normally
    this.method = init.method || 'GET'
    this.headers = new Headers(init.headers || {})
    this.body = init.body
    this._bodyUsed = false

    // Define cookies as read-only property
    Object.defineProperty(this, 'cookies', {
      value: {
        get: jest.fn((name) => ({ value: `mock-${name}` })),
        set: jest.fn(),
        delete: jest.fn(),
        has: jest.fn(() => false),
        getAll: jest.fn(() => [])
      },
      writable: false,
      enumerable: true,
      configurable: false
    })
  }

  // Implement required methods
  async json() {
    if (this._bodyUsed) throw new Error('Body already used')
    this._bodyUsed = true
    return JSON.parse(this.body || '{}')
  }

  async text() {
    if (this._bodyUsed) throw new Error('Body already used')
    this._bodyUsed = true
    return this.body || ''
  }

  async formData() {
    if (this._bodyUsed) throw new Error('Body already used')
    this._bodyUsed = true
    return this.body instanceof FormData ? this.body : new FormData()
  }

  clone() {
    return new MockNextRequest(this.url, {
      method: this.method,
      headers: Object.fromEntries(this.headers.entries()),
      body: this.body
    })
  }
}

global.NextRequest = MockNextRequest

global.NextResponse = {
  json: jest.fn((data, init) => ({
    status: init?.status || 200,
    headers: new Headers(init?.headers || {}),
    json: () => Promise.resolve(data),
    ok: (init?.status || 200) >= 200 && (init?.status || 200) < 300
  })),
  redirect: jest.fn((url, status = 302) => ({
    status,
    headers: new Headers({ 'Location': url }),
    ok: status >= 200 && status < 300
  }))
}

// Mock window.matchMedia
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

// Mock ResizeObserver
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}))

// Mock IntersectionObserver
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}))

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
})

// Mock sessionStorage
const sessionStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'sessionStorage', {
  value: sessionStorageMock,
})

// Mock URL methods
global.URL.createObjectURL = jest.fn(() => 'mocked-url')
global.URL.revokeObjectURL = jest.fn()

// Enhanced crypto API mock with Node.js crypto functions
if (!global.crypto) {
  Object.defineProperty(global, 'crypto', {
    value: {
      randomUUID: jest.fn(() => {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0
          const v = c === 'x' ? r : (r & 0x3 | 0x8)
          return v.toString(16)
        })
      }),
      getRandomValues: jest.fn(arr => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256)
        }
        return arr
      }),
      // Add Node.js crypto functions
      createHash: jest.fn((algorithm) => {
        try {
          const crypto = require('crypto')
          return crypto.createHash(algorithm)
        } catch (error) {
          // Fallback for test environment
          return {
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
          }
        }
      }),
      subtle: {
        importKey: jest.fn().mockResolvedValue({}),
        deriveBits: jest.fn().mockResolvedValue(new ArrayBuffer(32)),
        generateKey: jest.fn().mockResolvedValue({}),
        encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
        decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(16)),
        digest: jest.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    },
    writable: true,
  })
}

// Mock performance API
Object.defineProperty(window, 'performance', {
  value: {
    now: jest.fn(() => Date.now()),
    mark: jest.fn(),
    measure: jest.fn(),
    getEntriesByType: jest.fn(() => []),
    getEntriesByName: jest.fn(() => []),
  },
})

// Mock requestAnimationFrame
global.requestAnimationFrame = jest.fn(cb => setTimeout(cb, 0))
global.cancelAnimationFrame = jest.fn(id => clearTimeout(id))

// Mock document.documentElement.classList for dark mode tests
Object.defineProperty(document.documentElement, 'classList', {
  value: {
    toggle: jest.fn(),
    add: jest.fn(),
    remove: jest.fn(),
    contains: jest.fn(),
  },
  writable: true,
})

// Mock console methods to reduce noise during tests
const originalConsole = { ...console }
global.console = {
  ...originalConsole,
  info: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}

// Mock Request for Next.js API tests (using same implementation as NextRequest for consistency)
global.Request = MockNextRequest

global.Response = class MockResponse {
  constructor(body, init = {}) {
    this.body = body
    this.status = init.status || 200
    this.statusText = init.statusText || 'OK'

    // Create Headers object with CORS support
    const defaultHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
      'Access-Control-Allow-Credentials': 'true',
      'Content-Type': 'application/json',
      ...init.headers
    }

    this.headers = new Headers(defaultHeaders)
    this.ok = this.status >= 200 && this.status < 300
    this.url = init.url || ''
    this.redirected = false
    this.type = 'cors'
  }

  async json() {
    return JSON.parse(this.body || '{}')
  }

  async text() {
    return this.body || ''
  }

  async blob() {
    return new Blob([this.body || ''])
  }

  async arrayBuffer() {
    return new ArrayBuffer(0)
  }

  clone() {
    return new MockResponse(this.body, {
      status: this.status,
      statusText: this.statusText,
      headers: Object.fromEntries(this.headers.entries())
    })
  }

  static json(data, init = {}) {
    return new MockResponse(JSON.stringify(data), {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init.headers },
    })
  }

  static redirect(url, status = 302) {
    return new MockResponse('', {
      status,
      headers: { 'Location': url }
    })
  }
}

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
})

// Mock ResizeObserver
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}))

// Mock IntersectionObserver
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}))

// Mock Notification API
global.Notification = {
  requestPermission: jest.fn().mockResolvedValue('granted'),
  permission: 'granted',
}

// Mock WebSocket
global.WebSocket = jest.fn().mockImplementation(() => ({
  close: jest.fn(),
  send: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  readyState: 1,
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
}))

// clsx is now mocked via moduleNameMapper in jest.config.js

// Mock browser pool for performance tests
jest.mock('@/lib/browserPool', () => ({
  BrowserPool: jest.fn().mockImplementation(() => ({
    initialize: jest.fn().mockResolvedValue(true),
    acquirePage: jest.fn().mockResolvedValue({
      page: {
        goto: jest.fn().mockResolvedValue({}),
        evaluate: jest.fn().mockResolvedValue({}),
        close: jest.fn().mockResolvedValue({}),
        setViewport: jest.fn().mockResolvedValue({}),
        content: jest.fn().mockResolvedValue('<html></html>'),
        title: jest.fn().mockResolvedValue('Test Page'),
        url: jest.fn().mockReturnValue('http://localhost:3000'),
        screenshot: jest.fn().mockResolvedValue(Buffer.from('fake-screenshot')),
        pdf: jest.fn().mockResolvedValue(Buffer.from('fake-pdf'))
      },
      browserId: 'mock-browser-id',
      contextId: 'mock-context-id',
      createdAt: new Date(),
      lastUsed: new Date(),
      isActive: true
    }),
    releasePage: jest.fn().mockResolvedValue(undefined),
    cleanup: jest.fn().mockResolvedValue(undefined),
    getStats: jest.fn().mockReturnValue({
      totalBrowsers: 1,
      totalPages: 1,
      activePagesCount: 0,
      memoryUsage: { heapUsed: 1000000, heapTotal: 2000000 }
    }),
    isHealthy: jest.fn().mockReturnValue(true)
  })),
  browserPool: {
    initialize: jest.fn().mockResolvedValue(true),
    acquirePage: jest.fn().mockResolvedValue({
      page: {
        goto: jest.fn().mockResolvedValue({}),
        evaluate: jest.fn().mockResolvedValue({}),
        close: jest.fn().mockResolvedValue({}),
        setViewport: jest.fn().mockResolvedValue({}),
        content: jest.fn().mockResolvedValue('<html></html>'),
        title: jest.fn().mockResolvedValue('Test Page'),
        url: jest.fn().mockReturnValue('http://localhost:3000')
      },
      browserId: 'mock-browser-id',
      isActive: true
    }),
    releasePage: jest.fn().mockResolvedValue(undefined),
    cleanup: jest.fn().mockResolvedValue(undefined),
    getStats: jest.fn().mockReturnValue({
      totalBrowsers: 1,
      totalPages: 1,
      activePagesCount: 0
    })
  }
}))

// Enhanced test cleanup with CORS isolation
afterEach(() => {
  jest.clearAllMocks()

  // Clear fetch mock
  if (global.fetch && global.fetch.mockClear) {
    global.fetch.mockClear()
  }

  // Reset XMLHttpRequest mock state
  if (global.XMLHttpRequest && global.XMLHttpRequest.prototype) {
    // Reset any instance-specific state
  }

  // Clear any CORS-related environment variables
  delete process.env.CORS_ORIGIN
  delete process.env.CORS_METHODS
  delete process.env.CORS_HEADERS

  // Reset window location if it exists
  if (typeof window !== 'undefined' && window.location) {
    Object.defineProperty(window, 'location', {
      value: {
        origin: 'http://localhost:3000',
        protocol: 'http:',
        hostname: 'localhost',
        port: '3000',
        href: 'http://localhost:3000/',
        pathname: '/',
        search: '',
        hash: ''
      },
      writable: true,
      configurable: true
    })
  }
})

// Enhanced test setup for each test
beforeEach(() => {
  // Ensure consistent CORS environment for each test
  process.env.NODE_ENV = 'test'
  process.env.CORS_ORIGIN = 'http://localhost:3000'

  // Reset fetch mock to default CORS-enabled state
  if (global.fetch && global.fetch.mockImplementation) {
    global.fetch.mockImplementation((input, init = {}) => {
      const url = typeof input === 'string' ? input : input.url
      const method = init.method || 'GET'

      const corsHeaders = new Headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
        'Access-Control-Allow-Credentials': 'true',
        'Content-Type': 'application/json',
        ...(init.headers || {})
      })

      return Promise.resolve({
        ok: true,
        status: method === 'OPTIONS' ? 200 : 200,
        statusText: 'OK',
        headers: corsHeaders,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        blob: () => Promise.resolve(new Blob()),
        clone: () => global.fetch(input, init)
      })
    })
  }
})
