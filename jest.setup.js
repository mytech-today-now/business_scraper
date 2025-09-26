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

// Add crypto polyfills for test environment
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

// Mock IndexedDB
global.indexedDB = require('fake-indexeddb')
global.IDBKeyRange = require('fake-indexeddb/lib/FDBKeyRange')

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

// Mock fetch globally
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
  })
)

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

// Mock crypto API
if (!global.crypto) {
  Object.defineProperty(global, 'crypto', {
    value: {
      randomUUID: jest.fn(() => 'mocked-uuid'),
      getRandomValues: jest.fn(arr => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256)
        }
        return arr
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
    this.headers = new Map(Object.entries(init.headers || {}))
    this.ok = this.status >= 200 && this.status < 300
  }

  async json() {
    return JSON.parse(this.body || '{}')
  }

  async text() {
    return this.body || ''
  }

  static json(data, init = {}) {
    return new MockResponse(JSON.stringify(data), {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init.headers },
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

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks()
  if (global.fetch) {
    global.fetch.mockClear()
  }
})
