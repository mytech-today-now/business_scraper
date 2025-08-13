import '@testing-library/jest-dom'

// Mock environment variables for testing
process.env.NODE_ENV = 'test'
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db'
process.env.REDIS_URL = 'redis://localhost:6379'
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters'
process.env.JWT_SECRET = 'test-jwt-secret'

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
global.fetch = jest.fn()

// Mock Request and Response for Next.js API tests
global.Request = class MockRequest {
  constructor(input, init = {}) {
    this.url = typeof input === 'string' ? input : input.url
    this.method = init.method || 'GET'
    this.headers = new Map(Object.entries(init.headers || {}))
    this.body = init.body
    this._bodyUsed = false
  }

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
    const formData = new FormData()
    return formData
  }
}

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
      headers: { 'Content-Type': 'application/json', ...init.headers }
    })
  }
}

// Mock crypto for Node.js environment
global.crypto = {
  randomUUID: () => Math.random().toString(36).substring(2, 15),
  getRandomValues: (arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256)
    }
    return arr
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

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks()
  if (global.fetch) {
    global.fetch.mockClear()
  }
})
