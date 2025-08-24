/**
 * Jest Setup for Multi-User Tests
 * Global test setup and configuration for multi-user collaboration features
 */

import '@testing-library/jest-dom'
import { jest } from '@jest/globals'

// Mock environment variables
process.env.NODE_ENV = 'test'
process.env.DB_HOST = 'localhost'
process.env.DB_PORT = '5432'
process.env.DB_NAME = 'business_scraper_test'
process.env.DB_USER = 'test_user'
process.env.DB_PASSWORD = 'test_password'
process.env.JWT_SECRET = 'test_jwt_secret_key_for_testing_only'
process.env.CSRF_SECRET = 'test_csrf_secret_key_for_testing_only'
process.env.SESSION_SECRET = 'test_session_secret_key_for_testing_only'

// Mock Next.js router
jest.mock('next/router', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
    back: jest.fn(),
    pathname: '/test',
    query: {},
    asPath: '/test',
    route: '/test'
  })
}))

// Mock Next.js navigation
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    refresh: jest.fn()
  }),
  usePathname: () => '/test',
  useSearchParams: () => new URLSearchParams()
}))

// Mock WebSocket
global.WebSocket = jest.fn().mockImplementation(() => ({
  send: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  readyState: 1, // OPEN
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3
}))

// Mock Notification API
global.Notification = jest.fn().mockImplementation((title, options) => ({
  title,
  ...options,
  close: jest.fn()
}))

Object.defineProperty(global.Notification, 'permission', {
  value: 'granted',
  writable: true
})

Object.defineProperty(global.Notification, 'requestPermission', {
  value: jest.fn().mockResolvedValue('granted'),
  writable: true
})

// Mock fetch
global.fetch = jest.fn()

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
  length: 0,
  key: jest.fn()
}

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
})

// Mock sessionStorage
const sessionStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
  length: 0,
  key: jest.fn()
}

Object.defineProperty(window, 'sessionStorage', {
  value: sessionStorageMock
})

// Mock crypto for UUID generation
Object.defineProperty(global, 'crypto', {
  value: {
    randomUUID: jest.fn(() => 'test-uuid-' + Math.random().toString(36).substr(2, 9)),
    getRandomValues: jest.fn((arr) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256)
      }
      return arr
    })
  }
})

// Mock console methods to reduce noise in tests
const originalConsole = { ...console }

beforeEach(() => {
  // Reset all mocks before each test
  jest.clearAllMocks()
  
  // Reset localStorage and sessionStorage
  localStorageMock.getItem.mockClear()
  localStorageMock.setItem.mockClear()
  localStorageMock.removeItem.mockClear()
  localStorageMock.clear.mockClear()
  
  sessionStorageMock.getItem.mockClear()
  sessionStorageMock.setItem.mockClear()
  sessionStorageMock.removeItem.mockClear()
  sessionStorageMock.clear.mockClear()
  
  // Reset fetch mock
  ;(global.fetch as jest.Mock).mockClear()
  
  // Suppress console output during tests unless explicitly needed
  console.log = jest.fn()
  console.info = jest.fn()
  console.warn = jest.fn()
  console.error = jest.fn()
})

afterEach(() => {
  // Restore console methods
  console.log = originalConsole.log
  console.info = originalConsole.info
  console.warn = originalConsole.warn
  console.error = originalConsole.error
  
  // Clean up any timers
  jest.clearAllTimers()
  jest.useRealTimers()
})

// Global test utilities
global.testUtils = {
  // Create mock user
  createMockUser: (overrides = {}) => ({
    id: 'test-user-' + Math.random().toString(36).substr(2, 9),
    username: 'testuser',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    isActive: true,
    isVerified: true,
    roles: [],
    teams: [],
    workspaces: [],
    preferences: {},
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  
  // Create mock role
  createMockRole: (overrides = {}) => ({
    id: 'test-role-' + Math.random().toString(36).substr(2, 9),
    name: 'test-role',
    displayName: 'Test Role',
    description: 'A test role',
    isSystemRole: false,
    permissions: ['test.permission'],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  
  // Create mock team
  createMockTeam: (overrides = {}) => ({
    id: 'test-team-' + Math.random().toString(36).substr(2, 9),
    name: 'Test Team',
    description: 'A test team',
    ownerId: 'test-user-123',
    settings: {},
    isActive: true,
    memberCount: 1,
    workspaceCount: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  
  // Create mock workspace
  createMockWorkspace: (overrides = {}) => ({
    id: 'test-workspace-' + Math.random().toString(36).substr(2, 9),
    name: 'Test Workspace',
    description: 'A test workspace',
    teamId: 'test-team-123',
    ownerId: 'test-user-123',
    settings: {},
    defaultSearchRadius: 25,
    defaultSearchDepth: 3,
    defaultPagesPerSite: 5,
    isActive: true,
    memberCount: 1,
    campaignCount: 0,
    businessCount: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  
  // Create mock API response
  createMockApiResponse: (data = {}, success = true, status = 200) => ({
    ok: status >= 200 && status < 300,
    status,
    json: jest.fn().mockResolvedValue({
      success,
      data,
      ...(success ? {} : { error: 'Test error' })
    }),
    text: jest.fn().mockResolvedValue(JSON.stringify({
      success,
      data,
      ...(success ? {} : { error: 'Test error' })
    }))
  }),
  
  // Wait for async operations
  waitFor: (ms = 0) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Mock database query result
  createMockQueryResult: (rows = [], rowCount = null) => ({
    rows,
    rowCount: rowCount !== null ? rowCount : rows.length,
    command: 'SELECT',
    oid: 0,
    fields: []
  })
}

// Extend Jest matchers
expect.extend({
  toHavePermission(user, permission) {
    const hasPermission = user.roles?.some((userRole: any) =>
      userRole.role.permissions.includes(permission)
    ) || false
    
    return {
      message: () =>
        `expected user ${user.username} ${hasPermission ? 'not ' : ''}to have permission ${permission}`,
      pass: hasPermission
    }
  },
  
  toHaveRole(user, roleName) {
    const hasRole = user.roles?.some((userRole: any) =>
      userRole.role.name === roleName
    ) || false
    
    return {
      message: () =>
        `expected user ${user.username} ${hasRole ? 'not ' : ''}to have role ${roleName}`,
      pass: hasRole
    }
  }
})

// Declare global types for TypeScript
declare global {
  namespace jest {
    interface Matchers<R> {
      toHavePermission(permission: string): R
      toHaveRole(roleName: string): R
    }
  }
  
  var testUtils: {
    createMockUser: (overrides?: any) => any
    createMockRole: (overrides?: any) => any
    createMockTeam: (overrides?: any) => any
    createMockWorkspace: (overrides?: any) => any
    createMockApiResponse: (data?: any, success?: boolean, status?: number) => any
    waitFor: (ms?: number) => Promise<void>
    createMockQueryResult: (rows?: any[], rowCount?: number | null) => any
  }
}
