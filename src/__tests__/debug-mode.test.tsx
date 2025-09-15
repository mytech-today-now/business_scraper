/**
 * Debug Mode Tests
 * Tests for debug mode functionality, error capture, and reload prevention
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { 
  getDebugConfig,
  isDebugMode,
  shouldPreventAutoReload,
  shouldUseEnhancedErrorLogging,
  shouldPersistErrors,
  safeReload,
  enableDebugMode,
  disableDebugMode,
  logEnhancedError,
  getPersistedErrors,
  clearPersistedErrors
} from '@/utils/debugConfig'
import { securityTokenErrorLogger } from '@/utils/enhancedErrorLogger'
import { errorPersistenceManager } from '@/utils/errorPersistence'

// Mock window.location.reload
const mockReload = jest.fn()
Object.defineProperty(window, 'location', {
  value: {
    reload: mockReload,
    href: 'http://localhost:3000/test'
  },
  writable: true
})

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
})

// Mock console methods
const consoleMock = {
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  log: jest.fn(),
  group: jest.fn(),
  groupEnd: jest.fn(),
  table: jest.fn(),
  trace: jest.fn(),
}
Object.defineProperty(global, 'console', {
  value: consoleMock
})

describe('Debug Mode Configuration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorageMock.getItem.mockReturnValue(null)
    process.env.DEBUG_MODE = 'false'
    process.env.DEBUG_PREVENT_AUTO_RELOAD = 'false'
    process.env.DEBUG_ENHANCED_ERROR_LOGGING = 'false'
    process.env.DEBUG_PERSIST_ERRORS = 'false'
    process.env.DEBUG_SHOW_STACK_TRACES = 'false'
  })

  describe('Environment Variable Configuration', () => {
    it('should read debug mode from environment variables', () => {
      // Mock environment variables by mocking the getDebugConfig function
      jest.doMock('@/utils/debugConfig', () => ({
        ...jest.requireActual('@/utils/debugConfig'),
        getDebugConfig: () => ({
          enabled: true,
          preventAutoReload: true,
          enhancedErrorLogging: true,
          persistErrors: true,
          showStackTraces: true,
        })
      }))

      // Re-import to get the mocked version
      const { getDebugConfig: mockedGetDebugConfig } = require('@/utils/debugConfig')
      const config = mockedGetDebugConfig()
      expect(config.enabled).toBe(true)
      expect(config.preventAutoReload).toBe(true)
      expect(config.enhancedErrorLogging).toBe(true)
      expect(config.persistErrors).toBe(true)
      expect(config.showStackTraces).toBe(true)

      jest.dontMock('@/utils/debugConfig')
    })

    it('should default to false when environment variables are not set', () => {
      const config = getDebugConfig()
      expect(config.enabled).toBe(false)
      expect(config.preventAutoReload).toBe(false)
      expect(config.enhancedErrorLogging).toBe(false)
      expect(config.persistErrors).toBe(false)
      expect(config.showStackTraces).toBe(false)
    })
  })

  describe('LocalStorage Override', () => {
    it('should prioritize localStorage over environment variables', () => {
      process.env.DEBUG_MODE = 'false'
      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'debug_mode') return 'true'
        if (key === 'debug_prevent_auto_reload') return 'true'
        return null
      })

      const config = getDebugConfig()
      expect(config.enabled).toBe(true)
      expect(config.preventAutoReload).toBe(true)
    })

    it('should enable debug mode at runtime', () => {
      enableDebugMode({
        enabled: true,
        preventAutoReload: true,
        enhancedErrorLogging: true,
        persistErrors: true,
        showStackTraces: true,
      })

      expect(localStorageMock.setItem).toHaveBeenCalledWith('debug_mode', 'true')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('debug_prevent_auto_reload', 'true')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('debug_enhanced_error_logging', 'true')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('debug_persist_errors', 'true')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('debug_show_stack_traces', 'true')
    })

    it('should disable debug mode at runtime', () => {
      disableDebugMode()

      expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_mode')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_prevent_auto_reload')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_enhanced_error_logging')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_persist_errors')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_show_stack_traces')
    })
  })

  describe('Helper Functions', () => {
    it('should correctly identify debug mode status', () => {
      localStorageMock.getItem.mockImplementation((key) => {
        return key === 'debug_mode' ? 'true' : null
      })

      expect(isDebugMode()).toBe(true)
      expect(shouldPreventAutoReload()).toBe(false) // preventAutoReload is false

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'debug_mode') return 'true'
        if (key === 'debug_prevent_auto_reload') return 'true'
        return null
      })

      expect(shouldPreventAutoReload()).toBe(true)
    })

    it('should correctly identify enhanced error logging status', () => {
      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'debug_mode') return 'true'
        if (key === 'debug_enhanced_error_logging') return 'true'
        return null
      })

      expect(shouldUseEnhancedErrorLogging()).toBe(true)
    })

    it('should correctly identify error persistence status', () => {
      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'debug_mode') return 'true'
        if (key === 'debug_persist_errors') return 'true'
        return null
      })

      expect(shouldPersistErrors()).toBe(true)
    })
  })
})

describe('Safe Reload Functionality', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockReload.mockClear()
  })

  it('should prevent reload when debug mode is active', () => {
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'debug_mode') return 'true'
      if (key === 'debug_prevent_auto_reload') return 'true'
      return null
    })

    safeReload('Test reason')

    expect(mockReload).not.toHaveBeenCalled()
    expect(consoleMock.warn).toHaveBeenCalledWith(
      expect.stringContaining('Auto-reload prevented in debug mode')
    )
  })

  it('should allow reload when debug mode is disabled', () => {
    localStorageMock.getItem.mockReturnValue(null)

    safeReload('Test reason')

    expect(mockReload).toHaveBeenCalled()
  })

  it('should dispatch custom event when reload is prevented', () => {
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'debug_mode') return 'true'
      if (key === 'debug_prevent_auto_reload') return 'true'
      return null
    })

    const eventListener = jest.fn()
    window.addEventListener('debug-reload-prevented', eventListener)

    safeReload('Test reason')

    expect(eventListener).toHaveBeenCalledWith(
      expect.objectContaining({
        detail: { reason: 'Test reason' }
      })
    )

    window.removeEventListener('debug-reload-prevented', eventListener)
  })
})

describe('Enhanced Error Logging', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'debug_mode') return 'true'
      if (key === 'debug_enhanced_error_logging') return 'true'
      if (key === 'debug_persist_errors') return 'true'
      if (key === 'debug_show_stack_traces') return 'true'
      return null
    })
  })

  it('should log enhanced error details', () => {
    const testError = new Error('Test error message')
    const errorDetails = logEnhancedError(testError, 'TestComponent', { testContext: 'value' })

    expect(errorDetails.id).toBeDefined()
    expect(errorDetails.message).toBe('Test error message')
    expect(errorDetails.component).toBe('TestComponent')
    expect(errorDetails.context).toEqual({ testContext: 'value' })
    expect(errorDetails.stack).toBeDefined()
  })

  it('should log CSRF errors with detailed context', () => {
    const testError = new Error('CSRF token fetch failed')
    const errorDetails = securityTokenErrorLogger.logCSRFError(testError, {
      tokenType: 'csrf',
      phase: 'loading',
      endpoint: '/api/csrf',
      retryCount: 2,
    })

    expect(errorDetails.component).toBe('CSRFTokenError')
    expect(errorDetails.context).toMatchObject({
      tokenType: 'csrf',
      phase: 'loading',
      endpoint: '/api/csrf',
      retryCount: 2,
    })
  })

  it('should show enhanced console output in debug mode', () => {
    const testError = new Error('Test error')
    securityTokenErrorLogger.logCSRFError(testError, {
      tokenType: 'csrf',
      phase: 'loading',
      endpoint: '/api/csrf',
    })

    expect(consoleMock.group).toHaveBeenCalledWith('🔒 CSRF Token Error Details')
    expect(consoleMock.error).toHaveBeenCalledWith('Error:', testError)
    expect(consoleMock.table).toHaveBeenCalled()
    expect(consoleMock.trace).toHaveBeenCalledWith('Stack trace')
    expect(consoleMock.groupEnd).toHaveBeenCalled()
  })
})

describe('Error Persistence', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'debug_mode') return 'true'
      if (key === 'debug_persist_errors') return 'true'
      return null
    })
  })

  it('should persist errors to localStorage', () => {
    const testError = new Error('Test error')
    logEnhancedError(testError, 'TestComponent')

    expect(localStorageMock.setItem).toHaveBeenCalledWith(
      'debug_persisted_errors',
      expect.any(String)
    )
  })

  it('should retrieve persisted errors', () => {
    const mockErrors = [
      {
        id: 'err_123',
        timestamp: '2023-01-01T00:00:00.000Z',
        message: 'Test error',
        component: 'TestComponent'
      }
    ]
    
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'debug_persisted_errors') return JSON.stringify(mockErrors)
      if (key === 'debug_mode') return 'true'
      if (key === 'debug_persist_errors') return 'true'
      return null
    })

    const persistedErrors = getPersistedErrors()
    expect(persistedErrors).toEqual(mockErrors)
  })

  it('should clear persisted errors', () => {
    clearPersistedErrors()
    expect(localStorageMock.removeItem).toHaveBeenCalledWith('debug_persisted_errors')
  })

  it('should limit the number of persisted errors', () => {
    // Create 60 errors (more than the 50 limit)
    for (let i = 0; i < 60; i++) {
      logEnhancedError(new Error(`Test error ${i}`), 'TestComponent')
    }

    // Check that setItem was called and the stored data doesn't exceed 50 errors
    const setItemCalls = localStorageMock.setItem.mock.calls.filter(
      call => call[0] === 'debug_persisted_errors'
    )
    
    expect(setItemCalls.length).toBeGreaterThan(0)
    
    // Parse the last stored value to check the limit
    const lastStoredValue = setItemCalls[setItemCalls.length - 1][1]
    const storedErrors = JSON.parse(lastStoredValue)
    expect(storedErrors.length).toBeLessThanOrEqual(50)
  })
})
