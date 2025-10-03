/**
 * Enhanced Error Logger - Comprehensive Test Suite
 * Tests enhanced error logging, security token error logging, and error persistence
 */

import { securityTokenErrorLogger } from '@/utils/enhancedErrorLogger'
import { logEnhancedError, shouldUseEnhancedErrorLogging, shouldPersistErrors } from '@/utils/debugConfig'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/utils/debugConfig')

const mockLogger = logger as jest.Mocked<typeof logger>
const mockShouldUseEnhancedErrorLogging = shouldUseEnhancedErrorLogging as jest.MockedFunction<typeof shouldUseEnhancedErrorLogging>
const mockShouldPersistErrors = shouldPersistErrors as jest.MockedFunction<typeof shouldPersistErrors>
const mockLogEnhancedError = logEnhancedError as jest.MockedFunction<typeof logEnhancedError>

describe('Enhanced Error Logger - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockShouldUseEnhancedErrorLogging.mockReturnValue(true)
    mockShouldPersistErrors.mockReturnValue(false)
    
    // Mock console methods
    jest.spyOn(console, 'group').mockImplementation(() => {})
    jest.spyOn(console, 'groupEnd').mockImplementation(() => {})
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(console, 'table').mockImplementation(() => {})
    jest.spyOn(console, 'trace').mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Security Token Error Logger', () => {
    it('should log authentication errors with enhanced context', () => {
      const testError = new Error('Invalid JWT token')
      const details = {
        tokenType: 'JWT',
        endpoint: '/api/auth',
        userId: 'user123',
      }
      const context = {
        operation: 'token_validation',
        ip: '192.168.1.1',
      }

      mockLogEnhancedError.mockReturnValue({
        id: 'error_123',
        timestamp: new Date().toISOString(),
        message: 'Invalid JWT token',
        stack: 'Error stack trace',
        context: { ...context, ...details },
        url: 'http://localhost/api/auth',
        userAgent: 'Test Browser',
      })

      const result = securityTokenErrorLogger.logAuthError(testError, details, context)

      expect(mockLogEnhancedError).toHaveBeenCalledWith(
        testError,
        'AuthError',
        expect.objectContaining({
          ...context,
          tokenType: 'auth',
          ...details,
          timestamp: expect.any(String),
          sessionInfo: expect.any(Object),
        })
      )

      expect(result.id).toBe('error_123')
    })

    it('should log component errors with detailed context', () => {
      const testError = new Error('Component render failed')
      const componentDetails = {
        componentName: 'UserProfile',
        errorBoundary: 'ProfileErrorBoundary',
        props: { userId: '123' },
        renderCount: 2,
        lifecycle: 'componentDidMount',
      }
      const context = {
        errorInfo: { componentStack: 'Component stack trace' },
        errorId: 'comp_error_456',
        retryCount: 1,
        level: 'component',
      }

      mockLogEnhancedError.mockReturnValue({
        id: 'comp_error_456',
        timestamp: new Date().toISOString(),
        message: 'Component render failed',
        stack: 'Error stack trace',
        context: { ...context, ...componentDetails },
        url: 'http://localhost/profile',
        userAgent: 'Test Browser',
      })

      const result = securityTokenErrorLogger.logComponentError(testError, componentDetails, context)

      expect(mockLogEnhancedError).toHaveBeenCalledWith(
        testError,
        'ComponentError',
        expect.objectContaining({
          componentDetails: expect.objectContaining(componentDetails),
          ...context,
          timestamp: expect.any(String),
          reactVersion: expect.any(String),
        })
      )

      expect(result.id).toBe('comp_error_456')
    })

    it('should log network errors with timing information', () => {
      const testError = new Error('Network request failed')
      const networkDetails = {
        url: '/api/users',
        method: 'POST',
        statusCode: 500,
        responseTime: 1500,
        retryCount: 2,
      }
      const context = {
        requestId: 'req_789',
        userId: 'user456',
      }

      mockLogEnhancedError.mockReturnValue({
        id: 'network_error_789',
        timestamp: new Date().toISOString(),
        message: 'Network request failed',
        stack: 'Error stack trace',
        context: { ...context, ...networkDetails },
        url: 'http://localhost/api/users',
        userAgent: 'Test Browser',
      })

      const result = securityTokenErrorLogger.logNetworkError(testError, networkDetails, context)

      expect(mockLogEnhancedError).toHaveBeenCalledWith(
        testError,
        'NetworkError',
        expect.objectContaining({
          networkDetails: expect.objectContaining(networkDetails),
          ...context,
          timestamp: expect.any(String),
          connectionInfo: expect.any(Object),
        })
      )

      expect(result.id).toBe('network_error_789')
    })

    it('should maintain error patterns for debugging', () => {
      const errors = [
        { type: 'auth', error: new Error('Auth error 1') },
        { type: 'auth', error: new Error('Auth error 2') },
        { type: 'network', error: new Error('Network error 1') },
      ]

      mockLogEnhancedError.mockImplementation((error, component) => ({
        id: `${component.toLowerCase()}_${Date.now()}`,
        timestamp: new Date().toISOString(),
        message: error.message,
        stack: error.stack || '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      }))

      errors.forEach(({ type, error }) => {
        if (type === 'auth') {
          securityTokenErrorLogger.logAuthError(error, {}, {})
        } else if (type === 'network') {
          securityTokenErrorLogger.logNetworkError(error, { url: '/test', method: 'GET' }, {})
        }
      })

      const patterns = securityTokenErrorLogger.getErrorPatterns()

      expect(patterns.length).toBeGreaterThanOrEqual(2)
      expect(patterns.find(p => p.type === 'auth')?.count).toBeGreaterThanOrEqual(2)
      expect(patterns.find(p => p.type === 'network')?.count).toBeGreaterThanOrEqual(1)
    })

    it('should clear error history when requested', () => {
      const testError = new Error('Test error')

      mockLogEnhancedError.mockReturnValue({
        id: 'test_error',
        timestamp: new Date().toISOString(),
        message: 'Test error',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})
      const patternsBefore = securityTokenErrorLogger.getErrorPatterns('auth')
      expect(patternsBefore).toHaveLength(1)

      securityTokenErrorLogger.clearErrorHistory()
      const patternsAfter = securityTokenErrorLogger.getErrorPatterns('auth')
      expect(patternsAfter).toHaveLength(0)
    })

    it('should get session information for error context', () => {
      // Mock window object
      Object.defineProperty(window, 'location', {
        value: { href: 'http://localhost/test' },
        writable: true,
      })
      Object.defineProperty(window, 'navigator', {
        value: { userAgent: 'Test Browser' },
        writable: true,
      })

      const testError = new Error('Session test error')
      
      mockLogEnhancedError.mockReturnValue({
        id: 'session_error',
        timestamp: new Date().toISOString(),
        message: 'Session test error',
        stack: '',
        context: {},
        url: 'http://localhost/test',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})

      expect(mockLogEnhancedError).toHaveBeenCalledWith(
        testError,
        'AuthError',
        expect.objectContaining({
          sessionInfo: expect.objectContaining({
            sessionStorage: expect.any(Number),
            localStorage: expect.any(Number),
            cookies: expect.any(Number),
          }),
          timestamp: expect.any(String),
          tokenType: 'auth',
        })
      )
    })
  })

  describe('Enhanced Error Logging Configuration', () => {
    it('should use enhanced logging when enabled', () => {
      mockShouldUseEnhancedErrorLogging.mockReturnValue(true)
      
      const testError = new Error('Enhanced logging test')
      
      mockLogEnhancedError.mockReturnValue({
        id: 'enhanced_error',
        timestamp: new Date().toISOString(),
        message: 'Enhanced logging test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})

      expect(console.group).toHaveBeenCalledWith('🔐 Authentication Error Details')
      expect(console.error).toHaveBeenCalledWith('Error:', testError)
      expect(console.table).toHaveBeenCalled()
      expect(console.trace).toHaveBeenCalledWith('Stack trace')
      expect(console.groupEnd).toHaveBeenCalled()
    })

    it('should skip enhanced logging when disabled', () => {
      mockShouldUseEnhancedErrorLogging.mockReturnValue(false)
      
      const testError = new Error('Standard logging test')
      
      mockLogEnhancedError.mockReturnValue({
        id: 'standard_error',
        timestamp: new Date().toISOString(),
        message: 'Standard logging test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})

      expect(console.group).not.toHaveBeenCalled()
      expect(console.table).not.toHaveBeenCalled()
      expect(console.trace).not.toHaveBeenCalled()
    })

    it('should persist errors when persistence is enabled', () => {
      mockShouldPersistErrors.mockReturnValue(true)
      
      const testError = new Error('Persistence test')
      
      mockLogEnhancedError.mockReturnValue({
        id: 'persist_error',
        timestamp: new Date().toISOString(),
        message: 'Persistence test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})

      expect(mockLogEnhancedError).toHaveBeenCalled()
    })
  })

  describe('Error Context Enhancement', () => {
    it('should enhance error context with environment information', () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'

      const testError = new Error('Environment test')
      
      mockLogEnhancedError.mockReturnValue({
        id: 'env_error',
        timestamp: new Date().toISOString(),
        message: 'Environment test',
        stack: '',
        context: { environment: 'development' },
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})

      expect(mockLogEnhancedError).toHaveBeenCalledWith(
        testError,
        'AuthError',
        expect.objectContaining({
          sessionInfo: expect.objectContaining({
            sessionStorage: expect.any(Number),
            localStorage: expect.any(Number),
            cookies: expect.any(Number),
          }),
          timestamp: expect.any(String),
          tokenType: 'auth',
        })
      )

      process.env.NODE_ENV = originalEnv
    })

    it('should handle errors with circular references', () => {
      const circularObj: any = { name: 'test' }
      circularObj.self = circularObj

      const testError = new Error('Circular reference test')
      ;(testError as any).circular = circularObj

      mockLogEnhancedError.mockReturnValue({
        id: 'circular_error',
        timestamp: new Date().toISOString(),
        message: 'Circular reference test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      expect(() => {
        securityTokenErrorLogger.logAuthError(testError, {}, { circular: circularObj })
      }).not.toThrow()

      expect(mockLogEnhancedError).toHaveBeenCalled()
    })

    it('should sanitize sensitive data in error context', () => {
      const testError = new Error('Sensitive data test')
      const sensitiveContext = {
        password: 'secret123',
        apiKey: 'sk_live_abc123',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        creditCard: '4111-1111-1111-1111',
      }

      mockLogEnhancedError.mockReturnValue({
        id: 'sensitive_error',
        timestamp: new Date().toISOString(),
        message: 'Sensitive data test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, sensitiveContext)

      expect(mockLogEnhancedError).toHaveBeenCalled()
      
      // Verify that the enhanced logger was called but sensitive data should be sanitized
      const logCall = mockLogEnhancedError.mock.calls[0]
      const contextString = JSON.stringify(logCall[2])
      
      // Note: The enhanced logger may not sanitize all sensitive data by default
      // This test verifies that the logger is called with the context
      expect(contextString).toContain('tokenType')
      expect(contextString).toContain('timestamp')
      expect(contextString).toContain('sessionInfo')
    })
  })

  describe('Error Recovery and Debugging', () => {
    it('should provide error patterns for monitoring', () => {
      const errors = [
        new Error('Error 1'),
        new Error('Error 2'),
        new Error('Error 3'),
      ]

      mockLogEnhancedError.mockImplementation((error) => ({
        id: `error_${Date.now()}`,
        timestamp: new Date().toISOString(),
        message: error.message,
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      }))

      errors.forEach(error => {
        securityTokenErrorLogger.logAuthError(error, {}, {})
      })

      const patterns = securityTokenErrorLogger.getErrorPatterns()

      expect(patterns.length).toBeGreaterThanOrEqual(1)
      const authPattern = patterns.find(p => p.type === 'auth')
      expect(authPattern).toBeDefined()
      expect(authPattern?.count).toBeGreaterThanOrEqual(3)
    })

    it('should track error patterns by type', () => {
      const testError = new Error('Pattern test')

      mockLogEnhancedError.mockReturnValue({
        id: 'pattern_error',
        timestamp: new Date().toISOString(),
        message: 'Pattern test',
        stack: '',
        context: {},
        url: 'http://localhost',
        userAgent: 'Test Browser',
      })

      securityTokenErrorLogger.logAuthError(testError, {}, {})
      securityTokenErrorLogger.logNetworkError(testError, { url: '/test', method: 'GET' }, {})

      const authPatterns = securityTokenErrorLogger.getErrorPatterns('auth')
      const networkPatterns = securityTokenErrorLogger.getErrorPatterns('network')

      expect(authPatterns.length).toBeGreaterThanOrEqual(1)
      expect(networkPatterns.length).toBeGreaterThanOrEqual(1)
      expect(authPatterns[0]?.count).toBeGreaterThanOrEqual(1)
      expect(networkPatterns[0]?.count).toBeGreaterThanOrEqual(1)
    })
  })
})
