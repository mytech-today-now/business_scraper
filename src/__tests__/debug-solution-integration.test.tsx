/**
 * Debug Solution Integration Test
 * Tests the complete debug mode solution for security token error capture
 */

import { render, screen, waitFor } from '@testing-library/react'
import { act } from 'react-dom/test-utils'
import { DebugSystemInitializer } from '@/components/DebugSystemInitializer'
import { isDebugMode, enableDebugMode, disableDebugMode, safeReload } from '@/utils/debugConfig'
import { SecurityTokenErrorLogger } from '@/utils/enhancedErrorLogger'
import { errorPersistenceManager } from '@/utils/errorPersistence'

// Mock environment variables for testing
const originalEnv = process.env

beforeEach(() => {
  // Clear localStorage
  localStorage.clear()
  
  // Clear error persistence
  errorPersistenceManager.clearAllErrors()
  
  // Reset environment
  process.env = { ...originalEnv }
  
  // Mock console methods
  jest.spyOn(console, 'log').mockImplementation(() => {})
  jest.spyOn(console, 'error').mockImplementation(() => {})
  jest.spyOn(console, 'warn').mockImplementation(() => {})
  jest.spyOn(console, 'info').mockImplementation(() => {})
})

afterEach(() => {
  process.env = originalEnv
  jest.restoreAllMocks()
  
  // Clean up DOM
  const indicator = document.getElementById('debug-mode-indicator')
  if (indicator) {
    indicator.remove()
  }
})

describe('Debug Solution Integration', () => {
  describe('Complete Debug Mode Flow', () => {
    it('should enable debug mode and prevent auto-reload during security token errors', async () => {
      // Enable debug mode
      enableDebugMode()
      expect(isDebugMode()).toBe(true)
      
      // Initialize debug system
      render(<DebugSystemInitializer />)
      
      // Wait for debug indicator to appear
      await waitFor(() => {
        const indicator = document.getElementById('debug-mode-indicator')
        expect(indicator).toBeInTheDocument()
        expect(indicator?.textContent).toBe('🐛 DEBUG MODE')
      })
      
      // Simulate security token error
      const logger = new SecurityTokenErrorLogger()
      const mockError = new Error('CSRF token validation failed')
      
      // Log the error (should be captured and persisted)
      logger.logCSRFError(mockError, {
        endpoint: '/api/csrf',
        method: 'GET',
        headers: {},
        timestamp: Date.now()
      })
      
      // Verify error was persisted
      const persistedErrors = errorPersistenceManager.getCurrentSessionErrors()
      expect(persistedErrors).toHaveLength(1)
      expect(persistedErrors[0].message).toContain('CSRF token validation failed')
      
      // Test safe reload (should be prevented in debug mode)
      const originalReload = window.location.reload
      const reloadSpy = jest.fn()
      Object.defineProperty(window.location, 'reload', {
        writable: true,
        value: reloadSpy
      })

      safeReload('Security token error occurred')

      // Reload should be prevented
      expect(reloadSpy).not.toHaveBeenCalled()

      // Restore original reload
      Object.defineProperty(window.location, 'reload', {
        writable: true,
        value: originalReload
      })
    })

    it('should allow normal reload when debug mode is disabled', () => {
      // Disable debug mode
      disableDebugMode()
      expect(isDebugMode()).toBe(false)
      
      // Test safe reload (should proceed normally)
      const originalReload = window.location.reload
      const reloadSpy = jest.fn()
      Object.defineProperty(window.location, 'reload', {
        writable: true,
        value: reloadSpy
      })

      safeReload('Normal reload')

      // Reload should proceed
      expect(reloadSpy).toHaveBeenCalled()

      // Restore original reload
      Object.defineProperty(window.location, 'reload', {
        writable: true,
        value: originalReload
      })
    })

    it('should provide debug utilities in console when debug mode is active', async () => {
      // Enable debug mode
      enableDebugMode()
      
      // Initialize debug system
      render(<DebugSystemInitializer />)
      
      // Wait for debug utilities to be available
      await waitFor(() => {
        expect((window as any).debugUtils).toBeDefined()
        expect(typeof (window as any).debugUtils.enableDebugMode).toBe('function')
        expect(typeof (window as any).debugUtils.disableDebugMode).toBe('function')
        expect(typeof (window as any).debugUtils.getErrorAnalytics).toBe('function')
        expect(typeof (window as any).debugUtils.exportErrorData).toBe('function')
        expect(typeof (window as any).debugUtils.clearErrors).toBe('function')
        expect(typeof (window as any).debugUtils.getPersistedErrors).toBe('function')
      })
    })

    it('should capture and persist security token loading errors', () => {
      // Enable debug mode
      enableDebugMode()
      
      // Create logger
      const logger = new SecurityTokenErrorLogger()
      
      // Simulate various security token errors
      const errors = [
        { message: 'Loading Security Token...', type: 'loading' },
        { message: 'CSRF token expired', type: 'csrf' },
        { message: 'Authentication failed', type: 'auth' },
        { message: 'Network timeout during token fetch', type: 'network' }
      ]
      
      errors.forEach(({ message, type }) => {
        const error = new Error(message)
        logger.logCSRFError(error, {
          endpoint: '/api/csrf',
          method: 'GET',
          errorType: type,
          timestamp: Date.now()
        })
      })
      
      // Verify all errors were persisted
      const persistedErrors = errorPersistenceManager.getCurrentSessionErrors()
      expect(persistedErrors).toHaveLength(4)
      
      // Verify error analytics
      const analytics = errorPersistenceManager.getErrorAnalytics()
      expect(analytics.totalErrors).toBe(4)
      expect(analytics.errorPatterns).toHaveLength(4)
    })

    it('should show reload prevention notification when auto-reload is blocked', async () => {
      // Enable debug mode
      enableDebugMode()
      
      // Initialize debug system
      render(<DebugSystemInitializer />)
      
      // Simulate reload prevention event
      act(() => {
        const event = new CustomEvent('debug-reload-prevented', {
          detail: { reason: 'Security token error occurred' }
        })
        window.dispatchEvent(event)
      })
      
      // Wait for notification to appear
      await waitFor(() => {
        const notifications = document.querySelectorAll('div[style*="position: fixed"]')
        const reloadNotification = Array.from(notifications).find(el => 
          el.textContent?.includes('Auto-reload Prevented')
        )
        expect(reloadNotification).toBeInTheDocument()
        expect(reloadNotification?.textContent).toContain('Security token error occurred')
      })
    })
  })

  describe('Error Recovery and Debugging', () => {
    it('should provide comprehensive error data for debugging', () => {
      // Enable debug mode
      enableDebugMode()
      
      // Create logger and log multiple errors
      const logger = new SecurityTokenErrorLogger()
      
      // Simulate a sequence of errors that would occur during the reported issue
      logger.logCSRFError(new Error('Loading Security Token...'), {
        endpoint: '/api/csrf',
        method: 'GET',
        timestamp: Date.now()
      })
      
      logger.logCSRFError(new Error('Failed to fetch CSRF token'), {
        endpoint: '/api/csrf',
        method: 'GET',
        status: 500,
        timestamp: Date.now()
      })
      
      logger.logCSRFError(new Error('Page reload triggered'), {
        endpoint: 'window.location.reload',
        method: 'RELOAD',
        timestamp: Date.now()
      })
      
      // Export error data for debugging
      const exportedData = errorPersistenceManager.exportErrorData()
      
      expect(exportedData.summary.totalErrors).toBe(3)
      expect(exportedData.summary.totalSessions).toBe(1)
      expect(exportedData.errors).toHaveLength(3)
      
      // Verify error sequence is captured
      const errorMessages = exportedData.errors.map(e => e.message)
      expect(errorMessages).toContain('Loading Security Token...')
      expect(errorMessages).toContain('Failed to fetch CSRF token')
      expect(errorMessages).toContain('Page reload triggered')
    })
  })
})
