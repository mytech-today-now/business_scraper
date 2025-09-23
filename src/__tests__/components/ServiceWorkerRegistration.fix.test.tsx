/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen, waitFor, act } from '@testing-library/react'
import { ServiceWorkerRegistration } from '@/components/ServiceWorkerRegistration'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')

const mockLogger = logger as jest.Mocked<typeof logger>

// Mock service worker
const mockServiceWorker = {
  getRegistrations: jest.fn(),
  register: jest.fn(),
}

// Mock registration
const mockRegistration = {
  unregister: jest.fn(),
  scope: '/',
}

describe('ServiceWorkerRegistration React Warning Fix', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Mock navigator.serviceWorker
    Object.defineProperty(window.navigator, 'serviceWorker', {
      value: mockServiceWorker,
      writable: true,
    })

    // Mock console methods to capture React warnings
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(console, 'warn').mockImplementation(() => {})
    jest.spyOn(console, 'log').mockImplementation(() => {})

    // Default mock implementations
    mockServiceWorker.getRegistrations.mockResolvedValue([mockRegistration])
    mockRegistration.unregister.mockResolvedValue(true)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('React Warning Prevention', () => {
    it('should not trigger React warnings about state updates during render', async () => {
      const consoleSpy = jest.spyOn(console, 'error')
      
      render(<ServiceWorkerRegistration />)

      // Wait for any async operations to complete
      await waitFor(() => {
        expect(mockLogger.info).toHaveBeenCalledWith(
          'ServiceWorker',
          'ServiceWorkerRegistration component completely disabled (Issue #189)'
        )
      }, { timeout: 100 })

      // Check that no React warnings were logged
      const reactWarnings = consoleSpy.mock.calls.filter(call => 
        call[0] && typeof call[0] === 'string' && 
        call[0].includes('Cannot update a component')
      )

      expect(reactWarnings).toHaveLength(0)
    })

    it('should prevent multiple initializations with useRef', async () => {
      const { rerender } = render(<ServiceWorkerRegistration />)
      
      // Rerender the component multiple times
      rerender(<ServiceWorkerRegistration />)
      rerender(<ServiceWorkerRegistration />)
      rerender(<ServiceWorkerRegistration />)

      // Wait for async operations
      await waitFor(() => {
        expect(mockLogger.info).toHaveBeenCalledWith(
          'ServiceWorker',
          'ServiceWorkerRegistration component completely disabled (Issue #189)'
        )
      }, { timeout: 100 })

      // Should only be called once despite multiple rerenders
      expect(mockLogger.info).toHaveBeenCalledTimes(1)
    })

    it('should use setTimeout to defer service worker operations', async () => {
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout')
      
      render(<ServiceWorkerRegistration />)

      // Verify setTimeout was called to defer operations
      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 0)

      // Wait for the deferred operation to complete
      await act(async () => {
        jest.runAllTimers()
      })

      await waitFor(() => {
        expect(mockServiceWorker.getRegistrations).toHaveBeenCalled()
      })

      setTimeoutSpy.mockRestore()
    })
  })

  describe('Service Worker Cleanup', () => {
    it('should unregister existing service workers', async () => {
      render(<ServiceWorkerRegistration />)

      // Wait for async operations to complete
      await act(async () => {
        jest.runAllTimers()
      })

      await waitFor(() => {
        expect(mockServiceWorker.getRegistrations).toHaveBeenCalled()
        expect(mockRegistration.unregister).toHaveBeenCalled()
      })

      expect(mockLogger.info).toHaveBeenCalledWith(
        'ServiceWorker',
        'Unregistered existing service worker',
        { scope: '/' }
      )
    })

    it('should handle service worker registration errors gracefully', async () => {
      mockServiceWorker.getRegistrations.mockRejectedValue(new Error('Registration failed'))

      render(<ServiceWorkerRegistration />)

      await act(async () => {
        jest.runAllTimers()
      })

      await waitFor(() => {
        expect(mockLogger.error).toHaveBeenCalledWith(
          'ServiceWorker',
          'Failed to unregister service workers',
          expect.any(Error)
        )
      })
    })

    it('should handle missing service worker support', async () => {
      // Remove service worker support
      Object.defineProperty(window.navigator, 'serviceWorker', {
        value: undefined,
        writable: true,
      })

      render(<ServiceWorkerRegistration />)

      await act(async () => {
        jest.runAllTimers()
      })

      // Should not attempt to access service worker APIs
      expect(mockServiceWorker.getRegistrations).not.toHaveBeenCalled()
    })
  })

  describe('Component Behavior', () => {
    it('should return null and not render anything', () => {
      const { container } = render(<ServiceWorkerRegistration />)
      
      expect(container.firstChild).toBeNull()
    })

    it('should log the expected debug message', async () => {
      render(<ServiceWorkerRegistration />)

      await waitFor(() => {
        expect(mockLogger.info).toHaveBeenCalledWith(
          'ServiceWorker',
          'ServiceWorkerRegistration component completely disabled (Issue #189)'
        )
      })
    })

    it('should handle component unmounting gracefully', async () => {
      const { unmount } = render(<ServiceWorkerRegistration />)
      
      // Unmount the component
      unmount()

      // Should not cause any errors or warnings
      expect(console.error).not.toHaveBeenCalledWith(
        expect.stringContaining('Warning')
      )
    })
  })
})
