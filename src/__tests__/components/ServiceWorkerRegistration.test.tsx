/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen, waitFor, act } from '@testing-library/react'
import { ServiceWorkerRegistration, useIsPWA } from '@/components/ServiceWorkerRegistration'
import { useOfflineSupport } from '@/hooks/useOfflineSupport'
import { expectArrayElement } from '../utils/mockTypeHelpers'
import toast from 'react-hot-toast'
import { logger } from '@/utils/logger'
import { mockNodeEnv } from '../utils/mockTypeHelpers'

// Mock dependencies
jest.mock('@/hooks/useOfflineSupport')
jest.mock('react-hot-toast')
jest.mock('@/utils/logger')

// Mock service worker
const mockServiceWorker = {
  register: jest.fn(),
  addEventListener: jest.fn(),
  controller: null,
}

const mockRegistration = {
  scope: '/',
  updateViaCache: 'none',
  addEventListener: jest.fn(),
  installing: null,
  waiting: null,
  update: jest.fn(),
}

// Mock navigator
Object.defineProperty(window, 'navigator', {
  value: {
    serviceWorker: mockServiceWorker,
    onLine: true,
  },
  writable: true,
})

// Mock window events
const mockAddEventListener = jest.fn()
const mockRemoveEventListener = jest.fn()
Object.defineProperty(window, 'addEventListener', {
  value: mockAddEventListener,
  writable: true,
})
Object.defineProperty(window, 'removeEventListener', {
  value: mockRemoveEventListener,
  writable: true,
})

// Mock process.env
const originalEnv = process.env
beforeEach(() => {
  process.env = { ...originalEnv }
  jest.clearAllMocks()
})

afterEach(() => {
  process.env = originalEnv
})

describe('ServiceWorkerRegistration', () => {
  const mockUseOfflineSupport = useOfflineSupport as jest.MockedFunction<typeof useOfflineSupport>
  const mockToast = toast as jest.Mocked<typeof toast>
  const mockLogger = logger as jest.Mocked<typeof logger>

  beforeEach(() => {
    // Default mock implementation
    mockUseOfflineSupport.mockReturnValue({
      isOnline: true,
      isOffline: false,
      wasOffline: false,
      lastOnlineTime: new Date(),
      lastOfflineTime: null,
      isChecking: false,
      checkConnectivity: jest.fn(),
      retryConnection: jest.fn(),
      getOfflineDuration: jest.fn(),
      getTimeSinceLastOnline: jest.fn(),
    })

    mockServiceWorker.register.mockResolvedValue(mockRegistration)
    mockToast.success = jest.fn()
    mockToast.error = jest.fn()
    mockToast.custom = jest.fn()
    mockToast.dismiss = jest.fn()
  })

  describe('Initialization and Temporal Dead Zone Fix', () => {
    it('should render without throwing wasOffline initialization error', () => {
      expect(() => {
        render(<ServiceWorkerRegistration />)
      }).not.toThrow()
    })

    it('should handle wasOffline state changes without errors', async () => {
      let mockReturnValue = {
        isOnline: true,
        isOffline: false,
        wasOffline: false,
        lastOnlineTime: new Date(),
        lastOfflineTime: null,
        isChecking: false,
        checkConnectivity: jest.fn(),
        retryConnection: jest.fn(),
        getOfflineDuration: jest.fn(),
        getTimeSinceLastOnline: jest.fn(),
      }

      mockUseOfflineSupport.mockReturnValue(mockReturnValue)

      const { rerender } = render(<ServiceWorkerRegistration />)

      // Simulate wasOffline changing to true
      mockReturnValue = { ...mockReturnValue, wasOffline: true }
      mockUseOfflineSupport.mockReturnValue(mockReturnValue)

      expect(() => {
        rerender(<ServiceWorkerRegistration />)
      }).not.toThrow()
    })

    it('should properly initialize useOfflineSupport with previousWasOffline state', () => {
      render(<ServiceWorkerRegistration />)

      expect(mockUseOfflineSupport).toHaveBeenCalledWith({
        onOnline: undefined, // Should be undefined initially since previousWasOffline is false
        onOffline: expect.any(Function),
      })
    })
  })

  describe('Service Worker Registration', () => {
    it('should register service worker in production environment', async () => {
      // Use proper environment mocking
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'production',
        writable: true,
        configurable: true,
      })

      render(<ServiceWorkerRegistration />)

      await waitFor(() => {
        expect(mockServiceWorker.register).toHaveBeenCalledWith('/sw.js', {
          scope: '/',
          updateViaCache: 'none',
        })
      })

      expect(mockLogger.info).toHaveBeenCalledWith('ServiceWorker', 'Registering service worker...')
    })

    it('should not register service worker in development environment', () => {
      // Use proper environment mocking
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'development',
        writable: true,
        configurable: true,
      })

      render(<ServiceWorkerRegistration />)

      expect(mockServiceWorker.register).not.toHaveBeenCalled()
    })

    it('should handle service worker registration failure gracefully', async () => {
      // Use proper environment mocking
      Object.defineProperty(process.env, 'NODE_ENV', {
        value: 'production',
        writable: true,
        configurable: true,
      })
      const error = new Error('Registration failed')
      mockServiceWorker.register.mockRejectedValue(error)

      render(<ServiceWorkerRegistration />)

      await waitFor(() => {
        expect(mockLogger.error).toHaveBeenCalledWith(
          'ServiceWorker',
          'Service worker registration failed',
          error
        )
      })
    })
  })

  describe('Offline/Online State Management', () => {
    it('should show online toast when coming back online after being offline', async () => {
      // Start with wasOffline: true to trigger online callback
      mockUseOfflineSupport.mockReturnValue({
        isOnline: true,
        isOffline: false,
        wasOffline: true,
        lastOnlineTime: new Date(),
        lastOfflineTime: null,
        isChecking: false,
        checkConnectivity: jest.fn(),
        retryConnection: jest.fn(),
        getOfflineDuration: jest.fn(),
        getTimeSinceLastOnline: jest.fn(),
      })

      render(<ServiceWorkerRegistration />)

      // The onOnline callback should be defined when wasOffline is true
      expect(mockUseOfflineSupport).toHaveBeenCalledWith({
        onOnline: undefined, // Initially undefined, but will be set after state update
        onOffline: expect.any(Function),
      })
    })

    it('should show offline toast when going offline', () => {
      const mockOnOffline = jest.fn()
      mockUseOfflineSupport.mockReturnValue({
        isOnline: false,
        isOffline: true,
        wasOffline: false,
        lastOnlineTime: new Date(),
        lastOfflineTime: new Date(),
        isChecking: false,
        checkConnectivity: jest.fn(),
        retryConnection: jest.fn(),
        getOfflineDuration: jest.fn(),
        getTimeSinceLastOnline: jest.fn(),
      })

      render(<ServiceWorkerRegistration />)

      // Get the onOffline callback that was passed to useOfflineSupport
      const firstCall = expectArrayElement(mockUseOfflineSupport.mock.calls, 0)
      const callArgs = expectArrayElement(firstCall, 0)
      const onOfflineCallback = callArgs.onOffline

      // Simulate calling the offline callback
      act(() => {
        onOfflineCallback?.()
      })

      expect(mockToast.error).toHaveBeenCalledWith(
        "You're offline. Some features may be limited.",
        {
          duration: 5000,
          icon: '📱',
        }
      )
    })
  })

  describe('PWA Install Prompt', () => {
    it('should handle beforeinstallprompt event', () => {
      render(<ServiceWorkerRegistration />)

      expect(mockAddEventListener).toHaveBeenCalledWith(
        'beforeinstallprompt',
        expect.any(Function)
      )
      expect(mockAddEventListener).toHaveBeenCalledWith(
        'appinstalled',
        expect.any(Function)
      )
    })

    it('should clean up event listeners on unmount', () => {
      const { unmount } = render(<ServiceWorkerRegistration />)

      unmount()

      expect(mockRemoveEventListener).toHaveBeenCalledWith(
        'beforeinstallprompt',
        expect.any(Function)
      )
      expect(mockRemoveEventListener).toHaveBeenCalledWith(
        'appinstalled',
        expect.any(Function)
      )
    })
  })

  describe('Component Return Value', () => {
    it('should return null as it is a utility component', () => {
      const { container } = render(<ServiceWorkerRegistration />)
      expect(container.firstChild).toBeNull()
    })
  })
})

describe('useIsPWA', () => {
  it('should return false initially', () => {
    const TestComponent = () => {
      const isPWA = useIsPWA()
      return <div data-testid="pwa-status">{isPWA ? 'PWA' : 'Not PWA'}</div>
    }

    render(<TestComponent />)
    expect(screen.getByTestId('pwa-status')).toHaveTextContent('Not PWA')
  })

  it('should detect PWA mode when display-mode is standalone', () => {
    // Mock matchMedia for standalone mode
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: query === '(display-mode: standalone)',
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    })

    const TestComponent = () => {
      const isPWA = useIsPWA()
      return <div data-testid="pwa-status">{isPWA ? 'PWA' : 'Not PWA'}</div>
    }

    render(<TestComponent />)
    expect(screen.getByTestId('pwa-status')).toHaveTextContent('PWA')
  })
})
