/**
 * Error Persistence Tests
 * Tests for error persistence functionality across page reloads
 */

import { 
  ErrorPersistenceManager,
  errorPersistenceManager,
  setupErrorPersistence,
  type PersistedErrorSession,
  type ErrorAnalytics
} from '@/utils/errorPersistence'
import { createErrorDetails } from '@/utils/debugConfig'

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

// Mock window properties
Object.defineProperty(window, 'navigator', {
  value: {
    userAgent: 'Test User Agent'
  }
})

Object.defineProperty(window, 'location', {
  value: {
    href: 'http://localhost:3000/test'
  }
})

describe('ErrorPersistenceManager', () => {
  let manager: ErrorPersistenceManager

  beforeEach(() => {
    jest.clearAllMocks()
    localStorageMock.getItem.mockReturnValue(null)
    manager = new ErrorPersistenceManager()
  })

  describe('Session Management', () => {
    it('should create a new session on initialization', () => {
      expect(localStorageMock.setItem).toHaveBeenCalledWith(
        'error_persistence_current_session',
        expect.any(String)
      )

      const sessionData = JSON.parse(localStorageMock.setItem.mock.calls[0][1])
      expect(sessionData.sessionId).toBeDefined()
      expect(sessionData.startTime).toBeDefined()
      expect(sessionData.errors).toEqual([])
      expect(sessionData.metadata.userAgent).toBe('Test User Agent')
      expect(sessionData.metadata.url).toBe('http://localhost:3000/test')
    })

    it('should persist errors to current session', () => {
      const errorDetails = createErrorDetails(
        new Error('Test error'),
        'TestComponent',
        { testContext: 'value' }
      )

      // Mock shouldPersistErrors to return true by setting localStorage
      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'debug_mode') return 'true'
        if (key === 'debug_persist_errors') return 'true'
        return null
      })

      manager.persistError(errorDetails)

      // Check that setItem was called with the session data containing the error
      const setItemCalls = localStorageMock.setItem.mock.calls.filter(
        call => call[0] === 'error_persistence_current_session'
      )
      expect(setItemCalls.length).toBeGreaterThan(0)

      // Parse the last call to check if it contains the error
      const lastCall = setItemCalls[setItemCalls.length - 1]
      const sessionData = JSON.parse(lastCall[1])
      expect(sessionData.errors).toContainEqual(
        expect.objectContaining({
          id: errorDetails.id,
          message: 'Test error'
        })
      )
    })

    it('should limit errors per session', () => {
      // Mock shouldPersistErrors to return true
      jest.doMock('@/utils/debugConfig', () => ({
        shouldPersistErrors: () => true,
        createErrorDetails: jest.requireActual('@/utils/debugConfig').createErrorDetails
      }))

      // Add 150 errors (more than the 100 limit)
      for (let i = 0; i < 150; i++) {
        const errorDetails = createErrorDetails(
          new Error(`Test error ${i}`),
          'TestComponent'
        )
        manager.persistError(errorDetails)
      }

      const currentErrors = manager.getCurrentSessionErrors()
      expect(currentErrors.length).toBeLessThanOrEqual(100)
    })

    it('should end session and move to sessions list', () => {
      const mockSession: PersistedErrorSession = {
        sessionId: 'test-session',
        startTime: '2023-01-01T00:00:00.000Z',
        errors: [],
        metadata: {
          userAgent: 'Test User Agent',
          url: 'http://localhost:3000/test',
          timestamp: '2023-01-01T00:00:00.000Z',
          debugMode: true
        }
      }

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_current_session') {
          return JSON.stringify(mockSession)
        }
        if (key === 'error_persistence_sessions') {
          return JSON.stringify([])
        }
        return null
      })

      manager.endSession()

      expect(localStorageMock.setItem).toHaveBeenCalledWith(
        'error_persistence_sessions',
        expect.stringContaining('test-session')
      )
      expect(localStorageMock.removeItem).toHaveBeenCalledWith(
        'error_persistence_current_session'
      )
    })

    it('should limit number of stored sessions', () => {
      // Create 15 mock sessions (more than the 10 limit)
      const mockSessions: PersistedErrorSession[] = []
      for (let i = 0; i < 15; i++) {
        mockSessions.push({
          sessionId: `session-${i}`,
          startTime: `2023-01-0${i + 1}T00:00:00.000Z`,
          errors: [],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: `2023-01-0${i + 1}T00:00:00.000Z`,
            debugMode: true
          }
        })
      }

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_sessions') {
          return JSON.stringify(mockSessions)
        }
        if (key === 'error_persistence_current_session') {
          return JSON.stringify({
            sessionId: 'current-session',
            startTime: '2023-01-16T00:00:00.000Z',
            errors: [],
            metadata: {
              userAgent: 'Test User Agent',
              url: 'http://localhost:3000/test',
              timestamp: '2023-01-16T00:00:00.000Z',
              debugMode: true
            }
          })
        }
        return null
      })

      manager.endSession()

      const setItemCall = localStorageMock.setItem.mock.calls.find(
        call => call[0] === 'error_persistence_sessions'
      )
      expect(setItemCall).toBeDefined()

      const storedSessions = JSON.parse(setItemCall![1])
      expect(storedSessions.length).toBeLessThanOrEqual(10)
    })
  })

  describe('Error Analytics', () => {
    it('should generate error analytics from all sessions', () => {
      const mockSessions: PersistedErrorSession[] = [
        {
          sessionId: 'session-1',
          startTime: '2023-01-01T00:00:00.000Z',
          errors: [
            createErrorDetails(new Error('CSRF error'), 'CSRFComponent', { tokenType: 'csrf' }),
            createErrorDetails(new Error('Auth error'), 'AuthComponent', { tokenType: 'auth' }),
          ],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: '2023-01-01T00:00:00.000Z',
            debugMode: true
          }
        },
        {
          sessionId: 'session-2',
          startTime: '2023-01-02T00:00:00.000Z',
          errors: [
            createErrorDetails(new Error('CSRF error'), 'CSRFComponent', { tokenType: 'csrf' }),
          ],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: '2023-01-02T00:00:00.000Z',
            debugMode: true
          }
        }
      ]

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_sessions') {
          return JSON.stringify(mockSessions)
        }
        return null
      })

      const analytics = manager.getErrorAnalytics()

      expect(analytics.totalErrors).toBe(3)
      expect(analytics.errorsByComponent.CSRFComponent).toBe(2)
      expect(analytics.errorsByComponent.AuthComponent).toBe(1)
      expect(analytics.errorsByType.csrf).toBe(2)
      expect(analytics.errorsByType.auth).toBe(1)
      expect(analytics.recentErrors.length).toBe(3)
      expect(analytics.errorPatterns.length).toBeGreaterThan(0)
    })

    it('should extract error patterns correctly', () => {
      const mockSessions: PersistedErrorSession[] = [
        {
          sessionId: 'session-1',
          startTime: '2023-01-01T00:00:00.000Z',
          errors: [
            createErrorDetails(new Error('Failed to fetch CSRF token: 401'), 'CSRFComponent'),
            createErrorDetails(new Error('Failed to fetch CSRF token: 500'), 'CSRFComponent'),
            createErrorDetails(new Error('Authentication error'), 'AuthComponent'),
            createErrorDetails(new Error('Authentication error'), 'AuthComponent'),
          ],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: '2023-01-01T00:00:00.000Z',
            debugMode: true
          }
        }
      ]

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_sessions') {
          return JSON.stringify(mockSessions)
        }
        return null
      })

      const analytics = manager.getErrorAnalytics()

      expect(analytics.errorPatterns).toContainEqual(
        expect.objectContaining({
          pattern: 'Failed to fetch CSRF token: XXX',
          count: 2
        })
      )
      expect(analytics.errorPatterns).toContainEqual(
        expect.objectContaining({
          pattern: 'Authentication error',
          count: 2
        })
      )
    })
  })

  describe('Data Management', () => {
    it('should clear all persisted errors', () => {
      manager.clearAllErrors()

      expect(localStorageMock.removeItem).toHaveBeenCalledWith('error_persistence_sessions')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('error_persistence_current_session')
    })

    it('should clear old errors based on date', () => {
      const oldDate = new Date()
      oldDate.setDate(oldDate.getDate() - 10) // 10 days ago

      const recentDate = new Date()
      recentDate.setDate(recentDate.getDate() - 3) // 3 days ago

      const mockSessions: PersistedErrorSession[] = [
        {
          sessionId: 'old-session',
          startTime: oldDate.toISOString(),
          errors: [],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: oldDate.toISOString(),
            debugMode: true
          }
        },
        {
          sessionId: 'recent-session',
          startTime: recentDate.toISOString(),
          errors: [],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: recentDate.toISOString(),
            debugMode: true
          }
        }
      ]

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_sessions') {
          return JSON.stringify(mockSessions)
        }
        return null
      })

      manager.clearOldErrors(7) // Clear errors older than 7 days

      const setItemCall = localStorageMock.setItem.mock.calls.find(
        call => call[0] === 'error_persistence_sessions'
      )
      expect(setItemCall).toBeDefined()

      const remainingSessions = JSON.parse(setItemCall![1])
      expect(remainingSessions.length).toBe(1)
      expect(remainingSessions[0].sessionId).toBe('recent-session')
    })

    it('should export error data for debugging', () => {
      const mockSessions: PersistedErrorSession[] = [
        {
          sessionId: 'test-session',
          startTime: '2023-01-01T00:00:00.000Z',
          errors: [
            createErrorDetails(new Error('Test error'), 'TestComponent')
          ],
          metadata: {
            userAgent: 'Test User Agent',
            url: 'http://localhost:3000/test',
            timestamp: '2023-01-01T00:00:00.000Z',
            debugMode: true
          }
        }
      ]

      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'error_persistence_sessions') {
          return JSON.stringify(mockSessions)
        }
        return null
      })

      const exportData = manager.exportErrorData()
      const parsedData = JSON.parse(exportData)

      expect(parsedData.exportTimestamp).toBeDefined()
      expect(parsedData.analytics).toBeDefined()
      expect(parsedData.sessions).toEqual(mockSessions)
      expect(parsedData.metadata.userAgent).toBe('Test User Agent')
      expect(parsedData.metadata.url).toBe('http://localhost:3000/test')
    })
  })
})

describe('Setup Error Persistence', () => {
  it('should setup event listeners for session management', () => {
    const addEventListenerSpy = jest.spyOn(window, 'addEventListener')
    const setIntervalSpy = jest.spyOn(global, 'setInterval')

    setupErrorPersistence()

    expect(addEventListenerSpy).toHaveBeenCalledWith('beforeunload', expect.any(Function))
    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 24 * 60 * 60 * 1000)

    addEventListenerSpy.mockRestore()
    setIntervalSpy.mockRestore()
  })
})
