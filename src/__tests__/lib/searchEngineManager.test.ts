/**
 * Search Engine Manager Tests
 * 
 * Tests for duplicate detection, session management, and engine state management
 */

import { SearchEngineManager } from '@/lib/searchEngineManager'

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value
    },
    removeItem: (key: string) => {
      delete store[key]
    },
    clear: () => {
      store = {}
    }
  }
})()

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
})

// Mock toast
jest.mock('react-hot-toast', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn()
  }
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

describe('SearchEngineManager', () => {
  let manager: SearchEngineManager

  beforeEach(() => {
    localStorageMock.clear()
    manager = new SearchEngineManager()
  })

  describe('Session Management', () => {
    test('should start a new session', () => {
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)

      const engines = manager.getAllEngines()
      engines.forEach(engine => {
        expect(engine.sessionId).toBe(sessionId)
        expect(engine.isDisabledForSession).toBe(false)
        expect(engine.duplicateCount).toBe(0)
        expect(engine.lastResults).toEqual([])
      })
    })

    test('should end session and reset session state', () => {
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)
      
      // Simulate some session activity
      const engines = manager.getAllEngines()
      engines[0].duplicateCount = 1
      engines[0].isDisabledForSession = true

      manager.endSession()

      engines.forEach(engine => {
        expect(engine.sessionId).toBeNull()
        expect(engine.isDisabledForSession).toBe(false)
        expect(engine.duplicateCount).toBe(0)
        expect(engine.lastResults).toEqual([])
      })
    })
  })

  describe('Duplicate Detection', () => {
    test('should detect duplicate results', () => {
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)

      const results = [
        { url: 'https://example.com', title: 'Example Site', domain: 'example.com' },
        { url: 'https://test.com', title: 'Test Site', domain: 'test.com' }
      ]

      // First call should be fine
      const firstResult = manager.checkAndUpdateResults('google', results)
      expect(firstResult).toBe(true)

      // Second call with same results should detect duplicate
      const secondResult = manager.checkAndUpdateResults('google', results)
      expect(secondResult).toBe(true) // Still available after first duplicate

      // Third call should disable the engine
      const thirdResult = manager.checkAndUpdateResults('google', results)
      expect(thirdResult).toBe(false) // Engine should be disabled

      const googleEngine = manager.getAllEngines().find(e => e.id === 'google')
      expect(googleEngine?.isDisabledForSession).toBe(true)
      expect(googleEngine?.duplicateCount).toBe(2)
    })

    test('should not detect duplicates for different results', () => {
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)

      const results1 = [
        { url: 'https://example.com', title: 'Example Site', domain: 'example.com' }
      ]

      const results2 = [
        { url: 'https://different.com', title: 'Different Site', domain: 'different.com' }
      ]

      const firstResult = manager.checkAndUpdateResults('google', results1)
      expect(firstResult).toBe(true)

      const secondResult = manager.checkAndUpdateResults('google', results2)
      expect(secondResult).toBe(true)

      const googleEngine = manager.getAllEngines().find(e => e.id === 'google')
      expect(googleEngine?.isDisabledForSession).toBe(false)
      expect(googleEngine?.duplicateCount).toBe(0)
    })
  })

  describe('Engine Management', () => {
    test('should enable and disable engines', () => {
      manager.setEngineEnabled('google', false)
      
      const googleEngine = manager.getAllEngines().find(e => e.id === 'google')
      expect(googleEngine?.enabled).toBe(false)

      manager.setEngineEnabled('google', true)
      expect(googleEngine?.enabled).toBe(true)
    })

    test('should return only available engines', () => {
      manager.setEngineEnabled('google', false)
      
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)
      
      // Disable azure for session
      const azureEngine = manager.getAllEngines().find(e => e.id === 'azure')
      if (azureEngine) {
        azureEngine.isDisabledForSession = true
      }

      const availableEngines = manager.getAvailableEngines()
      
      // Should only have duckduckgo available
      expect(availableEngines).toHaveLength(1)
      expect(availableEngines[0].id).toBe('duckduckgo')
    })

    test('should check if any engines are available', () => {
      expect(manager.hasAvailableEngines()).toBe(true)

      // Disable all engines
      manager.setEngineEnabled('google', false)
      manager.setEngineEnabled('azure', false)
      manager.setEngineEnabled('duckduckgo', false)

      expect(manager.hasAvailableEngines()).toBe(false)
    })

    test('should reset all engines', () => {
      // Disable some engines
      manager.setEngineEnabled('google', false)
      manager.setEngineEnabled('azure', false)

      // Start session and disable one for session
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)
      
      const duckduckgoEngine = manager.getAllEngines().find(e => e.id === 'duckduckgo')
      if (duckduckgoEngine) {
        duckduckgoEngine.isDisabledForSession = true
        duckduckgoEngine.duplicateCount = 2
      }

      manager.resetAllEngines()

      const engines = manager.getAllEngines()
      engines.forEach(engine => {
        expect(engine.enabled).toBe(true)
        expect(engine.isDisabledForSession).toBe(false)
        expect(engine.duplicateCount).toBe(0)
        expect(engine.lastResults).toEqual([])
      })
    })
  })

  describe('State Persistence', () => {
    test('should save and load state from localStorage', () => {
      manager.setEngineEnabled('google', false)
      
      // Create new manager instance to test loading
      const newManager = new SearchEngineManager()
      
      const googleEngine = newManager.getAllEngines().find(e => e.id === 'google')
      expect(googleEngine?.enabled).toBe(false)
    })
  })

  describe('Error Handling', () => {
    test('should handle unknown engine gracefully', () => {
      const result = manager.checkAndUpdateResults('unknown-engine', [])
      expect(result).toBe(false)
    })

    test('should handle empty results', () => {
      const sessionId = 'test-session-123'
      manager.startSession(sessionId)

      const result = manager.checkAndUpdateResults('google', [])
      expect(result).toBe(true)
    })
  })
})
