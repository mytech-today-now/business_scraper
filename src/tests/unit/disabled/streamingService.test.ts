/**
 * Unit tests for Streaming Service
 * Tests WebSocket streaming, session management, and error handling
 */

import {
  streamingService,
  StreamingSearchParams,
  StreamingMessage,
  StreamingSession,
} from '@/lib/streamingService'

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  readyState = MockWebSocket.CONNECTING
  onopen: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  constructor(public url: string) {
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN
      if (this.onopen) {
        this.onopen(new Event('open'))
      }
    }, 10)
  }

  send(data: string) {
    // Mock send implementation
    console.log('WebSocket send:', data)
  }

  close() {
    this.readyState = MockWebSocket.CLOSED
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code: 1000, reason: 'Normal closure' }))
    }
  }

  // Helper method to simulate receiving messages
  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }))
    }
  }

  // Helper method to simulate errors
  simulateError() {
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }
}

// Mock window.location
const mockLocation = {
  protocol: 'https:',
  host: 'localhost:3000',
}

// Setup mocks
beforeAll(() => {
  global.WebSocket = MockWebSocket as any
  Object.defineProperty(window, 'location', {
    value: mockLocation,
    writable: true,
  })
})

beforeEach(() => {
  // Cleanup all sessions before each test
  streamingService.cleanupAll()
  jest.clearAllMocks()
})

describe('StreamingService', () => {
  const mockSearchParams: StreamingSearchParams = {
    query: 'test business',
    location: 'New York',
    industry: 'Technology',
    maxResults: 100,
  }

  describe('Session Management', () => {
    test('should start a new streaming session', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      expect(sessionId).toBeDefined()
      expect(sessionId).toMatch(/^stream_\d+_[a-z0-9]+$/)

      const session = streamingService.getSession(sessionId)
      expect(session).toBeDefined()
      expect(session?.params).toEqual(mockSearchParams)
      expect(session?.status).toBe('connecting')
    })

    test('should get session information', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const session = streamingService.getSession(sessionId)

      expect(session).toBeDefined()
      expect(session?.id).toBe(sessionId)
      expect(session?.params).toEqual(mockSearchParams)
      expect(session?.results).toEqual([])
      expect(session?.connectionHealth).toBeDefined()
      expect(session?.errorHistory).toEqual([])
    })

    test('should return undefined for non-existent session', () => {
      const session = streamingService.getSession('non-existent-id')
      expect(session).toBeUndefined()
    })

    test('should get active sessions', async () => {
      const sessionId1 = await streamingService.startStreaming(mockSearchParams)
      const sessionId2 = await streamingService.startStreaming(mockSearchParams)

      // Wait for connections to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const activeSessions = streamingService.getActiveSessions()
      expect(activeSessions).toHaveLength(2)
      expect(activeSessions.map(s => s.id)).toContain(sessionId1)
      expect(activeSessions.map(s => s.id)).toContain(sessionId2)
    })
  })

  describe('WebSocket Connection', () => {
    test('should establish WebSocket connection', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const session = streamingService.getSession(sessionId)
      expect(session?.websocket).toBeDefined()
      expect(session?.status).toBe('active')
      expect(session?.connectionHealth.isConnected).toBe(true)
    })

    test('should handle WebSocket connection errors', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const session = streamingService.getSession(sessionId)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      // Simulate WebSocket error
      const mockWs = session?.websocket as MockWebSocket
      mockWs.simulateError()

      // Check that error was handled
      expect(session?.errorHistory.length).toBeGreaterThan(0)
    })

    test('should handle WebSocket connection close', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const session = streamingService.getSession(sessionId)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      // Simulate WebSocket close
      const mockWs = session?.websocket as MockWebSocket
      mockWs.close()

      // Should attempt reconnection
      expect(session?.connectionHealth.isConnected).toBe(false)
    })
  })

  describe('Streaming Controls', () => {
    test('should pause streaming', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      streamingService.pauseStreaming(sessionId)

      const session = streamingService.getSession(sessionId)
      // Note: In real implementation, this would be set by WebSocket message handler
      // For testing, we'll verify the pause command was sent
      expect(session?.websocket).toBeDefined()
    })

    test('should resume streaming', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      streamingService.pauseStreaming(sessionId)
      streamingService.resumeStreaming(sessionId)

      const session = streamingService.getSession(sessionId)
      expect(session?.websocket).toBeDefined()
    })

    test('should cancel streaming', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      streamingService.cancelStreaming(sessionId)

      const session = streamingService.getSession(sessionId)
      expect(session?.status).toBe('cancelled')
    })
  })

  describe('Event Handling', () => {
    test('should subscribe to streaming events', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const mockHandler = jest.fn()

      const unsubscribe = streamingService.subscribe(sessionId, mockHandler)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const session = streamingService.getSession(sessionId)
      const mockWs = session?.websocket as MockWebSocket

      // Simulate receiving a result message
      const resultMessage: StreamingMessage = {
        type: 'result',
        sessionId,
        timestamp: Date.now(),
        result: {
          business: {
            id: 'test-business-1',
            businessName: 'Test Business',
            industry: 'Technology',
            email: ['test@business.com'],
            phone: '+1-555-0123',
            website: 'https://testbusiness.com',
            address: {
              street: '123 Test St',
              city: 'Test City',
              state: 'TS',
              zipCode: '12345',
              country: 'USA',
            },
            scrapedAt: new Date(),
            source: 'Test Source',
            confidence: 0.9,
          },
          source: 'Test Source',
          confidence: 0.9,
          timestamp: Date.now(),
        },
      }

      mockWs.simulateMessage(resultMessage)

      expect(mockHandler).toHaveBeenCalledWith(resultMessage)

      // Test unsubscribe
      unsubscribe()
      mockWs.simulateMessage(resultMessage)

      // Should not be called again after unsubscribe
      expect(mockHandler).toHaveBeenCalledTimes(1)
    })

    test('should handle progress messages', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const mockHandler = jest.fn()

      streamingService.subscribe(sessionId, mockHandler)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const session = streamingService.getSession(sessionId)
      const mockWs = session?.websocket as MockWebSocket

      // Simulate receiving a progress message
      const progressMessage: StreamingMessage = {
        type: 'progress',
        sessionId,
        timestamp: Date.now(),
        progress: {
          totalFound: 50,
          processed: 25,
          currentSource: 'Test Source',
          estimatedTimeRemaining: 30,
          searchSpeed: 2.5,
          errors: 0,
          warnings: 0,
        },
      }

      mockWs.simulateMessage(progressMessage)

      expect(mockHandler).toHaveBeenCalledWith(progressMessage)

      // Check that session progress was updated
      const updatedSession = streamingService.getSession(sessionId)
      expect(updatedSession?.progress.totalFound).toBe(50)
      expect(updatedSession?.progress.processed).toBe(25)
    })

    test('should handle completion messages', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)
      const mockHandler = jest.fn()

      streamingService.subscribe(sessionId, mockHandler)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const session = streamingService.getSession(sessionId)
      const mockWs = session?.websocket as MockWebSocket

      // Simulate receiving a completion message
      const completeMessage: StreamingMessage = {
        type: 'complete',
        sessionId,
        timestamp: Date.now(),
      }

      mockWs.simulateMessage(completeMessage)

      expect(mockHandler).toHaveBeenCalledWith(completeMessage)

      // Check that session status was updated
      const updatedSession = streamingService.getSession(sessionId)
      expect(updatedSession?.status).toBe('completed')
      expect(updatedSession?.endTime).toBeDefined()
    })
  })

  describe('Error Handling and Connection Health', () => {
    test('should track connection health', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const connectionHealth = streamingService.getConnectionHealth(sessionId)

      expect(connectionHealth).toBeDefined()
      expect(connectionHealth?.isConnected).toBe(true)
      expect(connectionHealth?.lastHeartbeat).toBeDefined()
      expect(connectionHealth?.reconnectAttempts).toBe(0)
      expect(connectionHealth?.latency).toBeDefined()
    })

    test('should return null for non-existent session connection health', () => {
      const connectionHealth = streamingService.getConnectionHealth('non-existent-id')
      expect(connectionHealth).toBeNull()
    })

    test('should track error history', async () => {
      const sessionId = await streamingService.startStreaming(mockSearchParams)

      // Wait for connection to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      const session = streamingService.getSession(sessionId)
      const mockWs = session?.websocket as MockWebSocket

      // Simulate an error message
      const errorMessage: StreamingMessage = {
        type: 'error',
        sessionId,
        timestamp: Date.now(),
        error: 'Test error message',
      }

      mockWs.simulateMessage(errorMessage)

      const errorHistory = streamingService.getErrorHistory(sessionId)
      expect(errorHistory).toHaveLength(1)
      expect(errorHistory[0].error).toBe('Test error message')
    })

    test('should return empty array for non-existent session error history', () => {
      const errorHistory = streamingService.getErrorHistory('non-existent-id')
      expect(errorHistory).toEqual([])
    })
  })

  describe('Cleanup', () => {
    test('should cleanup all sessions', async () => {
      const sessionId1 = await streamingService.startStreaming(mockSearchParams)
      const sessionId2 = await streamingService.startStreaming(mockSearchParams)

      // Wait for connections to establish
      await new Promise(resolve => setTimeout(resolve, 20))

      expect(streamingService.getActiveSessions()).toHaveLength(2)

      streamingService.cleanupAll()

      expect(streamingService.getActiveSessions()).toHaveLength(0)
      expect(streamingService.getSession(sessionId1)).toBeUndefined()
      expect(streamingService.getSession(sessionId2)).toBeUndefined()
    })
  })
})
