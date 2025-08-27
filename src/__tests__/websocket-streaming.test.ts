/**
 * WebSocket Streaming Tests
 * Tests for real-time result streaming functionality
 */

import { WebSocketStreamingServer } from '@/lib/websocket-server'
import { BusinessRecord } from '@/types/business'

describe('WebSocket Streaming Server', () => {
  let server: WebSocketStreamingServer
  const testPort = 3002 // Use different port for testing

  beforeEach(() => {
    server = new WebSocketStreamingServer(testPort)
  })

  afterEach(async () => {
    if (server) {
      await server.stop()
    }
  })

  describe('Server Lifecycle', () => {
    test('should start and stop server successfully', async () => {
      // Start server
      await server.start()
      const status = server.getStatus()

      expect(status.isRunning).toBe(true)
      expect(status.port).toBe(testPort)
      expect(status.clientCount).toBe(0)
      expect(status.sessionCount).toBe(0)

      // Stop server
      await server.stop()
      const stoppedStatus = server.getStatus()

      expect(stoppedStatus.isRunning).toBe(false)
    })

    test('should handle multiple start calls gracefully', async () => {
      await server.start()

      // Second start should not throw
      await expect(server.start()).resolves.not.toThrow()

      const status = server.getStatus()
      expect(status.isRunning).toBe(true)
    })

    test('should handle stop when not running', async () => {
      // Stop without starting should not throw
      await expect(server.stop()).resolves.not.toThrow()

      const status = server.getStatus()
      expect(status.isRunning).toBe(false)
    })
  })

  describe('Broadcasting', () => {
    beforeEach(async () => {
      await server.start()
    })

    test('should broadcast results to session', () => {
      const sessionId = 'test-session'
      const mockBusiness: BusinessRecord = {
        id: 'test-1',
        businessName: 'Test Business',
        email: ['test@example.com'],
        phone: '555-0123',
        websiteUrl: 'https://test.com',
        address: {
          street: '123 Test St',
          city: 'Test City',
          state: 'TS',
          zipCode: '12345',
        },
        industry: 'Testing',
        scrapedAt: new Date(),
      }

      // Should not throw even with no connected clients
      expect(() => {
        server.broadcastResult(sessionId, mockBusiness)
      }).not.toThrow()
    })

    test('should broadcast progress updates', () => {
      const sessionId = 'test-session'
      const progress = {
        totalFound: 10,
        processed: 5,
        currentBatch: 1,
        estimatedTimeRemaining: 30,
        status: 'processing' as const,
        percentage: 50,
      }

      expect(() => {
        server.broadcastProgress(sessionId, progress)
      }).not.toThrow()
    })

    test('should broadcast errors', () => {
      const sessionId = 'test-session'
      const error = 'Test error message'

      expect(() => {
        server.broadcastError(sessionId, error)
      }).not.toThrow()
    })

    test('should broadcast completion', () => {
      const sessionId = 'test-session'

      expect(() => {
        server.broadcastComplete(sessionId, 'Test completed')
      }).not.toThrow()
    })

    test('should stop session', () => {
      const sessionId = 'test-session'

      expect(() => {
        server.stopSession(sessionId)
      }).not.toThrow()
    })
  })

  describe('Status Reporting', () => {
    test('should return correct initial status', () => {
      const status = server.getStatus()

      expect(status).toEqual({
        isRunning: false,
        port: testPort,
        clientCount: 0,
        sessionCount: 0,
      })
    })

    test('should update status when server starts', async () => {
      await server.start()
      const status = server.getStatus()

      expect(status.isRunning).toBe(true)
      expect(status.port).toBe(testPort)
    })
  })
})

describe('WebSocket API Integration', () => {
  test('should handle WebSocket server start request', async () => {
    const mockRequest = new Request('http://localhost/api/websocket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'start' }),
    })

    // Mock the API route handler
    const { POST } = await import('@/app/api/websocket/route')

    const response = await POST(mockRequest as any)
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.success).toBe(true)
  })

  test('should handle WebSocket server status request', async () => {
    const mockRequest = new Request('http://localhost/api/websocket', {
      method: 'GET',
    })

    const { GET } = await import('@/app/api/websocket/route')

    const response = await GET(mockRequest as any)
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.success).toBe(true)
    expect(data.status).toBeDefined()
  })
})

describe('Real-Time Streaming Integration', () => {
  test('should handle session ID in scraper service', () => {
    const { ScraperService } = require('@/model/scraperService')
    const scraper = new ScraperService()

    const sessionId = 'test-session-123'
    scraper.setSessionId(sessionId)

    expect(scraper.getSessionId()).toBe(sessionId)
  })

  test('should handle session ID in client scraper service', () => {
    const { ClientScraperService } = require('@/model/clientScraperService')
    const clientScraper = new ClientScraperService()

    const sessionId = 'client-session-456'
    clientScraper.setSessionId(sessionId)

    expect(clientScraper.getSessionId()).toBe(sessionId)
  })
})
