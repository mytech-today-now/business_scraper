/**
 * WebSocket API endpoint for real-time result streaming
 * Handles streaming search requests and provides real-time updates
 */

import { NextApiRequest, NextApiResponse } from 'next'
import { WebSocketServer, WebSocket } from 'ws'
import { IncomingMessage } from 'http'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { enhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'

interface StreamingSearchParams {
  query: string
  location?: string
  industry?: string
  radius?: number
  maxResults?: number
  filters?: Record<string, any>
}

interface StreamingSession {
  id: string
  params: StreamingSearchParams
  status: 'active' | 'paused' | 'completed' | 'error' | 'cancelled'
  startTime: number
  websocket: WebSocket
  searchController?: AbortController
}

interface StreamingMessage {
  type: 'start_search' | 'pause' | 'resume' | 'cancel'
  sessionId: string
  params?: StreamingSearchParams
}

class StreamingServer {
  private wss: WebSocketServer | null = null
  private sessions: Map<string, StreamingSession> = new Map()
  private isInitialized = false

  /**
   * Initialize WebSocket server
   */
  initialize(server: any): void {
    if (this.isInitialized) return

    this.wss = new WebSocketServer({ 
      server,
      path: '/api/stream'
    })

    this.wss.on('connection', (ws: WebSocket, request: IncomingMessage) => {
      logger.info('WebSocket connection established', { 
        ip: request.socket.remoteAddress,
        userAgent: request.headers['user-agent']
      })

      ws.on('message', async (data: Buffer) => {
        try {
          const message: StreamingMessage = JSON.parse(data.toString())
          await this.handleMessage(ws, message)
        } catch (error) {
          logger.error('Failed to handle WebSocket message', { error })
          this.sendError(ws, 'Invalid message format')
        }
      })

      ws.on('close', (code: number, reason: Buffer) => {
        logger.info('WebSocket connection closed', { code, reason: reason.toString() })
        this.cleanupSessionByWebSocket(ws)
      })

      ws.on('error', (error: Error) => {
        logger.error('WebSocket error', { error })
        this.cleanupSessionByWebSocket(ws)
      })

      // Send connection confirmation
      this.sendMessage(ws, {
        type: 'connected',
        sessionId: '',
        timestamp: Date.now()
      })
    })

    this.isInitialized = true
    logger.info('WebSocket server initialized')
  }

  /**
   * Handle incoming WebSocket messages
   */
  private async handleMessage(ws: WebSocket, message: StreamingMessage): Promise<void> {
    switch (message.type) {
      case 'start_search':
        await this.startSearch(ws, message)
        break
      case 'pause':
        this.pauseSearch(message.sessionId)
        break
      case 'resume':
        this.resumeSearch(message.sessionId)
        break
      case 'cancel':
        this.cancelSearch(message.sessionId)
        break
      default:
        this.sendError(ws, `Unknown message type: ${message.type}`)
    }
  }

  /**
   * Start a new streaming search
   */
  private async startSearch(ws: WebSocket, message: StreamingMessage): Promise<void> {
    if (!message.params) {
      this.sendError(ws, 'Search parameters are required')
      return
    }

    const session: StreamingSession = {
      id: message.sessionId,
      params: message.params,
      status: 'active',
      startTime: Date.now(),
      websocket: ws,
      searchController: new AbortController()
    }

    this.sessions.set(message.sessionId, session)

    try {
      // Send initial progress
      this.sendProgress(session, {
        totalFound: 0,
        processed: 0,
        currentSource: 'Initializing search...',
        estimatedTimeRemaining: 0,
        searchSpeed: 0,
        errors: 0,
        warnings: 0
      })

      // Start the search process
      await this.performStreamingSearch(session)
    } catch (error) {
      logger.error('Streaming search failed', { sessionId: message.sessionId, error })
      this.sendError(ws, 'Search failed')
      session.status = 'error'
    }
  }

  /**
   * Perform the actual streaming search
   */
  private async performStreamingSearch(session: StreamingSession): Promise<void> {
    const { params, searchController } = session
    const startTime = Date.now()
    let totalFound = 0
    let processed = 0
    let errors = 0

    try {
      // Configure search engines based on parameters
      const searchEngines = this.getSearchEngines(params)
      
      for (const engine of searchEngines) {
        if (session.status !== 'active') break
        if (searchController?.signal.aborted) break

        this.sendProgress(session, {
          totalFound,
          processed,
          currentSource: engine.name,
          estimatedTimeRemaining: this.estimateTimeRemaining(startTime, processed, params.maxResults || 1000),
          searchSpeed: this.calculateSearchSpeed(startTime, totalFound),
          errors,
          warnings: 0
        })

        try {
          // Simulate streaming search results
          const results = await this.searchWithEngine(engine, params, session)
          
          for (const business of results) {
            if (session.status !== 'active') break
            if (searchController?.signal.aborted) break

            // Send individual result
            this.sendResult(session, {
              business,
              source: engine.name,
              confidence: this.calculateConfidence(business),
              timestamp: Date.now()
            })

            totalFound++
            processed++

            // Send progress update every 10 results
            if (totalFound % 10 === 0) {
              this.sendProgress(session, {
                totalFound,
                processed,
                currentSource: engine.name,
                estimatedTimeRemaining: this.estimateTimeRemaining(startTime, processed, params.maxResults || 1000),
                searchSpeed: this.calculateSearchSpeed(startTime, totalFound),
                errors,
                warnings: 0
              })
            }

            // Respect rate limiting
            await this.delay(50) // 50ms delay between results
          }
        } catch (engineError) {
          logger.error('Search engine error', { engine: engine.name, error: engineError })
          errors++
        }
      }

      // Send completion message
      session.status = 'completed'
      this.sendMessage(session.websocket, {
        type: 'complete',
        sessionId: session.id,
        timestamp: Date.now(),
        data: {
          totalResults: totalFound,
          duration: Date.now() - startTime,
          errors
        }
      })

    } catch (error) {
      logger.error('Streaming search error', { sessionId: session.id, error })
      session.status = 'error'
      this.sendError(session.websocket, 'Search failed')
    } finally {
      this.sessions.delete(session.id)
    }
  }

  /**
   * Get available search engines based on parameters
   */
  private getSearchEngines(params: StreamingSearchParams): Array<{ name: string; config: any }> {
    return [
      { name: 'Google Business', config: { priority: 1 } },
      { name: 'Bing Places', config: { priority: 2 } },
      { name: 'Yellow Pages', config: { priority: 3 } },
      { name: 'BBB Directory', config: { priority: 4 } },
      { name: 'Industry Directories', config: { priority: 5 } }
    ]
  }

  /**
   * Search with a specific engine (mock implementation)
   */
  private async searchWithEngine(engine: { name: string; config: any }, params: StreamingSearchParams, session: StreamingSession): Promise<BusinessRecord[]> {
    // This is a mock implementation - in real scenario, this would call actual search engines
    const mockResults: BusinessRecord[] = []
    const resultCount = Math.floor(Math.random() * 20) + 5 // 5-25 results per engine

    for (let i = 0; i < resultCount; i++) {
      if (session.status !== 'active') break

      mockResults.push({
        id: `${engine.name.toLowerCase().replace(/\s+/g, '_')}_${Date.now()}_${i}`,
        businessName: `${params.query} Business ${i + 1}`,
        industry: params.industry || 'General',
        email: [`contact${i}@${params.query.toLowerCase().replace(/\s+/g, '')}.com`],
        phone: `+1-555-${String(Math.floor(Math.random() * 9000) + 1000)}`,
        website: `https://www.${params.query.toLowerCase().replace(/\s+/g, '')}-${i}.com`,
        address: {
          street: `${Math.floor(Math.random() * 9999) + 1} Main St`,
          city: params.location || 'Anytown',
          state: 'CA',
          zipCode: String(Math.floor(Math.random() * 90000) + 10000),
          country: 'USA'
        },
        scrapedAt: new Date(),
        source: engine.name,
        confidence: Math.random() * 0.4 + 0.6 // 0.6-1.0
      })

      // Simulate processing time
      await this.delay(100 + Math.random() * 200) // 100-300ms per result
    }

    return mockResults
  }

  /**
   * Calculate confidence score for a business record
   */
  private calculateConfidence(business: BusinessRecord): number {
    let confidence = 0.5

    if (business.email && business.email.length > 0) confidence += 0.2
    if (business.phone) confidence += 0.15
    if (business.website) confidence += 0.1
    if (business.address?.street) confidence += 0.05

    return Math.min(confidence, 1.0)
  }

  /**
   * Estimate time remaining for search
   */
  private estimateTimeRemaining(startTime: number, processed: number, maxResults: number): number {
    if (processed === 0) return 0

    const elapsed = Date.now() - startTime
    const rate = processed / elapsed // results per ms
    const remaining = maxResults - processed

    return Math.round(remaining / rate / 1000) // seconds
  }

  /**
   * Calculate search speed
   */
  private calculateSearchSpeed(startTime: number, totalFound: number): number {
    const elapsed = (Date.now() - startTime) / 1000 // seconds
    return elapsed > 0 ? Math.round(totalFound / elapsed * 10) / 10 : 0
  }

  /**
   * Pause search session
   */
  private pauseSearch(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (session) {
      session.status = 'paused'
      this.sendMessage(session.websocket, {
        type: 'paused',
        sessionId,
        timestamp: Date.now()
      })
    }
  }

  /**
   * Resume search session
   */
  private resumeSearch(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (session) {
      session.status = 'active'
      this.sendMessage(session.websocket, {
        type: 'resumed',
        sessionId,
        timestamp: Date.now()
      })
    }
  }

  /**
   * Cancel search session
   */
  private cancelSearch(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (session) {
      session.status = 'cancelled'
      session.searchController?.abort()
      this.sessions.delete(sessionId)
    }
  }

  /**
   * Send progress update
   */
  private sendProgress(session: StreamingSession, progress: any): void {
    this.sendMessage(session.websocket, {
      type: 'progress',
      sessionId: session.id,
      timestamp: Date.now(),
      progress
    })
  }

  /**
   * Send search result
   */
  private sendResult(session: StreamingSession, result: any): void {
    this.sendMessage(session.websocket, {
      type: 'result',
      sessionId: session.id,
      timestamp: Date.now(),
      result
    })
  }

  /**
   * Send error message
   */
  private sendError(ws: WebSocket, error: string): void {
    this.sendMessage(ws, {
      type: 'error',
      sessionId: '',
      timestamp: Date.now(),
      error
    })
  }

  /**
   * Send message to WebSocket
   */
  private sendMessage(ws: WebSocket, message: any): void {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message))
    }
  }

  /**
   * Cleanup session by WebSocket
   */
  private cleanupSessionByWebSocket(ws: WebSocket): void {
    for (const [sessionId, session] of this.sessions) {
      if (session.websocket === ws) {
        session.searchController?.abort()
        this.sessions.delete(sessionId)
        break
      }
    }
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// Create singleton instance
const streamingServer = new StreamingServer()

// Export handler for Next.js API routes
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    // Handle WebSocket upgrade
    if (req.headers.upgrade === 'websocket') {
      // Initialize WebSocket server if not already done
      if (!streamingServer['isInitialized']) {
        streamingServer.initialize((res.socket as any).server)
      }
      
      res.status(200).json({ message: 'WebSocket server ready' })
    } else {
      res.status(200).json({ 
        message: 'Streaming API endpoint',
        status: 'ready',
        timestamp: new Date().toISOString()
      })
    }
  } else {
    res.setHeader('Allow', ['GET'])
    res.status(405).json({ error: 'Method not allowed' })
  }
}
