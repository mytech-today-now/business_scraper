/**
 * WebSocket Server for Real-Time Result Streaming
 * Provides real-time communication for scraping progress and results
 */

import WebSocket, { WebSocketServer } from 'ws'
import { createServer } from 'http'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface StreamingResult {
  type: 'result' | 'progress' | 'error' | 'complete' | 'started' | 'stopped'
  data?: BusinessRecord
  progress?: {
    totalFound: number
    processed: number
    currentBatch: number
    estimatedTimeRemaining: number
    status: 'searching' | 'processing' | 'completed' | 'error'
    currentUrl?: string
    currentIndustry?: string
    percentage?: number
  }
  error?: string
  message?: string
  timestamp: number
  sessionId: string
}

export interface WebSocketClient {
  id: string
  ws: WebSocket
  sessionId: string
  isActive: boolean
  connectedAt: number
}

export class WebSocketStreamingServer {
  private wss: WebSocketServer | null = null
  private server: any = null
  private clients: Map<string, WebSocketClient> = new Map()
  private activeSessions: Map<string, Set<string>> = new Map() // sessionId -> clientIds
  private port: number
  private isRunning: boolean = false

  constructor(port: number = 3001) {
    this.port = port
  }

  /**
   * Start the WebSocket server
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('WebSocketServer', 'Server is already running')
      return
    }

    try {
      // Create HTTP server
      this.server = createServer()
      
      // Create WebSocket server
      this.wss = new WebSocketServer({ 
        server: this.server,
        path: '/ws/streaming'
      })

      // Handle WebSocket connections
      this.wss.on('connection', (ws: WebSocket, request) => {
        this.handleConnection(ws, request)
      })

      // Start HTTP server
      await new Promise<void>((resolve, reject) => {
        this.server.listen(this.port, (error: any) => {
          if (error) {
            reject(error)
          } else {
            resolve()
          }
        })
      })

      this.isRunning = true
      logger.info('WebSocketServer', `WebSocket server started on port ${this.port}`)
    } catch (error) {
      logger.error('WebSocketServer', 'Failed to start WebSocket server', error)
      throw error
    }
  }

  /**
   * Stop the WebSocket server
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      return
    }

    try {
      // Close all client connections
      this.clients.forEach(client => {
        if (client.ws.readyState === WebSocket.OPEN) {
          client.ws.close()
        }
      })
      this.clients.clear()
      this.activeSessions.clear()

      // Close WebSocket server
      if (this.wss) {
        this.wss.close()
        this.wss = null
      }

      // Close HTTP server
      if (this.server) {
        await new Promise<void>((resolve) => {
          this.server.close(() => resolve())
        })
        this.server = null
      }

      this.isRunning = false
      logger.info('WebSocketServer', 'WebSocket server stopped')
    } catch (error) {
      logger.error('WebSocketServer', 'Error stopping WebSocket server', error)
      throw error
    }
  }

  /**
   * Handle new WebSocket connection
   */
  private handleConnection(ws: WebSocket, request: any): void {
    const clientId = this.generateClientId()
    const url = new URL(request.url || '', `http://${request.headers.host}`)
    const sessionId = url.searchParams.get('sessionId') || 'default'

    const client: WebSocketClient = {
      id: clientId,
      ws,
      sessionId,
      isActive: true,
      connectedAt: Date.now()
    }

    this.clients.set(clientId, client)

    // Add to session tracking
    if (!this.activeSessions.has(sessionId)) {
      this.activeSessions.set(sessionId, new Set())
    }
    this.activeSessions.get(sessionId)!.add(clientId)

    logger.info('WebSocketServer', `Client connected: ${clientId} (session: ${sessionId})`)

    // Send welcome message
    this.sendToClient(clientId, {
      type: 'started',
      message: 'Connected to real-time streaming',
      timestamp: Date.now(),
      sessionId
    })

    // Handle client messages
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString())
        this.handleClientMessage(clientId, message)
      } catch (error) {
        logger.error('WebSocketServer', `Invalid message from client ${clientId}`, error)
      }
    })

    // Handle client disconnect
    ws.on('close', () => {
      this.handleDisconnection(clientId)
    })

    // Handle errors
    ws.on('error', (error) => {
      logger.error('WebSocketServer', `WebSocket error for client ${clientId}`, error)
      this.handleDisconnection(clientId)
    })
  }

  /**
   * Handle client disconnection
   */
  private handleDisconnection(clientId: string): void {
    const client = this.clients.get(clientId)
    if (client) {
      // Remove from session tracking
      const sessionClients = this.activeSessions.get(client.sessionId)
      if (sessionClients) {
        sessionClients.delete(clientId)
        if (sessionClients.size === 0) {
          this.activeSessions.delete(client.sessionId)
        }
      }

      this.clients.delete(clientId)
      logger.info('WebSocketServer', `Client disconnected: ${clientId}`)
    }
  }

  /**
   * Handle messages from clients
   */
  private handleClientMessage(clientId: string, message: any): void {
    const client = this.clients.get(clientId)
    if (!client) return

    switch (message.type) {
      case 'ping':
        this.sendToClient(clientId, {
          type: 'pong',
          timestamp: Date.now(),
          sessionId: client.sessionId
        })
        break

      case 'stop_session':
        this.stopSession(client.sessionId)
        break

      default:
        logger.warn('WebSocketServer', `Unknown message type from client ${clientId}: ${message.type}`)
    }
  }

  /**
   * Broadcast result to all clients in a session
   */
  broadcastResult(sessionId: string, result: BusinessRecord): void {
    const streamingResult: StreamingResult = {
      type: 'result',
      data: result,
      timestamp: Date.now(),
      sessionId
    }

    this.broadcastToSession(sessionId, streamingResult)
  }

  /**
   * Broadcast progress update to all clients in a session
   */
  broadcastProgress(sessionId: string, progress: StreamingResult['progress']): void {
    const streamingResult: StreamingResult = {
      type: 'progress',
      progress,
      timestamp: Date.now(),
      sessionId
    }

    this.broadcastToSession(sessionId, streamingResult)
  }

  /**
   * Broadcast error to all clients in a session
   */
  broadcastError(sessionId: string, error: string): void {
    const streamingResult: StreamingResult = {
      type: 'error',
      error,
      timestamp: Date.now(),
      sessionId
    }

    this.broadcastToSession(sessionId, streamingResult)
  }

  /**
   * Broadcast completion to all clients in a session
   */
  broadcastComplete(sessionId: string, message: string = 'Scraping completed'): void {
    const streamingResult: StreamingResult = {
      type: 'complete',
      message,
      timestamp: Date.now(),
      sessionId
    }

    this.broadcastToSession(sessionId, streamingResult)
  }

  /**
   * Stop a scraping session
   */
  stopSession(sessionId: string): void {
    const streamingResult: StreamingResult = {
      type: 'stopped',
      message: 'Session stopped by user',
      timestamp: Date.now(),
      sessionId
    }

    this.broadcastToSession(sessionId, streamingResult)
    logger.info('WebSocketServer', `Session stopped: ${sessionId}`)
  }

  /**
   * Broadcast message to all clients in a session
   */
  private broadcastToSession(sessionId: string, data: StreamingResult): void {
    const clientIds = this.activeSessions.get(sessionId)
    if (!clientIds) return

    clientIds.forEach(clientId => {
      this.sendToClient(clientId, data)
    })
  }

  /**
   * Send message to a specific client
   */
  private sendToClient(clientId: string, data: StreamingResult): void {
    const client = this.clients.get(clientId)
    if (!client || client.ws.readyState !== WebSocket.OPEN) {
      return
    }

    try {
      client.ws.send(JSON.stringify(data))
    } catch (error) {
      logger.error('WebSocketServer', `Failed to send message to client ${clientId}`, error)
      this.handleDisconnection(clientId)
    }
  }

  /**
   * Generate unique client ID
   */
  private generateClientId(): string {
    return `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Get server status
   */
  getStatus(): {
    isRunning: boolean
    port: number
    clientCount: number
    sessionCount: number
  } {
    return {
      isRunning: this.isRunning,
      port: this.port,
      clientCount: this.clients.size,
      sessionCount: this.activeSessions.size
    }
  }
}

// Create singleton instance
export const webSocketServer = new WebSocketStreamingServer()
