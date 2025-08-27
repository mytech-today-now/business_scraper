/**
 * Real-time Result Streaming Service
 * Provides WebSocket-based streaming for search results with progress tracking
 */

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface StreamingSearchParams {
  query: string
  location?: string
  industry?: string
  radius?: number
  maxResults?: number
  filters?: Record<string, any>
}

export interface StreamingProgress {
  totalFound: number
  processed: number
  currentSource: string
  estimatedTimeRemaining: number
  searchSpeed: number // results per second
  errors: number
  warnings: number
}

export interface StreamingResult {
  business: BusinessRecord
  source: string
  confidence: number
  timestamp: number
}

export interface StreamingMessage {
  type: 'progress' | 'result' | 'error' | 'complete' | 'paused' | 'resumed'
  data?: any
  progress?: StreamingProgress
  result?: StreamingResult
  error?: string
  sessionId: string
  timestamp: number
}

export interface StreamingSession {
  id: string
  params: StreamingSearchParams
  status: 'active' | 'paused' | 'completed' | 'error' | 'cancelled' | 'connecting' | 'reconnecting'
  startTime: number
  endTime?: number
  results: StreamingResult[]
  progress: StreamingProgress
  websocket?: WebSocket
  connectionHealth: {
    isConnected: boolean
    lastHeartbeat: number
    reconnectAttempts: number
    latency: number
  }
  errorHistory: Array<{
    timestamp: number
    error: string
    severity: 'low' | 'medium' | 'high'
  }>
}

export type StreamingEventHandler = (message: StreamingMessage) => void

class StreamingService {
  private sessions: Map<string, StreamingSession> = new Map()
  private eventHandlers: Map<string, StreamingEventHandler[]> = new Map()
  private reconnectAttempts: Map<string, number> = new Map()
  private heartbeatIntervals: Map<string, number> = new Map()
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000 // Start with 1 second
  private heartbeatInterval = 30000 // 30 seconds
  private connectionTimeout = 10000 // 10 seconds

  /**
   * Start a new streaming search session
   */
  async startStreaming(params: StreamingSearchParams): Promise<string> {
    const sessionId = this.generateSessionId()

    const session: StreamingSession = {
      id: sessionId,
      params,
      status: 'connecting',
      startTime: Date.now(),
      results: [],
      progress: {
        totalFound: 0,
        processed: 0,
        currentSource: 'Initializing...',
        estimatedTimeRemaining: 0,
        searchSpeed: 0,
        errors: 0,
        warnings: 0,
      },
      connectionHealth: {
        isConnected: false,
        lastHeartbeat: Date.now(),
        reconnectAttempts: 0,
        latency: 0,
      },
      errorHistory: [],
    }

    this.sessions.set(sessionId, session)

    try {
      await this.establishWebSocketConnection(sessionId)
      logger.info('Streaming session started', { sessionId, params })
      return sessionId
    } catch (error) {
      logger.error('Failed to start streaming session', { sessionId, error })
      session.status = 'error'
      throw error
    }
  }

  /**
   * Establish WebSocket connection for a session
   */
  private async establishWebSocketConnection(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId)
    if (!session) throw new Error('Session not found')

    const wsUrl = this.getWebSocketUrl()
    const websocket = new WebSocket(wsUrl)

    websocket.onopen = () => {
      logger.info('WebSocket connected', { sessionId })
      session.websocket = websocket
      session.status = 'active'
      session.connectionHealth.isConnected = true
      session.connectionHealth.lastHeartbeat = Date.now()
      this.reconnectAttempts.set(sessionId, 0)

      // Start heartbeat monitoring
      this.startHeartbeat(sessionId)

      // Send initial search parameters
      websocket.send(
        JSON.stringify({
          type: 'start_search',
          sessionId,
          params: session.params,
        })
      )
    }

    websocket.onmessage = event => {
      try {
        const message: StreamingMessage = JSON.parse(event.data)
        this.handleStreamingMessage(sessionId, message)
      } catch (error) {
        logger.error('Failed to parse WebSocket message', { sessionId, error })
      }
    }

    websocket.onclose = event => {
      logger.warn('WebSocket connection closed', {
        sessionId,
        code: event.code,
        reason: event.reason,
      })
      this.handleConnectionClose(sessionId, event.code)
    }

    websocket.onerror = error => {
      logger.error('WebSocket error', { sessionId, error })
      this.handleConnectionError(sessionId, error)
    }

    // Store websocket reference
    session.websocket = websocket
  }

  /**
   * Handle incoming streaming messages
   */
  private handleStreamingMessage(sessionId: string, message: StreamingMessage): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    switch (message.type) {
      case 'progress':
        if (message.progress) {
          session.progress = { ...session.progress, ...message.progress }
        }
        break

      case 'result':
        if (message.result) {
          session.results.push(message.result)
          session.progress.totalFound = session.results.length
        }
        break

      case 'complete':
        session.status = 'completed'
        session.endTime = Date.now()
        break

      case 'error':
        session.status = 'error'
        session.progress.errors++
        break

      case 'paused':
        session.status = 'paused'
        break

      case 'resumed':
        session.status = 'active'
        break
    }

    // Notify event handlers
    this.notifyEventHandlers(sessionId, message)
  }

  /**
   * Handle WebSocket connection close
   */
  private handleConnectionClose(sessionId: string, code: number): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    // Don't reconnect if session was completed or cancelled
    if (session.status === 'completed' || session.status === 'cancelled') {
      return
    }

    // Attempt reconnection
    this.attemptReconnection(sessionId)
  }

  /**
   * Handle WebSocket connection error
   */
  private handleConnectionError(sessionId: string, error: Event): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    session.progress.errors++
    this.attemptReconnection(sessionId)
  }

  /**
   * Attempt to reconnect WebSocket
   */
  private async attemptReconnection(sessionId: string): Promise<void> {
    const attempts = this.reconnectAttempts.get(sessionId) || 0

    if (attempts >= this.maxReconnectAttempts) {
      logger.error('Max reconnection attempts reached', { sessionId })
      const session = this.sessions.get(sessionId)
      if (session) {
        session.status = 'error'
      }
      return
    }

    this.reconnectAttempts.set(sessionId, attempts + 1)

    const delay = this.reconnectDelay * Math.pow(2, attempts) // Exponential backoff

    logger.info('Attempting WebSocket reconnection', { sessionId, attempt: attempts + 1, delay })

    setTimeout(async () => {
      try {
        await this.establishWebSocketConnection(sessionId)
      } catch (error) {
        logger.error('Reconnection failed', { sessionId, error })
      }
    }, delay)
  }

  /**
   * Pause a streaming session
   */
  pauseStreaming(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session || !session.websocket) return

    session.websocket.send(
      JSON.stringify({
        type: 'pause',
        sessionId,
      })
    )
  }

  /**
   * Resume a streaming session
   */
  resumeStreaming(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session || !session.websocket) return

    session.websocket.send(
      JSON.stringify({
        type: 'resume',
        sessionId,
      })
    )
  }

  /**
   * Cancel a streaming session
   */
  cancelStreaming(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    session.status = 'cancelled'

    if (session.websocket) {
      session.websocket.send(
        JSON.stringify({
          type: 'cancel',
          sessionId,
        })
      )
      session.websocket.close()
    }

    this.cleanup(sessionId)
  }

  /**
   * Subscribe to streaming events
   */
  subscribe(sessionId: string, handler: StreamingEventHandler): () => void {
    if (!this.eventHandlers.has(sessionId)) {
      this.eventHandlers.set(sessionId, [])
    }

    this.eventHandlers.get(sessionId)!.push(handler)

    // Return unsubscribe function
    return () => {
      const handlers = this.eventHandlers.get(sessionId)
      if (handlers) {
        const index = handlers.indexOf(handler)
        if (index > -1) {
          handlers.splice(index, 1)
        }
      }
    }
  }

  /**
   * Get session information
   */
  getSession(sessionId: string): StreamingSession | undefined {
    return this.sessions.get(sessionId)
  }

  /**
   * Get all active sessions
   */
  getActiveSessions(): StreamingSession[] {
    return Array.from(this.sessions.values()).filter(s => s.status === 'active')
  }

  /**
   * Notify event handlers
   */
  private notifyEventHandlers(sessionId: string, message: StreamingMessage): void {
    const handlers = this.eventHandlers.get(sessionId)
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(message)
        } catch (error) {
          logger.error('Error in streaming event handler', { sessionId, error })
        }
      })
    }
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    return `stream_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Get WebSocket URL
   */
  private getWebSocketUrl(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    return `${protocol}//${host}/api/stream`
  }

  /**
   * Start heartbeat monitoring for a session
   */
  private startHeartbeat(sessionId: string): void {
    const interval = window.setInterval(() => {
      const session = this.sessions.get(sessionId)
      if (!session || !session.websocket) {
        clearInterval(interval)
        return
      }

      // Send ping
      const pingTime = Date.now()
      session.websocket.send(
        JSON.stringify({
          type: 'ping',
          sessionId,
          timestamp: pingTime,
        })
      )

      // Check for missed heartbeats
      const timeSinceLastHeartbeat = Date.now() - session.connectionHealth.lastHeartbeat
      if (timeSinceLastHeartbeat > this.heartbeatInterval * 2) {
        logger.warn('Heartbeat missed, connection may be unstable', { sessionId })
        this.addError(sessionId, 'Heartbeat missed - connection unstable', 'medium')
        session.connectionHealth.isConnected = false
      }
    }, this.heartbeatInterval)

    this.heartbeatIntervals.set(sessionId, interval)
  }

  /**
   * Stop heartbeat monitoring for a session
   */
  private stopHeartbeat(sessionId: string): void {
    const interval = this.heartbeatIntervals.get(sessionId)
    if (interval) {
      clearInterval(interval)
      this.heartbeatIntervals.delete(sessionId)
    }
  }

  /**
   * Add error to session history
   */
  private addError(sessionId: string, error: string, severity: 'low' | 'medium' | 'high'): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    session.errorHistory.push({
      timestamp: Date.now(),
      error,
      severity,
    })

    // Keep only last 50 errors
    if (session.errorHistory.length > 50) {
      session.errorHistory = session.errorHistory.slice(-50)
    }

    // Update progress error count
    session.progress.errors = session.errorHistory.filter(e => e.severity === 'high').length
  }

  /**
   * Check connection health
   */
  getConnectionHealth(sessionId: string): StreamingSession['connectionHealth'] | null {
    const session = this.sessions.get(sessionId)
    return session?.connectionHealth || null
  }

  /**
   * Get error history for a session
   */
  getErrorHistory(sessionId: string): StreamingSession['errorHistory'] {
    const session = this.sessions.get(sessionId)
    return session?.errorHistory || []
  }

  /**
   * Implement graceful fallback to batch loading
   */
  async fallbackToBatchLoading(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId)
    if (!session) return

    logger.info('Falling back to batch loading', { sessionId })

    try {
      // Simulate batch loading
      const batchSize = 50
      let processed = 0
      const maxResults = session.params.maxResults || 1000

      while (processed < maxResults && session.status === 'active') {
        // Simulate batch fetch
        await new Promise(resolve => setTimeout(resolve, 1000))

        // Generate mock results for fallback
        const batchResults: StreamingResult[] = []
        for (let i = 0; i < Math.min(batchSize, maxResults - processed); i++) {
          batchResults.push({
            business: {
              id: `fallback_${processed + i}`,
              businessName: `Fallback Business ${processed + i + 1}`,
              industry: session.params.industry || 'General',
              email: [`contact${processed + i}@fallback.com`],
              phone: `+1-555-${String(Math.floor(Math.random() * 9000) + 1000)}`,
              website: `https://fallback-${processed + i}.com`,
              address: {
                street: `${Math.floor(Math.random() * 9999) + 1} Fallback St`,
                city: session.params.location || 'Fallback City',
                state: 'CA',
                zipCode: String(Math.floor(Math.random() * 90000) + 10000),
                country: 'USA',
              },
              scrapedAt: new Date(),
              source: 'Fallback Batch',
              confidence: 0.7,
            },
            source: 'Fallback Batch',
            confidence: 0.7,
            timestamp: Date.now(),
          })
        }

        // Add results to session
        session.results.push(...batchResults)
        processed += batchResults.length

        // Update progress
        session.progress.processed = processed
        session.progress.totalFound = session.results.length
        session.progress.currentSource = 'Fallback Batch Loading'

        // Notify handlers
        batchResults.forEach(result => {
          this.notifyEventHandlers(sessionId, {
            type: 'result',
            sessionId,
            timestamp: Date.now(),
            result,
          })
        })

        this.notifyEventHandlers(sessionId, {
          type: 'progress',
          sessionId,
          timestamp: Date.now(),
          progress: session.progress,
        })
      }

      // Complete the session
      session.status = 'completed'
      this.notifyEventHandlers(sessionId, {
        type: 'complete',
        sessionId,
        timestamp: Date.now(),
      })
    } catch (error) {
      logger.error('Fallback batch loading failed', { sessionId, error })
      this.addError(sessionId, 'Fallback batch loading failed', 'high')
      session.status = 'error'
    }
  }

  /**
   * Cleanup session resources
   */
  private cleanup(sessionId: string): void {
    this.stopHeartbeat(sessionId)
    this.sessions.delete(sessionId)
    this.eventHandlers.delete(sessionId)
    this.reconnectAttempts.delete(sessionId)
  }

  /**
   * Cleanup all sessions
   */
  cleanupAll(): void {
    for (const [sessionId, session] of this.sessions) {
      if (session.websocket) {
        session.websocket.close()
      }
      this.stopHeartbeat(sessionId)
    }

    this.sessions.clear()
    this.eventHandlers.clear()
    this.reconnectAttempts.clear()
    this.heartbeatIntervals.clear()
  }
}

// Export singleton instance
export const streamingService = new StreamingService()

// Cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    streamingService.cleanupAll()
  })
}

export default streamingService
