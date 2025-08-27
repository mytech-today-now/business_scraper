/**
 * Collaboration WebSocket Service
 * Handles real-time collaboration features, conflict resolution, and team communication
 */

import { WebSocket } from 'ws'
import {
  WebSocketMessage,
  CollaborationEvent,
  RealtimeUpdate,
  NotificationMessage,
  HeartbeatMessage,
  User,
  CollaborationLock,
} from '@/types/multi-user'
import { logger } from '@/utils/logger'
import { database } from './postgresql-database'
import { UserManagementService } from './user-management'

interface CollaborationClient {
  id: string
  ws: WebSocket
  userId: string
  workspaceId?: string
  teamId?: string
  user: User
  lastHeartbeat: Date
  subscriptions: Set<string>
  isActive: boolean
}

export class CollaborationWebSocketService {
  private clients: Map<string, CollaborationClient> = new Map()
  private workspaceClients: Map<string, Set<string>> = new Map()
  private teamClients: Map<string, Set<string>> = new Map()
  private resourceLocks: Map<string, CollaborationLock> = new Map()
  private heartbeatInterval: NodeJS.Timeout | null = null

  /**
   * Initialize collaboration service
   */
  initialize(): void {
    this.startHeartbeatMonitoring()
    this.startLockCleanup()
    logger.info('Collaboration WebSocket', 'Service initialized')
  }

  /**
   * Add client to collaboration service
   */
  async addClient(ws: WebSocket, userId: string, sessionId: string): Promise<string> {
    try {
      // Get user details
      const user = await UserManagementService.getUserById(userId)
      if (!user) {
        throw new Error('User not found')
      }

      const clientId = this.generateClientId()
      const client: CollaborationClient = {
        id: clientId,
        ws,
        userId,
        user,
        lastHeartbeat: new Date(),
        subscriptions: new Set(),
        isActive: true,
      }

      this.clients.set(clientId, client)

      // Set up WebSocket event handlers
      ws.on('message', data => this.handleMessage(clientId, data))
      ws.on('close', () => this.removeClient(clientId))
      ws.on('error', error => this.handleError(clientId, error))

      // Send welcome message
      this.sendToClient(clientId, {
        type: 'heartbeat',
        payload: {
          userId,
          workspaceId: '',
          timestamp: new Date(),
        } as HeartbeatMessage,
        timestamp: new Date(),
        userId,
      })

      logger.info('Collaboration WebSocket', 'Client added', {
        clientId,
        userId,
        username: user.username,
      })

      return clientId
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error adding client', error)
      throw error
    }
  }

  /**
   * Remove client from collaboration service
   */
  removeClient(clientId: string): void {
    const client = this.clients.get(clientId)
    if (!client) return

    // Remove from workspace
    if (client.workspaceId) {
      this.removeClientFromWorkspace(clientId, client.workspaceId)
      this.broadcastUserLeft(client.workspaceId, client.user)
    }

    // Remove from team
    if (client.teamId) {
      this.removeClientFromTeam(clientId, client.teamId)
    }

    // Release any locks held by this user
    this.releaseUserLocks(client.userId)

    this.clients.delete(clientId)

    logger.info('Collaboration WebSocket', 'Client removed', {
      clientId,
      userId: client.userId,
      username: client.user.username,
    })
  }

  /**
   * Handle incoming WebSocket message
   */
  private async handleMessage(clientId: string, data: Buffer): Promise<void> {
    try {
      const client = this.clients.get(clientId)
      if (!client) return

      const message = JSON.parse(data.toString()) as WebSocketMessage
      client.lastHeartbeat = new Date()

      switch (message.type) {
        case 'heartbeat':
          await this.handleHeartbeat(clientId, message.payload as HeartbeatMessage)
          break

        case 'collaboration_event':
          await this.handleCollaborationEvent(clientId, message.payload as CollaborationEvent)
          break

        case 'realtime_update':
          await this.handleRealtimeUpdate(clientId, message.payload as RealtimeUpdate)
          break

        case 'notification':
          await this.handleNotification(clientId, message.payload as NotificationMessage)
          break

        default:
          logger.warn('Collaboration WebSocket', 'Unknown message type', {
            type: message.type,
            clientId,
          })
      }
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error handling message', { clientId, error })
    }
  }

  /**
   * Handle heartbeat message
   */
  private async handleHeartbeat(clientId: string, payload: HeartbeatMessage): Promise<void> {
    const client = this.clients.get(clientId)
    if (!client) return

    // Update workspace context
    if (payload.workspaceId && payload.workspaceId !== client.workspaceId) {
      // Remove from old workspace
      if (client.workspaceId) {
        this.removeClientFromWorkspace(clientId, client.workspaceId)
        this.broadcastUserLeft(client.workspaceId, client.user)
      }

      // Add to new workspace
      client.workspaceId = payload.workspaceId
      this.addClientToWorkspace(clientId, payload.workspaceId)
      this.broadcastUserJoined(payload.workspaceId, client.user, clientId)
    }

    // Send heartbeat response
    this.sendToClient(clientId, {
      type: 'heartbeat',
      payload: {
        userId: client.userId,
        workspaceId: client.workspaceId || '',
        timestamp: new Date(),
      } as HeartbeatMessage,
      timestamp: new Date(),
      userId: client.userId,
      workspaceId: client.workspaceId,
    })
  }

  /**
   * Handle collaboration event
   */
  private async handleCollaborationEvent(
    clientId: string,
    event: CollaborationEvent
  ): Promise<void> {
    const client = this.clients.get(clientId)
    if (!client || event.userId !== client.userId) return

    switch (event.type) {
      case 'resource_locked':
        await this.handleResourceLock(event)
        break

      case 'resource_unlocked':
        await this.handleResourceUnlock(event)
        break

      case 'data_updated':
        await this.handleDataUpdate(event)
        break
    }

    // Broadcast to workspace
    if (event.workspaceId) {
      this.broadcastToWorkspace(
        event.workspaceId,
        {
          type: 'collaboration_event',
          payload: event,
          timestamp: new Date(),
          userId: event.userId,
          workspaceId: event.workspaceId,
        },
        clientId
      )
    }

    // Log event
    await this.logCollaborationEvent(event)
  }

  /**
   * Handle realtime update
   */
  private async handleRealtimeUpdate(clientId: string, update: RealtimeUpdate): Promise<void> {
    const client = this.clients.get(clientId)
    if (!client || update.userId !== client.userId) return

    // Broadcast to workspace
    if (update.workspaceId) {
      this.broadcastToWorkspace(
        update.workspaceId,
        {
          type: 'realtime_update',
          payload: update,
          timestamp: new Date(),
          userId: update.userId,
          workspaceId: update.workspaceId,
        },
        clientId
      )
    }

    // Log update
    await this.logRealtimeUpdate(update)
  }

  /**
   * Handle notification
   */
  private async handleNotification(
    clientId: string,
    notification: NotificationMessage
  ): Promise<void> {
    // Send notification to specific user or workspace
    if (notification.workspaceId) {
      this.broadcastToWorkspace(notification.workspaceId, {
        type: 'notification',
        payload: notification,
        timestamp: new Date(),
        workspaceId: notification.workspaceId,
      })
    } else {
      // Send to specific user
      const targetClients = Array.from(this.clients.values()).filter(
        client => client.userId === notification.userId
      )

      targetClients.forEach(client => {
        this.sendToClient(client.id, {
          type: 'notification',
          payload: notification,
          timestamp: new Date(),
          userId: notification.userId,
        })
      })
    }
  }

  /**
   * Handle resource lock
   */
  private async handleResourceLock(event: CollaborationEvent): Promise<void> {
    if (!event.resourceType || !event.resourceId) return

    const lockKey = `${event.resourceType}:${event.resourceId}`
    const existingLock = this.resourceLocks.get(lockKey)

    // Check if resource is already locked by another user
    if (existingLock && existingLock.userId !== event.userId) {
      // Send lock conflict notification
      const client = Array.from(this.clients.values()).find(c => c.userId === event.userId)
      if (client) {
        this.sendToClient(client.id, {
          type: 'notification',
          payload: {
            id: this.generateId(),
            type: 'warning',
            title: 'Resource Locked',
            message: `This ${event.resourceType} is currently being edited by another user.`,
            userId: event.userId,
            workspaceId: event.workspaceId,
          } as NotificationMessage,
          timestamp: new Date(),
          userId: event.userId,
          workspaceId: event.workspaceId,
        })
      }
      return
    }

    // Create lock
    const lock: CollaborationLock = {
      id: this.generateId(),
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      userId: event.userId,
      user: {} as User, // Will be populated from client
      workspaceId: event.workspaceId,
      lockType: 'edit',
      acquiredAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      isActive: true,
      details: event.data || {},
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    this.resourceLocks.set(lockKey, lock)

    // Store in database
    try {
      await database.query(
        `
        INSERT INTO collaboration_locks (
          id, resource_type, resource_id, user_id, workspace_id, 
          lock_type, acquired_at, expires_at, details
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (resource_type, resource_id, lock_type) 
        DO UPDATE SET 
          user_id = EXCLUDED.user_id,
          acquired_at = EXCLUDED.acquired_at,
          expires_at = EXCLUDED.expires_at,
          is_active = true
      `,
        [
          lock.id,
          lock.resourceType,
          lock.resourceId,
          lock.userId,
          lock.workspaceId,
          lock.lockType,
          lock.acquiredAt,
          lock.expiresAt,
          JSON.stringify(lock.details),
        ]
      )
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error storing lock in database', error)
    }
  }

  /**
   * Handle resource unlock
   */
  private async handleResourceUnlock(event: CollaborationEvent): Promise<void> {
    if (!event.resourceType || !event.resourceId) return

    const lockKey = `${event.resourceType}:${event.resourceId}`
    const lock = this.resourceLocks.get(lockKey)

    if (lock && lock.userId === event.userId) {
      this.resourceLocks.delete(lockKey)

      // Remove from database
      try {
        await database.query(
          `
          UPDATE collaboration_locks 
          SET is_active = false 
          WHERE resource_type = $1 AND resource_id = $2 AND user_id = $3
        `,
          [event.resourceType, event.resourceId, event.userId]
        )
      } catch (error) {
        logger.error('Collaboration WebSocket', 'Error removing lock from database', error)
      }
    }
  }

  /**
   * Handle data update
   */
  private async handleDataUpdate(event: CollaborationEvent): Promise<void> {
    // Log data update for audit trail
    logger.info('Collaboration WebSocket', 'Data update event', {
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      userId: event.userId,
      workspaceId: event.workspaceId,
    })
  }

  /**
   * Send message to specific client
   */
  private sendToClient(clientId: string, message: WebSocketMessage): void {
    const client = this.clients.get(clientId)
    if (!client || !client.isActive || client.ws.readyState !== WebSocket.OPEN) return

    try {
      client.ws.send(JSON.stringify(message))
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error sending message', { clientId, error })
    }
  }

  /**
   * Broadcast message to workspace
   */
  private broadcastToWorkspace(
    workspaceId: string,
    message: WebSocketMessage,
    excludeClientId?: string
  ): void {
    const workspaceClients = this.workspaceClients.get(workspaceId)
    if (!workspaceClients) return

    workspaceClients.forEach(clientId => {
      if (clientId !== excludeClientId) {
        this.sendToClient(clientId, message)
      }
    })
  }

  /**
   * Add client to workspace
   */
  private addClientToWorkspace(clientId: string, workspaceId: string): void {
    if (!this.workspaceClients.has(workspaceId)) {
      this.workspaceClients.set(workspaceId, new Set())
    }
    this.workspaceClients.get(workspaceId)!.add(clientId)
  }

  /**
   * Remove client from workspace
   */
  private removeClientFromWorkspace(clientId: string, workspaceId: string): void {
    const workspaceClients = this.workspaceClients.get(workspaceId)
    if (workspaceClients) {
      workspaceClients.delete(clientId)
      if (workspaceClients.size === 0) {
        this.workspaceClients.delete(workspaceId)
      }
    }
  }

  /**
   * Add client to team
   */
  private addClientToTeam(clientId: string, teamId: string): void {
    if (!this.teamClients.has(teamId)) {
      this.teamClients.set(teamId, new Set())
    }
    this.teamClients.get(teamId)!.add(clientId)
  }

  /**
   * Remove client from team
   */
  private removeClientFromTeam(clientId: string, teamId: string): void {
    const teamClients = this.teamClients.get(teamId)
    if (teamClients) {
      teamClients.delete(clientId)
      if (teamClients.size === 0) {
        this.teamClients.delete(teamId)
      }
    }
  }

  /**
   * Broadcast user joined event
   */
  private broadcastUserJoined(workspaceId: string, user: User, excludeClientId?: string): void {
    this.broadcastToWorkspace(
      workspaceId,
      {
        type: 'collaboration_event',
        payload: {
          type: 'user_joined',
          userId: user.id,
          username: user.username,
          workspaceId,
          timestamp: new Date(),
        } as CollaborationEvent,
        timestamp: new Date(),
        userId: user.id,
        workspaceId,
      },
      excludeClientId
    )
  }

  /**
   * Broadcast user left event
   */
  private broadcastUserLeft(workspaceId: string, user: User): void {
    this.broadcastToWorkspace(workspaceId, {
      type: 'collaboration_event',
      payload: {
        type: 'user_left',
        userId: user.id,
        username: user.username,
        workspaceId,
        timestamp: new Date(),
      } as CollaborationEvent,
      timestamp: new Date(),
      userId: user.id,
      workspaceId,
    })
  }

  /**
   * Release all locks held by a user
   */
  private async releaseUserLocks(userId: string): Promise<void> {
    // Remove from memory
    for (const [lockKey, lock] of this.resourceLocks.entries()) {
      if (lock.userId === userId) {
        this.resourceLocks.delete(lockKey)
      }
    }

    // Remove from database
    try {
      await database.query(
        `
        UPDATE collaboration_locks 
        SET is_active = false 
        WHERE user_id = $1 AND is_active = true
      `,
        [userId]
      )
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error releasing user locks', error)
    }
  }

  /**
   * Start heartbeat monitoring
   */
  private startHeartbeatMonitoring(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = new Date()
      const timeout = 60000 // 1 minute

      this.clients.forEach((client, clientId) => {
        if (now.getTime() - client.lastHeartbeat.getTime() > timeout) {
          logger.warn('Collaboration WebSocket', 'Client heartbeat timeout', {
            clientId,
            userId: client.userId,
          })
          this.removeClient(clientId)
        }
      })
    }, 30000) // Check every 30 seconds
  }

  /**
   * Start lock cleanup
   */
  private startLockCleanup(): void {
    setInterval(() => {
      const now = new Date()

      for (const [lockKey, lock] of this.resourceLocks.entries()) {
        if (lock.expiresAt < now) {
          this.resourceLocks.delete(lockKey)
          logger.info('Collaboration WebSocket', 'Expired lock cleaned up', {
            lockKey,
            userId: lock.userId,
          })
        }
      }
    }, 60000) // Check every minute
  }

  /**
   * Log collaboration event
   */
  private async logCollaborationEvent(event: CollaborationEvent): Promise<void> {
    try {
      await database.query(
        `
        INSERT INTO audit_logs (
          user_id, action, resource_type, resource_id, workspace_id,
          details, timestamp, severity
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
        [
          event.userId,
          `collaboration.${event.type}`,
          event.resourceType || 'unknown',
          event.resourceId,
          event.workspaceId,
          JSON.stringify(event.data || {}),
          event.timestamp,
          'info',
        ]
      )
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error logging event', error)
    }
  }

  /**
   * Log realtime update
   */
  private async logRealtimeUpdate(update: RealtimeUpdate): Promise<void> {
    try {
      await database.query(
        `
        INSERT INTO audit_logs (
          user_id, action, resource_type, resource_id, workspace_id,
          details, timestamp, severity
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
        [
          update.userId,
          `realtime.${update.action}`,
          update.type,
          update.resourceId,
          update.workspaceId,
          JSON.stringify(update.data),
          update.timestamp,
          'info',
        ]
      )
    } catch (error) {
      logger.error('Collaboration WebSocket', 'Error logging update', error)
    }
  }

  /**
   * Handle WebSocket error
   */
  private handleError(clientId: string, error: Error): void {
    logger.error('Collaboration WebSocket', 'Client error', { clientId, error })
    this.removeClient(clientId)
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Generate unique client ID
   */
  private generateClientId(): string {
    return `client_${this.generateId()}`
  }

  /**
   * Get workspace client count
   */
  getWorkspaceClientCount(workspaceId: string): number {
    const clients = this.workspaceClients.get(workspaceId)
    return clients ? clients.size : 0
  }

  /**
   * Get active locks for workspace
   */
  getWorkspaceLocks(workspaceId: string): CollaborationLock[] {
    return Array.from(this.resourceLocks.values()).filter(
      lock => lock.workspaceId === workspaceId && lock.isActive
    )
  }

  /**
   * Shutdown service
   */
  shutdown(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval)
    }

    this.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.close(1001, 'Server shutdown')
      }
    })

    this.clients.clear()
    this.workspaceClients.clear()
    this.teamClients.clear()
    this.resourceLocks.clear()

    logger.info('Collaboration WebSocket', 'Service shutdown')
  }
}

// Export singleton instance
export const collaborationWS = new CollaborationWebSocketService()
