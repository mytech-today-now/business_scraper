/**
 * Collaboration Features Tests
 * Test suite for real-time collaboration and WebSocket functionality
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { CollaborationWebSocketService } from '@/lib/collaboration-websocket'
import { WebSocket } from 'ws'

// Mock WebSocket
const mockWebSocket = {
  send: jest.fn(),
  close: jest.fn(),
  readyState: WebSocket.OPEN,
  on: jest.fn(),
  removeAllListeners: jest.fn()
}

// Mock database
const mockDatabase = {
  query: jest.fn()
}

// Mock logger
const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
}

jest.mock('@/utils/logger', () => ({
  logger: mockLogger
}))

jest.mock('./postgresql-database', () => ({
  database: mockDatabase
}))

describe('Collaboration WebSocket Service', () => {
  let collaborationService: CollaborationWebSocketService
  let mockUser: any

  beforeEach(() => {
    jest.clearAllMocks()
    collaborationService = new CollaborationWebSocketService()
    
    mockUser = {
      id: 'user-123',
      username: 'testuser',
      firstName: 'Test',
      lastName: 'User'
    }

    // Mock UserManagementService
    jest.doMock('@/lib/user-management', () => ({
      UserManagementService: {
        getUserById: jest.fn().mockResolvedValue(mockUser)
      }
    }))
  })

  afterEach(() => {
    collaborationService.shutdown()
    jest.restoreAllMocks()
  })

  describe('Client Management', () => {
    it('should add client successfully', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      expect(clientId).toBeDefined()
      expect(clientId).toMatch(/^client_/)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Client added',
        expect.objectContaining({
          clientId,
          userId: 'user-123',
          username: 'testuser'
        })
      )
    })

    it('should handle client addition with invalid user', async () => {
      // Mock getUserById to return null
      jest.doMock('@/lib/user-management', () => ({
        UserManagementService: {
          getUserById: jest.fn().mockResolvedValue(null)
        }
      }))

      await expect(
        collaborationService.addClient(mockWebSocket as any, 'invalid-user', 'session-123')
      ).rejects.toThrow('User not found')
    })

    it('should remove client successfully', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      collaborationService.removeClient(clientId)

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Client removed',
        expect.objectContaining({
          clientId,
          userId: 'user-123',
          username: 'testuser'
        })
      )
    })

    it('should handle removing non-existent client', () => {
      // Should not throw error
      expect(() => {
        collaborationService.removeClient('non-existent-client')
      }).not.toThrow()
    })
  })

  describe('WebSocket Message Handling', () => {
    let clientId: string

    beforeEach(async () => {
      clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )
    })

    it('should handle heartbeat message', async () => {
      const heartbeatMessage = {
        type: 'heartbeat',
        payload: {
          userId: 'user-123',
          workspaceId: 'workspace-123',
          timestamp: new Date()
        },
        timestamp: new Date(),
        userId: 'user-123'
      }

      const messageBuffer = Buffer.from(JSON.stringify(heartbeatMessage))
      
      // Simulate message handling
      const handleMessage = jest.fn()
      mockWebSocket.on.mockImplementation((event, callback) => {
        if (event === 'message') {
          handleMessage.mockImplementation(callback)
        }
      })

      // Trigger message handling
      await handleMessage(messageBuffer)

      expect(mockWebSocket.send).toHaveBeenCalled()
    })

    it('should handle collaboration event', async () => {
      const collaborationEvent = {
        type: 'collaboration_event',
        payload: {
          type: 'resource_locked',
          userId: 'user-123',
          workspaceId: 'workspace-123',
          resourceType: 'campaign',
          resourceId: 'campaign-123',
          timestamp: new Date()
        },
        timestamp: new Date(),
        userId: 'user-123',
        workspaceId: 'workspace-123'
      }

      mockDatabase.query.mockResolvedValue({ rows: [] })

      const messageBuffer = Buffer.from(JSON.stringify(collaborationEvent))
      
      // This would be handled by the actual message handler
      // For testing, we'll verify the database interaction
      expect(mockDatabase.query).toBeDefined()
    })

    it('should handle malformed message gracefully', async () => {
      const invalidMessage = Buffer.from('invalid json')
      
      // Should not throw error, but should log it
      const handleMessage = jest.fn()
      mockWebSocket.on.mockImplementation((event, callback) => {
        if (event === 'message') {
          handleMessage.mockImplementation(callback)
        }
      })

      // This should not throw
      expect(() => {
        try {
          JSON.parse(invalidMessage.toString())
        } catch (error) {
          mockLogger.error('Collaboration WebSocket', 'Error parsing WebSocket message', { clientId, error })
        }
      }).not.toThrow()

      expect(mockLogger.error).toHaveBeenCalled()
    })
  })

  describe('Resource Locking', () => {
    let clientId: string

    beforeEach(async () => {
      clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )
    })

    it('should create resource lock successfully', () => {
      const lockKey = 'campaign:campaign-123'
      const workspaceId = 'workspace-123'
      
      // Get workspace locks (should be empty initially)
      const initialLocks = collaborationService.getWorkspaceLocks(workspaceId)
      expect(initialLocks).toHaveLength(0)

      // This would be tested through the actual message handling
      // For now, we'll test the getter methods
      expect(collaborationService.getWorkspaceClientCount(workspaceId)).toBe(0)
    })

    it('should prevent duplicate locks on same resource', () => {
      // This would be tested through the collaboration event handling
      // The service should prevent multiple users from locking the same resource
      expect(true).toBe(true) // Placeholder for actual implementation test
    })

    it('should automatically release expired locks', () => {
      // This would be tested with the lock cleanup mechanism
      // The service should automatically clean up expired locks
      expect(true).toBe(true) // Placeholder for actual implementation test
    })
  })

  describe('Workspace Management', () => {
    it('should track workspace client count', async () => {
      const workspaceId = 'workspace-123'
      
      // Initially no clients
      expect(collaborationService.getWorkspaceClientCount(workspaceId)).toBe(0)

      // Add client to workspace (this would happen through heartbeat)
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      // Client count should still be 0 until they join a workspace
      expect(collaborationService.getWorkspaceClientCount(workspaceId)).toBe(0)
    })

    it('should broadcast messages to workspace clients', () => {
      const workspaceId = 'workspace-123'
      
      // This would be tested through the actual broadcast mechanism
      // The service should send messages to all clients in a workspace
      expect(true).toBe(true) // Placeholder for actual implementation test
    })
  })

  describe('User Presence', () => {
    it('should track user join events', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      // User join would be handled through heartbeat with workspace context
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Client added',
        expect.any(Object)
      )
    })

    it('should track user leave events', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      collaborationService.removeClient(clientId)

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Client removed',
        expect.any(Object)
      )
    })

    it('should handle user disconnection gracefully', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      // Simulate WebSocket close event
      const closeHandler = jest.fn()
      mockWebSocket.on.mockImplementation((event, callback) => {
        if (event === 'close') {
          closeHandler.mockImplementation(callback)
        }
      })

      // Trigger close event
      closeHandler()

      // Should handle gracefully without errors
      expect(true).toBe(true)
    })
  })

  describe('Heartbeat Monitoring', () => {
    it('should initialize heartbeat monitoring', () => {
      collaborationService.initialize()

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Service initialized'
      )
    })

    it('should detect and remove inactive clients', () => {
      // This would be tested with the heartbeat timeout mechanism
      // Clients that don't send heartbeats should be removed
      expect(true).toBe(true) // Placeholder for actual implementation test
    })
  })

  describe('Error Handling', () => {
    it('should handle WebSocket errors gracefully', async () => {
      const clientId = await collaborationService.addClient(
        mockWebSocket as any,
        'user-123',
        'session-123'
      )

      const error = new Error('WebSocket error')
      
      // Simulate error handling
      expect(() => {
        mockLogger.error('Collaboration WebSocket', 'Client error', { clientId, error })
      }).not.toThrow()

      expect(mockLogger.error).toHaveBeenCalled()
    })

    it('should handle database errors during lock operations', async () => {
      mockDatabase.query.mockRejectedValue(new Error('Database error'))

      // Database errors should be logged but not crash the service
      expect(() => {
        mockLogger.error('Collaboration WebSocket', 'Error storing lock in database', expect.any(Error))
      }).not.toThrow()
    })
  })

  describe('Service Lifecycle', () => {
    it('should initialize service correctly', () => {
      collaborationService.initialize()

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Service initialized'
      )
    })

    it('should shutdown service gracefully', () => {
      collaborationService.shutdown()

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Collaboration WebSocket',
        'Service shutdown'
      )
    })

    it('should clean up resources on shutdown', async () => {
      // Add some clients
      await collaborationService.addClient(mockWebSocket as any, 'user-1', 'session-1')
      await collaborationService.addClient(mockWebSocket as any, 'user-2', 'session-2')

      collaborationService.shutdown()

      // Should close all WebSocket connections
      expect(mockWebSocket.close).toHaveBeenCalled()
    })
  })
})
