/**
 * Unit Tests for Authentication Utility Functions
 * Comprehensive test coverage for authentication helpers
 */

import { NextRequest } from 'next/server'
import {
  authenticateUser,
  authenticateUserWithResult,
  requireAuthentication,
  hasPermission,
  hasRole,
  requirePermission,
  requireRole,
  getUserId,
  isAuthenticated,
  getSessionInfo,
  isValidSessionToken,
  createAuthErrorResponse,
  createAuthSuccessResponse,
  AuthenticatedUser,
} from '@/utils/auth'
import { getSession, getClientIP } from '@/lib/security'

// Mock dependencies
jest.mock('@/lib/security')
jest.mock('@/utils/logger')

const mockGetSession = getSession as jest.MockedFunction<typeof getSession>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>

describe('Authentication Utility Functions', () => {
  const mockRequest = {
    cookies: {
      get: jest.fn(),
    },
  } as unknown as NextRequest

  const mockValidSession = {
    id: 'session-123',
    isValid: true,
    csrfToken: 'csrf-token',
  }

  const mockUser: AuthenticatedUser = {
    id: 'admin',
    email: 'admin@business-scraper.com',
    name: 'Administrator',
    sessionId: 'session-123',
    isAuthenticated: true,
    permissions: ['read', 'write', 'admin'],
    roles: ['admin'],
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockGetClientIP.mockReturnValue('127.0.0.1')
  })

  describe('authenticateUser', () => {
    it('should return user when valid session exists', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue(mockValidSession)

      const result = await authenticateUser(mockRequest)

      expect(result).toEqual(mockUser)
      expect(mockGetSession).toHaveBeenCalledWith('session-123')
    })

    it('should return null when no session ID provided', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      const result = await authenticateUser(mockRequest)

      expect(result).toBeNull()
    })

    it('should return null when session is invalid', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'invalid-session' })
      mockGetSession.mockReturnValue(null)

      const result = await authenticateUser(mockRequest)

      expect(result).toBeNull()
    })

    it('should return null when session is not valid', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue({ ...mockValidSession, isValid: false })

      const result = await authenticateUser(mockRequest)

      expect(result).toBeNull()
    })

    it('should handle authentication errors gracefully', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockImplementation(() => {
        throw new Error('Cookie error')
      })

      const result = await authenticateUser(mockRequest)

      expect(result).toBeNull()
    })
  })

  describe('authenticateUserWithResult', () => {
    it('should return success result with user when authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue(mockValidSession)

      const result = await authenticateUserWithResult(mockRequest)

      expect(result.success).toBe(true)
      expect(result.user).toEqual(mockUser)
      expect(result.error).toBeUndefined()
    })

    it('should return failure result when authentication fails', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      const result = await authenticateUserWithResult(mockRequest)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Authentication failed')
      expect(result.code).toBe('AUTH_FAILED')
      expect(result.user).toBeUndefined()
    })

    it('should handle authentication errors', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockImplementation(() => {
        throw new Error('Test error')
      })

      const result = await authenticateUserWithResult(mockRequest)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Authentication failed')
      expect(result.code).toBe('AUTH_FAILED')
    })
  })

  describe('requireAuthentication', () => {
    it('should return user when authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue(mockValidSession)

      const result = await requireAuthentication(mockRequest)

      expect(result).toEqual(mockUser)
    })

    it('should throw error when not authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      await expect(requireAuthentication(mockRequest)).rejects.toThrow('Authentication required')
    })
  })

  describe('hasPermission', () => {
    it('should return true for admin permission', () => {
      expect(hasPermission(mockUser, 'admin')).toBe(true)
    })

    it('should return true for existing permission', () => {
      expect(hasPermission(mockUser, 'read')).toBe(true)
      expect(hasPermission(mockUser, 'write')).toBe(true)
    })

    it('should return false for non-existing permission', () => {
      const userWithoutAdmin = { ...mockUser, permissions: ['read'] }
      expect(hasPermission(userWithoutAdmin, 'write')).toBe(false)
    })

    it('should return true for admin user regardless of specific permission', () => {
      expect(hasPermission(mockUser, 'any-permission')).toBe(true)
    })

    it('should handle user without permissions', () => {
      const userWithoutPermissions = { ...mockUser, permissions: undefined }
      expect(hasPermission(userWithoutPermissions, 'read')).toBe(false)
    })
  })

  describe('hasRole', () => {
    it('should return true for admin role', () => {
      expect(hasRole(mockUser, 'admin')).toBe(true)
    })

    it('should return false for non-existing role', () => {
      const userWithoutAdmin = { ...mockUser, roles: ['user'] }
      expect(hasRole(userWithoutAdmin, 'admin')).toBe(false)
    })

    it('should handle user without roles', () => {
      const userWithoutRoles = { ...mockUser, roles: undefined }
      expect(hasRole(userWithoutRoles, 'admin')).toBe(false)
    })
  })

  describe('requirePermission', () => {
    it('should not throw for valid permission', () => {
      expect(() => requirePermission(mockUser, 'read')).not.toThrow()
    })

    it('should throw for invalid permission', () => {
      const userWithoutPermission = { ...mockUser, permissions: ['read'] }
      expect(() => requirePermission(userWithoutPermission, 'write')).toThrow(
        'Permission denied: write required'
      )
    })
  })

  describe('requireRole', () => {
    it('should not throw for valid role', () => {
      expect(() => requireRole(mockUser, 'admin')).not.toThrow()
    })

    it('should throw for invalid role', () => {
      const userWithoutRole = { ...mockUser, roles: ['user'] }
      expect(() => requireRole(userWithoutRole, 'admin')).toThrow('Role denied: admin required')
    })
  })

  describe('getUserId', () => {
    it('should return user ID when authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue(mockValidSession)

      const result = await getUserId(mockRequest)

      expect(result).toBe('admin')
    })

    it('should return null when not authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      const result = await getUserId(mockRequest)

      expect(result).toBeNull()
    })
  })

  describe('isAuthenticated', () => {
    it('should return true when authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })
      mockGetSession.mockReturnValue(mockValidSession)

      const result = await isAuthenticated(mockRequest)

      expect(result).toBe(true)
    })

    it('should return false when not authenticated', async () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      const result = await isAuthenticated(mockRequest)

      expect(result).toBe(false)
    })
  })

  describe('getSessionInfo', () => {
    it('should return session info', () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue({ value: 'session-123' })

      const result = getSessionInfo(mockRequest)

      expect(result).toEqual({
        sessionId: 'session-123',
        ip: '127.0.0.1',
      })
    })

    it('should handle missing session', () => {
      ;(mockRequest.cookies.get as jest.Mock).mockReturnValue(undefined)

      const result = getSessionInfo(mockRequest)

      expect(result).toEqual({
        sessionId: null,
        ip: '127.0.0.1',
      })
    })
  })

  describe('isValidSessionToken', () => {
    it('should validate correct UUID format', () => {
      expect(isValidSessionToken('550e8400-e29b-41d4-a716-446655440000')).toBe(true)
    })

    it('should reject invalid formats', () => {
      expect(isValidSessionToken('invalid-token')).toBe(false)
      expect(isValidSessionToken('123')).toBe(false)
      expect(isValidSessionToken('')).toBe(false)
    })
  })

  describe('createAuthErrorResponse', () => {
    it('should create error response with default code', () => {
      const response = createAuthErrorResponse('Test error')

      expect(response.error).toBe('Test error')
      expect(response.code).toBe('AUTH_FAILED')
      expect(response.authenticated).toBe(false)
      expect(response.timestamp).toBeDefined()
    })

    it('should create error response with custom code', () => {
      const response = createAuthErrorResponse('Test error', 'CUSTOM_ERROR')

      expect(response.code).toBe('CUSTOM_ERROR')
    })
  })

  describe('createAuthSuccessResponse', () => {
    it('should create success response', () => {
      const response = createAuthSuccessResponse(mockUser)

      expect(response.message).toBe('Authentication successful')
      expect(response.authenticated).toBe(true)
      expect(response.user).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        permissions: mockUser.permissions,
        roles: mockUser.roles,
      })
      expect(response.timestamp).toBeDefined()
    })

    it('should create success response with custom message', () => {
      const response = createAuthSuccessResponse(mockUser, 'Custom success')

      expect(response.message).toBe('Custom success')
    })
  })
})
