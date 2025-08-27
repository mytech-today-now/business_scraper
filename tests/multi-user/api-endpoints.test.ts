/**
 * Multi-User API Endpoints Tests
 * Integration tests for multi-user API endpoints
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'

// Mock the RBAC middleware
const mockWithRBAC = jest.fn()
jest.mock('@/lib/rbac-middleware', () => ({
  withRBAC: mockWithRBAC,
}))

// Mock the audit service
const mockAuditService = {
  log: jest.fn(),
  logAuth: jest.fn(),
  logUserManagement: jest.fn(),
  extractContextFromRequest: jest.fn().mockReturnValue({
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
  }),
}
jest.mock('@/lib/audit-service', () => ({
  AuditService: mockAuditService,
}))

// Mock the user management service
const mockUserManagementService = {
  createUser: jest.fn(),
  getUserById: jest.fn(),
  getUsers: jest.fn(),
  updateUser: jest.fn(),
  deleteUser: jest.fn(),
  authenticateUser: jest.fn(),
  assignRole: jest.fn(),
  revokeRole: jest.fn(),
}
jest.mock('@/lib/user-management', () => ({
  UserManagementService: mockUserManagementService,
}))

describe('Multi-User API Endpoints', () => {
  const mockContext = {
    user: {
      id: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      roles: [
        {
          role: {
            id: 'role-123',
            name: 'admin',
            permissions: ['users.manage', 'teams.manage'],
          },
        },
      ],
    },
    sessionId: 'session-123',
    workspaceId: 'workspace-123',
    teamId: 'team-123',
    database: {
      query: jest.fn(),
    },
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockWithRBAC.mockImplementation((handler, options) => {
      return async (request: NextRequest) => {
        return handler(request, mockContext)
      }
    })
  })

  describe('Users API (/api/users)', () => {
    describe('GET /api/users', () => {
      it('should return paginated users list', async () => {
        const mockUsers = [
          {
            id: 'user-1',
            username: 'user1',
            email: 'user1@example.com',
            firstName: 'User',
            lastName: 'One',
          },
          {
            id: 'user-2',
            username: 'user2',
            email: 'user2@example.com',
            firstName: 'User',
            lastName: 'Two',
          },
        ]

        mockUserManagementService.getUsers.mockResolvedValue({
          users: mockUsers,
          total: 2,
          page: 1,
          totalPages: 1,
        })

        // Import and test the actual API handler
        const { GET } = await import('@/app/api/users/route')
        const request = new NextRequest('http://localhost/api/users?page=1&limit=10')
        const response = await GET(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.data).toHaveLength(2)
        expect(data.pagination.total).toBe(2)
        expect(mockUserManagementService.getUsers).toHaveBeenCalledWith({
          page: 1,
          limit: 10,
          search: '',
          role: '',
          isActive: undefined,
        })
      })

      it('should handle search and filtering', async () => {
        mockUserManagementService.getUsers.mockResolvedValue({
          users: [],
          total: 0,
          page: 1,
          totalPages: 0,
        })

        const { GET } = await import('@/app/api/users/route')
        const request = new NextRequest(
          'http://localhost/api/users?search=test&role=admin&isActive=true'
        )
        const response = await GET(request)

        expect(mockUserManagementService.getUsers).toHaveBeenCalledWith({
          page: 1,
          limit: 20,
          search: 'test',
          role: 'admin',
          isActive: true,
        })
      })
    })

    describe('POST /api/users', () => {
      it('should create a new user', async () => {
        const userData = {
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'password123',
          firstName: 'New',
          lastName: 'User',
        }

        const mockCreatedUser = {
          id: 'user-new',
          ...userData,
          isActive: true,
          createdAt: new Date(),
        }

        mockUserManagementService.createUser.mockResolvedValue({
          user: mockCreatedUser,
        })

        const { POST } = await import('@/app/api/users/route')
        const request = new NextRequest('http://localhost/api/users', {
          method: 'POST',
          body: JSON.stringify(userData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(201)
        expect(data.success).toBe(true)
        expect(data.data.username).toBe('newuser')
        expect(mockUserManagementService.createUser).toHaveBeenCalledWith(userData)
        expect(mockAuditService.logUserManagement).toHaveBeenCalledWith(
          'user.created',
          'user-new',
          'user-123',
          expect.any(Object),
          expect.any(Object)
        )
      })

      it('should validate required fields', async () => {
        const invalidUserData = {
          username: '',
          email: 'test@example.com',
        }

        const { POST } = await import('@/app/api/users/route')
        const request = new NextRequest('http://localhost/api/users', {
          method: 'POST',
          body: JSON.stringify(invalidUserData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(400)
        expect(data.error).toContain('required')
      })
    })

    describe('PUT /api/users', () => {
      it('should update multiple users', async () => {
        const updateData = {
          userIds: ['user-1', 'user-2'],
          updateData: {
            isActive: false,
          },
        }

        mockUserManagementService.updateUser
          .mockResolvedValueOnce({ id: 'user-1', isActive: false })
          .mockResolvedValueOnce({ id: 'user-2', isActive: false })

        const { PUT } = await import('@/app/api/users/route')
        const request = new NextRequest('http://localhost/api/users', {
          method: 'PUT',
          body: JSON.stringify(updateData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await PUT(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.data.updated).toBe(2)
        expect(mockUserManagementService.updateUser).toHaveBeenCalledTimes(2)
      })
    })

    describe('DELETE /api/users', () => {
      it('should delete multiple users', async () => {
        const deleteData = {
          userIds: ['user-1', 'user-2'],
          permanent: false,
        }

        mockUserManagementService.deleteUser
          .mockResolvedValueOnce({ id: 'user-1', isActive: false })
          .mockResolvedValueOnce({ id: 'user-2', isActive: false })

        const { DELETE } = await import('@/app/api/users/route')
        const request = new NextRequest('http://localhost/api/users', {
          method: 'DELETE',
          body: JSON.stringify(deleteData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await DELETE(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.data.deleted).toBe(2)
        expect(mockUserManagementService.deleteUser).toHaveBeenCalledTimes(2)
      })
    })
  })

  describe('Authentication API (/api/auth/multi-user)', () => {
    describe('POST /api/auth/multi-user (login)', () => {
      it('should authenticate user successfully', async () => {
        const loginData = {
          action: 'login',
          username: 'testuser',
          password: 'password123',
        }

        const mockAuthResult = {
          user: mockContext.user,
          session: {
            id: 'session-123',
            sessionToken: 'token-123',
            csrfToken: 'csrf-123',
            expiresAt: new Date(Date.now() + 3600000),
          },
        }

        mockUserManagementService.authenticateUser.mockResolvedValue(mockAuthResult)

        const { POST } = await import('@/app/api/auth/multi-user/route')
        const request = new NextRequest('http://localhost/api/auth/multi-user', {
          method: 'POST',
          body: JSON.stringify(loginData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(200)
        expect(data.success).toBe(true)
        expect(data.user.username).toBe('testuser')
        expect(data.sessionId).toBe('session-123')
        expect(mockAuditService.logAuth).toHaveBeenCalledWith(
          'user.login',
          'user-123',
          expect.any(Object),
          expect.any(Object)
        )
      })

      it('should reject invalid credentials', async () => {
        const loginData = {
          action: 'login',
          username: 'testuser',
          password: 'wrongpassword',
        }

        mockUserManagementService.authenticateUser.mockResolvedValue(null)

        const { POST } = await import('@/app/api/auth/multi-user/route')
        const request = new NextRequest('http://localhost/api/auth/multi-user', {
          method: 'POST',
          body: JSON.stringify(loginData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(401)
        expect(data.error).toBe('Invalid credentials')
        expect(mockAuditService.logAuth).toHaveBeenCalledWith(
          'user.login_failed',
          undefined,
          expect.any(Object),
          expect.any(Object)
        )
      })
    })

    describe('POST /api/auth/multi-user (register)', () => {
      it('should register new user successfully', async () => {
        const registerData = {
          action: 'register',
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'password123',
          firstName: 'New',
          lastName: 'User',
        }

        const mockCreatedUser = {
          id: 'user-new',
          username: 'newuser',
          email: 'newuser@example.com',
          firstName: 'New',
          lastName: 'User',
        }

        mockUserManagementService.createUser.mockResolvedValue({
          user: mockCreatedUser,
        })

        const { POST } = await import('@/app/api/auth/multi-user/route')
        const request = new NextRequest('http://localhost/api/auth/multi-user', {
          method: 'POST',
          body: JSON.stringify(registerData),
          headers: { 'Content-Type': 'application/json' },
        })
        const response = await POST(request)
        const data = await response.json()

        expect(response.status).toBe(201)
        expect(data.success).toBe(true)
        expect(data.user.username).toBe('newuser')
        expect(mockAuditService.logUserManagement).toHaveBeenCalledWith(
          'user.created',
          'user-new',
          undefined,
          expect.any(Object),
          expect.objectContaining({ selfRegistration: true })
        )
      })
    })
  })

  describe('Teams API (/api/teams)', () => {
    it('should create a new team', async () => {
      const teamData = {
        name: 'Test Team',
        description: 'A test team',
      }

      mockContext.database.query.mockResolvedValue({
        rows: [
          {
            id: 'team-123',
            name: 'Test Team',
            description: 'A test team',
            owner_id: 'user-123',
          },
        ],
      })

      const { POST } = await import('@/app/api/teams/route')
      const request = new NextRequest('http://localhost/api/teams', {
        method: 'POST',
        body: JSON.stringify(teamData),
        headers: { 'Content-Type': 'application/json' },
      })
      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(201)
      expect(data.success).toBe(true)
      expect(data.data.name).toBe('Test Team')
    })
  })

  describe('Analytics API (/api/analytics)', () => {
    it('should return dashboard metrics', async () => {
      const mockMetrics = {
        overview: {
          totalUsers: 10,
          activeUsers: 8,
          totalCampaigns: 5,
          totalBusinesses: 100,
        },
        performance: {
          avgScrapingTime: 2.5,
          successRate: 95.0,
          errorRate: 5.0,
        },
      }

      // Mock the analytics service
      jest.doMock('@/lib/analytics-service', () => ({
        AnalyticsService: {
          getDashboardMetrics: jest.fn().mockResolvedValue(mockMetrics),
        },
      }))

      const { GET } = await import('@/app/api/analytics/route')
      const request = new NextRequest('http://localhost/api/analytics?period=week')
      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.overview.totalUsers).toBe(10)
    })
  })

  describe('Error handling', () => {
    it('should handle database errors gracefully', async () => {
      mockContext.database.query.mockRejectedValue(new Error('Database connection failed'))

      const { GET } = await import('@/app/api/users/route')
      const request = new NextRequest('http://localhost/api/users')
      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to retrieve users')
    })

    it('should validate request body format', async () => {
      const { POST } = await import('@/app/api/users/route')
      const request = new NextRequest('http://localhost/api/users', {
        method: 'POST',
        body: 'invalid json',
        headers: { 'Content-Type': 'application/json' },
      })
      const response = await POST(request)

      expect(response.status).toBe(400)
    })

    it('should handle missing permissions', async () => {
      // Mock RBAC to deny access
      mockWithRBAC.mockImplementation((handler, options) => {
        return async (request: NextRequest) => {
          return new Response(JSON.stringify({ error: 'Insufficient permissions' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          })
        }
      })

      const { POST } = await import('@/app/api/users/route')
      const request = new NextRequest('http://localhost/api/users', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
      })
      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(403)
      expect(data.error).toBe('Insufficient permissions')
    })
  })
})
