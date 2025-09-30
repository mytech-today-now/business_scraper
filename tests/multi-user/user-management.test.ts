/**
 * User Management Service Tests
 * Comprehensive test suite for multi-user functionality
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { UserManagementService } from '@/lib/user-management'
import { CreateUserRequest, UpdateUserRequest } from '@/types/multi-user'
import { createSqlMock, createBcryptMock, MockedObject } from '../../src/__tests__/utils/mockTypeHelpers'

// Mock database with proper types
const mockDatabase = {
  query: jest.fn() as jest.MockedFunction<(query: string, params?: any[]) => Promise<any>>,
  transaction: jest.fn() as jest.MockedFunction<(callback: (client: any) => Promise<any>) => Promise<any>>,
}

// Mock bcrypt with proper types
const mockBcrypt = createBcryptMock()
jest.mock('bcrypt', () => mockBcrypt)

describe('UserManagementService', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('createUser', () => {
    it('should create a new user successfully', async () => {
      const userData: CreateUserRequest = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        firstName: 'Test',
        lastName: 'User',
      }

      const mockUser = {
        id: 'user-123',
        ...userData,
        password: 'hashed_password',
        isActive: true,
        isVerified: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockDatabase.query
        .mockResolvedValueOnce({ rows: [] }) // Check username availability
        .mockResolvedValueOnce({ rows: [] }) // Check email availability
        .mockResolvedValueOnce({ rows: [mockUser] }) // Insert user

      const result = await UserManagementService.createUser(userData)

      expect(result.user).toEqual(
        expect.objectContaining({
          username: userData.username,
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
        })
      )
      expect(mockDatabase.query).toHaveBeenCalledTimes(3)
    })

    it('should throw error if username already exists', async () => {
      const userData: CreateUserRequest = {
        username: 'existinguser',
        email: 'test@example.com',
        password: 'password123',
        firstName: 'Test',
        lastName: 'User',
      }

      mockDatabase.query.mockResolvedValueOnce({
        rows: [{ id: 'existing-user' }],
      })

      await expect(UserManagementService.createUser(userData)).rejects.toThrow(
        'Username already exists'
      )
    })

    it('should throw error if email already exists', async () => {
      const userData: CreateUserRequest = {
        username: 'testuser',
        email: 'existing@example.com',
        password: 'password123',
        firstName: 'Test',
        lastName: 'User',
      }

      mockDatabase.query
        .mockResolvedValueOnce({ rows: [] }) // Username check
        .mockResolvedValueOnce({ rows: [{ id: 'existing-user' }] }) // Email check

      await expect(UserManagementService.createUser(userData)).rejects.toThrow(
        'Email already exists'
      )
    })

    it('should validate required fields', async () => {
      const invalidUserData = {
        username: '',
        email: 'test@example.com',
        password: 'password123',
        firstName: 'Test',
        lastName: 'User',
      } as CreateUserRequest

      await expect(UserManagementService.createUser(invalidUserData)).rejects.toThrow(
        'Username is required'
      )
    })
  })

  describe('authenticateUser', () => {
    it('should authenticate user with valid credentials', async () => {
      const mockUser = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        passwordHash: 'hashed_password',
        salt: 'salt',
        isActive: true,
        isVerified: true,
        roles: [],
        teams: [],
        workspaces: [],
      }

      mockDatabase.query.mockResolvedValueOnce({ rows: [mockUser] })

      const result = await UserManagementService.authenticateUser(
        'testuser',
        'password123',
        '127.0.0.1'
      )

      expect(result).toBeDefined()
      expect(result?.user.username).toBe('testuser')
      expect(result?.session).toBeDefined()
    })

    it('should return null for invalid credentials', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      const result = await UserManagementService.authenticateUser(
        'nonexistent',
        'password123',
        '127.0.0.1'
      )

      expect(result).toBeNull()
    })

    it('should return null for inactive user', async () => {
      const mockUser = {
        id: 'user-123',
        username: 'testuser',
        isActive: false,
      }

      mockDatabase.query.mockResolvedValueOnce({ rows: [mockUser] })

      const result = await UserManagementService.authenticateUser(
        'testuser',
        'password123',
        '127.0.0.1'
      )

      expect(result).toBeNull()
    })
  })

  describe('updateUser', () => {
    it('should update user successfully', async () => {
      const updateData: UpdateUserRequest = {
        firstName: 'Updated',
        lastName: 'Name',
        email: 'updated@example.com',
      }

      const mockUpdatedUser = {
        id: 'user-123',
        username: 'testuser',
        ...updateData,
        updatedAt: new Date(),
      }

      mockDatabase.query.mockResolvedValueOnce({ rows: [mockUpdatedUser] })

      const result = await UserManagementService.updateUser('user-123', updateData)

      expect(result.firstName).toBe('Updated')
      expect(result.lastName).toBe('Name')
      expect(result.email).toBe('updated@example.com')
    })

    it('should throw error if user not found', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      await expect(UserManagementService.updateUser('nonexistent', {})).rejects.toThrow(
        'User not found'
      )
    })
  })

  describe('getUserById', () => {
    it('should return user with roles and teams', async () => {
      const mockUser = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        isActive: true,
        roles: [
          {
            role: {
              id: 'role-123',
              name: 'contributor',
              displayName: 'Contributor',
              permissions: ['campaigns.view', 'data.view'],
            },
          },
        ],
        teams: [
          {
            team: {
              id: 'team-123',
              name: 'Test Team',
            },
            role: 'member',
          },
        ],
      }

      mockDatabase.query.mockResolvedValueOnce({ rows: [mockUser] })

      const result = await UserManagementService.getUserById('user-123')

      expect(result).toBeDefined()
      expect(result?.username).toBe('testuser')
      expect(result?.roles).toHaveLength(1)
      expect(result?.teams).toHaveLength(1)
    })

    it('should return null if user not found', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      const result = await UserManagementService.getUserById('nonexistent')

      expect(result).toBeNull()
    })
  })

  describe('assignRole', () => {
    it('should assign role to user successfully', async () => {
      mockDatabase.query
        .mockResolvedValueOnce({ rows: [{ id: 'user-123' }] }) // User exists
        .mockResolvedValueOnce({ rows: [{ id: 'role-123' }] }) // Role exists
        .mockResolvedValueOnce({ rows: [] }) // No existing assignment
        .mockResolvedValueOnce({ rows: [{ user_id: 'user-123', role_id: 'role-123' }] }) // Insert

      await expect(
        UserManagementService.assignRole('user-123', 'role-123', 'admin-123')
      ).resolves.not.toThrow()
    })

    it('should throw error if user not found', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      await expect(
        UserManagementService.assignRole('nonexistent', 'role-123', 'admin-123')
      ).rejects.toThrow('User not found')
    })

    it('should throw error if role not found', async () => {
      mockDatabase.query
        .mockResolvedValueOnce({ rows: [{ id: 'user-123' }] })
        .mockResolvedValueOnce({ rows: [] })

      await expect(
        UserManagementService.assignRole('user-123', 'nonexistent', 'admin-123')
      ).rejects.toThrow('Role not found')
    })
  })

  describe('revokeRole', () => {
    it('should revoke role from user successfully', async () => {
      mockDatabase.query.mockResolvedValueOnce({
        rows: [{ user_id: 'user-123', role_id: 'role-123' }],
      })

      await expect(UserManagementService.revokeRole('user-123', 'role-123')).resolves.not.toThrow()
    })

    it('should throw error if role assignment not found', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      await expect(UserManagementService.revokeRole('user-123', 'role-123')).rejects.toThrow(
        'Role assignment not found'
      )
    })
  })

  describe('deleteUser', () => {
    it('should soft delete user successfully', async () => {
      mockDatabase.query.mockResolvedValueOnce({
        rows: [{ id: 'user-123', isActive: false }],
      })

      const result = await UserManagementService.deleteUser('user-123', false)

      expect(result.isActive).toBe(false)
    })

    it('should hard delete user successfully', async () => {
      mockDatabase.query.mockResolvedValueOnce({
        rows: [{ id: 'user-123' }],
      })

      await expect(UserManagementService.deleteUser('user-123', true)).resolves.not.toThrow()
    })

    it('should throw error if user not found', async () => {
      mockDatabase.query.mockResolvedValueOnce({ rows: [] })

      await expect(UserManagementService.deleteUser('nonexistent', false)).rejects.toThrow(
        'User not found'
      )
    })
  })

  describe('getUsers', () => {
    it('should return paginated users list', async () => {
      const mockUsers = [
        { id: 'user-1', username: 'user1', total_count: '2' },
        { id: 'user-2', username: 'user2', total_count: '2' },
      ]

      mockDatabase.query.mockResolvedValueOnce({ rows: mockUsers })

      const result = await UserManagementService.getUsers({
        page: 1,
        limit: 10,
      })

      expect(result.users).toHaveLength(2)
      expect(result.total).toBe(2)
      expect(result.page).toBe(1)
      expect(result.totalPages).toBe(1)
    })

    it('should filter users by search term', async () => {
      const mockUsers = [{ id: 'user-1', username: 'testuser', total_count: '1' }]

      mockDatabase.query.mockResolvedValueOnce({ rows: mockUsers })

      const result = await UserManagementService.getUsers({
        page: 1,
        limit: 10,
        search: 'test',
      })

      expect(result.users).toHaveLength(1)
      expect(result.users[0].username).toBe('testuser')
    })

    it('should filter users by role', async () => {
      const mockUsers = [{ id: 'user-1', username: 'admin', total_count: '1' }]

      mockDatabase.query.mockResolvedValueOnce({ rows: mockUsers })

      const result = await UserManagementService.getUsers({
        page: 1,
        limit: 10,
        role: 'admin',
      })

      expect(result.users).toHaveLength(1)
    })
  })
})
