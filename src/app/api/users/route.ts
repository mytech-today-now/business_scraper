/**
 * Users API Endpoint
 * Handles user management operations (CRUD, authentication, profile management)
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { UserManagementService } from '@/lib/user-management'
import { CreateUserRequest, UpdateUserRequest } from '@/types/multi-user'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * GET /api/users - List users with pagination and filtering
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const page = parseInt(searchParams.get('page') || '1')
      const limit = parseInt(searchParams.get('limit') || '20')
      const search = searchParams.get('search') || ''
      const role = searchParams.get('role') || ''
      const isActive = searchParams.get('isActive')
      const workspaceId = searchParams.get('workspaceId')

      // Build query conditions
      const conditions: string[] = ['1=1']
      const values: any[] = []
      let paramIndex = 1

      if (search) {
        conditions.push(`(
          u.username ILIKE $${paramIndex} OR 
          u.email ILIKE $${paramIndex} OR 
          u.first_name ILIKE $${paramIndex} OR 
          u.last_name ILIKE $${paramIndex}
        )`)
        values.push(`%${search}%`)
        paramIndex++
      }

      if (role) {
        conditions.push(`r.name = $${paramIndex}`)
        values.push(role)
        paramIndex++
      }

      if (isActive !== null) {
        conditions.push(`u.is_active = $${paramIndex}`)
        values.push(isActive === 'true')
        paramIndex++
      }

      if (workspaceId) {
        conditions.push(`wm.workspace_id = $${paramIndex}`)
        values.push(workspaceId)
        paramIndex++
      }

      // Calculate offset
      const offset = (page - 1) * limit
      values.push(limit, offset)

      // Query users with pagination
      const usersQuery = `
        SELECT DISTINCT
          u.id,
          u.username,
          u.email,
          u.first_name,
          u.last_name,
          u.avatar_url,
          u.is_active,
          u.is_verified,
          u.last_login_at,
          u.job_title,
          u.department,
          u.created_at,
          u.updated_at,
          COUNT(*) OVER() as total_count
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.is_active = true
        LEFT JOIN roles r ON ur.role_id = r.id
        LEFT JOIN workspace_members wm ON u.id = wm.user_id AND wm.is_active = true
        WHERE ${conditions.join(' AND ')}
        ORDER BY u.created_at DESC
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `

      const result = await context.database.query(usersQuery, values)
      const users = result.rows
      const totalCount = users.length > 0 ? parseInt(users[0].total_count) : 0
      const totalPages = Math.ceil(totalCount / limit)

      // Remove total_count from user objects
      const cleanUsers = users.map(user => {
        const { total_count, ...cleanUser } = user
        return {
          ...cleanUser,
          fullName: `${cleanUser.first_name} ${cleanUser.last_name}`,
        }
      })

      logger.info('Users API', 'Users listed successfully', {
        userId: context.user.id,
        page,
        limit,
        totalCount,
        filters: { search, role, isActive, workspaceId },
      })

      return NextResponse.json({
        success: true,
        data: cleanUsers,
        pagination: {
          page,
          limit,
          total: totalCount,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      })
    } catch (error) {
      logger.error('Users API', 'Error listing users', error)
      return NextResponse.json({ error: 'Failed to list users' }, { status: 500 })
    }
  },
  { permissions: ['users.view'] }
)

/**
 * POST /api/users - Create new user
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const userData: CreateUserRequest = body

      // Validate required fields
      if (
        !userData.username ||
        !userData.email ||
        !userData.password ||
        !userData.firstName ||
        !userData.lastName
      ) {
        return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
      }

      // Create user
      const { user } = await UserManagementService.createUser(userData, context.user.id)

      // Remove sensitive information from response
      const { roles, teams, workspaces, ...safeUser } = user

      logger.info('Users API', 'User created successfully', {
        createdBy: context.user.id,
        newUserId: user.id,
        username: user.username,
        email: user.email,
      })

      return NextResponse.json(
        {
          success: true,
          data: safeUser,
          message: 'User created successfully',
        },
        { status: 201 }
      )
    } catch (error) {
      logger.error('Users API', 'Error creating user', error)

      if (error instanceof Error) {
        return NextResponse.json({ error: error.message }, { status: 400 })
      }

      return NextResponse.json({ error: 'Failed to create user' }, { status: 500 })
    }
  },
  { permissions: ['users.manage'] }
)

/**
 * PUT /api/users - Bulk update users (admin only)
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { userIds, updateData } = body

      if (!Array.isArray(userIds) || userIds.length === 0) {
        return NextResponse.json({ error: 'User IDs array is required' }, { status: 400 })
      }

      if (!updateData || typeof updateData !== 'object') {
        return NextResponse.json({ error: 'Update data is required' }, { status: 400 })
      }

      const updatedUsers = []
      const errors = []

      // Update each user
      for (const userId of userIds) {
        try {
          const updatedUser = await UserManagementService.updateUser(
            userId,
            updateData,
            context.user.id
          )
          updatedUsers.push(updatedUser)
        } catch (error) {
          errors.push({
            userId,
            error: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      }

      logger.info('Users API', 'Bulk user update completed', {
        updatedBy: context.user.id,
        successCount: updatedUsers.length,
        errorCount: errors.length,
        userIds,
      })

      return NextResponse.json({
        success: true,
        data: {
          updated: updatedUsers.length,
          errors: errors.length,
          results: updatedUsers,
          errors: errors,
        },
        message: `Updated ${updatedUsers.length} users successfully`,
      })
    } catch (error) {
      logger.error('Users API', 'Error in bulk user update', error)
      return NextResponse.json({ error: 'Failed to update users' }, { status: 500 })
    }
  },
  { permissions: ['users.manage'] }
)

/**
 * DELETE /api/users - Bulk deactivate users (admin only)
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { userIds, permanent = false } = body

      if (!Array.isArray(userIds) || userIds.length === 0) {
        return NextResponse.json({ error: 'User IDs array is required' }, { status: 400 })
      }

      // Prevent self-deletion
      if (userIds.includes(context.user.id)) {
        return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 })
      }

      let query: string
      let successMessage: string

      if (permanent) {
        // Permanent deletion (admin only)
        query = `
          DELETE FROM users 
          WHERE id = ANY($1) AND id != $2
          RETURNING id, username
        `
        successMessage = 'Users deleted permanently'
      } else {
        // Soft deletion (deactivation)
        query = `
          UPDATE users 
          SET is_active = false, updated_at = CURRENT_TIMESTAMP
          WHERE id = ANY($1) AND id != $2
          RETURNING id, username
        `
        successMessage = 'Users deactivated successfully'
      }

      const result = await context.database.query(query, [userIds, context.user.id])
      const affectedUsers = result.rows

      logger.info('Users API', permanent ? 'Users deleted permanently' : 'Users deactivated', {
        deletedBy: context.user.id,
        userIds: affectedUsers.map(u => u.id),
        usernames: affectedUsers.map(u => u.username),
        permanent,
      })

      return NextResponse.json({
        success: true,
        data: {
          affected: affectedUsers.length,
          users: affectedUsers,
        },
        message: successMessage,
      })
    } catch (error) {
      logger.error('Users API', 'Error deleting users', error)
      return NextResponse.json({ error: 'Failed to delete users' }, { status: 500 })
    }
  },
  { permissions: ['users.delete'] }
)
