/**
 * Individual User API Endpoint
 * Handles operations for specific users (get, update, delete)
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { UserManagementService } from '@/lib/user-management'
import { UpdateUserRequest } from '@/types/multi-user'
import { logger } from '@/utils/logger'

interface RouteParams {
  params: {
    id: string
  }
}

/**
 * GET /api/users/[id] - Get user by ID
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const userId = context.resourceId

      if (!userId) {
        return NextResponse.json({ error: 'User ID is required' }, { status: 400 })
      }

      // Get user with full profile
      const user = await UserManagementService.getUserById(userId)

      if (!user) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 })
      }

      // Check if user can view this profile
      const canViewProfile =
        (context as any).user?.id === userId || // Own profile
        (context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.view'))

      if (!canViewProfile) {
        return NextResponse.json(
          { error: 'Insufficient permissions to view this user' },
          { status: 403 }
        )
      }

      // Remove sensitive information for non-admin users
      const isAdmin = (context as any).user?.roles?.some((role: any) => role.role.name === 'admin')

      let responseUser = { ...user }

      if (!isAdmin && (context as any).user?.id !== userId) {
        // Remove sensitive fields for non-admin viewing other users
        const { failedLoginAttempts, lockedUntil, twoFactorSecret, preferences, ...cleanUser } = responseUser
        responseUser = cleanUser as any
      }

      logger.info('Users API', 'User profile retrieved', {
        requestedBy: (context as any).user?.id,
        targetUserId: userId,
        isOwnProfile: (context as any).user?.id === userId,
      })

      return NextResponse.json({
        success: true,
        data: responseUser,
      })
    } catch (error) {
      logger.error('Users API', 'Error retrieving user', error)
      return NextResponse.json({ error: 'Failed to retrieve user' }, { status: 500 })
    }
  },
  {
    permissions: ['users.view' as any],
    allowSelfAccess: true,
  }
)

/**
 * PUT /api/users/[id] - Update user
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const userId = context.resourceId

      if (!userId) {
        return NextResponse.json({ error: 'User ID is required' }, { status: 400 })
      }

      const body = await request.json()
      const updateData: UpdateUserRequest = body

      // Check if user exists
      const existingUser = await UserManagementService.getUserById(userId)
      if (!existingUser) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 })
      }

      // Check permissions
      const canEditUser =
        (context as any).user?.id === userId || // Own profile
        (context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.edit'))

      if (!canEditUser) {
        return NextResponse.json(
          { error: 'Insufficient permissions to edit this user' },
          { status: 403 }
        )
      }

      // Restrict certain fields for non-admin users editing their own profile
      const isAdmin = (context as any).user?.roles?.some((role: any) => role.role.name === 'admin')

      if (!isAdmin && (context as any).user?.id === userId) {
        // Users can only edit their own basic profile information
        const allowedFields = [
          'firstName',
          'lastName',
          'jobTitle',
          'department',
          'phone',
          'timezone',
          'language',
          'preferences',
        ]

        const restrictedFields = Object.keys(updateData).filter(
          field => !allowedFields.includes(field)
        )

        if (restrictedFields.length > 0) {
          return NextResponse.json(
            {
              error: `Cannot modify restricted fields: ${restrictedFields.join(', ')}`,
            },
            { status: 403 }
          )
        }
      }

      // Update user
      const updatedUser = await UserManagementService.updateUser(
        userId,
        updateData,
        (context as any).user?.id
      )

      logger.info('Users API', 'User updated successfully', {
        updatedBy: (context as any).user?.id,
        targetUserId: userId,
        isOwnProfile: (context as any).user?.id === userId,
        fields: Object.keys(updateData),
      })

      return NextResponse.json({
        success: true,
        data: updatedUser,
        message: 'User updated successfully',
      })
    } catch (error) {
      logger.error('Users API', 'Error updating user', error)

      if (error instanceof Error) {
        return NextResponse.json({ error: error.message }, { status: 400 })
      }

      return NextResponse.json({ error: 'Failed to update user' }, { status: 500 })
    }
  },
  {
    permissions: ['users.edit' as any],
    allowSelfAccess: true,
  }
)

/**
 * DELETE /api/users/[id] - Delete/deactivate user
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const userId = context.resourceId

      if (!userId) {
        return NextResponse.json({ error: 'User ID is required' }, { status: 400 })
      }

      // Prevent self-deletion
      if ((context as any).user?.id === userId) {
        return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 })
      }

      // Check if user exists
      const existingUser = await UserManagementService.getUserById(userId)
      if (!existingUser) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 })
      }

      const { searchParams } = new URL(request.url)
      const permanent = searchParams.get('permanent') === 'true'

      let query: string
      let successMessage: string

      if (permanent) {
        // Permanent deletion (admin only)
        if (!(context as any).user?.roles?.some((role: any) => role.role.name === 'admin')) {
          return NextResponse.json(
            { error: 'Only administrators can permanently delete users' },
            { status: 403 }
          )
        }

        query = 'DELETE FROM users WHERE id = $1 RETURNING username'
        successMessage = 'User deleted permanently'
      } else {
        // Soft deletion (deactivation)
        query = `
          UPDATE users 
          SET is_active = false, updated_at = CURRENT_TIMESTAMP
          WHERE id = $1 
          RETURNING username
        `
        successMessage = 'User deactivated successfully'
      }

      const result = await (context as any).database.query(query, [userId])
      const deletedUser = result.rows[0]

      if (!deletedUser) {
        return NextResponse.json({ error: 'Failed to delete user' }, { status: 500 })
      }

      logger.info('Users API', permanent ? 'User deleted permanently' : 'User deactivated', {
        deletedBy: (context as any).user?.id,
        targetUserId: userId,
        username: deletedUser.username,
        permanent,
      })

      return NextResponse.json({
        success: true,
        data: {
          userId,
          username: deletedUser.username,
          permanent,
        },
        message: successMessage,
      })
    } catch (error) {
      logger.error('Users API', 'Error deleting user', error)
      return NextResponse.json({ error: 'Failed to delete user' }, { status: 500 })
    }
  },
  { permissions: ['users.delete' as any] }
)

/**
 * PATCH /api/users/[id] - Partial user update (for specific operations)
 */
export const PATCH = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const userId = context.resourceId

      if (!userId) {
        return NextResponse.json({ error: 'User ID is required' }, { status: 400 })
      }

      const body = await request.json()
      const { action, ...data } = body

      if (!action) {
        return NextResponse.json({ error: 'Action is required' }, { status: 400 })
      }

      // Check if user exists
      const existingUser = await UserManagementService.getUserById(userId)
      if (!existingUser) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 })
      }

      let result: any
      let message: string

      switch (action) {
        case 'activate':
          if (!(context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.manage'))) {
            return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 })
          }

          await (context as any).database.query(
            'UPDATE users SET is_active = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [userId]
          )
          message = 'User activated successfully'
          break

        case 'deactivate':
          if (!(context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.manage'))) {
            return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 })
          }

          if ((context as any).user?.id === userId) {
            return NextResponse.json(
              { error: 'Cannot deactivate your own account' },
              { status: 400 }
            )
          }

          await (context as any).database.query(
            'UPDATE users SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [userId]
          )
          message = 'User deactivated successfully'
          break

        case 'verify':
          if (!(context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.manage'))) {
            return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 })
          }

          await (context as any).database.query(
            'UPDATE users SET is_verified = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [userId]
          )
          message = 'User verified successfully'
          break

        case 'reset_password':
          if (!(context as any).user?.roles?.some((role: any) => role.role.permissions.includes('users.manage'))) {
            return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 })
          }

          // TODO: Implement password reset logic
          message = 'Password reset initiated'
          break

        default:
          return NextResponse.json({ error: `Unknown action: ${action}` }, { status: 400 })
      }

      logger.info('Users API', `User ${action} completed`, {
        actionBy: (context as any).user?.id,
        targetUserId: userId,
        action,
      })

      return NextResponse.json({
        success: true,
        data: { action, userId },
        message,
      })
    } catch (error) {
      logger.error('Users API', 'Error in user patch operation', error)
      return NextResponse.json({ error: 'Failed to perform operation' }, { status: 500 })
    }
  },
  {
    permissions: ['users.edit' as any],
    allowSelfAccess: true,
  }
)
