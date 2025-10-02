/**
 * Users API Endpoint
 * Handles user management operations (CRUD, authentication, profile management)
 * Enhanced with comprehensive data sanitization and security controls
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { UserManagementService } from '@/lib/user-management'
import { CreateUserRequest, UpdateUserRequest } from '@/types/multi-user'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { database } from '@/lib/postgresql-database'
import { withResponseSanitization, DataClassification } from '@/lib/response-sanitization'
import { createSecureErrorResponse, ErrorContext } from '@/lib/error-handling'
import { dataClassificationService } from '@/lib/data-classification'
import { piiDetectionService } from '@/lib/pii-detection'
import { sanitizeErrorMessage, createSecureApiResponse } from '@/lib/response-sanitization'

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

      // Query users with pagination - only select safe fields
      const usersQuery = `
        SELECT DISTINCT
          u.id,
          u.username,
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

      const result = await database.executeQuery(usersQuery, values)
      const users = result.rows
      const totalCount = users.length > 0 ? parseInt(users[0].total_count) : 0
      const totalPages = Math.ceil(totalCount / limit)

      // Enhanced: Sanitize user data and remove ALL sensitive information
      const sanitizedUsers = users.map((user: any) => {
        const { total_count, ...cleanUser } = user

        // Enhanced: Explicitly remove ALL authentication-related fields
        const sensitiveFields = [
          'password', 'password_hash', 'password_salt', 'passwordhash', 'passwordsalt',
          'secret', 'token', 'api_key', 'apikey', 'private_key', 'privatekey',
          'session_id', 'sessionid', 'csrf_token', 'csrftoken', 'auth_token',
          'access_token', 'refresh_token', 'salt', 'hash', 'encrypted_password'
        ]

        // Remove sensitive fields first
        for (const field of sensitiveFields) {
          delete cleanUser[field]
          delete cleanUser[field.toLowerCase()]
          delete cleanUser[field.toUpperCase()]
        }

        // Apply data classification and sanitization
        const userClassifications = dataClassificationService.classifyObject(cleanUser)

        // Remove or mask fields based on classification
        const sanitizedUser: any = {}
        for (const [key, value] of Object.entries(cleanUser)) {
          // Enhanced: Double-check for any remaining sensitive patterns
          const lowerKey = key.toLowerCase()
          if (sensitiveFields.some(field => lowerKey.includes(field.toLowerCase()))) {
            continue // Skip this field entirely
          }

          const classification = userClassifications.get(key)
          if (classification && classification.protectionPolicy.allowInResponses) {
            if (classification.protectionPolicy.maskInProduction && process.env.NODE_ENV === 'production') {
              // Apply PII detection and masking
              if (typeof value === 'string') {
                const { redactedText } = piiDetectionService.redactPII(value, `users.${key}`)
                sanitizedUser[key] = redactedText
              } else {
                sanitizedUser[key] = value
              }
            } else {
              sanitizedUser[key] = value
            }
          }
        }

        // Add computed safe fields
        if (sanitizedUser.first_name && sanitizedUser.last_name) {
          sanitizedUser.fullName = `${sanitizedUser.first_name} ${sanitizedUser.last_name}`
        }

        return sanitizedUser
      })

      logger.info('Users API', 'Users listed successfully', {
        userId: context.session?.user?.id,
        page,
        limit,
        totalCount,
        resultCount: sanitizedUsers.length,
        filters: { search, role, isActive, workspaceId },
      })

      // Use enhanced sanitization for the response
      return createSecureApiResponse({
        success: true,
        data: sanitizedUsers,
        pagination: {
          page,
          limit,
          total: totalCount,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      }, 200, {
        context: 'Users List API'
      })
    } catch (error) {
      const errorContext: ErrorContext = {
        endpoint: '/api/users',
        method: 'GET',
        ip: getClientIP(request),
        userAgent: request.headers.get('user-agent') || undefined,
        sessionId: context.session?.id,
        userId: context.session?.user?.id,
      }

      return createSecureErrorResponse(error, errorContext, {
        customMessage: sanitizeErrorMessage(error, 'Users List Retrieval'),
        statusCode: 500,
        sanitizeResponse: true,
      })
    }
  },
  { permissions: ['users.view' as any] }
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
      const { user } = await UserManagementService.createUser(userData, context.session?.user?.id || '')

      // Enhanced: Apply comprehensive data sanitization with strict authentication data removal
      const sensitiveFields = [
        'password', 'password_hash', 'password_salt', 'passwordhash', 'passwordsalt',
        'secret', 'token', 'api_key', 'apikey', 'private_key', 'privatekey',
        'session_id', 'sessionid', 'csrf_token', 'csrftoken', 'auth_token',
        'access_token', 'refresh_token', 'salt', 'hash', 'encrypted_password'
      ]

      // Create a clean copy without sensitive fields
      const cleanUser = { ...user }
      for (const field of sensitiveFields) {
        delete cleanUser[field]
        delete cleanUser[field.toLowerCase()]
        delete cleanUser[field.toUpperCase()]
      }

      const userClassifications = dataClassificationService.classifyObject(cleanUser)
      const sanitizedUser: any = {}

      for (const [key, value] of Object.entries(cleanUser as any)) {
        // Enhanced: Double-check for any remaining sensitive patterns
        const lowerKey = key.toLowerCase()
        if (sensitiveFields.some(field => lowerKey.includes(field.toLowerCase()))) {
          continue // Skip this field entirely
        }

        const classification = userClassifications.get(key)
        if (classification && classification.protectionPolicy.allowInResponses) {
          if (classification.protectionPolicy.maskInProduction && process.env.NODE_ENV === 'production') {
            if (typeof value === 'string') {
              const { redactedText } = piiDetectionService.redactPII(value, `user.${key}`)
              sanitizedUser[key] = redactedText
            } else {
              sanitizedUser[key] = value
            }
          } else {
            sanitizedUser[key] = value
          }
        }
      }

      logger.info('Users API', 'User created successfully', {
        createdBy: context.session?.user?.id,
        newUserId: user.id,
        username: sanitizedUser.username,
      })

      // Use enhanced sanitization for the response
      return createSecureApiResponse({
        success: true,
        data: sanitizedUser,
        message: 'User created successfully',
      }, 201, {
        context: 'User Creation API'
      })
    } catch (error) {
      const errorContext: ErrorContext = {
        endpoint: '/api/users',
        method: 'POST',
        ip: getClientIP(request),
        userAgent: request.headers.get('user-agent') || undefined,
        sessionId: context.session?.id,
        userId: context.session?.user?.id,
      }

      return createSecureErrorResponse(error, errorContext, {
        customMessage: sanitizeErrorMessage(error, 'User Creation'),
        statusCode: error instanceof Error ? 400 : 500,
        sanitizeResponse: true,
      })
    }
  },
  { permissions: ['users.manage' as any] }
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
            context.session?.user?.id || ''
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
        updatedBy: context.session?.user?.id,
        successCount: updatedUsers.length,
        errorCount: errors.length,
        userIds,
      })

      return NextResponse.json({
        success: true,
        data: {
          updated: updatedUsers.length,
          errorCount: errors.length,
          results: updatedUsers,
          errors: errors,
        },
        message: `Updated ${updatedUsers.length} users successfully`,
      })
    } catch (error) {
      const errorContext: ErrorContext = {
        endpoint: '/api/users',
        method: 'PUT',
        ip: getClientIP(request),
        userAgent: request.headers.get('user-agent') || undefined,
        sessionId: context.session?.id,
        userId: context.session?.user?.id,
      }

      return createSecureErrorResponse(error, errorContext, {
        customMessage: sanitizeErrorMessage(error, 'Users Bulk Update'),
        statusCode: 500,
        sanitizeResponse: true,
      })
    }
  },
  { permissions: ['users.manage' as any] }
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
      if (userIds.includes(context.session?.user?.id || '')) {
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

      const result = await database.executeQuery(query, [userIds, context.session?.user?.id])
      const affectedUsers = result.rows

      logger.info('Users API', permanent ? 'Users deleted permanently' : 'Users deactivated', {
        deletedBy: context.session?.user?.id,
        userIds: affectedUsers.map((u: any) => u.id),
        usernames: affectedUsers.map((u: any) => u.username),
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
      const errorContext: ErrorContext = {
        endpoint: '/api/users',
        method: 'DELETE',
        ip: getClientIP(request),
        userAgent: request.headers.get('user-agent') || undefined,
        sessionId: context.session?.id,
        userId: context.session?.user?.id,
      }

      return createSecureErrorResponse(error, errorContext, {
        customMessage: sanitizeErrorMessage(error, 'Users Deletion'),
        statusCode: 500,
        sanitizeResponse: true,
      })
    }
  },
  { permissions: ['users.delete' as any] }
)
