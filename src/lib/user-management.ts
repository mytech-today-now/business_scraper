/**
 * User Management Service
 * Handles user registration, authentication, profile management, and team assignments
 */

import {
  User,
  CreateUserRequest,
  UpdateUserRequest,
  UserProfile,
  UserSession,
  TeamMembership,
  WorkspaceMembership,
  RoleName,
} from '@/types/multi-user'
import { database } from './postgresql-database'
import { logger } from '@/utils/logger'
import { generateId, hashPassword, verifyPassword, generateSalt } from './security'
import { RBACService } from './rbac'

export class UserManagementService {
  /**
   * Create a new user account
   */
  static async createUser(
    userData: CreateUserRequest,
    createdBy?: string
  ): Promise<{ user: User; tempPassword?: string }> {
    try {
      // Validate input
      await this.validateUserData(userData)

      // Check if username or email already exists
      const existingUser = await this.findUserByUsernameOrEmail(userData.username, userData.email)

      if (existingUser) {
        throw new Error('Username or email already exists')
      }

      // Generate password hash and salt
      const salt = generateSalt()
      const passwordHash = await hashPassword(userData.password, salt)

      // Create user record
      const userId = generateId()
      const now = new Date()

      const user: User = {
        id: userId,
        username: userData.username,
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        avatarUrl: undefined,
        isActive: true,
        isVerified: false,
        lastLoginAt: undefined,
        passwordChangedAt: now,
        jobTitle: userData.jobTitle,
        department: userData.department,
        phone: userData.phone,
        timezone: userData.timezone || 'UTC',
        language: userData.language || 'en',
        preferences: {
          theme: 'light',
          notifications: {
            email: true,
            browser: true,
            scrapingComplete: true,
            teamInvites: true,
            dataValidation: true,
            systemAlerts: true,
          },
          dashboard: {
            defaultView: 'campaigns',
            chartsVisible: true,
            refreshInterval: 30000,
            compactMode: false,
          },
          scraping: {
            defaultSearchRadius: 25,
            defaultSearchDepth: 3,
            defaultPagesPerSite: 5,
            autoValidation: false,
          },
        },
        twoFactorEnabled: false,
        failedLoginAttempts: 0,
        createdAt: now,
        updatedAt: now,
        roles: [],
        teams: [],
        workspaces: [],
      }

      // Insert user into database
      await database.query(
        `
        INSERT INTO users (
          id, username, email, password_hash, salt, first_name, last_name,
          job_title, department, phone, timezone, language, preferences,
          is_active, is_verified, password_changed_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      `,
        [
          userId,
          userData.username,
          userData.email,
          passwordHash,
          salt,
          userData.firstName,
          userData.lastName,
          userData.jobTitle,
          userData.department,
          userData.phone,
          userData.timezone || 'UTC',
          userData.language || 'en',
          JSON.stringify(user.preferences),
          true,
          false,
          now,
          now,
          now,
        ]
      )

      // Assign default role (contributor) unless created by admin
      const defaultRole = createdBy ? 'contributor' : 'admin'
      await this.assignRole(userId, defaultRole, createdBy)

      // Log user creation
      logger.info('User Management', 'User created successfully', {
        userId,
        username: userData.username,
        email: userData.email,
        createdBy,
      })

      return { user }
    } catch (error) {
      logger.error('User Management', 'Error creating user', error)
      throw error
    }
  }

  /**
   * Authenticate user with username/email and password
   */
  static async authenticateUser(
    usernameOrEmail: string,
    password: string,
    ipAddress?: string
  ): Promise<{ user: User; session: UserSession } | null> {
    try {
      // Find user by username or email
      const user = await this.findUserByUsernameOrEmail(usernameOrEmail, usernameOrEmail)

      if (!user) {
        logger.warn('User Management', 'Authentication failed - user not found', {
          usernameOrEmail,
          ipAddress,
        })
        return null
      }

      // Check if user is active
      if (!user.isActive) {
        logger.warn('User Management', 'Authentication failed - user inactive', {
          userId: user.id,
          ipAddress,
        })
        return null
      }

      // Check if user is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        logger.warn('User Management', 'Authentication failed - user locked', {
          userId: user.id,
          lockedUntil: user.lockedUntil,
          ipAddress,
        })
        return null
      }

      // Get stored password hash and salt
      const userRecord = await database.query(
        'SELECT password_hash, salt FROM users WHERE id = $1',
        [user.id]
      )

      if (!userRecord.rows[0]) {
        throw new Error('User record not found')
      }

      const { password_hash: storedHash, salt } = userRecord.rows[0]

      // Verify password
      const isValidPassword = await verifyPassword(password, storedHash, salt)

      if (!isValidPassword) {
        // Increment failed login attempts
        await this.incrementFailedLoginAttempts(user.id)

        logger.warn('User Management', 'Authentication failed - invalid password', {
          userId: user.id,
          ipAddress,
        })
        return null
      }

      // Reset failed login attempts and update last login
      await this.resetFailedLoginAttempts(user.id)
      await this.updateLastLogin(user.id)

      // Create session
      const session = await this.createSession(user.id, ipAddress)

      // Load user with roles and memberships
      const fullUser = await this.getUserById(user.id)

      if (!fullUser) {
        throw new Error('Failed to load user after authentication')
      }

      logger.info('User Management', 'User authenticated successfully', {
        userId: user.id,
        username: user.username,
        ipAddress,
      })

      return { user: fullUser, session }
    } catch (error) {
      logger.error('User Management', 'Error during authentication', error)
      throw error
    }
  }

  /**
   * Get user by ID with full profile information
   */
  static async getUserById(userId: string): Promise<User | null> {
    try {
      const result = await database.query(
        `
        SELECT 
          u.*,
          COALESCE(
            json_agg(
              DISTINCT jsonb_build_object(
                'id', ur.id,
                'userId', ur.user_id,
                'roleId', ur.role_id,
                'role', jsonb_build_object(
                  'id', r.id,
                  'name', r.name,
                  'displayName', r.display_name,
                  'description', r.description,
                  'isSystemRole', r.is_system_role,
                  'permissions', r.permissions,
                  'createdAt', r.created_at,
                  'updatedAt', r.updated_at
                ),
                'assignedAt', ur.assigned_at,
                'expiresAt', ur.expires_at,
                'isActive', ur.is_active,
                'createdAt', ur.created_at,
                'updatedAt', ur.updated_at
              )
            ) FILTER (WHERE ur.id IS NOT NULL),
            '[]'
          ) as roles,
          COALESCE(
            json_agg(
              DISTINCT jsonb_build_object(
                'id', tm.id,
                'teamId', tm.team_id,
                'team', jsonb_build_object(
                  'id', t.id,
                  'name', t.name,
                  'description', t.description,
                  'ownerId', t.owner_id,
                  'isActive', t.is_active,
                  'createdAt', t.created_at,
                  'updatedAt', t.updated_at
                ),
                'userId', tm.user_id,
                'role', tm.role,
                'joinedAt', tm.joined_at,
                'isActive', tm.is_active,
                'createdAt', tm.created_at,
                'updatedAt', tm.updated_at
              )
            ) FILTER (WHERE tm.id IS NOT NULL),
            '[]'
          ) as teams,
          COALESCE(
            json_agg(
              DISTINCT jsonb_build_object(
                'id', wm.id,
                'workspaceId', wm.workspace_id,
                'workspace', jsonb_build_object(
                  'id', w.id,
                  'name', w.name,
                  'description', w.description,
                  'teamId', w.team_id,
                  'ownerId', w.owner_id,
                  'isActive', w.is_active,
                  'createdAt', w.created_at,
                  'updatedAt', w.updated_at
                ),
                'userId', wm.user_id,
                'role', wm.role,
                'permissions', wm.permissions,
                'joinedAt', wm.joined_at,
                'isActive', wm.is_active,
                'createdAt', wm.created_at,
                'updatedAt', wm.updated_at
              )
            ) FILTER (WHERE wm.id IS NOT NULL),
            '[]'
          ) as workspaces
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.is_active = true
        LEFT JOIN roles r ON ur.role_id = r.id
        LEFT JOIN team_members tm ON u.id = tm.user_id AND tm.is_active = true
        LEFT JOIN teams t ON tm.team_id = t.id
        LEFT JOIN workspace_members wm ON u.id = wm.user_id AND wm.is_active = true
        LEFT JOIN workspaces w ON wm.workspace_id = w.id
        WHERE u.id = $1
        GROUP BY u.id
      `,
        [userId]
      )

      if (!result.rows[0]) {
        return null
      }

      const row = result.rows[0]

      return {
        id: row.id,
        username: row.username,
        email: row.email,
        firstName: row.first_name,
        lastName: row.last_name,
        avatarUrl: row.avatar_url,
        isActive: row.is_active,
        isVerified: row.is_verified,
        lastLoginAt: row.last_login_at,
        passwordChangedAt: row.password_changed_at,
        jobTitle: row.job_title,
        department: row.department,
        phone: row.phone,
        timezone: row.timezone,
        language: row.language,
        preferences: row.preferences,
        twoFactorEnabled: row.two_factor_enabled,
        failedLoginAttempts: row.failed_login_attempts,
        lockedUntil: row.locked_until,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        roles: row.roles,
        teams: row.teams,
        workspaces: row.workspaces,
      }
    } catch (error) {
      logger.error('User Management', 'Error fetching user by ID', error)
      throw error
    }
  }

  /**
   * Update user profile
   */
  static async updateUser(
    userId: string,
    updateData: UpdateUserRequest,
    updatedBy?: string
  ): Promise<User> {
    try {
      const updates: string[] = []
      const values: any[] = []
      let paramIndex = 1

      // Build dynamic update query
      if (updateData.firstName !== undefined) {
        updates.push(`first_name = $${paramIndex++}`)
        values.push(updateData.firstName)
      }

      if (updateData.lastName !== undefined) {
        updates.push(`last_name = $${paramIndex++}`)
        values.push(updateData.lastName)
      }

      if (updateData.jobTitle !== undefined) {
        updates.push(`job_title = $${paramIndex++}`)
        values.push(updateData.jobTitle)
      }

      if (updateData.department !== undefined) {
        updates.push(`department = $${paramIndex++}`)
        values.push(updateData.department)
      }

      if (updateData.phone !== undefined) {
        updates.push(`phone = $${paramIndex++}`)
        values.push(updateData.phone)
      }

      if (updateData.timezone !== undefined) {
        updates.push(`timezone = $${paramIndex++}`)
        values.push(updateData.timezone)
      }

      if (updateData.language !== undefined) {
        updates.push(`language = $${paramIndex++}`)
        values.push(updateData.language)
      }

      if (updateData.preferences !== undefined) {
        updates.push(`preferences = $${paramIndex++}`)
        values.push(JSON.stringify(updateData.preferences))
      }

      if (updates.length === 0) {
        throw new Error('No valid update fields provided')
      }

      // Add updated_at
      updates.push(`updated_at = $${paramIndex++}`)
      values.push(new Date())

      // Add user ID for WHERE clause
      values.push(userId)

      const query = `
        UPDATE users 
        SET ${updates.join(', ')}
        WHERE id = $${paramIndex}
        RETURNING *
      `

      const result = await database.query(query, values)

      if (!result.rows[0]) {
        throw new Error('User not found')
      }

      // Get updated user with full profile
      const updatedUser = await this.getUserById(userId)

      if (!updatedUser) {
        throw new Error('Failed to fetch updated user')
      }

      logger.info('User Management', 'User updated successfully', {
        userId,
        updatedBy,
        fields: Object.keys(updateData),
      })

      return updatedUser
    } catch (error) {
      logger.error('User Management', 'Error updating user', error)
      throw error
    }
  }

  /**
   * Assign role to user
   */
  static async assignRole(
    userId: string,
    roleName: RoleName,
    assignedBy?: string,
    expiresAt?: Date
  ): Promise<void> {
    try {
      // Get role by name
      const roleResult = await database.query('SELECT id FROM roles WHERE name = $1', [roleName])

      if (!roleResult.rows[0]) {
        throw new Error(`Role '${roleName}' not found`)
      }

      const roleId = roleResult.rows[0].id

      // Check if user already has this role
      const existingRole = await database.query(
        'SELECT id FROM user_roles WHERE user_id = $1 AND role_id = $2 AND is_active = true',
        [userId, roleId]
      )

      if (existingRole.rows[0]) {
        throw new Error('User already has this role')
      }

      // Insert role assignment
      await database.query(
        `
        INSERT INTO user_roles (user_id, role_id, assigned_by, expires_at)
        VALUES ($1, $2, $3, $4)
      `,
        [userId, roleId, assignedBy, expiresAt]
      )

      logger.info('User Management', 'Role assigned successfully', {
        userId,
        roleName,
        assignedBy,
        expiresAt,
      })
    } catch (error) {
      logger.error('User Management', 'Error assigning role', error)
      throw error
    }
  }

  /**
   * Find user by username or email
   */
  private static async findUserByUsernameOrEmail(
    username: string,
    email: string
  ): Promise<User | null> {
    const result = await database.query('SELECT * FROM users WHERE username = $1 OR email = $2', [
      username,
      email,
    ])

    if (!result.rows[0]) {
      return null
    }

    const row = result.rows[0]
    return {
      id: row.id,
      username: row.username,
      email: row.email,
      firstName: row.first_name,
      lastName: row.last_name,
      avatarUrl: row.avatar_url,
      isActive: row.is_active,
      isVerified: row.is_verified,
      lastLoginAt: row.last_login_at,
      passwordChangedAt: row.password_changed_at,
      jobTitle: row.job_title,
      department: row.department,
      phone: row.phone,
      timezone: row.timezone,
      language: row.language,
      preferences: row.preferences,
      twoFactorEnabled: row.two_factor_enabled,
      failedLoginAttempts: row.failed_login_attempts,
      lockedUntil: row.locked_until,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      roles: [],
      teams: [],
      workspaces: [],
    }
  }

  /**
   * Validate user data
   */
  private static async validateUserData(userData: CreateUserRequest): Promise<void> {
    if (!userData.username || userData.username.length < 3) {
      throw new Error('Username must be at least 3 characters long')
    }

    if (!userData.email || !userData.email.includes('@')) {
      throw new Error('Valid email address is required')
    }

    if (!userData.password || userData.password.length < 8) {
      throw new Error('Password must be at least 8 characters long')
    }

    if (!userData.firstName || userData.firstName.trim().length === 0) {
      throw new Error('First name is required')
    }

    if (!userData.lastName || userData.lastName.trim().length === 0) {
      throw new Error('Last name is required')
    }
  }

  /**
   * Create user session
   */
  private static async createSession(userId: string, ipAddress?: string): Promise<UserSession> {
    const sessionId = generateId()
    const sessionToken = generateId()
    const csrfToken = generateId()
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours

    await database.query(
      `
      INSERT INTO user_sessions (
        id, user_id, session_token, csrf_token, ip_address, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6)
    `,
      [sessionId, userId, sessionToken, csrfToken, ipAddress, expiresAt]
    )

    return {
      id: sessionId,
      userId,
      sessionToken,
      csrfToken,
      ipAddress,
      isActive: true,
      expiresAt,
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      deviceInfo: { type: 'unknown' },
      locationInfo: {},
      user: {} as User, // Will be populated by caller
    }
  }

  /**
   * Increment failed login attempts
   */
  private static async incrementFailedLoginAttempts(userId: string): Promise<void> {
    await database.query(
      `
      UPDATE users 
      SET 
        failed_login_attempts = failed_login_attempts + 1,
        locked_until = CASE 
          WHEN failed_login_attempts >= 4 THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes'
          ELSE locked_until
        END
      WHERE id = $1
    `,
      [userId]
    )
  }

  /**
   * Reset failed login attempts
   */
  private static async resetFailedLoginAttempts(userId: string): Promise<void> {
    await database.query(
      `
      UPDATE users 
      SET failed_login_attempts = 0, locked_until = NULL
      WHERE id = $1
    `,
      [userId]
    )
  }

  /**
   * Update last login timestamp
   */
  private static async updateLastLogin(userId: string): Promise<void> {
    await database.query('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1', [
      userId,
    ])
  }
}
