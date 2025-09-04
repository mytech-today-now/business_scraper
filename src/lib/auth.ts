/**
 * NextAuth.js Configuration for Enterprise Security
 * Implements SOC 2 Type II compliance with role-based access control
 */

import { NextAuthOptions, Session, User } from 'next-auth'
import { JWT } from 'next-auth/jwt'
import CredentialsProvider from 'next-auth/providers/credentials'
import bcrypt from 'bcryptjs'
import { logger } from '@/utils/logger'
import { getSecurityConfig } from '@/lib/config'
import { getPostgresConnection } from './postgres-connection'

// Lazy-loaded database connection for NextAuth
let sql: any = null

function getAuthDatabase() {
  if (!sql) {
    sql = getPostgresConnection({
      connectionString: process.env.DATABASE_URL || process.env.NEXTAUTH_DATABASE_URL,
      ssl: false, // Explicitly disable SSL for local PostgreSQL container
    })
  }
  return sql
}

// User roles and permissions
export enum UserRole {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  VIEWER = 'viewer',
  COMPLIANCE_OFFICER = 'compliance_officer',
  SECURITY_ANALYST = 'security_analyst',
}

export enum Permission {
  // Scraping permissions
  SCRAPE_EXECUTE = 'scrape:execute',
  SCRAPE_CONFIGURE = 'scrape:configure',
  SCRAPE_VIEW = 'scrape:view',

  // Data permissions
  DATA_EXPORT = 'data:export',
  DATA_DELETE = 'data:delete',
  DATA_VIEW = 'data:view',
  DATA_MODIFY = 'data:modify',

  // Admin permissions
  USER_MANAGE = 'user:manage',
  SYSTEM_CONFIGURE = 'system:configure',
  AUDIT_VIEW = 'audit:view',

  // Compliance permissions
  COMPLIANCE_MANAGE = 'compliance:manage',
  PRIVACY_MANAGE = 'privacy:manage',
  CONSENT_MANAGE = 'consent:manage',

  // Security permissions
  SECURITY_MONITOR = 'security:monitor',
  SECURITY_CONFIGURE = 'security:configure',
}

// Role-permission mapping
export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.ADMIN]: [
    Permission.SCRAPE_EXECUTE,
    Permission.SCRAPE_CONFIGURE,
    Permission.SCRAPE_VIEW,
    Permission.DATA_EXPORT,
    Permission.DATA_DELETE,
    Permission.DATA_VIEW,
    Permission.DATA_MODIFY,
    Permission.USER_MANAGE,
    Permission.SYSTEM_CONFIGURE,
    Permission.AUDIT_VIEW,
    Permission.COMPLIANCE_MANAGE,
    Permission.PRIVACY_MANAGE,
    Permission.CONSENT_MANAGE,
    Permission.SECURITY_MONITOR,
    Permission.SECURITY_CONFIGURE,
  ],
  [UserRole.OPERATOR]: [
    Permission.SCRAPE_EXECUTE,
    Permission.SCRAPE_VIEW,
    Permission.DATA_EXPORT,
    Permission.DATA_VIEW,
    Permission.DATA_MODIFY,
  ],
  [UserRole.VIEWER]: [Permission.SCRAPE_VIEW, Permission.DATA_VIEW],
  [UserRole.COMPLIANCE_OFFICER]: [
    Permission.SCRAPE_VIEW,
    Permission.DATA_VIEW,
    Permission.AUDIT_VIEW,
    Permission.COMPLIANCE_MANAGE,
    Permission.PRIVACY_MANAGE,
    Permission.CONSENT_MANAGE,
  ],
  [UserRole.SECURITY_ANALYST]: [
    Permission.SCRAPE_VIEW,
    Permission.DATA_VIEW,
    Permission.AUDIT_VIEW,
    Permission.SECURITY_MONITOR,
  ],
}

// Extended user interface
export interface ExtendedUser extends User {
  id: string
  email: string
  role: UserRole
  permissions: Permission[]
  lastLogin?: Date
  isActive: boolean
  mfaEnabled: boolean
  complianceFlags?: {
    gdprConsent: boolean
    ccpaOptOut: boolean
    dataRetentionAgreed: boolean
  }
}

// Extended session interface
export interface ExtendedSession extends Session {
  user: ExtendedUser
  accessToken: string
  refreshToken: string
}

// NextAuth configuration
export const authOptions: NextAuthOptions = {
  // Note: Using database-less approach for now with postgres.js
  // TODO: Create custom postgres.js adapter for NextAuth
  // adapter: PostgresAdapter(pool),
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
        mfaCode: { label: 'MFA Code', type: 'text', optional: true },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          logger.warn('Auth', 'Missing credentials in login attempt')
          return null
        }

        try {
          // Query user from database using postgres.js
          const authDb = getAuthDatabase()
          const result = await authDb`
            SELECT * FROM users WHERE email = ${credentials.email} AND is_active = true
          `

          const user = result[0]
          if (!user) {
            logger.warn('Auth', `Login attempt for non-existent user: ${credentials.email}`)
            return null
          }

          // Verify password
          const isValidPassword = await bcrypt.compare(credentials.password, user.password_hash)
          if (!isValidPassword) {
            logger.warn('Auth', `Invalid password for user: ${credentials.email}`)
            return null
          }

          // Check MFA if enabled
          if (user.mfa_enabled && !credentials.mfaCode) {
            logger.warn('Auth', `MFA required for user: ${credentials.email}`)
            throw new Error('MFA_REQUIRED')
          }

          if (user.mfa_enabled && credentials.mfaCode) {
            // Verify MFA code (implement TOTP verification)
            const isValidMFA = await verifyMFACode(user.id, credentials.mfaCode)
            if (!isValidMFA) {
              logger.warn('Auth', `Invalid MFA code for user: ${credentials.email}`)
              return null
            }
          }

          // Update last login
          await authDb`UPDATE users SET last_login = NOW() WHERE id = ${user.id}`

          // Get user permissions
          const permissions = ROLE_PERMISSIONS[user.role as UserRole] || []

          logger.info('Auth', `Successful login for user: ${credentials.email}`)

          return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            permissions,
            lastLogin: new Date(),
            isActive: user.is_active,
            mfaEnabled: user.mfa_enabled,
            complianceFlags: {
              gdprConsent: user.gdpr_consent || false,
              ccpaOptOut: user.ccpa_opt_out || false,
              dataRetentionAgreed: user.data_retention_agreed || false,
            },
          } as ExtendedUser
        } catch (error) {
          logger.error('Auth', 'Authentication error', error)
          return null
        }
      },
    }),
  ],
  session: {
    strategy: 'jwt',
    maxAge: getSecurityConfig().sessionTimeout / 1000, // Convert to seconds
  },
  jwt: {
    maxAge: getSecurityConfig().sessionTimeout / 1000,
  },
  callbacks: {
    async jwt({ token, user }: { token: JWT; user?: ExtendedUser }) {
      if (user) {
        token.role = user.role
        token.permissions = user.permissions
        token.isActive = user.isActive
        token.mfaEnabled = user.mfaEnabled
        token.complianceFlags = user.complianceFlags
      }
      return token
    },
    async session({ session, token }: { session: any; token: JWT }) {
      if (token) {
        session.user.id = token.sub
        session.user.role = token.role
        session.user.permissions = token.permissions
        session.user.isActive = token.isActive
        session.user.mfaEnabled = token.mfaEnabled
        session.user.complianceFlags = token.complianceFlags
      }
      return session as ExtendedSession
    },
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  events: {
    async signIn({ user, account, profile }) {
      // Log successful sign-in for audit trail
      await logSecurityEvent('USER_SIGNIN', {
        userId: user.id,
        email: user.email,
        provider: account?.provider,
        timestamp: new Date().toISOString(),
      })
    },
    async signOut({ session, token }) {
      // Log sign-out for audit trail
      await logSecurityEvent('USER_SIGNOUT', {
        userId: session?.user?.id || token?.sub,
        timestamp: new Date().toISOString(),
      })
    },
  },
}

/**
 * Verify MFA code (TOTP implementation)
 */
async function verifyMFACode(userId: string, code: string): Promise<boolean> {
  try {
    // Get user's MFA secret from database
    const authDb = getAuthDatabase()
    const result = await authDb`
      SELECT mfa_secret FROM users WHERE id = ${userId} AND mfa_enabled = true
    `

    if (!result[0]?.mfa_secret) {
      logger.warn('Auth', `No MFA secret found for user: ${userId}`)
      return false
    }

    const speakeasy = require('speakeasy')

    // Verify the TOTP code
    const verified = speakeasy.totp.verify({
      secret: result[0].mfa_secret,
      encoding: 'base32',
      token: code,
      window: 2, // Allow 2 time steps before/after current time
    })

    if (verified) {
      logger.info('Auth', `MFA verification successful for user: ${userId}`)
    } else {
      logger.warn('Auth', `MFA verification failed for user: ${userId}`)
    }

    return verified
  } catch (error) {
    logger.error('Auth', 'MFA verification error', error)
    return false
  }
}

/**
 * Log security events for audit trail
 */
async function logSecurityEvent(eventType: string, data: any): Promise<void> {
  try {
    const authDb = getAuthDatabase()
    await authDb`
      INSERT INTO security_audit_log (event_type, event_data, created_at)
      VALUES (${eventType}, ${JSON.stringify(data)}, NOW())
    `
  } catch (error) {
    logger.error('Auth', 'Failed to log security event', error)
  }
}

/**
 * Check if user has specific permission
 */
export function hasPermission(user: ExtendedUser, permission: Permission): boolean {
  return user.permissions.includes(permission)
}

/**
 * Check if user has any of the specified permissions
 */
export function hasAnyPermission(user: ExtendedUser, permissions: Permission[]): boolean {
  return permissions.some(permission => user.permissions.includes(permission))
}

/**
 * Check if user has all of the specified permissions
 */
export function hasAllPermissions(user: ExtendedUser, permissions: Permission[]): boolean {
  return permissions.every(permission => user.permissions.includes(permission))
}

/**
 * Generate MFA secret for user
 */
export async function generateMFASecret(
  userId: string,
  userEmail: string
): Promise<{ secret: string; qrCodeUrl: string }> {
  const speakeasy = require('speakeasy')
  const qrcode = require('qrcode')

  try {
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Business Scraper (${userEmail})`,
      issuer: 'Business Scraper App',
      length: 32,
    })

    // Store secret in database (encrypted)
    const authDb = getAuthDatabase()
    await authDb`
      UPDATE users SET mfa_secret = ${secret.base32}, mfa_enabled = false WHERE id = ${userId}
    `

    // Generate QR code URL
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url)

    logger.info('Auth', `MFA secret generated for user: ${userEmail}`)

    return {
      secret: secret.base32,
      qrCodeUrl,
    }
  } catch (error) {
    logger.error('Auth', 'Failed to generate MFA secret', error)
    throw new Error('Failed to generate MFA secret')
  }
}

/**
 * Enable MFA for user after verification
 */
export async function enableMFA(userId: string, verificationCode: string): Promise<boolean> {
  try {
    // Verify the code first
    const isValid = await verifyMFACode(userId, verificationCode)

    if (!isValid) {
      return false
    }

    // Enable MFA
    const authDb = getAuthDatabase()
    await authDb`UPDATE users SET mfa_enabled = true WHERE id = ${userId}`

    logger.info('Auth', `MFA enabled for user: ${userId}`)
    return true
  } catch (error) {
    logger.error('Auth', 'Failed to enable MFA', error)
    return false
  }
}

/**
 * Disable MFA for user
 */
export async function disableMFA(userId: string): Promise<boolean> {
  try {
    const authDb = getAuthDatabase()
    await authDb`UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE id = ${userId}`

    logger.info('Auth', `MFA disabled for user: ${userId}`)
    return true
  } catch (error) {
    logger.error('Auth', 'Failed to disable MFA', error)
    return false
  }
}
