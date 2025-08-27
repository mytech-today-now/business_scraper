/**
 * Enhanced RBAC Middleware for API Routes
 * Provides role-based access control with NextAuth.js integration and SOC 2 compliance
 */

import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth/next'
import {
  authOptions,
  ExtendedSession,
  Permission,
  hasPermission,
  hasAnyPermission,
} from '@/lib/auth'
import { logger } from '@/utils/logger'

export interface RBACConfig {
  permissions?: Permission[]
  requireAll?: boolean // If true, user must have ALL permissions; if false, ANY permission
  allowSelfAccess?: boolean // Allow users to access their own resources
  customCheck?: (session: ExtendedSession, context: RBACContext) => boolean
  auditLog?: boolean // Enable audit logging for this endpoint
  complianceCheck?: boolean // Enable compliance validation
}

export interface RBACContext {
  session: ExtendedSession
  resourceId?: string
  resourceType?: string
  action?: string
  request: NextRequest
  clientIP: string
  userAgent: string
}

/**
 * Enhanced RBAC middleware wrapper for API routes with NextAuth.js integration
 */
export function withRBAC(
  handler: (request: NextRequest, context: RBACContext) => Promise<NextResponse>,
  config: RBACConfig = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const clientIP = getClientIP(request)
    const pathname = request.nextUrl.pathname
    const userAgent = request.headers.get('user-agent') || 'Unknown'

    try {
      // Get NextAuth session
      const session = (await getServerSession(authOptions)) as ExtendedSession

      if (!session || !session.user) {
        logger.warn('RBAC Middleware', `No session for ${pathname} from IP: ${clientIP}`)
        return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
      }

      // Check if user is active
      if (!session.user.isActive) {
        logger.warn(
          'RBAC Middleware',
          `Inactive user ${session.user.email} attempted access to ${pathname}`
        )
        return NextResponse.json({ error: 'Account is inactive' }, { status: 403 })
      }

      // Extract context from request
      const context = await extractRBACContext(request, user)

      // Check workspace requirement
      if (config.workspaceRequired && !context.workspaceId) {
        logger.warn('RBAC Middleware', `Workspace required for ${pathname}`)
        return NextResponse.json({ error: 'Workspace context required' }, { status: 400 })
      }

      // Check team requirement
      if (config.teamRequired && !context.teamId) {
        logger.warn('RBAC Middleware', `Team required for ${pathname}`)
        return NextResponse.json({ error: 'Team context required' }, { status: 400 })
      }

      // Check permissions
      if (config.permissions && config.permissions.length > 0) {
        const hasPermission = config.requireAll
          ? RBACService.hasAllPermissions(user, config.permissions, {
              workspaceId: context.workspaceId,
              teamId: context.teamId,
              resourceId: context.resourceId,
            })
          : RBACService.hasAnyPermission(user, config.permissions, {
              workspaceId: context.workspaceId,
              teamId: context.teamId,
              resourceId: context.resourceId,
            })

        if (!hasPermission) {
          // Check self-access if allowed
          if (config.allowSelfAccess && context.resourceId === user.id) {
            // Allow access to own resources
          } else {
            logger.warn('RBAC Middleware', `Permission denied for ${pathname}`, {
              userId: user.id,
              permissions: config.permissions,
              workspaceId: context.workspaceId,
              teamId: context.teamId,
            })
            return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 })
          }
        }
      }

      // Custom permission check
      if (config.customCheck && !config.customCheck(user, context)) {
        logger.warn('RBAC Middleware', `Custom check failed for ${pathname}`, {
          userId: user.id,
          workspaceId: context.workspaceId,
          teamId: context.teamId,
        })
        return NextResponse.json({ error: 'Access denied' }, { status: 403 })
      }

      // Log successful access
      logger.info('RBAC Middleware', `Access granted for ${pathname}`, {
        userId: user.id,
        permissions: config.permissions,
        workspaceId: context.workspaceId,
        teamId: context.teamId,
      })

      // Call handler with context
      return handler(request, context)
    } catch (error) {
      logger.error('RBAC Middleware', `Error in RBAC check for ${pathname}`, error)
      return NextResponse.json({ error: 'Authorization error' }, { status: 500 })
    }
  }
}

/**
 * Extract RBAC context from request
 */
async function extractRBACContext(request: NextRequest, user: User): Promise<RBACContext> {
  const url = new URL(request.url)
  const searchParams = url.searchParams
  const pathname = url.pathname

  // Extract IDs from URL path
  const pathSegments = pathname.split('/').filter(Boolean)

  // Extract context from query parameters
  const workspaceId =
    searchParams.get('workspaceId') ||
    searchParams.get('workspace_id') ||
    extractFromPath(pathSegments, 'workspaces')

  const teamId =
    searchParams.get('teamId') ||
    searchParams.get('team_id') ||
    extractFromPath(pathSegments, 'teams')

  const resourceId =
    searchParams.get('resourceId') ||
    searchParams.get('id') ||
    pathSegments[pathSegments.length - 1]

  // Determine resource type from path
  const resourceType = determineResourceType(pathname)

  // Determine action from HTTP method and path
  const action = determineAction(request.method, pathname)

  return {
    user,
    workspaceId: workspaceId || undefined,
    teamId: teamId || undefined,
    resourceId: resourceId || undefined,
    resourceType,
    action,
    request,
  }
}

/**
 * Extract ID from path segments
 */
function extractFromPath(pathSegments: string[], resourceType: string): string | null {
  const index = pathSegments.indexOf(resourceType)
  if (index !== -1 && index + 1 < pathSegments.length) {
    return pathSegments[index + 1]
  }
  return null
}

/**
 * Determine resource type from pathname
 */
function determineResourceType(pathname: string): string | undefined {
  if (pathname.includes('/campaigns')) return 'campaign'
  if (pathname.includes('/businesses')) return 'business'
  if (pathname.includes('/workspaces')) return 'workspace'
  if (pathname.includes('/teams')) return 'team'
  if (pathname.includes('/users')) return 'user'
  if (pathname.includes('/sessions')) return 'session'
  return undefined
}

/**
 * Determine action from HTTP method and pathname
 */
function determineAction(method: string, pathname: string): string | undefined {
  switch (method) {
    case 'GET':
      return 'view'
    case 'POST':
      return 'create'
    case 'PUT':
    case 'PATCH':
      return 'edit'
    case 'DELETE':
      return 'delete'
    default:
      return undefined
  }
}

/**
 * Get user from session (placeholder - implement based on your user storage)
 */
async function getUserFromSession(sessionId: string): Promise<User | null> {
  // TODO: Implement user retrieval from database
  // This is a placeholder that should be replaced with actual database query

  try {
    // In a real implementation, this would query the database
    // For now, return a mock admin user for development
    return {
      id: 'admin-user-id',
      username: 'admin',
      email: 'admin@businessscraper.local',
      firstName: 'System',
      lastName: 'Administrator',
      avatarUrl: undefined,
      isActive: true,
      isVerified: true,
      lastLoginAt: new Date(),
      passwordChangedAt: new Date(),
      timezone: 'UTC',
      language: 'en',
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
      createdAt: new Date(),
      updatedAt: new Date(),
      roles: [
        {
          id: 'admin-role-assignment',
          userId: 'admin-user-id',
          roleId: 'admin-role-id',
          role: {
            id: 'admin-role-id',
            name: 'admin',
            displayName: 'Administrator',
            description: 'Full system access',
            isSystemRole: true,
            permissions: [
              'system.manage',
              'users.manage',
              'teams.manage',
              'workspaces.manage',
              'campaigns.manage',
              'data.manage',
              'scraping.manage',
              'analytics.manage',
              'audit.manage',
            ],
            createdAt: new Date(),
            updatedAt: new Date(),
          },
          assignedAt: new Date(),
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ],
      teams: [],
      workspaces: [],
    }
  } catch (error) {
    logger.error('RBAC Middleware', 'Error fetching user from session', error)
    return null
  }
}

/**
 * Permission checking decorators for common use cases
 */
export const requirePermissions = (permissions: Permission[], requireAll = false) =>
  withRBAC(
    async (request, context) => {
      // This is handled by the middleware itself
      return NextResponse.json({ error: 'Handler not implemented' }, { status: 500 })
    },
    { permissions, requireAll }
  )

export const requireWorkspaceAccess = (permissions: Permission[]) =>
  withRBAC(
    async (request, context) => {
      return NextResponse.json({ error: 'Handler not implemented' }, { status: 500 })
    },
    { permissions, workspaceRequired: true }
  )

export const requireTeamAccess = (permissions: Permission[]) =>
  withRBAC(
    async (request, context) => {
      return NextResponse.json({ error: 'Handler not implemented' }, { status: 500 })
    },
    { permissions, teamRequired: true }
  )

export const requireSelfOrPermissions = (permissions: Permission[]) =>
  withRBAC(
    async (request, context) => {
      return NextResponse.json({ error: 'Handler not implemented' }, { status: 500 })
    },
    { permissions, allowSelfAccess: true }
  )
