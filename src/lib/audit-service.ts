/**
 * Audit Service
 * Comprehensive audit logging system for all user actions, scraping jobs, and data modifications
 */

import { AuditLog, AuditAction, AuditSeverity, User } from '@/types/multi-user'
import { database } from './postgresql-database'
import { logger } from '@/utils/logger'
import { getClientIP } from './security'
import { NextRequest } from 'next/server'

export interface AuditContext {
  userId?: string
  workspaceId?: string
  teamId?: string
  ipAddress?: string
  userAgent?: string
  sessionId?: string
  correlationId?: string
}

export interface AuditLogEntry {
  action: AuditAction
  resourceType: string
  resourceId?: string
  details: Record<string, any>
  severity?: AuditSeverity
  context?: AuditContext
}

export class AuditService {
  /**
   * Log an audit event
   */
  static async log(entry: AuditLogEntry): Promise<void> {
    try {
      const auditLog: Partial<AuditLog> = {
        id: this.generateId(),
        userId: entry.context?.userId,
        action: entry.action,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        workspaceId: entry.context?.workspaceId,
        teamId: entry.context?.teamId,
        details: entry.details,
        ipAddress: entry.context?.ipAddress,
        userAgent: entry.context?.userAgent,
        timestamp: new Date(),
        sessionId: entry.context?.sessionId,
        correlationId: entry.context?.correlationId,
        severity: entry.severity || 'info',
      }

      // Insert into database
      await database.query(
        `
        INSERT INTO audit_logs (
          id, user_id, action, resource_type, resource_id, workspace_id, team_id,
          details, ip_address, user_agent, timestamp, session_id, correlation_id, severity
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      `,
        [
          auditLog.id,
          auditLog.userId,
          auditLog.action,
          auditLog.resourceType,
          auditLog.resourceId,
          auditLog.workspaceId,
          auditLog.teamId,
          JSON.stringify(auditLog.details),
          auditLog.ipAddress,
          auditLog.userAgent,
          auditLog.timestamp,
          auditLog.sessionId,
          auditLog.correlationId,
          auditLog.severity,
        ]
      )

      // Log to application logger for immediate visibility
      logger.info('Audit', `${entry.action} - ${entry.resourceType}`, {
        userId: entry.context?.userId,
        resourceId: entry.resourceId,
        workspaceId: entry.context?.workspaceId,
        details: entry.details,
      })
    } catch (error) {
      logger.error('Audit Service', 'Error logging audit event', { entry, error })
      // Don't throw error to avoid breaking the main operation
    }
  }

  /**
   * Log user authentication events
   */
  static async logAuth(
    action: 'user.login' | 'user.logout' | 'user.login_failed',
    userId?: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'user',
      resourceId: userId,
      details: {
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action === 'user.login_failed' ? 'warn' : 'info',
      context,
    })
  }

  /**
   * Log user management events
   */
  static async logUserManagement(
    action: 'user.created' | 'user.updated' | 'user.deleted',
    targetUserId: string,
    performedBy?: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'user',
      resourceId: targetUserId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action === 'user.deleted' ? 'warn' : 'info',
      context: {
        ...context,
        userId: performedBy,
      },
    })
  }

  /**
   * Log team management events
   */
  static async logTeamManagement(
    action:
      | 'team.created'
      | 'team.updated'
      | 'team.deleted'
      | 'team.member.added'
      | 'team.member.removed',
    teamId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'team',
      resourceId: teamId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action.includes('deleted') || action.includes('removed') ? 'warn' : 'info',
      context: {
        ...context,
        userId: performedBy,
        teamId,
      },
    })
  }

  /**
   * Log workspace management events
   */
  static async logWorkspaceManagement(
    action:
      | 'workspace.created'
      | 'workspace.updated'
      | 'workspace.deleted'
      | 'workspace.member.added'
      | 'workspace.member.removed',
    workspaceId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action.includes('deleted') || action.includes('removed') ? 'warn' : 'info',
      context: {
        ...context,
        userId: performedBy,
        workspaceId,
      },
    })
  }

  /**
   * Log campaign management events
   */
  static async logCampaignManagement(
    action:
      | 'campaign.created'
      | 'campaign.updated'
      | 'campaign.deleted'
      | 'campaign.started'
      | 'campaign.completed',
    campaignId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'campaign',
      resourceId: campaignId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action === 'campaign.deleted' ? 'warn' : 'info',
      context: {
        ...context,
        userId: performedBy,
      },
    })
  }

  /**
   * Log scraping events
   */
  static async logScraping(
    action: 'scraping.started' | 'scraping.completed' | 'scraping.failed',
    sessionId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'scraping_session',
      resourceId: sessionId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action === 'scraping.failed' ? 'error' : 'info',
      context: {
        ...context,
        userId: performedBy,
      },
    })
  }

  /**
   * Log data management events
   */
  static async logDataManagement(
    action: 'data.validated' | 'data.enriched' | 'data.exported',
    resourceId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'business_data',
      resourceId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: 'info',
      context: {
        ...context,
        userId: performedBy,
      },
    })
  }

  /**
   * Log role and permission events
   */
  static async logRolePermission(
    action: 'role.assigned' | 'role.revoked' | 'permission.granted' | 'permission.revoked',
    targetUserId: string,
    performedBy: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action,
      resourceType: 'user_role',
      resourceId: targetUserId,
      details: {
        performedBy,
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: action.includes('revoked') ? 'warn' : 'info',
      context: {
        ...context,
        userId: performedBy,
      },
    })
  }

  /**
   * Log security events
   */
  static async logSecurity(
    action: string,
    resourceType: string,
    resourceId?: string,
    context?: AuditContext,
    details?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action: action as AuditAction,
      resourceType,
      resourceId,
      details: {
        timestamp: new Date().toISOString(),
        ...details,
      },
      severity: 'warn',
      context,
    })
  }

  /**
   * Get audit logs with filtering and pagination
   */
  static async getAuditLogs(filters: {
    userId?: string
    workspaceId?: string
    teamId?: string
    action?: AuditAction
    resourceType?: string
    resourceId?: string
    severity?: AuditSeverity
    startDate?: Date
    endDate?: Date
    page?: number
    limit?: number
  }): Promise<{
    logs: AuditLog[]
    total: number
    page: number
    totalPages: number
  }> {
    try {
      const conditions: string[] = ['1=1']
      const values: any[] = []
      let paramIndex = 1

      // Build WHERE conditions
      if (filters.userId) {
        conditions.push(`al.user_id = $${paramIndex++}`)
        values.push(filters.userId)
      }

      if (filters.workspaceId) {
        conditions.push(`al.workspace_id = $${paramIndex++}`)
        values.push(filters.workspaceId)
      }

      if (filters.teamId) {
        conditions.push(`al.team_id = $${paramIndex++}`)
        values.push(filters.teamId)
      }

      if (filters.action) {
        conditions.push(`al.action = $${paramIndex++}`)
        values.push(filters.action)
      }

      if (filters.resourceType) {
        conditions.push(`al.resource_type = $${paramIndex++}`)
        values.push(filters.resourceType)
      }

      if (filters.resourceId) {
        conditions.push(`al.resource_id = $${paramIndex++}`)
        values.push(filters.resourceId)
      }

      if (filters.severity) {
        conditions.push(`al.severity = $${paramIndex++}`)
        values.push(filters.severity)
      }

      if (filters.startDate) {
        conditions.push(`al.timestamp >= $${paramIndex++}`)
        values.push(filters.startDate)
      }

      if (filters.endDate) {
        conditions.push(`al.timestamp <= $${paramIndex++}`)
        values.push(filters.endDate)
      }

      // Pagination
      const page = filters.page || 1
      const limit = filters.limit || 50
      const offset = (page - 1) * limit

      // Count total records
      const countQuery = `
        SELECT COUNT(*) as total
        FROM audit_logs al
        WHERE ${conditions.join(' AND ')}
      `
      const countResult = await database.query(countQuery, values)
      const total = parseInt(countResult.rows[0].total)

      // Get paginated results
      values.push(limit, offset)
      const logsQuery = `
        SELECT 
          al.*,
          u.username,
          u.first_name,
          u.last_name,
          w.name as workspace_name,
          t.name as team_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN workspaces w ON al.workspace_id = w.id
        LEFT JOIN teams t ON al.team_id = t.id
        WHERE ${conditions.join(' AND ')}
        ORDER BY al.timestamp DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex}
      `

      const logsResult = await database.query(logsQuery, values)

      const logs: AuditLog[] = logsResult.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        user: row.user_id
          ? ({
              id: row.user_id,
              username: row.username,
              firstName: row.first_name,
              lastName: row.last_name,
            } as any)
          : undefined,
        action: row.action,
        resourceType: row.resource_type,
        resourceId: row.resource_id,
        workspaceId: row.workspace_id,
        workspace: row.workspace_name
          ? ({
              id: row.workspace_id,
              name: row.workspace_name,
            } as any)
          : undefined,
        teamId: row.team_id,
        team: row.team_name
          ? ({
              id: row.team_id,
              name: row.team_name,
            } as any)
          : undefined,
        details: row.details,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        timestamp: row.timestamp,
        sessionId: row.session_id,
        correlationId: row.correlation_id,
        severity: row.severity,
        createdAt: row.timestamp,
        updatedAt: row.timestamp,
      }))

      return {
        logs,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      }
    } catch (error) {
      logger.error('Audit Service', 'Error retrieving audit logs', error)
      throw error
    }
  }

  /**
   * Get audit statistics
   */
  static async getAuditStats(filters: {
    userId?: string
    workspaceId?: string
    teamId?: string
    startDate?: Date
    endDate?: Date
  }): Promise<{
    totalEvents: number
    eventsByAction: Record<string, number>
    eventsBySeverity: Record<string, number>
    eventsByResourceType: Record<string, number>
    topUsers: Array<{ userId: string; username: string; count: number }>
  }> {
    try {
      const conditions: string[] = ['1=1']
      const values: any[] = []
      let paramIndex = 1

      // Build WHERE conditions
      if (filters.userId) {
        conditions.push(`al.user_id = $${paramIndex++}`)
        values.push(filters.userId)
      }

      if (filters.workspaceId) {
        conditions.push(`al.workspace_id = $${paramIndex++}`)
        values.push(filters.workspaceId)
      }

      if (filters.teamId) {
        conditions.push(`al.team_id = $${paramIndex++}`)
        values.push(filters.teamId)
      }

      if (filters.startDate) {
        conditions.push(`al.timestamp >= $${paramIndex++}`)
        values.push(filters.startDate)
      }

      if (filters.endDate) {
        conditions.push(`al.timestamp <= $${paramIndex++}`)
        values.push(filters.endDate)
      }

      const whereClause = `WHERE ${conditions.join(' AND ')}`

      // Get total events
      const totalResult = await database.query(
        `
        SELECT COUNT(*) as total FROM audit_logs al ${whereClause}
      `,
        values
      )
      const totalEvents = parseInt(totalResult.rows[0].total)

      // Get events by action
      const actionResult = await database.query(
        `
        SELECT action, COUNT(*) as count 
        FROM audit_logs al ${whereClause}
        GROUP BY action 
        ORDER BY count DESC
      `,
        values
      )
      const eventsByAction = actionResult.rows.reduce((acc, row) => {
        acc[row.action] = parseInt(row.count)
        return acc
      }, {})

      // Get events by severity
      const severityResult = await database.query(
        `
        SELECT severity, COUNT(*) as count 
        FROM audit_logs al ${whereClause}
        GROUP BY severity 
        ORDER BY count DESC
      `,
        values
      )
      const eventsBySeverity = severityResult.rows.reduce((acc, row) => {
        acc[row.severity] = parseInt(row.count)
        return acc
      }, {})

      // Get events by resource type
      const resourceResult = await database.query(
        `
        SELECT resource_type, COUNT(*) as count 
        FROM audit_logs al ${whereClause}
        GROUP BY resource_type 
        ORDER BY count DESC
      `,
        values
      )
      const eventsByResourceType = resourceResult.rows.reduce((acc, row) => {
        acc[row.resource_type] = parseInt(row.count)
        return acc
      }, {})

      // Get top users
      const usersResult = await database.query(
        `
        SELECT 
          al.user_id, 
          u.username, 
          COUNT(*) as count 
        FROM audit_logs al 
        LEFT JOIN users u ON al.user_id = u.id
        ${whereClause}
        AND al.user_id IS NOT NULL
        GROUP BY al.user_id, u.username 
        ORDER BY count DESC 
        LIMIT 10
      `,
        values
      )
      const topUsers = usersResult.rows.map(row => ({
        userId: row.user_id,
        username: row.username || 'Unknown',
        count: parseInt(row.count),
      }))

      return {
        totalEvents,
        eventsByAction,
        eventsBySeverity,
        eventsByResourceType,
        topUsers,
      }
    } catch (error) {
      logger.error('Audit Service', 'Error retrieving audit statistics', error)
      throw error
    }
  }

  /**
   * Extract audit context from request
   */
  static extractContextFromRequest(
    request: NextRequest,
    userId?: string,
    sessionId?: string
  ): AuditContext {
    return {
      userId,
      ipAddress: getClientIP(request),
      userAgent: request.headers.get('user-agent') || undefined,
      sessionId,
      correlationId: request.headers.get('x-correlation-id') || this.generateId(),
    }
  }

  /**
   * Generate unique ID
   */
  private static generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
}

/**
 * Audit middleware for automatic logging
 */
export function withAuditLogging(
  action: AuditAction,
  resourceType: string,
  getResourceId?: (request: NextRequest) => string | undefined
) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value

    descriptor.value = async function (request: NextRequest, context?: any) {
      const startTime = Date.now()
      let error: Error | undefined

      try {
        const result = await originalMethod.call(this, request, context)

        // Log successful operation
        await AuditService.log({
          action,
          resourceType,
          resourceId: getResourceId ? getResourceId(request) : undefined,
          details: {
            duration: Date.now() - startTime,
            success: true,
            method: request.method,
            url: request.url,
          },
          severity: 'info',
          context: context
            ? AuditService.extractContextFromRequest(request, context.user?.id, context.sessionId)
            : undefined,
        })

        return result
      } catch (err) {
        error = err as Error

        // Log failed operation
        await AuditService.log({
          action,
          resourceType,
          resourceId: getResourceId ? getResourceId(request) : undefined,
          details: {
            duration: Date.now() - startTime,
            success: false,
            error: error.message,
            method: request.method,
            url: request.url,
          },
          severity: 'error',
          context: context
            ? AuditService.extractContextFromRequest(request, context.user?.id, context.sessionId)
            : undefined,
        })

        throw error
      }
    }

    return descriptor
  }
}
