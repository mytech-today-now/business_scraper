/**
 * Audit Logs API Endpoint
 * Provides access to audit logs with filtering, pagination, and statistics
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { AuditService } from '@/lib/audit-service'
import { AuditAction, AuditSeverity } from '@/types/multi-user'
import { logger } from '@/utils/logger'

/**
 * GET /api/audit - Get audit logs with filtering and pagination
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)

      // Extract filter parameters
      const filters = {
        userId: searchParams.get('userId') || undefined,
        workspaceId: searchParams.get('workspaceId') || context.workspaceId,
        teamId: searchParams.get('teamId') || context.teamId,
        action: (searchParams.get('action') as AuditAction) || undefined,
        resourceType: searchParams.get('resourceType') || undefined,
        resourceId: searchParams.get('resourceId') || undefined,
        severity: (searchParams.get('severity') as AuditSeverity) || undefined,
        startDate: searchParams.get('startDate')
          ? new Date(searchParams.get('startDate')!)
          : undefined,
        endDate: searchParams.get('endDate') ? new Date(searchParams.get('endDate')!) : undefined,
        page: parseInt(searchParams.get('page') || '1'),
        limit: Math.min(parseInt(searchParams.get('limit') || '50'), 100), // Max 100 per page
      }

      // Validate date range
      if (filters.startDate && filters.endDate && filters.startDate > filters.endDate) {
        return NextResponse.json({ error: 'Start date must be before end date' }, { status: 400 })
      }

      // Get audit logs
      const result = await AuditService.getAuditLogs(filters)

      // Log audit access
      await AuditService.log({
        action: 'audit.view',
        resourceType: 'audit_logs',
        details: {
          filters,
          resultCount: result.logs.length,
          totalCount: result.total,
        },
        context: AuditService.extractContextFromRequest(
          request,
          context.user.id,
          context.sessionId
        ),
      })

      logger.info('Audit API', 'Audit logs retrieved', {
        userId: context.user.id,
        filters,
        resultCount: result.logs.length,
        totalCount: result.total,
      })

      return NextResponse.json({
        success: true,
        data: result.logs,
        pagination: {
          page: result.page,
          limit: filters.limit,
          total: result.total,
          totalPages: result.totalPages,
          hasNext: result.page < result.totalPages,
          hasPrev: result.page > 1,
        },
        filters,
      })
    } catch (error) {
      logger.error('Audit API', 'Error retrieving audit logs', error)
      return NextResponse.json({ error: 'Failed to retrieve audit logs' }, { status: 500 })
    }
  },
  { permissions: ['audit.view'] }
)

/**
 * POST /api/audit - Create audit log entry (for manual logging)
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { action, resourceType, resourceId, details, severity } = body

      // Validate required fields
      if (!action || !resourceType) {
        return NextResponse.json(
          { error: 'Action and resource type are required' },
          { status: 400 }
        )
      }

      // Validate action format
      if (typeof action !== 'string' || !action.includes('.')) {
        return NextResponse.json(
          { error: 'Action must be in format "category.action"' },
          { status: 400 }
        )
      }

      // Validate severity
      const validSeverities = ['debug', 'info', 'warn', 'error', 'critical']
      if (severity && !validSeverities.includes(severity)) {
        return NextResponse.json(
          { error: `Severity must be one of: ${validSeverities.join(', ')}` },
          { status: 400 }
        )
      }

      // Create audit log entry
      await AuditService.log({
        action: action as AuditAction,
        resourceType,
        resourceId,
        details: {
          manualEntry: true,
          createdBy: context.user.id,
          ...details,
        },
        severity: severity || 'info',
        context: {
          ...AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
          workspaceId: context.workspaceId,
          teamId: context.teamId,
        },
      })

      logger.info('Audit API', 'Manual audit log created', {
        action,
        resourceType,
        resourceId,
        createdBy: context.user.id,
      })

      return NextResponse.json(
        {
          success: true,
          message: 'Audit log entry created successfully',
        },
        { status: 201 }
      )
    } catch (error) {
      logger.error('Audit API', 'Error creating audit log', error)
      return NextResponse.json({ error: 'Failed to create audit log entry' }, { status: 500 })
    }
  },
  { permissions: ['audit.manage'] }
)

/**
 * DELETE /api/audit - Bulk delete audit logs (admin only)
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { logIds, olderThan, severity } = body

      let deletedCount = 0

      if (logIds && Array.isArray(logIds)) {
        // Delete specific log entries
        const result = await context.database.query(
          `
          DELETE FROM audit_logs 
          WHERE id = ANY($1)
          RETURNING id
        `,
          [logIds]
        )

        deletedCount = result.rows.length

        // Log the deletion
        await AuditService.log({
          action: 'audit.deleted',
          resourceType: 'audit_logs',
          details: {
            deletedIds: result.rows.map(row => row.id),
            deletedCount,
            deletedBy: context.user.id,
          },
          severity: 'warn',
          context: AuditService.extractContextFromRequest(
            request,
            context.user.id,
            context.sessionId
          ),
        })
      } else if (olderThan) {
        // Delete logs older than specified date
        const cutoffDate = new Date(olderThan)
        if (isNaN(cutoffDate.getTime())) {
          return NextResponse.json(
            { error: 'Invalid date format for olderThan parameter' },
            { status: 400 }
          )
        }

        let query = 'DELETE FROM audit_logs WHERE timestamp < $1'
        const values = [cutoffDate]

        // Optional severity filter
        if (severity) {
          query += ' AND severity = $2'
          values.push(severity)
        }

        query += ' RETURNING id'

        const result = await context.database.query(query, values)
        deletedCount = result.rows.length

        // Log the bulk deletion
        await AuditService.log({
          action: 'audit.bulk_deleted',
          resourceType: 'audit_logs',
          details: {
            cutoffDate: cutoffDate.toISOString(),
            severity,
            deletedCount,
            deletedBy: context.user.id,
          },
          severity: 'warn',
          context: AuditService.extractContextFromRequest(
            request,
            context.user.id,
            context.sessionId
          ),
        })
      } else {
        return NextResponse.json(
          { error: 'Either logIds array or olderThan date must be provided' },
          { status: 400 }
        )
      }

      logger.info('Audit API', 'Audit logs deleted', {
        deletedCount,
        deletedBy: context.user.id,
        logIds: logIds?.length || 0,
        olderThan,
        severity,
      })

      return NextResponse.json({
        success: true,
        data: {
          deletedCount,
        },
        message: `Successfully deleted ${deletedCount} audit log entries`,
      })
    } catch (error) {
      logger.error('Audit API', 'Error deleting audit logs', error)
      return NextResponse.json({ error: 'Failed to delete audit logs' }, { status: 500 })
    }
  },
  { permissions: ['audit.manage'] }
)
