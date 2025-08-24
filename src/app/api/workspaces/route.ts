/**
 * Workspaces API Endpoint
 * Handles workspace management operations (CRUD, membership management)
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { WorkspaceManagementService } from '@/lib/workspace-management'
import { CreateWorkspaceRequest, UpdateWorkspaceRequest } from '@/types/multi-user'
import { logger } from '@/utils/logger'

/**
 * GET /api/workspaces - List workspaces with pagination and filtering
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const page = parseInt(searchParams.get('page') || '1')
      const limit = parseInt(searchParams.get('limit') || '20')
      const search = searchParams.get('search') || ''
      const teamId = searchParams.get('teamId') || ''
      const ownedOnly = searchParams.get('ownedOnly') === 'true'
      const memberOnly = searchParams.get('memberOnly') === 'true'

      // Build query conditions
      const conditions: string[] = ['w.is_active = true']
      const values: any[] = []
      let paramIndex = 1

      if (search) {
        conditions.push(`(w.name ILIKE $${paramIndex} OR w.description ILIKE $${paramIndex})`)
        values.push(`%${search}%`)
        paramIndex++
      }

      if (teamId) {
        conditions.push(`w.team_id = $${paramIndex}`)
        values.push(teamId)
        paramIndex++
      }

      if (ownedOnly) {
        conditions.push(`w.owner_id = $${paramIndex}`)
        values.push(context.user.id)
        paramIndex++
      } else if (memberOnly) {
        conditions.push(`wm.user_id = $${paramIndex} AND wm.is_active = true`)
        values.push(context.user.id)
        paramIndex++
      } else {
        // Show workspaces where user is a member or has workspaces.view permission
        const hasWorkspacesView = context.user.roles?.some(role => 
          role.role.permissions.includes('workspaces.view')
        )
        
        if (!hasWorkspacesView) {
          conditions.push(`wm.user_id = $${paramIndex} AND wm.is_active = true`)
          values.push(context.user.id)
          paramIndex++
        }
      }

      // Calculate offset
      const offset = (page - 1) * limit
      values.push(limit, offset)

      // Query workspaces with pagination
      const workspacesQuery = `
        SELECT DISTINCT
          w.id,
          w.name,
          w.description,
          w.team_id,
          w.owner_id,
          w.is_active,
          w.default_search_radius,
          w.default_search_depth,
          w.default_pages_per_site,
          w.created_at,
          w.updated_at,
          t.name as team_name,
          u.username as owner_username,
          u.first_name as owner_first_name,
          u.last_name as owner_last_name,
          COUNT(DISTINCT wm2.user_id) as member_count,
          COUNT(DISTINCT c.id) as campaign_count,
          COUNT(DISTINCT b.id) as business_count,
          wm.role as user_role,
          wm.permissions as user_permissions,
          COUNT(*) OVER() as total_count
        FROM workspaces w
        JOIN teams t ON w.team_id = t.id
        JOIN users u ON w.owner_id = u.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = $${paramIndex - 2}
        LEFT JOIN workspace_members wm2 ON w.id = wm2.workspace_id AND wm2.is_active = true
        LEFT JOIN campaigns c ON w.id = c.workspace_id
        LEFT JOIN businesses b ON c.id = b.campaign_id
        WHERE ${conditions.join(' AND ')}
        GROUP BY w.id, t.name, u.username, u.first_name, u.last_name, wm.role, wm.permissions
        ORDER BY w.created_at DESC
        LIMIT $${paramIndex - 1} OFFSET $${paramIndex}
      `

      const result = await context.database.query(workspacesQuery, values)
      const workspaces = result.rows
      const totalCount = workspaces.length > 0 ? parseInt(workspaces[0].total_count) : 0
      const totalPages = Math.ceil(totalCount / limit)

      // Clean up response data
      const cleanWorkspaces = workspaces.map(workspace => {
        const { total_count, ...cleanWorkspace } = workspace
        return {
          ...cleanWorkspace,
          team: {
            id: cleanWorkspace.team_id,
            name: cleanWorkspace.team_name
          },
          owner: {
            id: cleanWorkspace.owner_id,
            username: cleanWorkspace.owner_username,
            firstName: cleanWorkspace.owner_first_name,
            lastName: cleanWorkspace.owner_last_name,
            fullName: `${cleanWorkspace.owner_first_name} ${cleanWorkspace.owner_last_name}`
          },
          memberCount: parseInt(cleanWorkspace.member_count),
          campaignCount: parseInt(cleanWorkspace.campaign_count),
          businessCount: parseInt(cleanWorkspace.business_count),
          userRole: cleanWorkspace.user_role,
          userPermissions: cleanWorkspace.user_permissions
        }
      })

      logger.info('Workspaces API', 'Workspaces listed successfully', {
        userId: context.user.id,
        page,
        limit,
        totalCount,
        filters: { search, teamId, ownedOnly, memberOnly }
      })

      return NextResponse.json({
        success: true,
        data: cleanWorkspaces,
        pagination: {
          page,
          limit,
          total: totalCount,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      })
    } catch (error) {
      logger.error('Workspaces API', 'Error listing workspaces', error)
      return NextResponse.json(
        { error: 'Failed to list workspaces' },
        { status: 500 }
      )
    }
  },
  { permissions: ['workspaces.view'] }
)

/**
 * POST /api/workspaces - Create new workspace
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const workspaceData: CreateWorkspaceRequest = body

      // Validate required fields
      if (!workspaceData.name || workspaceData.name.trim().length === 0) {
        return NextResponse.json(
          { error: 'Workspace name is required' },
          { status: 400 }
        )
      }

      if (!workspaceData.teamId) {
        return NextResponse.json(
          { error: 'Team ID is required' },
          { status: 400 }
        )
      }

      // Check if workspace name already exists in the team
      const existingWorkspace = await context.database.query(
        'SELECT id FROM workspaces WHERE name = $1 AND team_id = $2 AND is_active = true',
        [workspaceData.name.trim(), workspaceData.teamId]
      )

      if (existingWorkspace.rows[0]) {
        return NextResponse.json(
          { error: 'Workspace name already exists in this team' },
          { status: 400 }
        )
      }

      // Create workspace
      const workspace = await WorkspaceManagementService.createWorkspace(
        workspaceData,
        context.user.id
      )

      logger.info('Workspaces API', 'Workspace created successfully', {
        createdBy: context.user.id,
        workspaceId: workspace.id,
        name: workspace.name,
        teamId: workspace.teamId
      })

      return NextResponse.json({
        success: true,
        data: workspace,
        message: 'Workspace created successfully'
      }, { status: 201 })
    } catch (error) {
      logger.error('Workspaces API', 'Error creating workspace', error)
      
      if (error instanceof Error) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        )
      }
      
      return NextResponse.json(
        { error: 'Failed to create workspace' },
        { status: 500 }
      )
    }
  },
  { permissions: ['workspaces.create'] }
)

/**
 * PUT /api/workspaces - Bulk update workspaces
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { workspaceIds, updateData } = body

      if (!Array.isArray(workspaceIds) || workspaceIds.length === 0) {
        return NextResponse.json(
          { error: 'Workspace IDs array is required' },
          { status: 400 }
        )
      }

      if (!updateData || typeof updateData !== 'object') {
        return NextResponse.json(
          { error: 'Update data is required' },
          { status: 400 }
        )
      }

      const updatedWorkspaces = []
      const errors = []

      // Update each workspace
      for (const workspaceId of workspaceIds) {
        try {
          // Check if user can edit this workspace
          const workspace = await WorkspaceManagementService.getWorkspaceById(workspaceId)
          if (!workspace) {
            errors.push({ workspaceId, error: 'Workspace not found' })
            continue
          }

          const membership = await WorkspaceManagementService.getWorkspaceMembership(workspaceId, context.user.id)
          const canEdit = workspace.ownerId === context.user.id || 
                         membership?.role === 'admin' ||
                         context.user.roles?.some(role => role.role.permissions.includes('workspaces.manage'))

          if (!canEdit) {
            errors.push({ workspaceId, error: 'Insufficient permissions' })
            continue
          }

          // Build update query
          const updates: string[] = []
          const values: any[] = []
          let paramIndex = 1

          if (updateData.name !== undefined) {
            updates.push(`name = $${paramIndex++}`)
            values.push(updateData.name)
          }

          if (updateData.description !== undefined) {
            updates.push(`description = $${paramIndex++}`)
            values.push(updateData.description)
          }

          if (updateData.settings !== undefined) {
            updates.push(`settings = $${paramIndex++}`)
            values.push(JSON.stringify(updateData.settings))
          }

          if (updateData.defaultSearchRadius !== undefined) {
            updates.push(`default_search_radius = $${paramIndex++}`)
            values.push(updateData.defaultSearchRadius)
          }

          if (updateData.defaultSearchDepth !== undefined) {
            updates.push(`default_search_depth = $${paramIndex++}`)
            values.push(updateData.defaultSearchDepth)
          }

          if (updateData.defaultPagesPerSite !== undefined) {
            updates.push(`default_pages_per_site = $${paramIndex++}`)
            values.push(updateData.defaultPagesPerSite)
          }

          if (updates.length === 0) {
            errors.push({ workspaceId, error: 'No valid update fields' })
            continue
          }

          updates.push(`updated_at = $${paramIndex++}`)
          values.push(new Date())
          values.push(workspaceId)

          const updateQuery = `
            UPDATE workspaces 
            SET ${updates.join(', ')}
            WHERE id = $${paramIndex}
            RETURNING *
          `

          const result = await context.database.query(updateQuery, values)
          if (result.rows[0]) {
            updatedWorkspaces.push(result.rows[0])
          }
        } catch (error) {
          errors.push({
            workspaceId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Workspaces API', 'Bulk workspace update completed', {
        updatedBy: context.user.id,
        successCount: updatedWorkspaces.length,
        errorCount: errors.length,
        workspaceIds
      })

      return NextResponse.json({
        success: true,
        data: {
          updated: updatedWorkspaces.length,
          errors: errors.length,
          results: updatedWorkspaces,
          errors: errors
        },
        message: `Updated ${updatedWorkspaces.length} workspaces successfully`
      })
    } catch (error) {
      logger.error('Workspaces API', 'Error in bulk workspace update', error)
      return NextResponse.json(
        { error: 'Failed to update workspaces' },
        { status: 500 }
      )
    }
  },
  { permissions: ['workspaces.edit'] }
)

/**
 * DELETE /api/workspaces - Bulk delete workspaces
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { workspaceIds, permanent = false } = body

      if (!Array.isArray(workspaceIds) || workspaceIds.length === 0) {
        return NextResponse.json(
          { error: 'Workspace IDs array is required' },
          { status: 400 }
        )
      }

      const deletedWorkspaces = []
      const errors = []

      // Delete each workspace
      for (const workspaceId of workspaceIds) {
        try {
          // Check if user can delete this workspace
          const workspace = await WorkspaceManagementService.getWorkspaceById(workspaceId)
          if (!workspace) {
            errors.push({ workspaceId, error: 'Workspace not found' })
            continue
          }

          const canDelete = workspace.ownerId === context.user.id ||
                           context.user.roles?.some(role => role.role.permissions.includes('workspaces.delete'))

          if (!canDelete) {
            errors.push({ workspaceId, error: 'Insufficient permissions' })
            continue
          }

          let query: string
          if (permanent) {
            query = 'DELETE FROM workspaces WHERE id = $1 RETURNING id, name'
          } else {
            query = `
              UPDATE workspaces 
              SET is_active = false, updated_at = CURRENT_TIMESTAMP
              WHERE id = $1 
              RETURNING id, name
            `
          }

          const result = await context.database.query(query, [workspaceId])
          if (result.rows[0]) {
            deletedWorkspaces.push(result.rows[0])
          }
        } catch (error) {
          errors.push({
            workspaceId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Workspaces API', permanent ? 'Workspaces deleted permanently' : 'Workspaces deactivated', {
        deletedBy: context.user.id,
        successCount: deletedWorkspaces.length,
        errorCount: errors.length,
        workspaceIds,
        permanent
      })

      return NextResponse.json({
        success: true,
        data: {
          deleted: deletedWorkspaces.length,
          errors: errors.length,
          results: deletedWorkspaces,
          errors: errors
        },
        message: `${permanent ? 'Deleted' : 'Deactivated'} ${deletedWorkspaces.length} workspaces successfully`
      })
    } catch (error) {
      logger.error('Workspaces API', 'Error deleting workspaces', error)
      return NextResponse.json(
        { error: 'Failed to delete workspaces' },
        { status: 500 }
      )
    }
  },
  { permissions: ['workspaces.delete'] }
)
