/**
 * Teams API Endpoint
 * Handles team management operations (CRUD, membership management)
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { WorkspaceManagementService } from '@/lib/workspace-management'
import { CreateTeamRequest, UpdateTeamRequest } from '@/types/multi-user'
import { logger } from '@/utils/logger'

/**
 * GET /api/teams - List teams with pagination and filtering
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const page = parseInt(searchParams.get('page') || '1')
      const limit = parseInt(searchParams.get('limit') || '20')
      const search = searchParams.get('search') || ''
      const ownedOnly = searchParams.get('ownedOnly') === 'true'
      const memberOnly = searchParams.get('memberOnly') === 'true'

      // Build query conditions
      const conditions: string[] = ['t.is_active = true']
      const values: any[] = []
      let paramIndex = 1

      if (search) {
        conditions.push(`(t.name ILIKE $${paramIndex} OR t.description ILIKE $${paramIndex})`)
        values.push(`%${search}%`)
        paramIndex++
      }

      if (ownedOnly) {
        conditions.push(`t.owner_id = $${paramIndex}`)
        values.push(context.user.id)
        paramIndex++
      } else if (memberOnly) {
        conditions.push(`tm.user_id = $${paramIndex} AND tm.is_active = true`)
        values.push(context.user.id)
        paramIndex++
      } else {
        // Show teams where user is a member or has teams.view permission
        const hasTeamsView = context.user.roles?.some(role => 
          role.role.permissions.includes('teams.view')
        )
        
        if (!hasTeamsView) {
          conditions.push(`tm.user_id = $${paramIndex} AND tm.is_active = true`)
          values.push(context.user.id)
          paramIndex++
        }
      }

      // Calculate offset
      const offset = (page - 1) * limit
      values.push(limit, offset)

      // Query teams with pagination
      const teamsQuery = `
        SELECT DISTINCT
          t.id,
          t.name,
          t.description,
          t.owner_id,
          t.is_active,
          t.created_at,
          t.updated_at,
          u.username as owner_username,
          u.first_name as owner_first_name,
          u.last_name as owner_last_name,
          COUNT(DISTINCT tm2.user_id) as member_count,
          COUNT(DISTINCT w.id) as workspace_count,
          tm.role as user_role,
          COUNT(*) OVER() as total_count
        FROM teams t
        JOIN users u ON t.owner_id = u.id
        LEFT JOIN team_members tm ON t.id = tm.team_id AND tm.user_id = $${paramIndex - 2}
        LEFT JOIN team_members tm2 ON t.id = tm2.team_id AND tm2.is_active = true
        LEFT JOIN workspaces w ON t.id = w.team_id AND w.is_active = true
        WHERE ${conditions.join(' AND ')}
        GROUP BY t.id, u.username, u.first_name, u.last_name, tm.role
        ORDER BY t.created_at DESC
        LIMIT $${paramIndex - 1} OFFSET $${paramIndex}
      `

      const result = await context.database.query(teamsQuery, values)
      const teams = result.rows
      const totalCount = teams.length > 0 ? parseInt(teams[0].total_count) : 0
      const totalPages = Math.ceil(totalCount / limit)

      // Clean up response data
      const cleanTeams = teams.map(team => {
        const { total_count, ...cleanTeam } = team
        return {
          ...cleanTeam,
          owner: {
            id: cleanTeam.owner_id,
            username: cleanTeam.owner_username,
            firstName: cleanTeam.owner_first_name,
            lastName: cleanTeam.owner_last_name,
            fullName: `${cleanTeam.owner_first_name} ${cleanTeam.owner_last_name}`
          },
          memberCount: parseInt(cleanTeam.member_count),
          workspaceCount: parseInt(cleanTeam.workspace_count),
          userRole: cleanTeam.user_role
        }
      })

      logger.info('Teams API', 'Teams listed successfully', {
        userId: context.user.id,
        page,
        limit,
        totalCount,
        filters: { search, ownedOnly, memberOnly }
      })

      return NextResponse.json({
        success: true,
        data: cleanTeams,
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
      logger.error('Teams API', 'Error listing teams', error)
      return NextResponse.json(
        { error: 'Failed to list teams' },
        { status: 500 }
      )
    }
  },
  { permissions: ['teams.view'] }
)

/**
 * POST /api/teams - Create new team
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const teamData: CreateTeamRequest = body

      // Validate required fields
      if (!teamData.name || teamData.name.trim().length === 0) {
        return NextResponse.json(
          { error: 'Team name is required' },
          { status: 400 }
        )
      }

      // Check if team name already exists for this user
      const existingTeam = await context.database.query(
        'SELECT id FROM teams WHERE name = $1 AND owner_id = $2 AND is_active = true',
        [teamData.name.trim(), context.user.id]
      )

      if (existingTeam.rows[0]) {
        return NextResponse.json(
          { error: 'Team name already exists' },
          { status: 400 }
        )
      }

      // Create team
      const team = await WorkspaceManagementService.createTeam(
        teamData,
        context.user.id
      )

      logger.info('Teams API', 'Team created successfully', {
        createdBy: context.user.id,
        teamId: team.id,
        name: team.name
      })

      return NextResponse.json({
        success: true,
        data: team,
        message: 'Team created successfully'
      }, { status: 201 })
    } catch (error) {
      logger.error('Teams API', 'Error creating team', error)
      
      if (error instanceof Error) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        )
      }
      
      return NextResponse.json(
        { error: 'Failed to create team' },
        { status: 500 }
      )
    }
  },
  { permissions: ['teams.create'] }
)

/**
 * PUT /api/teams - Bulk update teams (admin only)
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { teamIds, updateData } = body

      if (!Array.isArray(teamIds) || teamIds.length === 0) {
        return NextResponse.json(
          { error: 'Team IDs array is required' },
          { status: 400 }
        )
      }

      if (!updateData || typeof updateData !== 'object') {
        return NextResponse.json(
          { error: 'Update data is required' },
          { status: 400 }
        )
      }

      const updatedTeams = []
      const errors = []

      // Update each team
      for (const teamId of teamIds) {
        try {
          // Check if user can edit this team
          const team = await WorkspaceManagementService.getTeamById(teamId)
          if (!team) {
            errors.push({ teamId, error: 'Team not found' })
            continue
          }

          const membership = await WorkspaceManagementService.getTeamMembership(teamId, context.user.id)
          const canEdit = team.ownerId === context.user.id || 
                         membership?.role === 'admin' ||
                         context.user.roles?.some(role => role.role.permissions.includes('teams.manage'))

          if (!canEdit) {
            errors.push({ teamId, error: 'Insufficient permissions' })
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

          if (updates.length === 0) {
            errors.push({ teamId, error: 'No valid update fields' })
            continue
          }

          updates.push(`updated_at = $${paramIndex++}`)
          values.push(new Date())
          values.push(teamId)

          const updateQuery = `
            UPDATE teams 
            SET ${updates.join(', ')}
            WHERE id = $${paramIndex}
            RETURNING *
          `

          const result = await context.database.query(updateQuery, values)
          if (result.rows[0]) {
            updatedTeams.push(result.rows[0])
          }
        } catch (error) {
          errors.push({
            teamId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Teams API', 'Bulk team update completed', {
        updatedBy: context.user.id,
        successCount: updatedTeams.length,
        errorCount: errors.length,
        teamIds
      })

      return NextResponse.json({
        success: true,
        data: {
          updated: updatedTeams.length,
          errors: errors.length,
          results: updatedTeams,
          errors: errors
        },
        message: `Updated ${updatedTeams.length} teams successfully`
      })
    } catch (error) {
      logger.error('Teams API', 'Error in bulk team update', error)
      return NextResponse.json(
        { error: 'Failed to update teams' },
        { status: 500 }
      )
    }
  },
  { permissions: ['teams.edit'] }
)

/**
 * DELETE /api/teams - Bulk delete teams
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { teamIds, permanent = false } = body

      if (!Array.isArray(teamIds) || teamIds.length === 0) {
        return NextResponse.json(
          { error: 'Team IDs array is required' },
          { status: 400 }
        )
      }

      const deletedTeams = []
      const errors = []

      // Delete each team
      for (const teamId of teamIds) {
        try {
          // Check if user can delete this team
          const team = await WorkspaceManagementService.getTeamById(teamId)
          if (!team) {
            errors.push({ teamId, error: 'Team not found' })
            continue
          }

          const canDelete = team.ownerId === context.user.id ||
                           context.user.roles?.some(role => role.role.permissions.includes('teams.delete'))

          if (!canDelete) {
            errors.push({ teamId, error: 'Insufficient permissions' })
            continue
          }

          let query: string
          if (permanent) {
            query = 'DELETE FROM teams WHERE id = $1 RETURNING id, name'
          } else {
            query = `
              UPDATE teams 
              SET is_active = false, updated_at = CURRENT_TIMESTAMP
              WHERE id = $1 
              RETURNING id, name
            `
          }

          const result = await context.database.query(query, [teamId])
          if (result.rows[0]) {
            deletedTeams.push(result.rows[0])
          }
        } catch (error) {
          errors.push({
            teamId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Teams API', permanent ? 'Teams deleted permanently' : 'Teams deactivated', {
        deletedBy: context.user.id,
        successCount: deletedTeams.length,
        errorCount: errors.length,
        teamIds,
        permanent
      })

      return NextResponse.json({
        success: true,
        data: {
          deleted: deletedTeams.length,
          errors: errors.length,
          results: deletedTeams,
          errors: errors
        },
        message: `${permanent ? 'Deleted' : 'Deactivated'} ${deletedTeams.length} teams successfully`
      })
    } catch (error) {
      logger.error('Teams API', 'Error deleting teams', error)
      return NextResponse.json(
        { error: 'Failed to delete teams' },
        { status: 500 }
      )
    }
  },
  { permissions: ['teams.delete'] }
)
