/**
 * Campaigns API Endpoint
 * Handles campaign management with multi-user authorization
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

/**
 * GET /api/campaigns - List campaigns with filtering and pagination
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const page = parseInt(searchParams.get('page') || '1')
      const limit = parseInt(searchParams.get('limit') || '20')
      const search = searchParams.get('search') || ''
      const status = searchParams.get('status') || ''
      const industry = searchParams.get('industry') || ''
      const workspaceId = searchParams.get('workspaceId') || context.workspaceId

      // Build query conditions
      const conditions: string[] = ['1=1']
      const values: any[] = []
      let paramIndex = 1

      if (workspaceId) {
        conditions.push(`c.workspace_id = $${paramIndex++}`)
        values.push(workspaceId)
      }

      if (search) {
        conditions.push(`(c.name ILIKE $${paramIndex} OR c.description ILIKE $${paramIndex})`)
        values.push(`%${search}%`)
        paramIndex++
      }

      if (status) {
        conditions.push(`c.status = $${paramIndex++}`)
        values.push(status)
      }

      if (industry) {
        conditions.push(`c.industry = $${paramIndex++}`)
        values.push(industry)
      }

      // Calculate offset
      const offset = (page - 1) * limit
      values.push(limit, offset)

      // Query campaigns with pagination
      const campaignsQuery = `
        SELECT 
          c.*,
          u.username as created_by_username,
          u.first_name as created_by_first_name,
          u.last_name as created_by_last_name,
          w.name as workspace_name,
          COUNT(DISTINCT b.id) as business_count,
          COUNT(DISTINCT ss.id) as session_count,
          AVG(b.confidence_score) as avg_confidence_score,
          COUNT(*) OVER() as total_count
        FROM campaigns c
        LEFT JOIN users u ON c.created_by = u.id
        LEFT JOIN workspaces w ON c.workspace_id = w.id
        LEFT JOIN businesses b ON c.id = b.campaign_id
        LEFT JOIN scraping_sessions ss ON c.id = ss.campaign_id
        WHERE ${conditions.join(' AND ')}
        GROUP BY c.id, u.username, u.first_name, u.last_name, w.name
        ORDER BY c.created_at DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex}
      `

      const result = await context.database.query(campaignsQuery, values)
      const campaigns = result.rows
      const totalCount = campaigns.length > 0 ? parseInt(campaigns[0].total_count) : 0
      const totalPages = Math.ceil(totalCount / limit)

      // Clean up response data
      const cleanCampaigns = campaigns.map(campaign => {
        const { total_count, ...cleanCampaign } = campaign
        return {
          ...cleanCampaign,
          createdBy: {
            username: cleanCampaign.created_by_username,
            firstName: cleanCampaign.created_by_first_name,
            lastName: cleanCampaign.created_by_last_name,
            fullName: `${cleanCampaign.created_by_first_name} ${cleanCampaign.created_by_last_name}`
          },
          workspace: {
            name: cleanCampaign.workspace_name
          },
          businessCount: parseInt(cleanCampaign.business_count) || 0,
          sessionCount: parseInt(cleanCampaign.session_count) || 0,
          avgConfidenceScore: parseFloat(cleanCampaign.avg_confidence_score) || 0
        }
      })

      logger.info('Campaigns API', 'Campaigns listed successfully', {
        userId: context.user.id,
        workspaceId,
        page,
        limit,
        totalCount
      })

      return NextResponse.json({
        success: true,
        data: cleanCampaigns,
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
      logger.error('Campaigns API', 'Error listing campaigns', error)
      return NextResponse.json(
        { error: 'Failed to list campaigns' },
        { status: 500 }
      )
    }
  },
  { permissions: ['campaigns.view'] }
)

/**
 * POST /api/campaigns - Create new campaign
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const {
        name,
        description,
        industry,
        location,
        workspaceId,
        parameters,
        settings
      } = body

      // Validate required fields
      if (!name || !industry || !location) {
        return NextResponse.json(
          { error: 'Name, industry, and location are required' },
          { status: 400 }
        )
      }

      const targetWorkspaceId = workspaceId || context.workspaceId
      if (!targetWorkspaceId) {
        return NextResponse.json(
          { error: 'Workspace ID is required' },
          { status: 400 }
        )
      }

      // Check if user has access to the workspace
      const workspaceAccess = await context.database.query(`
        SELECT wm.role, wm.permissions
        FROM workspace_members wm
        WHERE wm.workspace_id = $1 AND wm.user_id = $2 AND wm.is_active = true
      `, [targetWorkspaceId, context.user.id])

      if (!workspaceAccess.rows[0]) {
        return NextResponse.json(
          { error: 'Access denied to workspace' },
          { status: 403 }
        )
      }

      // Generate campaign ID
      const campaignId = `campaign_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

      // Insert campaign
      const insertQuery = `
        INSERT INTO campaigns (
          id, name, description, industry, location, workspace_id, created_by,
          parameters, settings, status, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *
      `

      const campaignResult = await context.database.query(insertQuery, [
        campaignId,
        name,
        description || null,
        industry,
        location,
        targetWorkspaceId,
        context.user.id,
        JSON.stringify(parameters || {}),
        JSON.stringify(settings || {}),
        'draft',
        new Date(),
        new Date()
      ])

      const campaign = campaignResult.rows[0]

      // Log campaign creation
      await AuditService.logCampaignManagement(
        'campaign.created',
        campaignId,
        context.user.id,
        AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
        {
          name,
          industry,
          location,
          workspaceId: targetWorkspaceId
        }
      )

      logger.info('Campaigns API', 'Campaign created successfully', {
        campaignId,
        name,
        createdBy: context.user.id,
        workspaceId: targetWorkspaceId
      })

      return NextResponse.json({
        success: true,
        data: campaign,
        message: 'Campaign created successfully'
      }, { status: 201 })
    } catch (error) {
      logger.error('Campaigns API', 'Error creating campaign', error)
      
      if (error instanceof Error) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        )
      }
      
      return NextResponse.json(
        { error: 'Failed to create campaign' },
        { status: 500 }
      )
    }
  },
  { permissions: ['campaigns.create'] }
)

/**
 * PUT /api/campaigns - Bulk update campaigns
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { campaignIds, updateData } = body

      if (!Array.isArray(campaignIds) || campaignIds.length === 0) {
        return NextResponse.json(
          { error: 'Campaign IDs array is required' },
          { status: 400 }
        )
      }

      if (!updateData || typeof updateData !== 'object') {
        return NextResponse.json(
          { error: 'Update data is required' },
          { status: 400 }
        )
      }

      const updatedCampaigns = []
      const errors = []

      // Update each campaign
      for (const campaignId of campaignIds) {
        try {
          // Check if user can edit this campaign
          const campaignAccess = await context.database.query(`
            SELECT c.*, wm.role, wm.permissions
            FROM campaigns c
            JOIN workspace_members wm ON c.workspace_id = wm.workspace_id
            WHERE c.id = $1 AND wm.user_id = $2 AND wm.is_active = true
          `, [campaignId, context.user.id])

          if (!campaignAccess.rows[0]) {
            errors.push({ campaignId, error: 'Campaign not found or access denied' })
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

          if (updateData.status !== undefined) {
            updates.push(`status = $${paramIndex++}`)
            values.push(updateData.status)
          }

          if (updateData.parameters !== undefined) {
            updates.push(`parameters = $${paramIndex++}`)
            values.push(JSON.stringify(updateData.parameters))
          }

          if (updateData.settings !== undefined) {
            updates.push(`settings = $${paramIndex++}`)
            values.push(JSON.stringify(updateData.settings))
          }

          if (updates.length === 0) {
            errors.push({ campaignId, error: 'No valid update fields' })
            continue
          }

          updates.push(`updated_at = $${paramIndex++}`)
          updates.push(`updated_by = $${paramIndex++}`)
          values.push(new Date())
          values.push(context.user.id)
          values.push(campaignId)

          const updateQuery = `
            UPDATE campaigns 
            SET ${updates.join(', ')}
            WHERE id = $${paramIndex}
            RETURNING *
          `

          const result = await context.database.query(updateQuery, values)
          if (result.rows[0]) {
            updatedCampaigns.push(result.rows[0])

            // Log campaign update
            await AuditService.logCampaignManagement(
              'campaign.updated',
              campaignId,
              context.user.id,
              AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
              { fields: Object.keys(updateData) }
            )
          }
        } catch (error) {
          errors.push({
            campaignId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Campaigns API', 'Bulk campaign update completed', {
        updatedBy: context.user.id,
        successCount: updatedCampaigns.length,
        errorCount: errors.length,
        campaignIds
      })

      return NextResponse.json({
        success: true,
        data: {
          updated: updatedCampaigns.length,
          errors: errors.length,
          results: updatedCampaigns,
          errors: errors
        },
        message: `Updated ${updatedCampaigns.length} campaigns successfully`
      })
    } catch (error) {
      logger.error('Campaigns API', 'Error in bulk campaign update', error)
      return NextResponse.json(
        { error: 'Failed to update campaigns' },
        { status: 500 }
      )
    }
  },
  { permissions: ['campaigns.edit'] }
)

/**
 * DELETE /api/campaigns - Bulk delete campaigns
 */
export const DELETE = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { campaignIds, permanent = false } = body

      if (!Array.isArray(campaignIds) || campaignIds.length === 0) {
        return NextResponse.json(
          { error: 'Campaign IDs array is required' },
          { status: 400 }
        )
      }

      const deletedCampaigns = []
      const errors = []

      // Delete each campaign
      for (const campaignId of campaignIds) {
        try {
          // Check if user can delete this campaign
          const campaignAccess = await context.database.query(`
            SELECT c.*, wm.role, wm.permissions
            FROM campaigns c
            JOIN workspace_members wm ON c.workspace_id = wm.workspace_id
            WHERE c.id = $1 AND wm.user_id = $2 AND wm.is_active = true
          `, [campaignId, context.user.id])

          if (!campaignAccess.rows[0]) {
            errors.push({ campaignId, error: 'Campaign not found or access denied' })
            continue
          }

          let query: string
          if (permanent) {
            query = 'DELETE FROM campaigns WHERE id = $1 RETURNING id, name'
          } else {
            query = `
              UPDATE campaigns 
              SET status = 'deleted', updated_at = CURRENT_TIMESTAMP, updated_by = $2
              WHERE id = $1 
              RETURNING id, name
            `
          }

          const values = permanent ? [campaignId] : [campaignId, context.user.id]
          const result = await context.database.query(query, values)
          
          if (result.rows[0]) {
            deletedCampaigns.push(result.rows[0])

            // Log campaign deletion
            await AuditService.logCampaignManagement(
              'campaign.deleted',
              campaignId,
              context.user.id,
              AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
              { permanent }
            )
          }
        } catch (error) {
          errors.push({
            campaignId,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Campaigns API', permanent ? 'Campaigns deleted permanently' : 'Campaigns marked as deleted', {
        deletedBy: context.user.id,
        successCount: deletedCampaigns.length,
        errorCount: errors.length,
        campaignIds,
        permanent
      })

      return NextResponse.json({
        success: true,
        data: {
          deleted: deletedCampaigns.length,
          errors: errors.length,
          results: deletedCampaigns,
          errors: errors
        },
        message: `${permanent ? 'Deleted' : 'Marked as deleted'} ${deletedCampaigns.length} campaigns successfully`
      })
    } catch (error) {
      logger.error('Campaigns API', 'Error deleting campaigns', error)
      return NextResponse.json(
        { error: 'Failed to delete campaigns' },
        { status: 500 }
      )
    }
  },
  { permissions: ['campaigns.delete'] }
)
