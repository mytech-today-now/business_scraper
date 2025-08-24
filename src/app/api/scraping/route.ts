/**
 * Multi-User Scraping API Endpoint
 * Handles web scraping operations with workspace-based authorization
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { scraperService } from '@/model/scraperService'
import { AuditService } from '@/lib/audit-service'
import { getClientIP, sanitizeInput, validateInput } from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * POST /api/scraping - Execute scraping operations
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    const ip = getClientIP(request)
    
    try {
      const body = await request.json()
      const { 
        action, 
        campaignId,
        workspaceId,
        query, 
        zipCode, 
        maxResults, 
        url, 
        depth, 
        maxPages, 
        sessionId 
      } = body

      // Validate action parameter
      if (!action || typeof action !== 'string') {
        logger.warn('Scraping API', `Invalid action parameter from IP: ${ip}`)
        return NextResponse.json({ error: 'Action parameter is required' }, { status: 400 })
      }

      // Sanitize action
      const sanitizedAction = sanitizeInput(action)

      // Validate action against allowed values
      const allowedActions = ['initialize', 'search', 'scrape', 'cleanup', 'status']
      if (!allowedActions.includes(sanitizedAction)) {
        logger.warn('Scraping API', `Invalid action '${sanitizedAction}' from IP: ${ip}`)
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
      }

      const targetWorkspaceId = workspaceId || context.workspaceId
      
      // For actions that require workspace context
      if (['search', 'scrape'].includes(sanitizedAction) && !targetWorkspaceId) {
        return NextResponse.json(
          { error: 'Workspace ID is required for this action' },
          { status: 400 }
        )
      }

      // Verify workspace access if workspace is specified
      if (targetWorkspaceId) {
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
      }

      logger.info('Scraping API', `${sanitizedAction} request from user ${context.user.username}`, {
        action: sanitizedAction,
        workspaceId: targetWorkspaceId,
        campaignId,
        ip
      })

      let result: any

      switch (sanitizedAction) {
        case 'initialize':
          result = await handleInitialize(context)
          break

        case 'search':
          result = await handleSearch({
            query,
            zipCode,
            maxResults,
            workspaceId: targetWorkspaceId,
            campaignId,
            userId: context.user.id
          }, context)
          break

        case 'scrape':
          result = await handleScrape({
            url,
            depth,
            maxPages,
            workspaceId: targetWorkspaceId,
            campaignId,
            userId: context.user.id
          }, context)
          break

        case 'cleanup':
          result = await handleCleanup(context)
          break

        case 'status':
          result = await handleStatus(sessionId, context)
          break

        default:
          return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
      }

      // Log scraping action
      await AuditService.logScraping(
        `scraping.${sanitizedAction}` as any,
        sessionId || 'unknown',
        context.user.id,
        AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
        {
          action: sanitizedAction,
          workspaceId: targetWorkspaceId,
          campaignId,
          parameters: { query, zipCode, maxResults, url, depth, maxPages }
        }
      )

      return NextResponse.json({
        success: true,
        action: sanitizedAction,
        data: result,
        timestamp: new Date().toISOString()
      })

    } catch (error) {
      logger.error('Scraping API', `Error processing ${body?.action || 'unknown'} request from IP: ${ip}`, error)
      
      // Log failed scraping attempt
      await AuditService.logScraping(
        'scraping.failed',
        'unknown',
        context.user.id,
        AuditService.extractContextFromRequest(request, context.user.id, context.sessionId),
        {
          error: error instanceof Error ? error.message : 'Unknown error',
          action: body?.action
        }
      )

      return NextResponse.json(
        { 
          error: 'Scraping operation failed',
          message: error instanceof Error ? error.message : 'Unknown error'
        },
        { status: 500 }
      )
    }
  },
  { permissions: ['scraping.run'] }
)

/**
 * Handle scraper initialization
 */
async function handleInitialize(context: any): Promise<any> {
  try {
    await scraperService.initialize()
    
    logger.info('Scraping API', 'Scraper initialized successfully', {
      userId: context.user.id
    })
    
    return { message: 'Scraper initialized successfully' }
  } catch (error) {
    logger.error('Scraping API', 'Failed to initialize scraper', error)
    throw error
  }
}

/**
 * Handle search operation
 */
async function handleSearch(params: {
  query?: string
  zipCode?: string
  maxResults?: number
  workspaceId?: string
  campaignId?: string
  userId: string
}, context: any): Promise<any> {
  const { query, zipCode, maxResults, workspaceId, campaignId, userId } = params

  // Validate required parameters
  if (!query || !zipCode) {
    throw new Error('Query and ZIP code are required for search')
  }

  // Sanitize inputs
  const sanitizedQuery = sanitizeInput(query)
  const sanitizedZipCode = sanitizeInput(zipCode)

  // Validate inputs
  const queryValidation = validateInput(sanitizedQuery)
  if (!queryValidation.isValid) {
    throw new Error('Invalid query format')
  }

  const zipValidation = validateInput(sanitizedZipCode)
  if (!zipValidation.isValid) {
    throw new Error('Invalid ZIP code format')
  }

  try {
    // Create scraping session record
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    await context.database.query(`
      INSERT INTO scraping_sessions (
        id, workspace_id, campaign_id, created_by, query, zip_code, 
        max_results, status, started_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      sessionId,
      workspaceId,
      campaignId,
      userId,
      sanitizedQuery,
      sanitizedZipCode,
      maxResults || 50,
      'running',
      new Date()
    ])

    // Perform search
    const searchResults = await scraperService.searchBusinesses(
      sanitizedQuery,
      sanitizedZipCode,
      maxResults || 50
    )

    // Update session with results
    await context.database.query(`
      UPDATE scraping_sessions 
      SET status = $1, completed_at = $2, successful_scrapes = $3, total_urls = $4
      WHERE id = $5
    `, ['completed', new Date(), searchResults.length, searchResults.length, sessionId])

    logger.info('Scraping API', 'Search completed successfully', {
      sessionId,
      query: sanitizedQuery,
      zipCode: sanitizedZipCode,
      resultsCount: searchResults.length,
      userId
    })

    return {
      sessionId,
      results: searchResults,
      count: searchResults.length,
      query: sanitizedQuery,
      zipCode: sanitizedZipCode
    }
  } catch (error) {
    logger.error('Scraping API', 'Search operation failed', error)
    throw error
  }
}

/**
 * Handle scrape operation
 */
async function handleScrape(params: {
  url?: string
  depth?: number
  maxPages?: number
  workspaceId?: string
  campaignId?: string
  userId: string
}, context: any): Promise<any> {
  const { url, depth, maxPages, workspaceId, campaignId, userId } = params

  // Validate required parameters
  if (!url) {
    throw new Error('URL is required for scraping')
  }

  // Sanitize inputs
  const sanitizedUrl = sanitizeInput(url)
  const numDepth = Math.min(Math.max(parseInt(String(depth || 3)), 1), 10)
  const numMaxPages = Math.min(Math.max(parseInt(String(maxPages || 5)), 1), 50)

  // Validate URL
  try {
    new URL(sanitizedUrl)
  } catch {
    throw new Error('Invalid URL format')
  }

  try {
    // Create scraping session record
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    await context.database.query(`
      INSERT INTO scraping_sessions (
        id, workspace_id, campaign_id, created_by, url, depth, 
        max_pages, status, started_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      sessionId,
      workspaceId,
      campaignId,
      userId,
      sanitizedUrl,
      numDepth,
      numMaxPages,
      'running',
      new Date()
    ])

    // Perform scraping
    const businesses = await scraperService.scrapeWebsite(sanitizedUrl, numDepth, numMaxPages)

    // Store businesses in database if campaign is specified
    if (campaignId && businesses.length > 0) {
      for (const business of businesses) {
        await context.database.query(`
          INSERT INTO businesses (
            campaign_id, name, address, phone, email, website, 
            confidence_score, scraped_at, scraped_by
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `, [
          campaignId,
          business.name,
          business.address,
          business.phone ? [business.phone] : [],
          business.email ? [business.email] : [],
          business.website,
          business.confidence || 0.5,
          new Date(),
          userId
        ])
      }
    }

    // Update session with results
    await context.database.query(`
      UPDATE scraping_sessions 
      SET status = $1, completed_at = $2, successful_scrapes = $3, total_urls = $4
      WHERE id = $5
    `, ['completed', new Date(), businesses.length, businesses.length, sessionId])

    logger.info('Scraping API', 'Scrape completed successfully', {
      sessionId,
      url: sanitizedUrl,
      businessesFound: businesses.length,
      userId
    })

    return {
      sessionId,
      businesses,
      count: businesses.length,
      url: sanitizedUrl
    }
  } catch (error) {
    logger.error('Scraping API', 'Scrape operation failed', error)
    throw error
  }
}

/**
 * Handle cleanup operation
 */
async function handleCleanup(context: any): Promise<any> {
  try {
    await scraperService.cleanup()
    
    logger.info('Scraping API', 'Scraper cleanup completed', {
      userId: context.user.id
    })
    
    return { message: 'Scraper cleanup completed' }
  } catch (error) {
    logger.error('Scraping API', 'Failed to cleanup scraper', error)
    throw error
  }
}

/**
 * Handle status check
 */
async function handleStatus(sessionId: string | undefined, context: any): Promise<any> {
  if (!sessionId) {
    return { message: 'No session ID provided' }
  }

  try {
    const sessionResult = await context.database.query(`
      SELECT * FROM scraping_sessions WHERE id = $1
    `, [sessionId])

    if (!sessionResult.rows[0]) {
      return { message: 'Session not found' }
    }

    const session = sessionResult.rows[0]
    
    return {
      sessionId,
      status: session.status,
      startedAt: session.started_at,
      completedAt: session.completed_at,
      successfulScrapes: session.successful_scrapes,
      totalUrls: session.total_urls
    }
  } catch (error) {
    logger.error('Scraping API', 'Failed to get session status', error)
    throw error
  }
}

/**
 * GET /api/scraping - Get scraping status and capabilities
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const sessionId = searchParams.get('sessionId')
      const workspaceId = searchParams.get('workspaceId') || context.workspaceId

      if (sessionId) {
        // Get specific session status
        const result = await handleStatus(sessionId, context)
        return NextResponse.json({
          success: true,
          data: result
        })
      }

      // Get general scraping capabilities and recent sessions
      const recentSessions = await context.database.query(`
        SELECT id, status, started_at, completed_at, query, url, successful_scrapes
        FROM scraping_sessions
        WHERE created_by = $1 ${workspaceId ? 'AND workspace_id = $2' : ''}
        ORDER BY started_at DESC
        LIMIT 10
      `, workspaceId ? [context.user.id, workspaceId] : [context.user.id])

      return NextResponse.json({
        success: true,
        data: {
          status: 'Scraping API is operational',
          capabilities: {
            actions: ['initialize', 'search', 'scrape', 'cleanup', 'status'],
            maxDepth: 10,
            maxPages: 50,
            maxResults: 100
          },
          recentSessions: recentSessions.rows,
          timestamp: new Date().toISOString()
        }
      })
    } catch (error) {
      logger.error('Scraping API', 'Error getting scraping status', error)
      return NextResponse.json(
        { error: 'Failed to get scraping status' },
        { status: 500 }
      )
    }
  },
  { permissions: ['scraping.view'] }
)
