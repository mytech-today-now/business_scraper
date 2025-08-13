/**
 * Enhanced Scraping API Endpoint
 * Provides access to the enhanced scraping engine with advanced features
 */

import { NextRequest, NextResponse } from 'next/server'
import { enhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'
import { scraperService } from '@/model/scraperService'
import { logger } from '@/utils/logger'
import { validationService } from '@/utils/validation'
import { withApiSecurity } from '@/lib/api-security'
import { withErrorHandling, createSecureErrorResponse } from '@/lib/error-handling'
import { getClientIP } from '@/lib/security'

/**
 * POST /api/enhanced-scrape - Enhanced scraping operations
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, ...params } = body

    logger.info('EnhancedScrapeAPI', `Received ${action} request`)

    switch (action) {
      case 'initialize':
        await enhancedScrapingEngine.initialize()
        return NextResponse.json({ 
          success: true, 
          message: 'Enhanced scraping engine initialized' 
        })

      case 'add-job':
        const { url, depth = 2, priority = 1, maxPages = 5 } = params

        // Validate URL
        if (!url || typeof url !== 'string') {
          return NextResponse.json({ error: 'URL parameter is required' }, { status: 400 })
        }

        const sanitizedUrl = validationService.sanitizeInput(url)

        // Basic URL validation
        try {
          new URL(sanitizedUrl)
        } catch {
          return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 })
        }

        // Validate depth, priority, and maxPages
        const numDepth = Math.min(Math.max(parseInt(depth) || 2, 1), 5)
        const numPriority = Math.min(Math.max(parseInt(priority) || 1, 1), 10)
        const numMaxPages = Math.min(Math.max(parseInt(maxPages) || 5, 1), 20)

        const jobId = await enhancedScrapingEngine.addJob(sanitizedUrl, numDepth, numPriority, numMaxPages)
        
        return NextResponse.json({
          success: true,
          jobId,
          url: sanitizedUrl,
          depth: numDepth,
          priority: numPriority,
          maxPages: numMaxPages
        })

      case 'add-multiple-jobs':
        const { urls, depth: batchDepth = 2, priority: batchPriority = 1, maxPages: batchMaxPages = 5 } = params

        // Validate URLs array
        if (!Array.isArray(urls) || urls.length === 0) {
          return NextResponse.json({ error: 'URLs array is required' }, { status: 400 })
        }

        if (urls.length > 50) {
          return NextResponse.json({ error: 'Maximum 50 URLs allowed per batch' }, { status: 400 })
        }

        const jobIds: string[] = []
        const errors: string[] = []

        for (const url of urls) {
          try {
            const sanitizedUrl = validationService.sanitizeInput(url)
            new URL(sanitizedUrl) // Validate URL
            
            const jobId = await enhancedScrapingEngine.addJob(
              sanitizedUrl,
              Math.min(Math.max(parseInt(batchDepth) || 2, 1), 5),
              Math.min(Math.max(parseInt(batchPriority) || 1, 1), 10),
              Math.min(Math.max(parseInt(batchMaxPages) || 5, 1), 20)
            )
            jobIds.push(jobId)
          } catch (error) {
            errors.push(`Failed to add job for ${url}: ${error}`)
          }
        }

        return NextResponse.json({ 
          success: true, 
          jobIds,
          totalJobs: jobIds.length,
          errors: errors.length > 0 ? errors : undefined
        })

      case 'get-job-status':
        const { jobId: statusJobId } = params

        if (!statusJobId) {
          return NextResponse.json({ error: 'Job ID is required' }, { status: 400 })
        }

        const job = enhancedScrapingEngine.getJobStatus(statusJobId)
        
        if (!job) {
          return NextResponse.json({ error: 'Job not found' }, { status: 404 })
        }

        return NextResponse.json({ 
          success: true, 
          job: {
            id: job.id,
            url: job.url,
            status: job.status,
            depth: job.depth,
            priority: job.priority,
            retries: job.retries,
            maxRetries: job.maxRetries,
            createdAt: job.createdAt,
            startedAt: job.startedAt,
            completedAt: job.completedAt,
            error: job.error,
            resultCount: job.result?.length || 0,
          }
        })

      case 'get-job-result':
        const { jobId: resultJobId } = params

        if (!resultJobId) {
          return NextResponse.json({ error: 'Job ID is required' }, { status: 400 })
        }

        const resultJob = enhancedScrapingEngine.getJobStatus(resultJobId)
        
        if (!resultJob) {
          return NextResponse.json({ error: 'Job not found' }, { status: 404 })
        }

        if (resultJob.status !== 'completed') {
          return NextResponse.json({ 
            error: 'Job not completed', 
            status: resultJob.status 
          }, { status: 400 })
        }

        return NextResponse.json({ 
          success: true, 
          job: {
            id: resultJob.id,
            url: resultJob.url,
            status: resultJob.status,
            completedAt: resultJob.completedAt,
            businesses: resultJob.result || [],
          }
        })

      case 'cancel-job':
        const { jobId: cancelJobId } = params

        if (!cancelJobId) {
          return NextResponse.json({ error: 'Job ID is required' }, { status: 400 })
        }

        const cancelled = enhancedScrapingEngine.cancelJob(cancelJobId)
        
        return NextResponse.json({ 
          success: cancelled, 
          message: cancelled ? 'Job cancelled successfully' : 'Job not found or cannot be cancelled'
        })

      case 'get-stats':
        const stats = enhancedScrapingEngine.getStats()
        
        return NextResponse.json({ 
          success: true, 
          stats
        })

      case 'scrape-website-enhanced':
        const { url: scrapeUrl, depth: scrapeDepth = 2, maxPages: scrapeMaxPages = 5 } = params

        // Validate URL
        if (!scrapeUrl || typeof scrapeUrl !== 'string') {
          return NextResponse.json({ error: 'URL parameter is required' }, { status: 400 })
        }

        const sanitizedScrapeUrl = validationService.sanitizeInput(scrapeUrl)

        // Basic URL validation
        try {
          new URL(sanitizedScrapeUrl)
        } catch {
          return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 })
        }

        // Validate depth and maxPages
        const numScrapeDepth = Math.min(Math.max(parseInt(scrapeDepth) || 2, 1), 5)
        const numScrapeMaxPages = Math.min(Math.max(parseInt(scrapeMaxPages) || 5, 1), 20)

        const businesses = await scraperService.scrapeWebsiteEnhanced(sanitizedScrapeUrl, numScrapeDepth, numScrapeMaxPages)
        
        return NextResponse.json({
          success: true,
          businesses,
          url: sanitizedScrapeUrl,
          depth: numScrapeDepth,
          maxPages: numScrapeMaxPages,
          count: businesses.length
        })

      case 'wait-for-jobs':
        const { jobIds: waitJobIds, timeout = 300000 } = params

        if (!Array.isArray(waitJobIds) || waitJobIds.length === 0) {
          return NextResponse.json({ error: 'Job IDs array is required' }, { status: 400 })
        }

        const completedJobs = await scraperService.waitForEnhancedJobs(
          waitJobIds, 
          Math.min(parseInt(timeout) || 300000, 600000) // Max 10 minutes
        )

        return NextResponse.json({ 
          success: true, 
          completedJobs: completedJobs.map(job => ({
            id: job.id,
            url: job.url,
            status: job.status,
            completedAt: job.completedAt,
            resultCount: job.result?.length || 0,
            error: job.error,
          })),
          totalCompleted: completedJobs.length,
          totalRequested: waitJobIds.length
        })

      case 'shutdown':
        await enhancedScrapingEngine.shutdown()
        return NextResponse.json({ 
          success: true, 
          message: 'Enhanced scraping engine shutdown' 
        })

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }

  } catch (error) {
    logger.error('EnhancedScrapeAPI', 'Request failed', error)
    
    return NextResponse.json({ 
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

/**
 * GET /api/enhanced-scrape - Get enhanced scraping statistics
 */
export async function GET(request: NextRequest) {
  try {
    const stats = enhancedScrapingEngine.getStats()
    
    return NextResponse.json({ 
      success: true, 
      stats,
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('EnhancedScrapeAPI', 'GET request failed', error)
    
    return NextResponse.json({ 
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
