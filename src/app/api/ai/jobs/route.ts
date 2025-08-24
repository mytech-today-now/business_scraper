'use strict'

/**
 * Background Jobs Management API Route
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { NextRequest, NextResponse } from 'next/server'
import { backgroundJobScheduler } from '@/lib/backgroundJobScheduler'
import { logger } from '@/utils/logger'

/**
 * GET /api/ai/jobs
 * Get background job status
 */
export async function GET(request: NextRequest) {
  try {
    logger.info('Jobs API', 'Getting background job status')

    const jobStatus = backgroundJobScheduler.getJobStatus()

    return NextResponse.json({
      success: true,
      data: {
        jobs: jobStatus,
        totalJobs: jobStatus.length,
        enabledJobs: jobStatus.filter(job => job.enabled).length,
        lastUpdate: new Date().toISOString()
      }
    })

  } catch (error) {
    logger.error('Jobs API', 'Failed to get job status', error)
    return NextResponse.json(
      { 
        error: 'Failed to get job status',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/ai/jobs
 * Start or manage background jobs
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, jobId, enabled } = body

    logger.info('Jobs API', `Job management request: ${action}`)

    switch (action) {
      case 'start':
        backgroundJobScheduler.start()
        return NextResponse.json({
          success: true,
          message: 'Background job scheduler started'
        })

      case 'stop':
        backgroundJobScheduler.stop()
        return NextResponse.json({
          success: true,
          message: 'Background job scheduler stopped'
        })

      case 'toggle':
        if (!jobId || typeof enabled !== 'boolean') {
          return NextResponse.json(
            { error: 'Job ID and enabled status are required for toggle action' },
            { status: 400 }
          )
        }
        
        backgroundJobScheduler.setJobEnabled(jobId, enabled)
        return NextResponse.json({
          success: true,
          message: `Job ${jobId} ${enabled ? 'enabled' : 'disabled'}`
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action. Use: start, stop, or toggle' },
          { status: 400 }
        )
    }

  } catch (error) {
    logger.error('Jobs API', 'Job management failed', error)
    return NextResponse.json(
      { 
        error: 'Failed to manage jobs',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}
