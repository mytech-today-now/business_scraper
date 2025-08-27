'use strict'

/**
 * AI Batch Processing API Route
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { NextRequest, NextResponse } from 'next/server'
import { aiService } from '@/lib/aiService'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { AIProcessingJob } from '@/types/ai'

/**
 * POST /api/ai/batch-process
 * Start batch processing of businesses for AI analysis
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { businessIds, analysisType = 'lead-scoring' } = body

    if (!businessIds || !Array.isArray(businessIds) || businessIds.length === 0) {
      return NextResponse.json({ error: 'Business IDs array is required' }, { status: 400 })
    }

    if (businessIds.length > 100) {
      return NextResponse.json(
        { error: 'Maximum 100 businesses can be processed in a single batch' },
        { status: 400 }
      )
    }

    logger.info('AI API', `Starting batch processing for ${businessIds.length} businesses`)

    // Initialize AI service if needed
    if (!aiService.isInitialized()) {
      await aiService.initialize()
    }

    // Create processing jobs
    const jobs: AIProcessingJob[] = []
    const jobPromises: Promise<void>[] = []

    for (const businessId of businessIds) {
      const job: AIProcessingJob = {
        id: `job-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: 'batch-processing',
        status: 'pending',
        businessId,
        progress: 0,
        result: null,
        error: null,
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
      }

      jobs.push(job)

      // Save job to storage
      await storage.saveAIJob(job)

      // Start processing (don't await - run in background)
      const processPromise = processBusinessJob(job)
      jobPromises.push(processPromise)
    }

    // Don't wait for all jobs to complete - return immediately
    logger.info('AI API', `Created ${jobs.length} processing jobs`)

    return NextResponse.json({
      success: true,
      data: {
        jobIds: jobs.map(job => job.id),
        totalJobs: jobs.length,
        message: 'Batch processing started. Use job IDs to check progress.',
      },
    })
  } catch (error) {
    logger.error('AI API', 'Batch processing failed', error)
    return NextResponse.json(
      {
        error: 'Failed to start batch processing',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * GET /api/ai/batch-process?jobId=xxx or ?status=xxx
 * Get batch processing job status
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url)
    const jobId = searchParams.get('jobId')
    const status = searchParams.get('status')

    if (jobId) {
      // Get specific job
      const job = await storage.getAIJob(jobId)
      if (!job) {
        return NextResponse.json({ error: 'Job not found' }, { status: 404 })
      }

      return NextResponse.json({
        success: true,
        data: job,
      })
    } else if (status) {
      // Get jobs by status
      const jobs = await storage.getAIJobsByStatus(status)
      return NextResponse.json({
        success: true,
        data: jobs,
      })
    } else {
      // Get all recent jobs (last 24 hours)
      const allJobs = await storage.getAIJobsByStatus('pending')
      const runningJobs = await storage.getAIJobsByStatus('running')
      const completedJobs = await storage.getAIJobsByStatus('completed')
      const failedJobs = await storage.getAIJobsByStatus('failed')

      return NextResponse.json({
        success: true,
        data: {
          pending: allJobs.length,
          running: runningJobs.length,
          completed: completedJobs.length,
          failed: failedJobs.length,
          jobs: [...allJobs, ...runningJobs, ...completedJobs, ...failedJobs]
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
            .slice(0, 50), // Return last 50 jobs
        },
      })
    }
  } catch (error) {
    logger.error('AI API', 'Failed to get batch processing status', error)
    return NextResponse.json(
      {
        error: 'Failed to get batch processing status',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Process a single business job
 */
async function processBusinessJob(job: AIProcessingJob): Promise<void> {
  try {
    // Update job status to running
    await storage.updateAIJobStatus(job.id, 'running')

    logger.info('AI API', `Processing job ${job.id} for business ${job.businessId}`)

    // Get business record
    const business = await storage.getBusiness(job.businessId)
    if (!business) {
      await storage.updateAIJobStatus(job.id, 'failed', undefined, 'Business not found')
      return
    }

    // Update progress
    job.progress = 0.2
    await storage.saveAIJob(job)

    // Run AI analysis
    const analytics = await aiService.analyzeBusinessRecord(business)

    // Update progress
    job.progress = 0.8
    await storage.saveAIJob(job)

    // Save analytics
    await storage.saveAIAnalytics(job.businessId, analytics)

    // Complete job
    await storage.updateAIJobStatus(job.id, 'completed', analytics)

    logger.info('AI API', `Completed job ${job.id} for business ${business.businessName}`)
  } catch (error) {
    logger.error('AI API', `Failed to process job ${job.id}`, error)
    await storage.updateAIJobStatus(
      job.id,
      'failed',
      undefined,
      error instanceof Error ? error.message : 'Unknown error'
    )
  }
}

/**
 * DELETE /api/ai/batch-process?jobId=xxx
 * Cancel or delete a batch processing job
 */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url)
    const jobId = searchParams.get('jobId')

    if (!jobId) {
      return NextResponse.json({ error: 'Job ID is required' }, { status: 400 })
    }

    logger.info('AI API', `Deleting job: ${jobId}`)

    // Get job to check status
    const job = await storage.getAIJob(jobId)
    if (!job) {
      return NextResponse.json({ error: 'Job not found' }, { status: 404 })
    }

    // Only allow deletion of completed or failed jobs
    if (job.status === 'running') {
      return NextResponse.json(
        { error: 'Cannot delete running job. Wait for completion or failure.' },
        { status: 400 }
      )
    }

    // Delete job
    await storage.deleteAIJob(jobId)

    return NextResponse.json({
      success: true,
      message: 'Job deleted successfully',
    })
  } catch (error) {
    logger.error('AI API', 'Failed to delete job', error)
    return NextResponse.json(
      {
        error: 'Failed to delete job',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
