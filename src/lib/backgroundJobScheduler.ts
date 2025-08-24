'use strict'

/**
 * Background Job Scheduler - Automation and scheduled tasks
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { aiService } from './aiService'
import { predictiveAnalyticsEngine } from './predictiveAnalyticsEngine'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { AIProcessingJob, AIInsightsSummary } from '@/types/ai'

/**
 * Job definition interface
 */
interface ScheduledJob {
  id: string
  name: string
  schedule: string // Cron-like schedule
  handler: () => Promise<void>
  enabled: boolean
  lastRun?: Date
  nextRun?: Date
}

/**
 * Background Job Scheduler class
 * Handles automated tasks and scheduled operations
 */
export class BackgroundJobScheduler {
  private jobs: Map<string, ScheduledJob> = new Map()
  private intervals: Map<string, NodeJS.Timeout> = new Map()
  private running = false

  constructor() {
    this.setupDefaultJobs()
  }

  /**
   * Setup default scheduled jobs
   */
  private setupDefaultJobs(): void {
    // Daily insights generation
    this.addJob({
      id: 'daily-insights',
      name: 'Generate Daily AI Insights',
      schedule: '0 6 * * *', // 6 AM daily
      handler: this.generateDailyInsights.bind(this),
      enabled: true
    })

    // Weekly trend analysis
    this.addJob({
      id: 'weekly-trends',
      name: 'Weekly Industry Trend Analysis',
      schedule: '0 8 * * 1', // 8 AM every Monday
      handler: this.analyzeWeeklyTrends.bind(this),
      enabled: true
    })

    // Hourly job processing
    this.addJob({
      id: 'process-pending-jobs',
      name: 'Process Pending AI Jobs',
      schedule: '0 * * * *', // Every hour
      handler: this.processPendingJobs.bind(this),
      enabled: true
    })

    // Daily cleanup
    this.addJob({
      id: 'daily-cleanup',
      name: 'Daily Data Cleanup',
      schedule: '0 2 * * *', // 2 AM daily
      handler: this.performDailyCleanup.bind(this),
      enabled: true
    })

    // Model retraining (weekly)
    this.addJob({
      id: 'model-retraining',
      name: 'Weekly Model Retraining',
      schedule: '0 3 * * 0', // 3 AM every Sunday
      handler: this.performModelRetraining.bind(this),
      enabled: false // Disabled by default
    })
  }

  /**
   * Add a new scheduled job
   */
  addJob(job: ScheduledJob): void {
    this.jobs.set(job.id, job)
    logger.info('BackgroundJobScheduler', `Added job: ${job.name}`)
  }

  /**
   * Remove a scheduled job
   */
  removeJob(jobId: string): void {
    const interval = this.intervals.get(jobId)
    if (interval) {
      clearInterval(interval)
      this.intervals.delete(jobId)
    }
    this.jobs.delete(jobId)
    logger.info('BackgroundJobScheduler', `Removed job: ${jobId}`)
  }

  /**
   * Start the job scheduler
   */
  start(): void {
    if (this.running) {
      logger.warn('BackgroundJobScheduler', 'Scheduler is already running')
      return
    }

    this.running = true
    logger.info('BackgroundJobScheduler', 'Starting background job scheduler')

    // Start all enabled jobs
    for (const [jobId, job] of this.jobs) {
      if (job.enabled) {
        this.scheduleJob(jobId, job)
      }
    }

    logger.info('BackgroundJobScheduler', `Started ${this.intervals.size} scheduled jobs`)
  }

  /**
   * Stop the job scheduler
   */
  stop(): void {
    if (!this.running) {
      return
    }

    this.running = false
    logger.info('BackgroundJobScheduler', 'Stopping background job scheduler')

    // Clear all intervals
    for (const [jobId, interval] of this.intervals) {
      clearInterval(interval)
    }
    this.intervals.clear()

    logger.info('BackgroundJobScheduler', 'Background job scheduler stopped')
  }

  /**
   * Schedule a specific job
   */
  private scheduleJob(jobId: string, job: ScheduledJob): void {
    // For simplicity, we'll use intervals instead of full cron parsing
    // In production, you'd use a proper cron library
    const intervalMs = this.parseScheduleToInterval(job.schedule)
    
    if (intervalMs > 0) {
      const interval = setInterval(async () => {
        await this.executeJob(jobId, job)
      }, intervalMs)
      
      this.intervals.set(jobId, interval)
      logger.info('BackgroundJobScheduler', `Scheduled job: ${job.name} (${intervalMs}ms interval)`)
    }
  }

  /**
   * Parse schedule to interval (simplified)
   */
  private parseScheduleToInterval(schedule: string): number {
    // Simplified schedule parsing
    // In production, use a proper cron parser
    switch (schedule) {
      case '0 * * * *': // Every hour
        return 60 * 60 * 1000
      case '0 6 * * *': // Daily at 6 AM
        return 24 * 60 * 60 * 1000
      case '0 8 * * 1': // Weekly on Monday at 8 AM
        return 7 * 24 * 60 * 60 * 1000
      case '0 2 * * *': // Daily at 2 AM
        return 24 * 60 * 60 * 1000
      case '0 3 * * 0': // Weekly on Sunday at 3 AM
        return 7 * 24 * 60 * 60 * 1000
      default:
        logger.warn('BackgroundJobScheduler', `Unknown schedule format: ${schedule}`)
        return 0
    }
  }

  /**
   * Execute a job
   */
  private async executeJob(jobId: string, job: ScheduledJob): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', `Executing job: ${job.name}`)
      
      const startTime = Date.now()
      await job.handler()
      const duration = Date.now() - startTime
      
      // Update job metadata
      job.lastRun = new Date()
      job.nextRun = new Date(Date.now() + this.parseScheduleToInterval(job.schedule))
      
      logger.info('BackgroundJobScheduler', `Job completed: ${job.name} (${duration}ms)`)
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', `Job failed: ${job.name}`, error)
    }
  }

  /**
   * Generate daily AI insights
   */
  private async generateDailyInsights(): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', 'Generating daily AI insights')
      
      // Get all businesses with analytics
      const allAnalytics = await storage.getAllAIAnalytics()
      
      if (allAnalytics.length === 0) {
        logger.info('BackgroundJobScheduler', 'No analytics data available for insights generation')
        return
      }

      // Generate insights summary
      const insights: AIInsightsSummary = {
        totalAnalyzed: allAnalytics.length,
        averageLeadScore: Math.round(
          allAnalytics.reduce((sum, a) => sum + a.leadScoring.overallScore, 0) / allAnalytics.length
        ),
        highPriorityLeads: allAnalytics.filter(a => a.leadScoring.overallScore >= 80).length,
        topIndustries: ['Technology', 'Healthcare', 'Finance'], // Simplified
        keyTrends: [
          'AI adoption increasing across industries',
          'Remote work driving digital transformation',
          'Sustainability becoming key business priority'
        ],
        recommendations: [
          'Focus on high-scoring leads for immediate outreach',
          'Develop industry-specific messaging strategies',
          'Implement automated follow-up sequences'
        ],
        generatedAt: new Date()
      }

      // Save insights
      await storage.saveAIInsights(insights)
      
      logger.info('BackgroundJobScheduler', 'Daily insights generated successfully')
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', 'Failed to generate daily insights', error)
    }
  }

  /**
   * Analyze weekly trends
   */
  private async analyzeWeeklyTrends(): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', 'Analyzing weekly industry trends')
      
      // Initialize predictive analytics engine
      if (!predictiveAnalyticsEngine.isInitialized()) {
        await predictiveAnalyticsEngine.initialize()
      }

      // Analyze trends for major industries
      const industries = ['Technology', 'Healthcare', 'Finance', 'Construction', 'Retail']
      
      for (const industry of industries) {
        try {
          const trendAnalysis = await predictiveAnalyticsEngine.analyzeIndustryTrends(industry)
          logger.info('BackgroundJobScheduler', `Analyzed trends for ${industry}: ${trendAnalysis.trendDirection}`)
        } catch (error) {
          logger.warn('BackgroundJobScheduler', `Failed to analyze trends for ${industry}`, error)
        }
      }
      
      logger.info('BackgroundJobScheduler', 'Weekly trend analysis completed')
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', 'Failed to analyze weekly trends', error)
    }
  }

  /**
   * Process pending AI jobs
   */
  private async processPendingJobs(): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', 'Processing pending AI jobs')
      
      // Get pending jobs
      const pendingJobs = await storage.getAIJobsByStatus('pending')
      
      if (pendingJobs.length === 0) {
        logger.info('BackgroundJobScheduler', 'No pending AI jobs to process')
        return
      }

      // Initialize AI service
      if (!aiService.isInitialized()) {
        await aiService.initialize()
      }

      // Process up to 5 jobs at a time
      const jobsToProcess = pendingJobs.slice(0, 5)
      
      for (const job of jobsToProcess) {
        try {
          // Update job status
          await storage.updateAIJobStatus(job.id, 'running')
          
          // Get business record
          const business = await storage.getBusiness(job.businessId)
          if (!business) {
            await storage.updateAIJobStatus(job.id, 'failed', undefined, 'Business not found')
            continue
          }

          // Run AI analysis
          const analytics = await aiService.analyzeBusinessRecord(business)
          
          // Save results
          await storage.saveAIAnalytics(job.businessId, analytics)
          await storage.updateAIJobStatus(job.id, 'completed', analytics)
          
          logger.info('BackgroundJobScheduler', `Processed job ${job.id} for business ${business.businessName}`)
          
        } catch (error) {
          logger.error('BackgroundJobScheduler', `Failed to process job ${job.id}`, error)
          await storage.updateAIJobStatus(
            job.id, 
            'failed', 
            undefined, 
            error instanceof Error ? error.message : 'Unknown error'
          )
        }
      }
      
      logger.info('BackgroundJobScheduler', `Processed ${jobsToProcess.length} AI jobs`)
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', 'Failed to process pending jobs', error)
    }
  }

  /**
   * Perform daily cleanup
   */
  private async performDailyCleanup(): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', 'Performing daily cleanup')
      
      // Clean up old completed jobs (older than 7 days)
      const completedJobs = await storage.getAIJobsByStatus('completed')
      const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      
      let cleanedJobs = 0
      for (const job of completedJobs) {
        if (job.completedAt && job.completedAt < weekAgo) {
          await storage.deleteAIJob(job.id)
          cleanedJobs++
        }
      }
      
      // Clean up old failed jobs (older than 3 days)
      const failedJobs = await storage.getAIJobsByStatus('failed')
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000)
      
      for (const job of failedJobs) {
        if (job.completedAt && job.completedAt < threeDaysAgo) {
          await storage.deleteAIJob(job.id)
          cleanedJobs++
        }
      }
      
      logger.info('BackgroundJobScheduler', `Daily cleanup completed: removed ${cleanedJobs} old jobs`)
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', 'Failed to perform daily cleanup', error)
    }
  }

  /**
   * Perform model retraining
   */
  private async performModelRetraining(): Promise<void> {
    try {
      logger.info('BackgroundJobScheduler', 'Performing model retraining')
      
      // This would implement actual model retraining logic
      // For now, just log the operation
      logger.info('BackgroundJobScheduler', 'Model retraining completed (placeholder)')
      
    } catch (error) {
      logger.error('BackgroundJobScheduler', 'Failed to perform model retraining', error)
    }
  }

  /**
   * Get job status
   */
  getJobStatus(): { id: string; name: string; enabled: boolean; lastRun?: Date; nextRun?: Date }[] {
    return Array.from(this.jobs.values()).map(job => ({
      id: job.id,
      name: job.name,
      enabled: job.enabled,
      lastRun: job.lastRun,
      nextRun: job.nextRun
    }))
  }

  /**
   * Enable/disable a job
   */
  setJobEnabled(jobId: string, enabled: boolean): void {
    const job = this.jobs.get(jobId)
    if (job) {
      job.enabled = enabled
      
      if (this.running) {
        if (enabled) {
          this.scheduleJob(jobId, job)
        } else {
          const interval = this.intervals.get(jobId)
          if (interval) {
            clearInterval(interval)
            this.intervals.delete(jobId)
          }
        }
      }
      
      logger.info('BackgroundJobScheduler', `Job ${job.name} ${enabled ? 'enabled' : 'disabled'}`)
    }
  }
}

// Export singleton instance
export const backgroundJobScheduler = new BackgroundJobScheduler()
