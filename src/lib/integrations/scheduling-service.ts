/**
 * Export Scheduling Service
 * Automated export scheduling with configurable intervals and delivery methods
 */

import { ExportScheduleConfig, ScheduledExportResult } from '@/types/integrations'
import { BusinessRecord } from '@/types/business'
import { enhancedExportService } from '@/lib/enhanced-export-service'
import { webhookService } from './webhook-service'
import { logger } from '@/utils/logger'
import cron from 'node-cron'

/**
 * Export Scheduling Service implementation
 */
export class ExportSchedulingService {
  private schedules: Map<string, ExportScheduleConfig> = new Map()
  private cronJobs: Map<string, any> = new Map()
  private executionHistory: Map<string, ScheduledExportResult[]> = new Map()

  constructor() {
    this.initializeService()
  }

  /**
   * Initialize the scheduling service
   */
  private initializeService(): void {
    logger.info('SchedulingService', 'Initializing export scheduling service')

    // Start cleanup interval for old execution history
    setInterval(
      () => {
        this.cleanupExecutionHistory()
      },
      24 * 60 * 60 * 1000
    ) // Daily cleanup
  }

  /**
   * Create export schedule
   */
  async createSchedule(
    scheduleData: Omit<
      ExportScheduleConfig,
      'id' | 'status' | 'createdAt' | 'updatedAt' | 'runCount' | 'successCount' | 'failureCount'
    >
  ): Promise<ExportScheduleConfig> {
    const scheduleId = this.generateScheduleId()

    const schedule: ExportScheduleConfig = {
      id: scheduleId,
      name: scheduleData.name,
      description: scheduleData.description,
      templateId: scheduleData.templateId,
      schedule: scheduleData.schedule,
      filters: scheduleData.filters,
      delivery: scheduleData.delivery,
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      runCount: 0,
      successCount: 0,
      failureCount: 0,
    }

    // Validate schedule expression
    if (!this.validateScheduleExpression(schedule.schedule)) {
      throw new Error('Invalid schedule expression')
    }

    // Validate template exists
    const template = enhancedExportService.getTemplate(schedule.templateId)
    if (!template) {
      throw new Error(`Template not found: ${schedule.templateId}`)
    }

    this.schedules.set(scheduleId, schedule)
    this.executionHistory.set(scheduleId, [])

    // Start the cron job
    await this.startSchedule(scheduleId)

    logger.info('SchedulingService', `Created export schedule: ${scheduleId}`, {
      scheduleId,
      name: schedule.name,
      templateId: schedule.templateId,
      expression: schedule.schedule.expression,
    })

    return schedule
  }

  /**
   * Update export schedule
   */
  async updateSchedule(
    scheduleId: string,
    updates: Partial<ExportScheduleConfig>
  ): Promise<ExportScheduleConfig> {
    const schedule = this.schedules.get(scheduleId)
    if (!schedule) {
      throw new Error('Schedule not found')
    }

    // Stop current cron job if schedule expression is changing
    if (updates.schedule && updates.schedule.expression !== schedule.schedule.expression) {
      await this.stopSchedule(scheduleId)
    }

    const updatedSchedule: ExportScheduleConfig = {
      ...schedule,
      ...updates,
      id: scheduleId, // Prevent ID changes
      updatedAt: new Date().toISOString(),
    }

    // Validate new schedule expression if provided
    if (updates.schedule) {
      if (!this.validateScheduleExpression(updatedSchedule.schedule)) {
        throw new Error('Invalid schedule expression')
      }
    }

    this.schedules.set(scheduleId, updatedSchedule)

    // Restart cron job if it was stopped
    if (updates.schedule && updatedSchedule.status === 'active') {
      await this.startSchedule(scheduleId)
    }

    logger.info('SchedulingService', `Updated export schedule: ${scheduleId}`, {
      scheduleId,
      updates: Object.keys(updates),
    })

    return updatedSchedule
  }

  /**
   * Delete export schedule
   */
  async deleteSchedule(scheduleId: string): Promise<void> {
    const schedule = this.schedules.get(scheduleId)
    if (!schedule) {
      throw new Error('Schedule not found')
    }

    // Stop cron job
    await this.stopSchedule(scheduleId)

    // Remove from storage
    this.schedules.delete(scheduleId)
    this.executionHistory.delete(scheduleId)

    logger.info('SchedulingService', `Deleted export schedule: ${scheduleId}`)
  }

  /**
   * Get export schedule
   */
  async getSchedule(scheduleId: string): Promise<ExportScheduleConfig | null> {
    return this.schedules.get(scheduleId) || null
  }

  /**
   * List export schedules
   */
  async listSchedules(filters?: {
    status?: 'active' | 'inactive' | 'paused'
    templateId?: string
  }): Promise<ExportScheduleConfig[]> {
    let schedules = Array.from(this.schedules.values())

    if (filters?.status) {
      schedules = schedules.filter(s => s.status === filters.status)
    }

    if (filters?.templateId) {
      schedules = schedules.filter(s => s.templateId === filters.templateId)
    }

    return schedules
  }

  /**
   * Start schedule (activate cron job)
   */
  async startSchedule(scheduleId: string): Promise<void> {
    const schedule = this.schedules.get(scheduleId)
    if (!schedule) {
      throw new Error('Schedule not found')
    }

    if (schedule.status !== 'active') {
      throw new Error('Schedule is not active')
    }

    // Stop existing cron job if any
    await this.stopSchedule(scheduleId)

    try {
      let cronExpression: string

      if (schedule.schedule.type === 'cron') {
        cronExpression = schedule.schedule.expression
      } else {
        // Convert interval to cron expression
        cronExpression = this.intervalToCron(schedule.schedule.expression)
      }

      const cronJob = cron.schedule(
        cronExpression,
        async () => {
          await this.executeScheduledExport(scheduleId)
        },
        {
          scheduled: true,
          timezone: schedule.schedule.timezone || 'UTC',
        }
      )

      this.cronJobs.set(scheduleId, cronJob)

      // Update next run time
      schedule.nextRun = this.calculateNextRun(schedule.schedule)
      this.schedules.set(scheduleId, schedule)

      logger.info('SchedulingService', `Started schedule: ${scheduleId}`, {
        scheduleId,
        cronExpression,
        nextRun: schedule.nextRun,
      })
    } catch (error) {
      logger.error('SchedulingService', `Failed to start schedule: ${scheduleId}`, error)
      throw error
    }
  }

  /**
   * Stop schedule (deactivate cron job)
   */
  async stopSchedule(scheduleId: string): Promise<void> {
    const cronJob = this.cronJobs.get(scheduleId)
    if (cronJob) {
      cronJob.stop()
      cronJob.destroy()
      this.cronJobs.delete(scheduleId)

      logger.info('SchedulingService', `Stopped schedule: ${scheduleId}`)
    }
  }

  /**
   * Execute scheduled export
   */
  private async executeScheduledExport(scheduleId: string): Promise<void> {
    const schedule = this.schedules.get(scheduleId)
    if (!schedule) {
      logger.error('SchedulingService', `Schedule not found during execution: ${scheduleId}`)
      return
    }

    const executionId = this.generateExecutionId()
    const startTime = new Date().toISOString()

    logger.info('SchedulingService', `Executing scheduled export: ${scheduleId}`, {
      scheduleId,
      executionId,
      templateId: schedule.templateId,
    })

    try {
      // Update run statistics
      schedule.runCount++
      schedule.lastRun = startTime
      schedule.nextRun = this.calculateNextRun(schedule.schedule)

      // Get business data (this would typically come from your data source)
      const businesses = await this.getBusinessDataForExport(schedule.filters)

      if (businesses.length === 0) {
        logger.warn(
          'SchedulingService',
          `No business data found for scheduled export: ${scheduleId}`
        )

        const result: ScheduledExportResult = {
          id: executionId,
          scheduleId,
          templateId: schedule.templateId,
          status: 'success',
          startTime,
          endTime: new Date().toISOString(),
          duration: 0,
          recordsProcessed: 0,
          recordsExported: 0,
          errors: ['No business data found matching filters'],
          deliveryStatus: 'pending',
        }

        this.recordExecutionResult(scheduleId, result)
        return
      }

      // Execute export
      const exportResult = await enhancedExportService.exportWithTemplate(
        schedule.templateId,
        businesses,
        {
          validateData: true,
          skipErrors: true,
          includeMetadata: true,
        }
      )

      const endTime = new Date().toISOString()
      const duration = new Date(endTime).getTime() - new Date(startTime).getTime()

      const result: ScheduledExportResult = {
        id: executionId,
        scheduleId,
        templateId: schedule.templateId,
        status: exportResult.success ? 'success' : 'failed',
        startTime,
        endTime,
        duration,
        recordsProcessed: exportResult.recordsProcessed,
        recordsExported: exportResult.recordsExported,
        errors: exportResult.errors.map(e => e.error),
        deliveryStatus: 'pending',
      }

      // Handle delivery
      if (exportResult.success && exportResult.exportData.length > 0) {
        try {
          await this.deliverExportResult(schedule, exportResult, result)
          result.deliveryStatus = 'delivered'
          schedule.successCount++
        } catch (deliveryError) {
          result.deliveryStatus = 'failed'
          result.deliveryDetails = {
            method: schedule.delivery.method,
            destination: schedule.delivery.destination,
            error: deliveryError instanceof Error ? deliveryError.message : 'Delivery failed',
          }
          schedule.failureCount++
        }
      } else {
        schedule.failureCount++
      }

      this.recordExecutionResult(scheduleId, result)
      this.schedules.set(scheduleId, schedule)

      // Trigger webhook event
      await webhookService.triggerEvent('export.completed', {
        scheduleId,
        executionId,
        templateId: schedule.templateId,
        status: result.status,
        recordsExported: result.recordsExported,
      })

      logger.info('SchedulingService', `Completed scheduled export: ${scheduleId}`, {
        scheduleId,
        executionId,
        status: result.status,
        recordsExported: result.recordsExported,
        duration: result.duration,
      })
    } catch (error) {
      const endTime = new Date().toISOString()
      const duration = new Date(endTime).getTime() - new Date(startTime).getTime()

      const result: ScheduledExportResult = {
        id: executionId,
        scheduleId,
        templateId: schedule.templateId,
        status: 'failed',
        startTime,
        endTime,
        duration,
        recordsProcessed: 0,
        recordsExported: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        deliveryStatus: 'failed',
      }

      schedule.failureCount++
      this.recordExecutionResult(scheduleId, result)
      this.schedules.set(scheduleId, schedule)

      // Trigger webhook event
      await webhookService.triggerEvent('export.failed', {
        scheduleId,
        executionId,
        templateId: schedule.templateId,
        error: result.errors[0],
      })

      logger.error('SchedulingService', `Scheduled export failed: ${scheduleId}`, error)
    }
  }

  /**
   * Get business data for export based on filters
   */
  private async getBusinessDataForExport(
    filters?: ExportScheduleConfig['filters']
  ): Promise<BusinessRecord[]> {
    // This is a placeholder implementation
    // In a real application, this would query your business data source
    // with the provided filters (industries, locations, date range, etc.)

    logger.info('SchedulingService', 'Getting business data for scheduled export', { filters })

    // Return empty array for now - this would be replaced with actual data fetching
    return []
  }

  /**
   * Deliver export result based on delivery configuration
   */
  private async deliverExportResult(
    schedule: ExportScheduleConfig,
    exportResult: any,
    executionResult: ScheduledExportResult
  ): Promise<void> {
    const { method, destination, format, compression } = schedule.delivery

    switch (method) {
      case 'webhook':
        await this.deliverViaWebhook(destination, exportResult, executionResult)
        break
      case 'email':
        await this.deliverViaEmail(destination, exportResult, executionResult, format, compression)
        break
      case 'ftp':
        await this.deliverViaFTP(destination, exportResult, executionResult, format, compression)
        break
      case 'api':
        await this.deliverViaAPI(destination, exportResult, executionResult)
        break
      default:
        throw new Error(`Unsupported delivery method: ${method}`)
    }
  }

  /**
   * Deliver via webhook
   */
  private async deliverViaWebhook(
    webhookUrl: string,
    exportResult: any,
    executionResult: ScheduledExportResult
  ): Promise<void> {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Export-ID': executionResult.id,
        'X-Schedule-ID': executionResult.scheduleId,
      },
      body: JSON.stringify({
        executionResult,
        exportData: exportResult.exportData,
      }),
    })

    if (!response.ok) {
      throw new Error(`Webhook delivery failed: ${response.status} ${response.statusText}`)
    }

    executionResult.deliveryDetails = {
      method: 'webhook',
      destination: webhookUrl,
      deliveredAt: new Date().toISOString(),
    }
  }

  /**
   * Deliver via email (placeholder)
   */
  private async deliverViaEmail(
    email: string,
    exportResult: any,
    executionResult: ScheduledExportResult,
    format?: string,
    compression?: string
  ): Promise<void> {
    // Placeholder for email delivery implementation
    logger.info('SchedulingService', 'Email delivery not yet implemented', {
      email,
      format,
      compression,
    })

    executionResult.deliveryDetails = {
      method: 'email',
      destination: email,
      deliveredAt: new Date().toISOString(),
    }
  }

  /**
   * Deliver via FTP (placeholder)
   */
  private async deliverViaFTP(
    ftpUrl: string,
    exportResult: any,
    executionResult: ScheduledExportResult,
    format?: string,
    compression?: string
  ): Promise<void> {
    // Placeholder for FTP delivery implementation
    logger.info('SchedulingService', 'FTP delivery not yet implemented', {
      ftpUrl,
      format,
      compression,
    })

    executionResult.deliveryDetails = {
      method: 'ftp',
      destination: ftpUrl,
      deliveredAt: new Date().toISOString(),
    }
  }

  /**
   * Deliver via API (placeholder)
   */
  private async deliverViaAPI(
    apiUrl: string,
    exportResult: any,
    executionResult: ScheduledExportResult
  ): Promise<void> {
    // Placeholder for API delivery implementation
    logger.info('SchedulingService', 'API delivery not yet implemented', {
      apiUrl,
    })

    executionResult.deliveryDetails = {
      method: 'api',
      destination: apiUrl,
      deliveredAt: new Date().toISOString(),
    }
  }

  /**
   * Record execution result
   */
  private recordExecutionResult(scheduleId: string, result: ScheduledExportResult): void {
    const history = this.executionHistory.get(scheduleId) || []
    history.push(result)

    // Keep only last 100 executions
    if (history.length > 100) {
      history.splice(0, history.length - 100)
    }

    this.executionHistory.set(scheduleId, history)
  }

  /**
   * Get execution history
   */
  async getExecutionHistory(
    scheduleId: string,
    limit: number = 50
  ): Promise<ScheduledExportResult[]> {
    const history = this.executionHistory.get(scheduleId) || []
    return history.slice(-limit).reverse()
  }

  /**
   * Validate schedule expression
   */
  private validateScheduleExpression(schedule: ExportScheduleConfig['schedule']): boolean {
    try {
      if (schedule.type === 'cron') {
        return cron.validate(schedule.expression)
      } else {
        // Validate interval format (e.g., '1h', '30m', '1d')
        return /^\d+[mhd]$/.test(schedule.expression)
      }
    } catch {
      return false
    }
  }

  /**
   * Convert interval to cron expression
   */
  private intervalToCron(interval: string): string {
    const match = interval.match(/^(\d+)([mhd])$/)
    if (!match) {
      throw new Error('Invalid interval format')
    }

    const [, value, unit] = match
    const num = parseInt(value)

    switch (unit) {
      case 'm': // minutes
        return `*/${num} * * * *`
      case 'h': // hours
        return `0 */${num} * * *`
      case 'd': // days
        return `0 0 */${num} * *`
      default:
        throw new Error('Invalid interval unit')
    }
  }

  /**
   * Calculate next run time
   */
  private calculateNextRun(schedule: ExportScheduleConfig['schedule']): string {
    // This is a simplified implementation
    // In a real application, you would use a proper cron parser
    const now = new Date()
    const nextRun = new Date(now.getTime() + 60 * 60 * 1000) // Add 1 hour as placeholder
    return nextRun.toISOString()
  }

  /**
   * Cleanup old execution history
   */
  private cleanupExecutionHistory(): void {
    const cutoffDate = new Date()
    cutoffDate.setDate(cutoffDate.getDate() - 30) // Keep 30 days

    for (const [scheduleId, history] of this.executionHistory.entries()) {
      const filteredHistory = history.filter(result => new Date(result.startTime) > cutoffDate)

      if (filteredHistory.length !== history.length) {
        this.executionHistory.set(scheduleId, filteredHistory)
        logger.debug(
          'SchedulingService',
          `Cleaned up execution history for schedule: ${scheduleId}`
        )
      }
    }
  }

  /**
   * Generate unique IDs
   */
  private generateScheduleId(): string {
    return `schedule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Get scheduling statistics
   */
  getSchedulingStatistics(): {
    totalSchedules: number
    activeSchedules: number
    totalExecutions: number
    successfulExecutions: number
    failedExecutions: number
  } {
    const schedules = Array.from(this.schedules.values())
    const totalSchedules = schedules.length
    const activeSchedules = schedules.filter(s => s.status === 'active').length
    const totalSuccessful = schedules.reduce((sum, s) => sum + s.successCount, 0)
    const totalFailed = schedules.reduce((sum, s) => sum + s.failureCount, 0)

    return {
      totalSchedules,
      activeSchedules,
      totalExecutions: totalSuccessful + totalFailed,
      successfulExecutions: totalSuccessful,
      failedExecutions: totalFailed,
    }
  }
}

// Export singleton instance
export const exportSchedulingService = new ExportSchedulingService()
