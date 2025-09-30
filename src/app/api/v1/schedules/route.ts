/**
 * API v1 - Schedules Endpoint
 * RESTful API for export schedule management
 */

import { NextRequest } from 'next/server'
import { apiFramework } from '@/lib/integrations/api-framework'
import { exportSchedulingService } from '@/lib/integrations/scheduling-service'
import { ApiResponse, ApiRequestContext } from '@/types/integrations'
import { logger } from '@/utils/logger'

/**
 * GET /api/v1/schedules - List export schedules
 */
export const GET = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const status = searchParams.get('status') as any
    const templateId = searchParams.get('templateId')

    try {
      const schedules = await exportSchedulingService.listSchedules({
        status,
        templateId: templateId || undefined,
      })

      const statistics = exportSchedulingService.getSchedulingStatistics()

      return {
        success: true,
        data: {
          schedules: schedules.map(schedule => ({
            id: schedule.id,
            name: schedule.name,
            description: schedule.description,
            templateId: schedule.templateId,
            schedule: schedule.schedule,
            status: schedule.status,
            createdAt: schedule.createdAt,
            lastRun: schedule.lastRun,
            nextRun: schedule.nextRun,
            runCount: schedule.runCount,
            successCount: schedule.successCount,
            failureCount: schedule.failureCount,
          })),
          count: schedules.length,
          statistics,
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      }
    } catch (error) {
      logger.error('SchedulesAPI', 'Failed to list schedules', error)
      throw error
    }
  },
  {
    permissions: ['read:exports'],
  }
)

/**
 * POST /api/v1/schedules - Create export schedule
 */
export const POST = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { name, description, templateId, schedule, filters, delivery } = body

      // Validation
      if (!name || !templateId || !schedule || !delivery) {
        throw new Error('Missing required fields: name, templateId, schedule, delivery')
      }

      if (!schedule.type || !schedule.expression) {
        throw new Error('Schedule must have type and expression')
      }

      if (!delivery.method || !delivery.destination) {
        throw new Error('Delivery must have method and destination')
      }

      logger.info('SchedulesAPI', `Creating export schedule`, {
        requestId: context.requestId,
        name,
        templateId,
        scheduleType: schedule.type,
        deliveryMethod: delivery.method,
        clientId: context.clientId,
      })

      const newSchedule = await exportSchedulingService.createSchedule({
        name,
        description: description || '',
        templateId,
        schedule: {
          type: schedule.type,
          expression: schedule.expression,
          timezone: schedule.timezone || 'UTC',
        },
        filters: filters || {},
        delivery: {
          method: delivery.method,
          destination: delivery.destination,
          format: delivery.format || 'csv',
          compression: delivery.compression,
        },
      })

      return {
        success: true,
        data: {
          schedule: {
            id: newSchedule.id,
            name: newSchedule.name,
            description: newSchedule.description,
            templateId: newSchedule.templateId,
            schedule: newSchedule.schedule,
            filters: newSchedule.filters,
            delivery: newSchedule.delivery,
            status: newSchedule.status,
            createdAt: newSchedule.createdAt,
            nextRun: newSchedule.nextRun,
          },
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      }
    } catch (error) {
      logger.error('SchedulesAPI', 'Schedule creation failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
      throw error
    }
  },
  {
    permissions: ['write:exports'],
    rateLimit: {
      requestsPerMinute: 10,
      requestsPerHour: 50,
    },
  }
)

/**
 * GET /api/v1/schedules/{id} - Get specific schedule
 */
const getSchedule = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const url = new URL(request.url)
      const pathParts = url.pathname.split('/')
      const scheduleId = pathParts[pathParts.length - 1]

      if (!scheduleId) {
        throw new Error('Schedule ID is required')
      }

      const schedule = await exportSchedulingService.getSchedule(scheduleId)

      if (!schedule) {
        throw new Error('Schedule not found')
      }

      // Get execution history
      const executionHistory = await exportSchedulingService.getExecutionHistory(scheduleId, 10)

      return {
        success: true,
        data: {
          schedule,
          executionHistory: executionHistory.map(exec => ({
            id: exec.id,
            status: exec.status,
            startTime: exec.startTime,
            endTime: exec.endTime,
            duration: exec.duration,
            recordsProcessed: exec.recordsProcessed,
            recordsExported: exec.recordsExported,
            deliveryStatus: exec.deliveryStatus,
            errors: exec.errors,
          })),
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      }
    } catch (error) {
      logger.error('SchedulesAPI', 'Failed to get schedule', error)
      throw error
    }
  },
  {
    permissions: ['read:exports'],
  }
)

/**
 * PUT /api/v1/schedules/{id} - Update schedule
 */
const updateSchedule = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const url = new URL(request.url)
      const pathParts = url.pathname.split('/')
      const scheduleId = pathParts[pathParts.length - 1]

      if (!scheduleId) {
        throw new Error('Schedule ID is required')
      }

      const body = await request.json()
      const updates = body

      logger.info('SchedulesAPI', `Updating schedule: ${scheduleId}`, {
        requestId: context.requestId,
        scheduleId,
        updates: Object.keys(updates),
        clientId: context.clientId,
      })

      const updatedSchedule = await exportSchedulingService.updateSchedule(scheduleId, updates)

      return {
        success: true,
        data: {
          schedule: updatedSchedule,
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      }
    } catch (error) {
      logger.error('SchedulesAPI', 'Schedule update failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
      throw error
    }
  },
  {
    permissions: ['write:exports'],
  }
)

/**
 * DELETE /api/v1/schedules/{id} - Delete schedule
 */
const deleteSchedule = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const url = new URL(request.url)
      const pathParts = url.pathname.split('/')
      const scheduleId = pathParts[pathParts.length - 1]

      if (!scheduleId) {
        throw new Error('Schedule ID is required')
      }

      logger.info('SchedulesAPI', `Deleting schedule: ${scheduleId}`, {
        requestId: context.requestId,
        scheduleId,
        clientId: context.clientId,
      })

      await exportSchedulingService.deleteSchedule(scheduleId)

      return {
        success: true,
        data: {
          message: 'Schedule deleted successfully',
          scheduleId,
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      }
    } catch (error) {
      logger.error('SchedulesAPI', 'Schedule deletion failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
      throw error
    }
  },
  {
    permissions: ['write:exports'],
  }
)

// Named functions for specific endpoints (not exported to avoid Next.js route conflicts)
// These are available internally but not as module exports
