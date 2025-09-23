/**
 * Edge Runtime Compatible Cleanup Service
 * Provides scheduled cleanup functionality without setInterval
 */

import { logger } from '@/utils/logger'

export interface CleanupService {
  name: string
  endpoint: string
  intervalMs: number
  lastRun: number
}

export class EdgeRuntimeCleanupManager {
  private services: CleanupService[] = [
    {
      name: 'sessions',
      endpoint: '/api/cleanup/sessions',
      intervalMs: 5 * 60 * 1000, // 5 minutes
      lastRun: 0
    },
    {
      name: 'csrf-tokens',
      endpoint: '/api/cleanup/csrf-tokens',
      intervalMs: 10 * 60 * 1000, // 10 minutes
      lastRun: 0
    },
    {
      name: 'rate-limits',
      endpoint: '/api/cleanup/rate-limits',
      intervalMs: 5 * 60 * 1000, // 5 minutes
      lastRun: 0
    }
  ]

  private internalApiKey: string

  constructor() {
    this.internalApiKey = process.env.INTERNAL_API_KEY || 'default-internal-key'
  }

  /**
   * Check if any cleanup services need to run and trigger them
   */
  async performScheduledCleanup(): Promise<void> {
    const now = Date.now()
    
    for (const service of this.services) {
      if (now - service.lastRun > service.intervalMs) {
        try {
          await this.triggerCleanup(service)
          service.lastRun = now
        } catch (error) {
          logger.error('Cleanup Manager', `Failed to trigger cleanup for ${service.name}`, error)
        }
      }
    }
  }

  /**
   * Trigger cleanup for a specific service
   */
  private async triggerCleanup(service: CleanupService): Promise<void> {
    try {
      // In Edge Runtime, we can't make HTTP requests to ourselves easily
      // So we'll use dynamic imports to call the cleanup functions directly
      
      if (service.name === 'sessions') {
        const { cleanupExpiredSessions } = await import('@/lib/security')
        cleanupExpiredSessions()
      } else if (service.name === 'csrf-tokens') {
        const { csrfProtectionService } = await import('@/lib/csrfProtection')
        csrfProtectionService.cleanupExpiredTokens()
      } else if (service.name === 'rate-limits') {
        const { advancedRateLimitService } = await import('@/lib/advancedRateLimit')
        // Trigger cleanup by accessing the service
        advancedRateLimitService.getAllRateLimits()
      }
      
      logger.info('Cleanup Manager', `Successfully triggered cleanup for ${service.name}`)
    } catch (error) {
      logger.error('Cleanup Manager', `Failed to trigger cleanup for ${service.name}`, error)
      throw error
    }
  }

  /**
   * Get cleanup status for all services
   */
  getCleanupStatus(): { service: string; lastRun: number; nextRun: number; overdue: boolean }[] {
    const now = Date.now()
    
    return this.services.map(service => ({
      service: service.name,
      lastRun: service.lastRun,
      nextRun: service.lastRun + service.intervalMs,
      overdue: now - service.lastRun > service.intervalMs
    }))
  }

  /**
   * Force cleanup for all services
   */
  async forceCleanupAll(): Promise<void> {
    logger.info('Cleanup Manager', 'Forcing cleanup for all services')
    
    for (const service of this.services) {
      try {
        await this.triggerCleanup(service)
        service.lastRun = Date.now()
      } catch (error) {
        logger.error('Cleanup Manager', `Failed to force cleanup for ${service.name}`, error)
      }
    }
  }
}

// Export singleton instance
export const edgeRuntimeCleanupManager = new EdgeRuntimeCleanupManager()

/**
 * Utility function to trigger cleanup from middleware or other contexts
 */
export async function performCleanupIfNeeded(): Promise<void> {
  try {
    await edgeRuntimeCleanupManager.performScheduledCleanup()
  } catch (error) {
    logger.error('Cleanup Utility', 'Failed to perform scheduled cleanup', error)
  }
}
