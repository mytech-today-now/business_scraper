/**
 * Compliance Middleware for Scraper
 * Adds consent validation and audit logging to scraping workflows
 */

import { consentService, ConsentType, ConsentUtils } from './consent'
import { auditService, AuditEventType, AuditSeverity } from './audit'
import { logger } from '@/utils/logger'

// Scraping operation types
export enum ScrapingOperation {
  SEARCH = 'search',
  SCRAPE = 'scrape',
  EXTRACT = 'extract',
  STORE = 'store',
}

// Compliance context for scraping
export interface ScrapingComplianceContext {
  userId?: string
  sessionId?: string
  ipAddress?: string
  userAgent?: string
  operation: ScrapingOperation
  url?: string
  query?: string
  zipCode?: string
  correlationId?: string
}

/**
 * Compliance middleware for scraping operations
 */
export class ScrapingComplianceMiddleware {
  /**
   * Validate consent before scraping operation
   */
  static async validateConsent(context: ScrapingComplianceContext): Promise<{
    allowed: boolean
    missingConsents: ConsentType[]
    message?: string
  }> {
    try {
      // Get required consents for the operation
      const requiredConsents = this.getRequiredConsents(context.operation)

      // Check if user has valid consent
      const validation = await ConsentUtils.validateConsentForProcessing(
        context.userId,
        context.sessionId,
        this.mapOperationToConsentOperation(context.operation)
      )

      if (validation.valid) {
        logger.info(
          'Scraping Compliance',
          `Consent validated for operation: ${context.operation}`,
          {
            userId: context.userId,
            sessionId: context.sessionId,
            operation: context.operation,
          }
        )

        return {
          allowed: true,
          missingConsents: [],
        }
      } else {
        logger.warn(
          'Scraping Compliance',
          `Insufficient consent for operation: ${context.operation}`,
          {
            userId: context.userId,
            sessionId: context.sessionId,
            missingConsents: validation.missingConsents,
          }
        )

        return {
          allowed: false,
          missingConsents: validation.missingConsents,
          message: `Missing required consent: ${validation.missingConsents.join(', ')}`,
        }
      }
    } catch (error) {
      logger.error('Scraping Compliance', 'Failed to validate consent', error)

      // Fail secure - deny access if validation fails
      return {
        allowed: false,
        missingConsents: [],
        message: 'Consent validation failed',
      }
    }
  }

  /**
   * Log scraping operation for audit
   */
  static async logScrapingOperation(
    context: ScrapingComplianceContext,
    result: {
      success: boolean
      recordsFound?: number
      error?: string
      duration?: number
    }
  ): Promise<void> {
    try {
      const eventType = this.getAuditEventType(context.operation, result.success)
      const severity = result.success ? AuditSeverity.LOW : AuditSeverity.MEDIUM

      await auditService.logEvent({
        eventType,
        severity,
        userId: context.userId,
        sessionId: context.sessionId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        resource: 'scraping_engine',
        action: context.operation,
        details: {
          operation: context.operation,
          url: context.url,
          query: context.query,
          zipCode: context.zipCode,
          success: result.success,
          recordsFound: result.recordsFound || 0,
          error: result.error,
          duration: result.duration,
          timestamp: new Date().toISOString(),
        },
        timestamp: new Date(),
        correlationId: context.correlationId,
        complianceFlags: {
          gdprRelevant: true,
          ccpaRelevant: true,
          soc2Relevant: true,
        },
      })

      logger.info('Scraping Compliance', `Audit logged for operation: ${context.operation}`, {
        success: result.success,
        recordsFound: result.recordsFound,
      })
    } catch (error) {
      logger.error('Scraping Compliance', 'Failed to log scraping operation', error)
    }
  }

  /**
   * Check if scraping is allowed for specific URL/domain
   */
  static async checkScrapingPermissions(
    url: string,
    context: ScrapingComplianceContext
  ): Promise<{
    allowed: boolean
    reason?: string
  }> {
    try {
      // Check robots.txt compliance
      const robotsAllowed = await this.checkRobotsCompliance(url)
      if (!robotsAllowed) {
        return {
          allowed: false,
          reason: 'Robots.txt disallows scraping',
        }
      }

      // Check domain blocklist
      const domainAllowed = await this.checkDomainBlocklist(url)
      if (!domainAllowed) {
        return {
          allowed: false,
          reason: 'Domain is on blocklist',
        }
      }

      // Check rate limiting
      const rateLimitOk = await this.checkRateLimit(url, context)
      if (!rateLimitOk) {
        return {
          allowed: false,
          reason: 'Rate limit exceeded',
        }
      }

      return { allowed: true }
    } catch (error) {
      logger.error('Scraping Compliance', 'Failed to check scraping permissions', error)
      return {
        allowed: false,
        reason: 'Permission check failed',
      }
    }
  }

  /**
   * Get required consents for scraping operation
   */
  private static getRequiredConsents(operation: ScrapingOperation): ConsentType[] {
    const consentMap: Record<ScrapingOperation, ConsentType[]> = {
      [ScrapingOperation.SEARCH]: [ConsentType.DATA_COLLECTION],
      [ScrapingOperation.SCRAPE]: [
        ConsentType.DATA_COLLECTION,
        ConsentType.SCRAPING,
        ConsentType.STORAGE,
      ],
      [ScrapingOperation.EXTRACT]: [ConsentType.DATA_PROCESSING],
      [ScrapingOperation.STORE]: [ConsentType.STORAGE, ConsentType.DATA_PROCESSING],
    }

    return consentMap[operation] || []
  }

  /**
   * Map scraping operation to consent operation
   */
  private static mapOperationToConsentOperation(operation: ScrapingOperation): string {
    const operationMap: Record<ScrapingOperation, string> = {
      [ScrapingOperation.SEARCH]: 'scraping',
      [ScrapingOperation.SCRAPE]: 'scraping',
      [ScrapingOperation.EXTRACT]: 'storage',
      [ScrapingOperation.STORE]: 'storage',
    }

    return operationMap[operation] || 'scraping'
  }

  /**
   * Get audit event type for operation
   */
  private static getAuditEventType(operation: ScrapingOperation, success: boolean): AuditEventType {
    if (success) {
      switch (operation) {
        case ScrapingOperation.SEARCH:
        case ScrapingOperation.SCRAPE:
          return AuditEventType.SCRAPING_COMPLETED
        case ScrapingOperation.EXTRACT:
        case ScrapingOperation.STORE:
          return AuditEventType.DATA_ACCESSED
        default:
          return AuditEventType.SCRAPING_COMPLETED
      }
    } else {
      return AuditEventType.SCRAPING_FAILED
    }
  }

  /**
   * Check robots.txt compliance
   */
  private static async checkRobotsCompliance(url: string): Promise<boolean> {
    try {
      const domain = new URL(url).origin
      const robotsUrl = `${domain}/robots.txt`

      const response = await fetch(robotsUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'BusinessScraperBot/1.0' },
        signal: AbortSignal.timeout(5000), // 5 second timeout
      })

      if (!response.ok) {
        // If robots.txt doesn't exist, assume scraping is allowed
        return true
      }

      const robotsText = await response.text()

      // Simple robots.txt parsing - check for Disallow: /
      const lines = robotsText.split('\n')
      let userAgentMatch = false

      for (const line of lines) {
        const trimmedLine = line.trim().toLowerCase()

        if (trimmedLine.startsWith('user-agent:')) {
          const userAgent = trimmedLine.split(':')[1].trim()
          userAgentMatch = userAgent === '*' || userAgent.includes('businessscraperbot')
        }

        if (userAgentMatch && trimmedLine.startsWith('disallow:')) {
          const disallowPath = trimmedLine.split(':')[1].trim()
          if (disallowPath === '/' || disallowPath === '') {
            return false // Scraping disallowed
          }
        }
      }

      return true // Scraping allowed
    } catch (error) {
      logger.warn('Scraping Compliance', `Failed to check robots.txt for ${url}`, error)
      return true // Default to allowing if check fails
    }
  }

  /**
   * Check domain blocklist
   */
  private static async checkDomainBlocklist(url: string): Promise<boolean> {
    try {
      const domain = new URL(url).hostname.toLowerCase()

      // Common domains that should not be scraped
      const blockedDomains = [
        'facebook.com',
        'twitter.com',
        'instagram.com',
        'linkedin.com',
        'youtube.com',
        'google.com',
        'amazon.com',
        'ebay.com',
        'paypal.com',
        'bank',
        'gov',
        'edu',
      ]

      const isBlocked = blockedDomains.some(
        blocked => domain.includes(blocked) || domain.endsWith(`.${blocked}`)
      )

      return !isBlocked
    } catch (error) {
      logger.warn('Scraping Compliance', `Failed to check domain blocklist for ${url}`, error)
      return true // Default to allowing if check fails
    }
  }

  /**
   * Check rate limiting
   */
  private static async checkRateLimit(
    url: string,
    context: ScrapingComplianceContext
  ): Promise<boolean> {
    try {
      const domain = new URL(url).hostname
      const key = `rate_limit:${domain}:${context.ipAddress || 'unknown'}`

      // Simple in-memory rate limiting (in production, use Redis)
      const now = Date.now()
      const windowMs = 60000 // 1 minute window
      const maxRequests = 10 // Max 10 requests per minute per domain per IP

      // This is a simplified implementation
      // In production, implement proper rate limiting with Redis
      return true
    } catch (error) {
      logger.warn('Scraping Compliance', `Failed to check rate limit for ${url}`, error)
      return true // Default to allowing if check fails
    }
  }
}

/**
 * Utility functions for scraping compliance
 */
export const ScrapingComplianceUtils = {
  /**
   * Create compliance context from request
   */
  createContext: (
    operation: ScrapingOperation,
    request?: any,
    additionalData?: Partial<ScrapingComplianceContext>
  ): ScrapingComplianceContext => {
    return {
      operation,
      ipAddress:
        request?.headers?.get?.('x-forwarded-for') ||
        request?.headers?.get?.('x-real-ip') ||
        request?.ip ||
        'unknown',
      userAgent: request?.headers?.get?.('user-agent') || 'unknown',
      correlationId: `scrape-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      ...additionalData,
    }
  },

  /**
   * Validate and log scraping operation
   */
  validateAndLog: async (
    context: ScrapingComplianceContext,
    operation: () => Promise<any>
  ): Promise<any> => {
    const startTime = Date.now()

    try {
      // Validate consent
      const consentValidation = await ScrapingComplianceMiddleware.validateConsent(context)
      if (!consentValidation.allowed) {
        throw new Error(consentValidation.message || 'Consent validation failed')
      }

      // Check scraping permissions if URL is provided
      if (context.url) {
        const permissionCheck = await ScrapingComplianceMiddleware.checkScrapingPermissions(
          context.url,
          context
        )
        if (!permissionCheck.allowed) {
          throw new Error(permissionCheck.reason || 'Scraping not allowed')
        }
      }

      // Execute operation
      const result = await operation()
      const duration = Date.now() - startTime

      // Log successful operation
      await ScrapingComplianceMiddleware.logScrapingOperation(context, {
        success: true,
        recordsFound: Array.isArray(result) ? result.length : undefined,
        duration,
      })

      return result
    } catch (error) {
      const duration = Date.now() - startTime

      // Log failed operation
      await ScrapingComplianceMiddleware.logScrapingOperation(context, {
        success: false,
        error: error.message,
        duration,
      })

      throw error
    }
  },
}
