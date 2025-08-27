/**
 * Audit Logger Hook
 * Provides structured logging for compliance and audit events
 */

import { useCallback, useRef } from 'react'
import { logger } from '@/utils/logger'

// Audit event types
export enum AuditEventType {
  // User actions
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_ACTION = 'USER_ACTION',
  
  // Data operations
  DATA_ACCESSED = 'DATA_ACCESSED',
  DATA_EXPORTED = 'DATA_EXPORTED',
  DATA_MODIFIED = 'DATA_MODIFIED',
  DATA_DELETED = 'DATA_DELETED',
  
  // Scraping operations
  SCRAPING_STARTED = 'SCRAPING_STARTED',
  SCRAPING_COMPLETED = 'SCRAPING_COMPLETED',
  SCRAPING_FAILED = 'SCRAPING_FAILED',
  
  // Compliance events
  CONSENT_GIVEN = 'CONSENT_GIVEN',
  CONSENT_WITHDRAWN = 'CONSENT_WITHDRAWN',
  PRIVACY_SETTINGS_CHANGED = 'PRIVACY_SETTINGS_CHANGED',
  DSAR_REQUEST = 'DSAR_REQUEST',
  CCPA_OPT_OUT = 'CCPA_OPT_OUT',
  
  // Security events
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY'
}

// Audit severity levels
export enum AuditSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

// Audit event interface
interface AuditEvent {
  eventType: AuditEventType
  severity: AuditSeverity
  resource?: string
  action?: string
  details: Record<string, any>
  userId?: string
  sessionId?: string
  correlationId?: string
  complianceFlags?: {
    gdprRelevant: boolean
    ccpaRelevant: boolean
    soc2Relevant: boolean
  }
}

// Audit context
interface AuditContext {
  logEvent: (event: Omit<AuditEvent, 'correlationId'>) => Promise<void>
  logUserAction: (action: string, details: Record<string, any>) => Promise<void>
  logDataAccess: (resource: string, action: string, details: Record<string, any>) => Promise<void>
  logScrapingEvent: (eventType: AuditEventType, details: Record<string, any>) => Promise<void>
  logComplianceEvent: (eventType: AuditEventType, details: Record<string, any>) => Promise<void>
  logSecurityEvent: (eventType: AuditEventType, details: Record<string, any>) => Promise<void>
  setCorrelationId: (id: string) => void
  generateCorrelationId: () => string
}

/**
 * Audit logger hook
 */
export function useAuditLogger(): AuditContext {
  const correlationIdRef = useRef<string | null>(null)

  // Generate correlation ID
  const generateCorrelationId = useCallback((): string => {
    const id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    correlationIdRef.current = id
    return id
  }, [])

  // Set correlation ID
  const setCorrelationId = useCallback((id: string): void => {
    correlationIdRef.current = id
  }, [])

  // Get browser information
  const getBrowserInfo = useCallback(() => {
    return {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      timestamp: new Date().toISOString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth
      },
      viewport: {
        width: window.innerWidth,
        height: window.innerHeight
      }
    }
  }, [])

  // Get session information
  const getSessionInfo = useCallback(() => {
    try {
      const sessionId = localStorage.getItem('session-id') || 
                       sessionStorage.getItem('session-id') ||
                       document.cookie.split(';').find(c => c.trim().startsWith('session-id='))?.split('=')[1]
      
      const userId = localStorage.getItem('user-id') ||
                    sessionStorage.getItem('user-id')

      return { sessionId, userId }
    } catch (error) {
      logger.warn('Audit Logger', 'Failed to get session info', error)
      return { sessionId: null, userId: null }
    }
  }, [])

  // Log audit event
  const logEvent = useCallback(async (event: Omit<AuditEvent, 'correlationId'>): Promise<void> => {
    try {
      const { sessionId, userId } = getSessionInfo()
      const browserInfo = getBrowserInfo()
      
      const auditEvent: AuditEvent = {
        ...event,
        userId: event.userId || userId || undefined,
        sessionId: event.sessionId || sessionId || undefined,
        correlationId: correlationIdRef.current || generateCorrelationId(),
        details: {
          ...event.details,
          browser: browserInfo,
          url: window.location.href,
          referrer: document.referrer
        }
      }

      // Send to audit API
      const response = await fetch('/api/compliance/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(auditEvent)
      })

      if (!response.ok) {
        throw new Error(`Audit API error: ${response.status}`)
      }

      // Also log locally for immediate debugging
      logger.info('Audit', `${event.eventType}: ${event.action || 'N/A'}`, {
        severity: event.severity,
        correlationId: auditEvent.correlationId,
        resource: event.resource
      })

    } catch (error) {
      logger.error('Audit Logger', 'Failed to log audit event', error)
      
      // Fallback: store in localStorage for later retry
      try {
        const failedEvents = JSON.parse(localStorage.getItem('failed-audit-events') || '[]')
        failedEvents.push({
          ...event,
          timestamp: new Date().toISOString(),
          error: error.message
        })
        
        // Keep only last 100 failed events
        if (failedEvents.length > 100) {
          failedEvents.splice(0, failedEvents.length - 100)
        }
        
        localStorage.setItem('failed-audit-events', JSON.stringify(failedEvents))
      } catch (storageError) {
        logger.error('Audit Logger', 'Failed to store failed audit event', storageError)
      }
    }
  }, [generateCorrelationId, getBrowserInfo, getSessionInfo])

  // Log user action
  const logUserAction = useCallback(async (action: string, details: Record<string, any>): Promise<void> => {
    await logEvent({
      eventType: AuditEventType.USER_ACTION,
      severity: AuditSeverity.LOW,
      action,
      details,
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  // Log data access
  const logDataAccess = useCallback(async (resource: string, action: string, details: Record<string, any>): Promise<void> => {
    await logEvent({
      eventType: AuditEventType.DATA_ACCESSED,
      severity: AuditSeverity.MEDIUM,
      resource,
      action,
      details,
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  // Log scraping event
  const logScrapingEvent = useCallback(async (eventType: AuditEventType, details: Record<string, any>): Promise<void> => {
    const severity = eventType === AuditEventType.SCRAPING_FAILED ? AuditSeverity.HIGH : AuditSeverity.MEDIUM
    
    await logEvent({
      eventType,
      severity,
      resource: 'scraping_engine',
      details,
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  // Log compliance event
  const logComplianceEvent = useCallback(async (eventType: AuditEventType, details: Record<string, any>): Promise<void> => {
    await logEvent({
      eventType,
      severity: AuditSeverity.HIGH,
      resource: 'compliance_system',
      details,
      complianceFlags: {
        gdprRelevant: eventType.includes('CONSENT') || eventType.includes('DSAR'),
        ccpaRelevant: eventType.includes('CCPA') || eventType.includes('OPT_OUT'),
        soc2Relevant: true
      }
    })
  }, [logEvent])

  // Log security event
  const logSecurityEvent = useCallback(async (eventType: AuditEventType, details: Record<string, any>): Promise<void> => {
    const severity = eventType === AuditEventType.SECURITY_VIOLATION ? AuditSeverity.CRITICAL : AuditSeverity.HIGH
    
    await logEvent({
      eventType,
      severity,
      resource: 'security_system',
      details,
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  return {
    logEvent,
    logUserAction,
    logDataAccess,
    logScrapingEvent,
    logComplianceEvent,
    logSecurityEvent,
    setCorrelationId,
    generateCorrelationId
  }
}

/**
 * Hook for automatic page view logging
 */
export function usePageViewLogger() {
  const { logUserAction } = useAuditLogger()

  const logPageView = useCallback(async (pageName: string, additionalData?: Record<string, any>) => {
    await logUserAction('page_view', {
      page: pageName,
      url: window.location.href,
      referrer: document.referrer,
      timestamp: new Date().toISOString(),
      ...additionalData
    })
  }, [logUserAction])

  return { logPageView }
}

/**
 * Hook for form interaction logging
 */
export function useFormLogger() {
  const { logUserAction } = useAuditLogger()

  const logFormStart = useCallback(async (formName: string) => {
    await logUserAction('form_start', {
      form: formName,
      timestamp: new Date().toISOString()
    })
  }, [logUserAction])

  const logFormSubmit = useCallback(async (formName: string, success: boolean, errors?: string[]) => {
    await logUserAction('form_submit', {
      form: formName,
      success,
      errors,
      timestamp: new Date().toISOString()
    })
  }, [logUserAction])

  const logFormAbandonment = useCallback(async (formName: string, fieldsCompleted: number, totalFields: number) => {
    await logUserAction('form_abandonment', {
      form: formName,
      fieldsCompleted,
      totalFields,
      completionRate: (fieldsCompleted / totalFields) * 100,
      timestamp: new Date().toISOString()
    })
  }, [logUserAction])

  return {
    logFormStart,
    logFormSubmit,
    logFormAbandonment
  }
}

/**
 * Hook for error logging
 */
export function useErrorLogger() {
  const { logEvent } = useAuditLogger()

  const logError = useCallback(async (error: Error, context?: Record<string, any>) => {
    await logEvent({
      eventType: AuditEventType.USER_ACTION,
      severity: AuditSeverity.HIGH,
      action: 'error_occurred',
      details: {
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        },
        context,
        timestamp: new Date().toISOString()
      },
      complianceFlags: {
        gdprRelevant: false,
        ccpaRelevant: false,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  const logApiError = useCallback(async (endpoint: string, status: number, error: string) => {
    await logEvent({
      eventType: AuditEventType.USER_ACTION,
      severity: AuditSeverity.MEDIUM,
      action: 'api_error',
      resource: endpoint,
      details: {
        status,
        error,
        timestamp: new Date().toISOString()
      },
      complianceFlags: {
        gdprRelevant: false,
        ccpaRelevant: false,
        soc2Relevant: true
      }
    })
  }, [logEvent])

  return {
    logError,
    logApiError
  }
}

/**
 * Utility functions for audit logging
 */
export const AuditUtils = {
  /**
   * Create correlation ID for tracking related events
   */
  createCorrelationId: (): string => {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  },

  /**
   * Retry failed audit events
   */
  retryFailedEvents: async (): Promise<void> => {
    try {
      const failedEvents = JSON.parse(localStorage.getItem('failed-audit-events') || '[]')
      
      if (failedEvents.length === 0) return

      for (const event of failedEvents) {
        try {
          const response = await fetch('/api/compliance/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event)
          })

          if (response.ok) {
            // Remove successful event from failed list
            const index = failedEvents.indexOf(event)
            if (index > -1) {
              failedEvents.splice(index, 1)
            }
          }
        } catch (retryError) {
          logger.warn('Audit Utils', 'Failed to retry audit event', retryError)
        }
      }

      // Update failed events list
      localStorage.setItem('failed-audit-events', JSON.stringify(failedEvents))
      
      if (failedEvents.length === 0) {
        localStorage.removeItem('failed-audit-events')
      }

    } catch (error) {
      logger.error('Audit Utils', 'Failed to retry failed events', error)
    }
  },

  /**
   * Get failed events count
   */
  getFailedEventsCount: (): number => {
    try {
      const failedEvents = JSON.parse(localStorage.getItem('failed-audit-events') || '[]')
      return failedEvents.length
    } catch (error) {
      return 0
    }
  }
}
