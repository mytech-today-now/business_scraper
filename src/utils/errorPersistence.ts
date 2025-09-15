/**
 * Error Persistence Utility
 * Provides mechanisms to persist error information across page reloads
 * and browser sessions for debugging purposes
 */

import { logger } from './logger'
import { shouldPersistErrors, type ErrorDetails } from './debugConfig'

export interface PersistedErrorSession {
  sessionId: string
  startTime: string
  endTime?: string
  errors: ErrorDetails[]
  metadata: {
    userAgent: string
    url: string
    timestamp: string
    debugMode: boolean
  }
}

export interface ErrorAnalytics {
  totalErrors: number
  errorsByType: Record<string, number>
  errorsByComponent: Record<string, number>
  recentErrors: ErrorDetails[]
  errorPatterns: {
    pattern: string
    count: number
    lastOccurrence: string
  }[]
}

/**
 * Error Persistence Manager
 */
export class ErrorPersistenceManager {
  private static instance: ErrorPersistenceManager
  private currentSessionId: string
  private sessionStartTime: string
  private maxErrorsPerSession = 100
  private maxSessions = 10
  
  constructor() {
    this.currentSessionId = this.generateSessionId()
    this.sessionStartTime = new Date().toISOString()
    this.initializeSession()
  }
  
  static getInstance(): ErrorPersistenceManager {
    if (!ErrorPersistenceManager.instance) {
      ErrorPersistenceManager.instance = new ErrorPersistenceManager()
    }
    return ErrorPersistenceManager.instance
  }
  
  /**
   * Persist an error to localStorage
   */
  persistError(errorDetails: ErrorDetails): void {
    if (!shouldPersistErrors() || typeof window === 'undefined') {
      return
    }
    
    try {
      const currentSession = this.getCurrentSession()
      currentSession.errors.push(errorDetails)
      
      // Limit errors per session
      if (currentSession.errors.length > this.maxErrorsPerSession) {
        currentSession.errors = currentSession.errors.slice(-this.maxErrorsPerSession)
      }
      
      this.saveSession(currentSession)
      logger.info('ErrorPersistence', `Error persisted: ${errorDetails.id}`)
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to persist error', err)
    }
  }
  
  /**
   * Get all persisted errors from current session
   */
  getCurrentSessionErrors(): ErrorDetails[] {
    if (typeof window === 'undefined') {
      return []
    }
    
    try {
      const session = this.getCurrentSession()
      return session.errors
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to get current session errors', err)
      return []
    }
  }
  
  /**
   * Get all persisted error sessions
   */
  getAllSessions(): PersistedErrorSession[] {
    if (typeof window === 'undefined') {
      return []
    }
    
    try {
      const stored = localStorage.getItem('error_persistence_sessions')
      return stored ? JSON.parse(stored) : []
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to get all sessions', err)
      return []
    }
  }
  
  /**
   * Get error analytics across all sessions
   */
  getErrorAnalytics(): ErrorAnalytics {
    const sessions = this.getAllSessions()
    const allErrors = sessions.flatMap(session => session.errors)
    
    const errorsByType: Record<string, number> = {}
    const errorsByComponent: Record<string, number> = {}
    const errorPatterns: Map<string, { count: number; lastOccurrence: string }> = new Map()
    
    allErrors.forEach(error => {
      // Count by component
      const component = error.component || 'Unknown'
      errorsByComponent[component] = (errorsByComponent[component] || 0) + 1
      
      // Count by error message pattern
      const pattern = this.extractErrorPattern(error.message)
      if (pattern) {
        const existing = errorPatterns.get(pattern) || { count: 0, lastOccurrence: error.timestamp }
        errorPatterns.set(pattern, {
          count: existing.count + 1,
          lastOccurrence: error.timestamp > existing.lastOccurrence ? error.timestamp : existing.lastOccurrence
        })
      }
      
      // Count by error type (from context)
      if (error.context && typeof error.context === 'object') {
        const errorType = error.context.tokenType || error.context.type || 'unknown'
        errorsByType[errorType] = (errorsByType[errorType] || 0) + 1
      }
    })
    
    return {
      totalErrors: allErrors.length,
      errorsByType,
      errorsByComponent,
      recentErrors: allErrors.slice(-20).reverse(), // Last 20 errors, newest first
      errorPatterns: Array.from(errorPatterns.entries()).map(([pattern, data]) => ({
        pattern,
        count: data.count,
        lastOccurrence: data.lastOccurrence
      })).sort((a, b) => b.count - a.count)
    }
  }
  
  /**
   * Clear all persisted errors
   */
  clearAllErrors(): void {
    if (typeof window === 'undefined') {
      return
    }
    
    try {
      localStorage.removeItem('error_persistence_sessions')
      localStorage.removeItem('error_persistence_current_session')
      this.initializeSession()
      logger.info('ErrorPersistence', 'All persisted errors cleared')
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to clear persisted errors', err)
    }
  }
  
  /**
   * Clear errors older than specified days
   */
  clearOldErrors(daysOld: number = 7): void {
    if (typeof window === 'undefined') {
      return
    }
    
    try {
      const sessions = this.getAllSessions()
      const cutoffDate = new Date()
      cutoffDate.setDate(cutoffDate.getDate() - daysOld)
      
      const filteredSessions = sessions.filter(session => 
        new Date(session.startTime) > cutoffDate
      )
      
      localStorage.setItem('error_persistence_sessions', JSON.stringify(filteredSessions))
      logger.info('ErrorPersistence', `Cleared errors older than ${daysOld} days`)
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to clear old errors', err)
    }
  }
  
  /**
   * Export error data for debugging
   */
  exportErrorData(): string {
    const analytics = this.getErrorAnalytics()
    const sessions = this.getAllSessions()
    
    const exportData = {
      exportTimestamp: new Date().toISOString(),
      analytics,
      sessions,
      metadata: {
        userAgent: typeof window !== 'undefined' ? navigator.userAgent : 'unknown',
        url: typeof window !== 'undefined' ? window.location.href : 'unknown',
        debugMode: shouldPersistErrors(),
      }
    }
    
    return JSON.stringify(exportData, null, 2)
  }
  
  /**
   * End current session
   */
  endSession(): void {
    if (typeof window === 'undefined') {
      return
    }
    
    try {
      const currentSession = this.getCurrentSession()
      currentSession.endTime = new Date().toISOString()
      this.saveSession(currentSession)
      
      // Add to sessions list
      const sessions = this.getAllSessions()
      sessions.push(currentSession)
      
      // Limit number of sessions
      if (sessions.length > this.maxSessions) {
        sessions.splice(0, sessions.length - this.maxSessions)
      }
      
      localStorage.setItem('error_persistence_sessions', JSON.stringify(sessions))
      localStorage.removeItem('error_persistence_current_session')
      
      logger.info('ErrorPersistence', `Session ended: ${this.currentSessionId}`)
    } catch (err) {
      logger.warn('ErrorPersistence', 'Failed to end session', err)
    }
  }
  
  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
  
  private initializeSession(): void {
    if (typeof window === 'undefined') {
      return
    }
    
    const session: PersistedErrorSession = {
      sessionId: this.currentSessionId,
      startTime: this.sessionStartTime,
      errors: [],
      metadata: {
        userAgent: navigator.userAgent,
        url: window.location.href,
        timestamp: new Date().toISOString(),
        debugMode: shouldPersistErrors(),
      }
    }
    
    this.saveSession(session)
  }
  
  private getCurrentSession(): PersistedErrorSession {
    if (typeof window === 'undefined') {
      throw new Error('Cannot access localStorage in server environment')
    }
    
    const stored = localStorage.getItem('error_persistence_current_session')
    if (stored) {
      return JSON.parse(stored)
    }
    
    // Create new session if none exists
    const session: PersistedErrorSession = {
      sessionId: this.currentSessionId,
      startTime: this.sessionStartTime,
      errors: [],
      metadata: {
        userAgent: navigator.userAgent,
        url: window.location.href,
        timestamp: new Date().toISOString(),
        debugMode: shouldPersistErrors(),
      }
    }
    
    this.saveSession(session)
    return session
  }
  
  private saveSession(session: PersistedErrorSession): void {
    if (typeof window === 'undefined') {
      return
    }
    
    localStorage.setItem('error_persistence_current_session', JSON.stringify(session))
  }
  
  private extractErrorPattern(message: string): string | null {
    // Extract common error patterns for analysis
    const patterns = [
      /Failed to fetch CSRF token: (\d+)/,
      /Authentication error/,
      /Network request failed/,
      /Component error/,
      /Session.*expired/,
      /Token.*invalid/,
    ]
    
    for (const pattern of patterns) {
      const match = message.match(pattern)
      if (match) {
        return match[0].replace(/\d+/g, 'XXX') // Replace numbers with XXX for pattern matching
      }
    }
    
    // Fallback to first 50 characters
    return message.length > 50 ? message.substring(0, 50) + '...' : message
  }
}

/**
 * Global error persistence manager instance
 */
export const errorPersistenceManager = ErrorPersistenceManager.getInstance()

/**
 * Setup error persistence with automatic session management
 */
export function setupErrorPersistence(): void {
  if (typeof window === 'undefined') {
    return
  }
  
  // TEMPORARILY DISABLED: Session ending on page unload to fix navigation loop
  // The automatic session ending was causing continuous reload issues
  // where navigation from /login to / would end the session, causing redirect back to /login

  // TODO: Implement proper session management that:
  // 1. Doesn't end sessions on internal navigation
  // 2. Only ends sessions on actual browser close/tab close
  // 3. Handles session cleanup properly without interfering with auth flow

  console.log('[ErrorPersistence] Session ending temporarily disabled to prevent navigation loops')
  
  // Clean up old errors periodically
  const cleanupInterval = setInterval(() => {
    errorPersistenceManager.clearOldErrors(7) // Keep errors for 7 days
  }, 24 * 60 * 60 * 1000) // Check daily
  
  // Clear interval on page unload
  window.addEventListener('beforeunload', () => {
    clearInterval(cleanupInterval)
  })
  
  logger.info('ErrorPersistence', 'Error persistence setup complete')
}
