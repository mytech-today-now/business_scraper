/**
 * Enhanced Error Logger
 * Provides detailed error logging with network information, timing, and debugging context
 */

import { logger } from './logger'
import {
  logEnhancedError,
  shouldUseEnhancedErrorLogging,
  shouldPersistErrors,
  createErrorDetails,
  type ErrorDetails
} from './debugConfig'
import { errorPersistenceManager } from './errorPersistence'

export interface NetworkErrorDetails {
  url: string
  method: string
  status?: number
  statusText?: string
  headers?: Record<string, string>
  requestHeaders?: Record<string, string>
  responseTime?: number
  retryAttempt?: number
  maxRetries?: number
}

export interface SecurityTokenErrorDetails {
  tokenType: 'csrf' | 'session' | 'auth'
  phase: 'loading' | 'validation' | 'refresh' | 'expired'
  endpoint: string
  errorCode?: string
  retryCount?: number
  timeoutDuration?: number
  networkDetails?: NetworkErrorDetails
}

export interface ComponentErrorDetails {
  componentName: string
  errorBoundary?: string
  props?: any
  state?: any
  lifecycle?: string
  renderCount?: number
}

/**
 * Enhanced error logger for security token issues
 */
export class SecurityTokenErrorLogger {
  private static instance: SecurityTokenErrorLogger
  private errorHistory: Map<string, ErrorDetails[]> = new Map()
  
  static getInstance(): SecurityTokenErrorLogger {
    if (!SecurityTokenErrorLogger.instance) {
      SecurityTokenErrorLogger.instance = new SecurityTokenErrorLogger()
    }
    return SecurityTokenErrorLogger.instance
  }
  
  /**
   * Log CSRF token error with detailed context
   */
  logCSRFError(
    error: Error | string,
    details: Partial<SecurityTokenErrorDetails>,
    context?: any
  ): ErrorDetails {
    const enhancedContext = {
      ...context,
      tokenType: 'csrf',
      ...details,
      timestamp: new Date().toISOString(),
      userAgent: typeof window !== 'undefined' ? navigator.userAgent : undefined,
      url: typeof window !== 'undefined' ? window.location.href : undefined,
    }
    
    const errorDetails = logEnhancedError(error, 'CSRFTokenError', enhancedContext)

    // Store in error history for pattern analysis
    this.addToErrorHistory('csrf', errorDetails)

    // Persist error for cross-reload debugging
    if (shouldPersistErrors()) {
      errorPersistenceManager.persistError(errorDetails)
    }
    
    // Log to console with enhanced formatting if in debug mode
    if (shouldUseEnhancedErrorLogging()) {
      console.group('🔒 CSRF Token Error Details')
      console.error('Error:', error)
      console.table(enhancedContext)
      console.trace('Stack trace')
      console.groupEnd()
    }
    
    return errorDetails
  }
  
  /**
   * Log authentication error with detailed context
   */
  logAuthError(
    error: Error | string,
    details: Partial<SecurityTokenErrorDetails>,
    context?: any
  ): ErrorDetails {
    const enhancedContext = {
      ...context,
      tokenType: 'auth',
      ...details,
      timestamp: new Date().toISOString(),
      sessionInfo: this.getSessionInfo(),
    }
    
    const errorDetails = logEnhancedError(error, 'AuthError', enhancedContext)

    this.addToErrorHistory('auth', errorDetails)

    // Persist error for cross-reload debugging
    if (shouldPersistErrors()) {
      errorPersistenceManager.persistError(errorDetails)
    }
    
    if (shouldUseEnhancedErrorLogging()) {
      console.group('🔐 Authentication Error Details')
      console.error('Error:', error)
      console.table(enhancedContext)
      console.trace('Stack trace')
      console.groupEnd()
    }
    
    return errorDetails
  }
  
  /**
   * Log network error with timing and retry information
   */
  logNetworkError(
    error: Error | string,
    networkDetails: NetworkErrorDetails,
    context?: any
  ): ErrorDetails {
    const enhancedContext = {
      ...context,
      networkDetails,
      timestamp: new Date().toISOString(),
      connectionInfo: this.getConnectionInfo(),
    }
    
    const errorDetails = logEnhancedError(error, 'NetworkError', enhancedContext)
    
    this.addToErrorHistory('network', errorDetails)
    
    if (shouldUseEnhancedErrorLogging()) {
      console.group('🌐 Network Error Details')
      console.error('Error:', error)
      console.table(networkDetails)
      console.table(this.getConnectionInfo())
      console.trace('Stack trace')
      console.groupEnd()
    }
    
    return errorDetails
  }
  
  /**
   * Log component error with React-specific context
   */
  logComponentError(
    error: Error | string,
    componentDetails: ComponentErrorDetails,
    context?: any
  ): ErrorDetails {
    const enhancedContext = {
      ...context,
      componentDetails,
      timestamp: new Date().toISOString(),
      reactVersion: this.getReactVersion(),
    }
    
    const errorDetails = logEnhancedError(error, 'ComponentError', enhancedContext)
    
    this.addToErrorHistory('component', errorDetails)
    
    if (shouldUseEnhancedErrorLogging()) {
      console.group('⚛️ React Component Error Details')
      console.error('Error:', error)
      console.table(componentDetails)
      console.trace('Stack trace')
      console.groupEnd()
    }
    
    return errorDetails
  }
  
  /**
   * Get error patterns for analysis
   */
  getErrorPatterns(type?: string): { type: string; count: number; lastOccurrence: string }[] {
    const patterns: { type: string; count: number; lastOccurrence: string }[] = []
    
    for (const [errorType, errors] of this.errorHistory.entries()) {
      if (!type || errorType === type) {
        patterns.push({
          type: errorType,
          count: errors.length,
          lastOccurrence: errors[errors.length - 1]?.timestamp || 'Unknown'
        })
      }
    }
    
    return patterns.sort((a, b) => b.count - a.count)
  }
  
  /**
   * Clear error history
   */
  clearErrorHistory(): void {
    this.errorHistory.clear()
    logger.info('SecurityTokenErrorLogger', 'Error history cleared')
  }
  
  private addToErrorHistory(type: string, errorDetails: ErrorDetails): void {
    if (!this.errorHistory.has(type)) {
      this.errorHistory.set(type, [])
    }
    
    const errors = this.errorHistory.get(type)!
    errors.push(errorDetails)
    
    // Keep only last 20 errors per type
    if (errors.length > 20) {
      errors.splice(0, errors.length - 20)
    }
  }
  
  private getSessionInfo(): any {
    if (typeof window === 'undefined') {
      return null
    }
    
    return {
      sessionStorage: Object.keys(sessionStorage).length,
      localStorage: Object.keys(localStorage).length,
      cookies: document.cookie ? document.cookie.split(';').length : 0,
    }
  }
  
  private getConnectionInfo(): any {
    if (typeof window === 'undefined' || !('navigator' in window)) {
      return null
    }
    
    const connection = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection
    
    return {
      online: navigator.onLine,
      effectiveType: connection?.effectiveType,
      downlink: connection?.downlink,
      rtt: connection?.rtt,
      saveData: connection?.saveData,
    }
  }
  
  private getReactVersion(): string {
    try {
      // Try to get React version from various sources
      if (typeof window !== 'undefined') {
        const reactFiber = (window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__
        if (reactFiber?.renderers) {
          const renderer = Array.from(reactFiber.renderers.values())[0] as any
          return renderer?.version || 'Unknown'
        }
      }
      
      // Fallback to package.json version if available
      return process.env.NEXT_PUBLIC_REACT_VERSION || 'Unknown'
    } catch {
      return 'Unknown'
    }
  }
}

/**
 * Convenience function to get the singleton instance
 */
export const securityTokenErrorLogger = SecurityTokenErrorLogger.getInstance()

/**
 * Enhanced fetch wrapper with error logging
 */
export async function fetchWithErrorLogging(
  url: string,
  options: RequestInit = {},
  context?: any
): Promise<Response> {
  const startTime = Date.now()
  const requestHeaders: Record<string, string> = {}
  
  // Capture request headers
  if (options.headers) {
    const headers = new Headers(options.headers)
    headers.forEach((value, key) => {
      requestHeaders[key] = value
    })
  }
  
  try {
    const response = await fetch(url, options)
    const responseTime = Date.now() - startTime
    
    if (!response.ok) {
      const responseHeaders: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value
      })
      
      const networkDetails: NetworkErrorDetails = {
        url,
        method: options.method || 'GET',
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        requestHeaders,
        responseTime,
      }
      
      securityTokenErrorLogger.logNetworkError(
        `HTTP ${response.status}: ${response.statusText}`,
        networkDetails,
        context
      )
    }
    
    return response
  } catch (error) {
    const responseTime = Date.now() - startTime
    
    const networkDetails: NetworkErrorDetails = {
      url,
      method: options.method || 'GET',
      requestHeaders,
      responseTime,
    }
    
    securityTokenErrorLogger.logNetworkError(
      error instanceof Error ? error : new Error(String(error)),
      networkDetails,
      context
    )
    
    throw error
  }
}

/**
 * Global error handler setup
 */
export function setupGlobalErrorHandling(): void {
  if (typeof window === 'undefined') {
    return
  }
  
  // Handle unhandled promise rejections
  window.addEventListener('unhandledrejection', (event) => {
    securityTokenErrorLogger.logComponentError(
      event.reason instanceof Error ? event.reason : new Error(String(event.reason)),
      {
        componentName: 'Global',
        lifecycle: 'unhandledrejection',
      },
      {
        promise: event.promise,
        type: 'unhandledrejection',
      }
    )
  })
  
  // Handle global errors
  window.addEventListener('error', (event) => {
    securityTokenErrorLogger.logComponentError(
      event.error || new Error(event.message),
      {
        componentName: 'Global',
        lifecycle: 'error',
      },
      {
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        type: 'error',
      }
    )
  })
  
  logger.info('EnhancedErrorLogger', 'Global error handling setup complete')
}
