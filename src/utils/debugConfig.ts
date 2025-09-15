/**
 * Debug Configuration Utility
 * Provides centralized debug mode configuration for preventing automatic page reloads
 * and enhancing error capture during development
 */

import { logger } from './logger'

export interface DebugConfig {
  enabled: boolean
  preventAutoReload: boolean
  enhancedErrorLogging: boolean
  persistErrors: boolean
  showStackTraces: boolean
}

export interface ErrorDetails {
  id: string
  timestamp: string
  message: string
  stack?: string
  component?: string
  context?: any
  url?: string
  userAgent?: string
  sessionId?: string
}

/**
 * Get debug configuration from environment variables
 */
export function getDebugConfig(): DebugConfig {
  // Check both client and server environment variables
  const isClient = typeof window !== 'undefined'
  
  const debugMode = isClient 
    ? process.env.NEXT_PUBLIC_DEBUG_MODE === 'true' || localStorage.getItem('debug_mode') === 'true'
    : process.env.DEBUG_MODE === 'true'
    
  const preventAutoReload = isClient
    ? process.env.NEXT_PUBLIC_DEBUG_PREVENT_AUTO_RELOAD === 'true' || localStorage.getItem('debug_prevent_auto_reload') === 'true'
    : process.env.DEBUG_PREVENT_AUTO_RELOAD === 'true'
    
  const enhancedErrorLogging = isClient
    ? process.env.NEXT_PUBLIC_DEBUG_ENHANCED_ERROR_LOGGING === 'true' || localStorage.getItem('debug_enhanced_error_logging') === 'true'
    : process.env.DEBUG_ENHANCED_ERROR_LOGGING === 'true'
    
  const persistErrors = isClient
    ? process.env.NEXT_PUBLIC_DEBUG_PERSIST_ERRORS === 'true' || localStorage.getItem('debug_persist_errors') === 'true'
    : process.env.DEBUG_PERSIST_ERRORS === 'true'
    
  const showStackTraces = isClient
    ? process.env.NEXT_PUBLIC_DEBUG_SHOW_STACK_TRACES === 'true' || localStorage.getItem('debug_show_stack_traces') === 'true'
    : process.env.DEBUG_SHOW_STACK_TRACES === 'true'

  return {
    enabled: debugMode,
    preventAutoReload,
    enhancedErrorLogging,
    persistErrors,
    showStackTraces,
  }
}

/**
 * Check if debug mode is enabled
 */
export function isDebugMode(): boolean {
  return getDebugConfig().enabled
}

/**
 * Check if auto-reload should be prevented
 */
export function shouldPreventAutoReload(): boolean {
  const config = getDebugConfig()
  return config.enabled && config.preventAutoReload
}

/**
 * Check if enhanced error logging is enabled
 */
export function shouldUseEnhancedErrorLogging(): boolean {
  const config = getDebugConfig()
  return config.enabled && config.enhancedErrorLogging
}

/**
 * Check if errors should be persisted
 */
export function shouldPersistErrors(): boolean {
  const config = getDebugConfig()
  return config.enabled && config.persistErrors
}

/**
 * Check if stack traces should be shown
 */
export function shouldShowStackTraces(): boolean {
  const config = getDebugConfig()
  return config.enabled && config.showStackTraces
}

/**
 * Generate unique error ID
 */
export function generateErrorId(): string {
  return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

/**
 * Create detailed error information
 */
export function createErrorDetails(
  error: Error | string,
  component?: string,
  context?: any
): ErrorDetails {
  const errorId = generateErrorId()
  const timestamp = new Date().toISOString()
  
  const errorMessage = error instanceof Error ? error.message : String(error)
  const stack = error instanceof Error ? error.stack : undefined
  
  const details: ErrorDetails = {
    id: errorId,
    timestamp,
    message: errorMessage,
    component,
    context,
  }
  
  if (shouldShowStackTraces() && stack) {
    details.stack = stack
  }
  
  if (typeof window !== 'undefined') {
    details.url = window.location.href
    details.userAgent = navigator.userAgent
  }
  
  return details
}

/**
 * Persist error details to localStorage
 */
export function persistErrorDetails(errorDetails: ErrorDetails): void {
  if (!shouldPersistErrors() || typeof window === 'undefined') {
    return
  }
  
  try {
    const existingErrors = getPersistedErrors()
    const updatedErrors = [errorDetails, ...existingErrors.slice(0, 49)] // Keep last 50 errors
    
    localStorage.setItem('debug_persisted_errors', JSON.stringify(updatedErrors))
    logger.info('DebugConfig', `Error persisted with ID: ${errorDetails.id}`)
  } catch (err) {
    logger.warn('DebugConfig', 'Failed to persist error details', err)
  }
}

/**
 * Get persisted error details from localStorage
 */
export function getPersistedErrors(): ErrorDetails[] {
  if (typeof window === 'undefined') {
    return []
  }
  
  try {
    const stored = localStorage.getItem('debug_persisted_errors')
    return stored ? JSON.parse(stored) : []
  } catch (err) {
    logger.warn('DebugConfig', 'Failed to retrieve persisted errors', err)
    return []
  }
}

/**
 * Clear persisted error details
 */
export function clearPersistedErrors(): void {
  if (typeof window === 'undefined') {
    return
  }
  
  try {
    localStorage.removeItem('debug_persisted_errors')
    logger.info('DebugConfig', 'Persisted errors cleared')
  } catch (err) {
    logger.warn('DebugConfig', 'Failed to clear persisted errors', err)
  }
}

/**
 * Enhanced error logging with debug information
 */
export function logEnhancedError(
  error: Error | string,
  component?: string,
  context?: any
): ErrorDetails {
  const errorDetails = createErrorDetails(error, component, context)
  
  if (shouldUseEnhancedErrorLogging()) {
    logger.error(component || 'Unknown', `Enhanced error logging: ${errorDetails.id}`, {
      errorId: errorDetails.id,
      timestamp: errorDetails.timestamp,
      message: errorDetails.message,
      stack: errorDetails.stack,
      context: errorDetails.context,
      url: errorDetails.url,
      userAgent: errorDetails.userAgent,
    })
  }
  
  if (shouldPersistErrors()) {
    persistErrorDetails(errorDetails)
  }
  
  return errorDetails
}

/**
 * Safe reload function that respects debug mode
 */
export function safeReload(reason?: string): void {
  const config = getDebugConfig()
  
  if (config.enabled && config.preventAutoReload) {
    logger.warn('DebugConfig', `Auto-reload prevented in debug mode. Reason: ${reason || 'Unknown'}`)
    
    // Show a notification instead of reloading
    if (typeof window !== 'undefined') {
      console.warn(`🚫 Auto-reload prevented in debug mode. Reason: ${reason || 'Unknown'}`)
      
      // Optionally show a toast or modal
      const event = new CustomEvent('debug-reload-prevented', {
        detail: { reason: reason || 'Unknown' }
      })
      window.dispatchEvent(event)
    }
    
    return
  }
  
  // Normal reload behavior
  if (typeof window !== 'undefined') {
    logger.info('DebugConfig', `Performing page reload. Reason: ${reason || 'Unknown'}`)
    window.location.reload()
  }
}

/**
 * Enable debug mode at runtime (for development)
 */
export function enableDebugMode(options?: Partial<DebugConfig>): void {
  if (typeof window === 'undefined') {
    return
  }
  
  const defaultOptions: DebugConfig = {
    enabled: true,
    preventAutoReload: true,
    enhancedErrorLogging: true,
    persistErrors: true,
    showStackTraces: true,
  }
  
  const config = { ...defaultOptions, ...options }
  
  localStorage.setItem('debug_mode', String(config.enabled))
  localStorage.setItem('debug_prevent_auto_reload', String(config.preventAutoReload))
  localStorage.setItem('debug_enhanced_error_logging', String(config.enhancedErrorLogging))
  localStorage.setItem('debug_persist_errors', String(config.persistErrors))
  localStorage.setItem('debug_show_stack_traces', String(config.showStackTraces))
  
  logger.info('DebugConfig', 'Debug mode enabled at runtime', config)
}

/**
 * Disable debug mode at runtime
 */
export function disableDebugMode(): void {
  if (typeof window === 'undefined') {
    return
  }
  
  localStorage.removeItem('debug_mode')
  localStorage.removeItem('debug_prevent_auto_reload')
  localStorage.removeItem('debug_enhanced_error_logging')
  localStorage.removeItem('debug_persist_errors')
  localStorage.removeItem('debug_show_stack_traces')
  
  logger.info('DebugConfig', 'Debug mode disabled at runtime')
}
