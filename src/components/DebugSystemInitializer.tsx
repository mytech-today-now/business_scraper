'use client'

/**
 * Debug System Initializer
 * Client-side component to initialize debug mode and error handling
 */

import { useEffect } from 'react'
import { setupGlobalErrorHandling } from '@/utils/enhancedErrorLogger'
import { setupErrorPersistence } from '@/utils/errorPersistence'
import { isDebugMode, shouldUseEnhancedErrorLogging } from '@/utils/debugConfig'
import { logger } from '@/utils/logger'

export function DebugSystemInitializer() {
  useEffect(() => {
    // Initialize global error handling
    setupGlobalErrorHandling()
    
    // Initialize error persistence
    setupErrorPersistence()
    
    // Log debug mode status
    if (isDebugMode()) {
      logger.info('DebugSystem', 'Debug mode is active', {
        enhancedErrorLogging: shouldUseEnhancedErrorLogging(),
        errorPersistence: true,
      })
      
      // Add debug mode indicator to the page
      const debugIndicator = document.createElement('div')
      debugIndicator.id = 'debug-mode-indicator'
      debugIndicator.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #ff6b35;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 12px;
        z-index: 10000;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        pointer-events: none;
      `
      debugIndicator.textContent = '🐛 DEBUG MODE'
      document.body.appendChild(debugIndicator)
      
      // Listen for debug reload prevention events
      window.addEventListener('debug-reload-prevented', (event: any) => {
        const notification = document.createElement('div')
        notification.style.cssText = `
          position: fixed;
          top: 50px;
          right: 10px;
          background: #fbbf24;
          color: #92400e;
          padding: 12px 16px;
          border-radius: 4px;
          font-family: system-ui, sans-serif;
          font-size: 14px;
          z-index: 10001;
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          max-width: 300px;
          border-left: 4px solid #f59e0b;
        `
        notification.innerHTML = `
          <div style="font-weight: 600; margin-bottom: 4px;">🚫 Auto-reload Prevented</div>
          <div style="font-size: 12px; opacity: 0.8;">Reason: ${event.detail.reason}</div>
          <div style="font-size: 11px; margin-top: 8px; opacity: 0.7;">Debug mode is active. Check console for details.</div>
        `
        document.body.appendChild(notification)
        
        // Auto-remove notification after 5 seconds
        setTimeout(() => {
          if (notification.parentNode) {
            notification.parentNode.removeChild(notification)
          }
        }, 5000)
      })
      
      // Add global debug utilities to window object for console access
      ;(window as any).debugUtils = {
        enableDebugMode: () => {
          const { enableDebugMode } = require('@/utils/debugConfig')
          enableDebugMode()
          window.location.reload()
        },
        disableDebugMode: () => {
          const { disableDebugMode } = require('@/utils/debugConfig')
          disableDebugMode()
          window.location.reload()
        },
        getErrorAnalytics: () => {
          const { errorPersistenceManager } = require('@/utils/errorPersistence')
          return errorPersistenceManager.getErrorAnalytics()
        },
        exportErrorData: () => {
          const { errorPersistenceManager } = require('@/utils/errorPersistence')
          const data = errorPersistenceManager.exportErrorData()
          console.log('Error data exported to console:')
          console.log(data)
          return data
        },
        clearErrors: () => {
          const { errorPersistenceManager } = require('@/utils/errorPersistence')
          const { clearPersistedErrors } = require('@/utils/debugConfig')
          errorPersistenceManager.clearAllErrors()
          clearPersistedErrors()
          console.log('All error data cleared')
        },
        getPersistedErrors: () => {
          const { getPersistedErrors } = require('@/utils/debugConfig')
          return getPersistedErrors()
        }
      }
      
      console.log(`
🐛 Debug Mode Active
===================
Available debug utilities:
- debugUtils.enableDebugMode() - Enable debug mode
- debugUtils.disableDebugMode() - Disable debug mode  
- debugUtils.getErrorAnalytics() - Get error analytics
- debugUtils.exportErrorData() - Export all error data
- debugUtils.clearErrors() - Clear all error data
- debugUtils.getPersistedErrors() - Get persisted errors

Auto-reload prevention is active. Errors will be logged with enhanced details.
      `)
    }
    
    // Cleanup function
    return () => {
      const indicator = document.getElementById('debug-mode-indicator')
      if (indicator) {
        indicator.remove()
      }
    }
  }, [])

  return null // This component doesn't render anything
}
