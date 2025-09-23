'use client'

import { useEffect, useRef } from 'react'
import { logger } from '@/utils/logger'

/**
 * Service Worker Registration Component - DISABLED FOR ISSUE #189
 * This component is completely disabled to fix endless reload loop bug
 * Fixed React warning about state updates during render
 */
export function ServiceWorkerRegistration(): null {
  const hasInitialized = useRef(false)

  useEffect(() => {
    // Prevent multiple initializations and state updates during render
    if (hasInitialized.current) return
    hasInitialized.current = true

    // COMPLETELY DISABLED TO FIX ISSUE #189 - ENDLESS RELOAD LOOP
    console.log('🚨🚨🚨 NEW SERVICEWORKER COMPONENT RUNNING - ISSUE #189 FIX 🚨🚨🚨')
    logger.info('ServiceWorker', 'ServiceWorkerRegistration component completely disabled (Issue #189)')

    // Unregister any existing service workers to clean up
    // Use setTimeout to avoid state updates during render
    setTimeout(() => {
      if (typeof window !== 'undefined' && 'serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(registrations => {
          registrations.forEach(registration => {
            registration.unregister().then(() => {
              logger.info('ServiceWorker', 'Unregistered existing service worker', { scope: registration.scope })
            })
          })
        }).catch(error => {
          logger.error('ServiceWorker', 'Failed to unregister service workers', error)
        })
      }
    }, 0)
  }, [])

  return null
}

/**
 * Hook to check if app is running as PWA - DISABLED FOR ISSUE #189
 */
export function useIsPWA(): boolean {
  return false
}
