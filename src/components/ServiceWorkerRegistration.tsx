'use client'

import { useEffect, useState } from 'react'
import { useOfflineSupport } from '@/hooks/useOfflineSupport'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

/**
 * Service Worker Registration Component
 * Handles PWA functionality and offline support
 */
export function ServiceWorkerRegistration(): null {
  const { isOnline, isOffline, wasOffline } = useOfflineSupport({
    onOnline: () => {
      if (wasOffline) {
        toast.success("Connection restored! You're back online.", {
          duration: 3000,
          icon: '🌐',
        })
      }
    },
    onOffline: () => {
      toast.error("You're offline. Some features may be limited.", {
        duration: 5000,
        icon: '📱',
      })
    },
  })

  useEffect(() => {
    // Only register service worker in production and if supported
    if (
      typeof window !== 'undefined' &&
      'serviceWorker' in navigator &&
      process.env.NODE_ENV === 'production'
    ) {
      registerServiceWorker()
    }
    // Note: In development, service worker registration is disabled to prevent caching issues
    // Any existing service workers will be automatically unregistered by the browser when not in use
  }, [])

  const registerServiceWorker = async () => {
    try {
      logger.info('ServiceWorker', 'Registering service worker...')

      const registration = await navigator.serviceWorker.register('/sw.js', {
        scope: '/',
        updateViaCache: 'none',
      })

      logger.info('ServiceWorker', 'Service worker registered successfully', {
        scope: registration.scope,
        updateViaCache: registration.updateViaCache,
      })

      // Handle service worker updates
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing

        if (newWorker) {
          logger.info('ServiceWorker', 'New service worker found, installing...')

          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed') {
              if (navigator.serviceWorker.controller) {
                // New update available
                logger.info('ServiceWorker', 'New service worker installed, update available')

                toast.success('App update available! Refresh to get the latest version.', {
                  duration: 8000,
                  icon: '🔄',
                })
              } else {
                // First time installation
                logger.info('ServiceWorker', 'Service worker installed for the first time')

                toast.success('App is ready for offline use!', {
                  duration: 4000,
                  icon: '📱',
                })
              }
            }
          })
        }
      })

      // Handle service worker controller change
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        logger.info('ServiceWorker', 'Service worker controller changed')

        // Optionally reload the page to ensure consistency
        if (confirm('App has been updated. Reload to get the latest version?')) {
          window.location.reload()
        }
      })

      // Check for waiting service worker
      if (registration.waiting) {
        logger.info('ServiceWorker', 'Service worker is waiting to activate')

        toast.success('App update is ready! Refresh to activate.', {
          duration: 8000,
          icon: '🔄',
        })
      }

      // Periodic update check (every 24 hours)
      setInterval(
        () => {
          registration.update()
        },
        24 * 60 * 60 * 1000
      )
    } catch (error) {
      logger.error('ServiceWorker', 'Service worker registration failed', error)

      // Don't show error toast to users as this is not critical
      console.warn('Service worker registration failed:', error)
    }
  }

  // Handle PWA install prompt
  useEffect(() => {
    let deferredPrompt: any = null

    const handleBeforeInstallPrompt = (event: Event) => {
      // Prevent the mini-infobar from appearing on mobile
      event.preventDefault()

      // Stash the event so it can be triggered later
      deferredPrompt = event

      logger.info('PWA', 'Install prompt available')

      // Show custom install prompt after a delay
      setTimeout(() => {
        showInstallPrompt(deferredPrompt)
      }, 10000) // Show after 10 seconds
    }

    const handleAppInstalled = () => {
      logger.info('PWA', 'App was installed')

      toast.success('Business Scraper installed successfully!', {
        duration: 4000,
        icon: '📱',
      })

      deferredPrompt = null
    }

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
    window.addEventListener('appinstalled', handleAppInstalled)

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
      window.removeEventListener('appinstalled', handleAppInstalled)
    }
  }, [])

  const showInstallPrompt = (deferredPrompt: any) => {
    if (!deferredPrompt) return

    // Only show if not already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      return // Already installed
    }

    toast.custom(
      t => (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg border max-w-sm">
          <div className="flex items-start space-x-3">
            <div className="text-2xl">📱</div>
            <div className="flex-1">
              <h3 className="font-semibold text-sm">Install Business Scraper</h3>
              <p className="text-xs text-muted-foreground mt-1">
                Add to your home screen for quick access and offline use.
              </p>
              <div className="flex space-x-2 mt-3">
                <button
                  onClick={async () => {
                    toast.dismiss(t.id)

                    try {
                      const result = await deferredPrompt.prompt()
                      logger.info('PWA', 'Install prompt result', { outcome: result.outcome })

                      if (result.outcome === 'accepted') {
                        toast.success('Installing app...', { duration: 2000 })
                      }
                    } catch (error) {
                      logger.error('PWA', 'Install prompt failed', error)
                    }

                    deferredPrompt = null
                  }}
                  className="px-3 py-1 bg-primary text-primary-foreground text-xs rounded hover:bg-primary/90"
                >
                  Install
                </button>
                <button
                  onClick={() => toast.dismiss(t.id)}
                  className="px-3 py-1 bg-muted text-muted-foreground text-xs rounded hover:bg-muted/80"
                >
                  Later
                </button>
              </div>
            </div>
          </div>
        </div>
      ),
      {
        duration: 15000,
        position: 'bottom-center',
      }
    )
  }

  // This component doesn't render anything
  return null
}

/**
 * Hook to check if app is running as PWA
 */
export function useIsPWA(): boolean {
  const [isPWA, setIsPWA] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return

    const checkPWA = () => {
      const isPWAMode = (
        window.matchMedia('(display-mode: standalone)').matches ||
        (window.navigator as any).standalone === true ||
        document.referrer.includes('android-app://')
      )
      setIsPWA(isPWAMode)
    }

    checkPWA()
  }, [])

  return isPWA
}
