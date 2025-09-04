'use client'

import React, { useState, useEffect } from 'react'
import { Elements } from '@stripe/react-stripe-js'
import { loadStripe, Stripe } from '@stripe/stripe-js'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'

const config = getConfig()

// Enhanced Stripe loading with retry mechanism and error handling
let stripePromise: Promise<Stripe | null> | null = null

const loadStripeWithRetry = async (retries = 5, delay = 1000): Promise<Stripe | null> => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      logger.info('StripeProvider', `Loading Stripe.js (attempt ${attempt}/${retries})`)

      // Check if we have a valid publishable key
      if (
        !config.payments.stripePublishableKey ||
        config.payments.stripePublishableKey === 'pk_test_...'
      ) {
        logger.warn('StripeProvider', 'Stripe publishable key not configured properly')
        return null
      }

      // Check network connectivity first
      if (typeof window !== 'undefined' && !window.navigator.onLine) {
        logger.warn('StripeProvider', 'Device is offline, skipping Stripe.js loading attempt')
        throw new Error('Device is offline')
      }

      // Add timeout to prevent hanging - increased for better reliability
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Stripe loading timeout')), 15000)
      })

      // Enhanced Stripe loading with better error handling
      const stripePromise = loadStripe(config.payments.stripePublishableKey, {
        stripeAccount: undefined, // Use default account
        locale: 'auto',
        // Note: apiVersion removed as it's not supported in current Stripe.js version
      })

      const stripe = await Promise.race([stripePromise, timeoutPromise])

      if (stripe) {
        logger.info('StripeProvider', 'Stripe.js loaded successfully')
        return stripe
      } else {
        throw new Error('Stripe.js returned null')
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      logger.error(
        'StripeProvider',
        `Failed to load Stripe.js (attempt ${attempt}/${retries})`,
        error
      )

      // Handle specific error types
      if (errorMessage.includes('503') || errorMessage.includes('Service Unavailable')) {
        logger.warn('StripeProvider', 'Stripe.js service temporarily unavailable (503)')
      } else if (errorMessage.includes('timeout')) {
        logger.warn('StripeProvider', 'Stripe.js loading timed out')
      } else if (errorMessage.includes('offline')) {
        logger.warn('StripeProvider', 'Device is offline, will retry when online')
      }

      if (attempt === retries) {
        logger.error(
          'StripeProvider',
          'All Stripe.js loading attempts failed - payment features will be disabled'
        )

        // Log comprehensive debugging information
        logger.info('StripeProvider', 'Stripe loading debug info', {
          userAgent: typeof window !== 'undefined' ? window.navigator.userAgent : 'server',
          online: typeof window !== 'undefined' ? window.navigator.onLine : 'unknown',
          publishableKey: config.payments.stripePublishableKey ? 'configured' : 'missing',
          environment: process.env.NODE_ENV,
          lastError: errorMessage,
          totalAttempts: retries,
        })

        // Emit custom event for monitoring
        if (typeof window !== 'undefined') {
          window.dispatchEvent(
            new CustomEvent('stripe-loading-failed', {
              detail: { attempts: retries, lastError: errorMessage },
            })
          )
        }

        return null
      }

      // Enhanced exponential backoff with jitter and network-aware delays
      const baseDelay = delay * Math.pow(2, attempt - 1)
      const jitter = Math.random() * 1000
      const networkDelay = errorMessage.includes('503') ? 5000 : 0 // Extra delay for 503 errors
      const totalDelay = baseDelay + jitter + networkDelay

      logger.info('StripeProvider', `Retrying in ${Math.round(totalDelay)}ms...`)
      await new Promise(resolve => setTimeout(resolve, totalDelay))
    }
  }

  return null
}

// Initialize Stripe promise with retry logic
if (!stripePromise) {
  stripePromise = loadStripeWithRetry()
}

interface StripeProviderProps {
  children: React.ReactNode
  clientSecret?: string
}

export const StripeProvider: React.FC<StripeProviderProps> = ({ children, clientSecret }) => {
  const [stripeLoadError, setStripeLoadError] = useState<string | null>(null)
  const [isStripeLoading, setIsStripeLoading] = useState(true)
  const [retryCount, setRetryCount] = useState(0)

  useEffect(() => {
    // Monitor Stripe loading status with enhanced error handling
    const checkStripeStatus = async () => {
      try {
        const stripe = await stripePromise
        if (stripe) {
          setIsStripeLoading(false)
          setStripeLoadError(null)
          setRetryCount(0)
          logger.info('StripeProvider', 'Stripe provider initialized successfully')
        } else {
          setIsStripeLoading(false)
          setStripeLoadError('Stripe.js failed to load. Payment features may be unavailable.')
          logger.warn('StripeProvider', 'Stripe.js failed to load - payment features disabled')
        }
      } catch (error) {
        setIsStripeLoading(false)
        setStripeLoadError('Payment system temporarily unavailable')
        logger.error('StripeProvider', 'Error initializing Stripe provider', error)
      }
    }

    // Listen for custom Stripe loading events
    const handleStripeLoadingFailed = (event: CustomEvent) => {
      logger.error('StripeProvider', 'Received stripe-loading-failed event', event.detail)
      setStripeLoadError(`Payment system unavailable after ${event.detail.attempts} attempts`)
      setRetryCount(event.detail.attempts)
    }

    if (typeof window !== 'undefined') {
      window.addEventListener('stripe-loading-failed', handleStripeLoadingFailed as EventListener)
    }

    checkStripeStatus()

    // Cleanup event listener
    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener(
          'stripe-loading-failed',
          handleStripeLoadingFailed as EventListener
        )
      }
    }
  }, [])

  const options = {
    clientSecret,
    appearance: {
      theme: 'stripe' as const,
      variables: {
        colorPrimary: '#667eea',
        colorBackground: '#ffffff',
        colorText: '#2d3748',
        colorDanger: '#e53e3e',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        spacingUnit: '4px',
        borderRadius: '8px',
      },
    },
  }

  // Show loading state while Stripe is initializing
  if (isStripeLoading) {
    return (
      <div className="stripe-loading">
        {children}
        {/* Stripe is loading in background - app continues to function */}
      </div>
    )
  }

  // Show error state if Stripe failed to load, but still render children
  if (stripeLoadError) {
    logger.warn('StripeProvider', `Rendering with Stripe error: ${stripeLoadError}`)
    // Still render Elements with null stripe to prevent crashes
    return (
      <Elements stripe={null} options={undefined}>
        {children}
      </Elements>
    )
  }

  return (
    <Elements stripe={stripePromise} options={clientSecret ? options : undefined}>
      {children}
    </Elements>
  )
}
