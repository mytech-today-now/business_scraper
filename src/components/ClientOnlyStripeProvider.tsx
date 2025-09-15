'use client'

import React, { useEffect, useState, Suspense } from 'react'
import dynamic from 'next/dynamic'
import { logger } from '@/utils/logger'

interface ClientOnlyStripeProviderProps {
  children: React.ReactNode
}

// Dynamically import StripeProvider with error handling
const StripeProvider = dynamic(
  () => import('@/view/components/payments/StripeProvider').then(mod => ({ default: mod.StripeProvider })),
  {
    ssr: false,
    loading: () => <div data-testid="stripe-loading">Loading payment system...</div>,
  }
)

/**
 * Client-only wrapper for StripeProvider to prevent SSR issues
 * This component ensures Stripe is only initialized on the client side
 * with proper error handling and fallback mechanisms
 */
export function ClientOnlyStripeProvider({ children }: ClientOnlyStripeProviderProps): JSX.Element {
  const [isClient, setIsClient] = useState(false)
  const [hasError, setHasError] = useState(false)

  useEffect(() => {
    try {
      // Only set to true after component mounts on client
      setIsClient(true)
      logger.info('ClientOnlyStripeProvider', 'Client-side initialization complete')
    } catch (error) {
      logger.error('ClientOnlyStripeProvider', 'Error during client initialization', { error })
      setHasError(true)
    }
  }, [])

  // During SSR or before client hydration, render children without Stripe
  if (!isClient) {
    return <>{children}</>
  }

  // If there's an error, render children without Stripe but log the issue
  if (hasError) {
    logger.warn('ClientOnlyStripeProvider', 'Rendering without Stripe due to initialization error')
    return <>{children}</>
  }

  // After client hydration, render with StripeProvider wrapped in error boundary
  return (
    <Suspense fallback={<div data-testid="stripe-suspense-loading">Initializing payment system...</div>}>
      <ErrorBoundaryWrapper>
        <StripeProvider>
          {children}
        </StripeProvider>
      </ErrorBoundaryWrapper>
    </Suspense>
  )
}

/**
 * Error boundary wrapper for Stripe provider to handle any loading errors
 */
class ErrorBoundaryWrapper extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error) {
    logger.error('ClientOnlyStripeProvider', 'Stripe provider error boundary triggered', { error })
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    logger.error('ClientOnlyStripeProvider', 'Stripe provider component error', {
      error: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack
    })
  }

  render() {
    if (this.state.hasError) {
      logger.warn('ClientOnlyStripeProvider', 'Rendering children without Stripe due to error boundary')
      return this.props.children
    }

    return this.props.children
  }
}
