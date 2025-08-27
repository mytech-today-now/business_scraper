'use client'

import React, { Component, ErrorInfo, ReactNode } from 'react'
import { logger } from '@/utils/logger'
import { Button } from '../view/components/ui/Button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../view/components/ui/Card'
import { AlertTriangle, RefreshCw, Home, Bug } from 'lucide-react'

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  errorId: string | null
}

interface ErrorBoundaryProps {
  children: ReactNode
  fallback?: ReactNode
  onError?: (error: Error, errorInfo: ErrorInfo) => void
  showDetails?: boolean
  level?: 'page' | 'component' | 'section'
}

/**
 * Comprehensive React Error Boundary with logging, recovery options, and user-friendly fallback UI
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private retryCount = 0
  private maxRetries = 3

  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
    }
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    // Update state so the next render will show the fallback UI
    return {
      hasError: true,
      error,
      errorId: generateErrorId(),
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const errorId = this.state.errorId || generateErrorId()

    // Log the error with full context
    logger.error('ErrorBoundary', `React Error Boundary caught error ${errorId}`, {
      errorId,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
      errorInfo: {
        componentStack: errorInfo.componentStack,
      },
      level: this.props.level || 'component',
      retryCount: this.retryCount,
      url: typeof window !== 'undefined' ? window.location.href : 'unknown',
      userAgent: typeof window !== 'undefined' ? window.navigator.userAgent : 'unknown',
    })

    // Update state with error info
    this.setState({
      errorInfo,
      errorId,
    })

    // Call custom error handler if provided
    this.props.onError?.(error, errorInfo)

    // Report to external error tracking service if available
    this.reportError(error, errorInfo, errorId)
  }

  private reportError = (error: Error, errorInfo: ErrorInfo, errorId: string) => {
    // In a real application, you would send this to an error tracking service
    // like Sentry, Bugsnag, or LogRocket
    if (process.env.NODE_ENV === 'production') {
      // Example: Sentry.captureException(error, { extra: errorInfo, tags: { errorId } })
      console.error('Error reported to tracking service:', { error, errorInfo, errorId })
    }
  }

  private handleRetry = () => {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++
      logger.info(
        'ErrorBoundary',
        `Retrying component render (attempt ${this.retryCount}/${this.maxRetries})`
      )

      this.setState({
        hasError: false,
        error: null,
        errorInfo: null,
        errorId: null,
      })
    }
  }

  private handleReload = () => {
    if (typeof window !== 'undefined') {
      window.location.reload()
    }
  }

  private handleGoHome = () => {
    if (typeof window !== 'undefined') {
      window.location.href = '/'
    }
  }

  private copyErrorDetails = () => {
    const errorDetails = {
      errorId: this.state.errorId,
      error: this.state.error?.message,
      stack: this.state.error?.stack,
      componentStack: this.state.errorInfo?.componentStack,
      timestamp: new Date().toISOString(),
      url: typeof window !== 'undefined' ? window.location.href : 'unknown',
    }

    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard
        .writeText(JSON.stringify(errorDetails, null, 2))
        .then(() => {
          // Could show a toast notification here
          console.log('Error details copied to clipboard')
        })
        .catch(err => {
          console.error('Failed to copy error details:', err)
        })
    }
  }

  render() {
    if (this.state.hasError) {
      // Custom fallback UI provided
      if (this.props.fallback) {
        return this.props.fallback
      }

      // Default fallback UI
      const { level = 'component' } = this.props
      const canRetry = this.retryCount < this.maxRetries

      return (
        <div className="error-boundary-container p-4" data-testid="error-boundary">
          <Card className="max-w-2xl mx-auto">
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <CardTitle className="text-destructive">
                  {level === 'page' ? 'Page Error' : 'Component Error'}
                </CardTitle>
              </div>
              <CardDescription>
                Something went wrong while rendering this {level}.
                {this.state.errorId && ` Error ID: ${this.state.errorId}`}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Error message */}
              <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3">
                <p className="text-sm text-destructive font-medium">
                  {this.state.error?.message || 'An unexpected error occurred'}
                </p>
              </div>

              {/* Action buttons */}
              <div className="flex flex-wrap gap-2">
                {canRetry && (
                  <Button
                    onClick={this.handleRetry}
                    variant="default"
                    size="sm"
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="h-4 w-4" />
                    Try Again ({this.maxRetries - this.retryCount} left)
                  </Button>
                )}

                <Button
                  onClick={this.handleReload}
                  variant="outline"
                  size="sm"
                  className="flex items-center gap-2"
                >
                  <RefreshCw className="h-4 w-4" />
                  Reload Page
                </Button>

                {level === 'page' && (
                  <Button
                    onClick={this.handleGoHome}
                    variant="outline"
                    size="sm"
                    className="flex items-center gap-2"
                  >
                    <Home className="h-4 w-4" />
                    Go Home
                  </Button>
                )}
              </div>

              {/* Error details (development only or when explicitly enabled) */}
              {(process.env.NODE_ENV === 'development' || this.props.showDetails) && (
                <details className="mt-4">
                  <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground">
                    <span className="flex items-center gap-2">
                      <Bug className="h-4 w-4" />
                      Technical Details
                    </span>
                  </summary>
                  <div
                    className="mt-2 p-3 bg-muted rounded-lg text-xs font-mono overflow-auto max-h-40"
                    data-testid="error-details"
                  >
                    <div className="space-y-2">
                      <div>
                        <strong>Error:</strong> {this.state.error?.name}
                      </div>
                      <div>
                        <strong>Message:</strong> {this.state.error?.message}
                      </div>
                      {this.state.error?.stack && (
                        <div>
                          <strong>Stack:</strong>
                          <pre className="mt-1 whitespace-pre-wrap">{this.state.error.stack}</pre>
                        </div>
                      )}
                      {this.state.errorInfo?.componentStack && (
                        <div>
                          <strong>Component Stack:</strong>
                          <pre className="mt-1 whitespace-pre-wrap">
                            {this.state.errorInfo.componentStack}
                          </pre>
                        </div>
                      )}
                    </div>
                    <Button
                      onClick={this.copyErrorDetails}
                      variant="ghost"
                      size="sm"
                      className="mt-2"
                    >
                      Copy Details
                    </Button>
                  </div>
                </details>
              )}
            </CardContent>
          </Card>
        </div>
      )
    }

    return this.props.children
  }
}

/**
 * Generate a unique error ID for tracking
 */
function generateErrorId(): string {
  return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

/**
 * Hook-based error boundary for functional components
 */
export function useErrorHandler() {
  return (error: Error, errorInfo?: ErrorInfo) => {
    const errorId = generateErrorId()

    logger.error('ErrorHandler', `Unhandled error ${errorId}`, {
      errorId,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
      errorInfo,
    })

    // In a real application, report to error tracking service
    if (process.env.NODE_ENV === 'production') {
      console.error('Error reported:', { error, errorInfo, errorId })
    }

    throw error // Re-throw to trigger error boundary
  }
}

/**
 * Higher-order component for wrapping components with error boundary
 */
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  errorBoundaryProps?: Omit<ErrorBoundaryProps, 'children'>
) {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <Component {...props} />
    </ErrorBoundary>
  )

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`

  return WrappedComponent
}
