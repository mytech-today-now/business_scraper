/**
 * Error Boundary Component
 * Catches JavaScript errors anywhere in the child component tree and displays a fallback UI
 */

import React, { Component, ErrorInfo, ReactNode } from 'react'
import { logger } from '@/utils/logger'
import { Alert } from './ui/Alert'
import { Button } from './ui/Button'
import { Card } from './ui/Card'

interface Props {
  children: ReactNode
  level?: 'page' | 'section' | 'component'
  fallback?: ReactNode
  showDetails?: boolean
  onError?: (error: Error, errorInfo: ErrorInfo) => void
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  errorId: string | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    // Update state so the next render will show the fallback UI
    return {
      hasError: true,
      error,
      errorId: `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log the error
    const errorId = this.state.errorId || `error_${Date.now()}`
    
    logger.error('ErrorBoundary', 'Component error caught', {
      error: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      errorId,
      level: this.props.level || 'component'
    })

    // Update state with error info
    this.setState({
      errorInfo,
      errorId
    })

    // Call custom error handler if provided
    if (this.props.onError) {
      this.props.onError(error, errorInfo)
    }
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    })
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      if (this.props.fallback) {
        return this.props.fallback
      }

      // Default fallback UI based on level
      const { level = 'component', showDetails = false } = this.props
      const { error, errorInfo, errorId } = this.state

      if (level === 'page') {
        return (
          <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md w-full space-y-8">
              <Card className="p-8">
                <div className="text-center">
                  <div className="mx-auto h-12 w-12 text-red-500 mb-4">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  </div>
                  <h2 className="text-2xl font-bold text-gray-900 mb-2">
                    Something went wrong
                  </h2>
                  <p className="text-gray-600 mb-6">
                    We're sorry, but something unexpected happened. Please try refreshing the page.
                  </p>
                  {showDetails && error && (
                    <Alert variant="destructive" className="text-left mb-4">
                      <div className="font-mono text-sm">
                        <div className="font-bold mb-2">Error: {error.message}</div>
                        {errorId && <div className="text-xs opacity-75">ID: {errorId}</div>}
                      </div>
                    </Alert>
                  )}
                  <div className="space-y-3">
                    <Button onClick={this.handleReload} className="w-full">
                      Reload Page
                    </Button>
                    <Button onClick={this.handleRetry} variant="outline" className="w-full">
                      Try Again
                    </Button>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        )
      }

      if (level === 'section') {
        return (
          <div className="py-8">
            <Alert variant="destructive">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="font-medium">Section Error</h3>
                  <p className="text-sm mt-1">
                    This section encountered an error and couldn't be displayed.
                  </p>
                  {showDetails && error && (
                    <div className="mt-3 font-mono text-xs bg-red-50 p-2 rounded border">
                      <div className="font-bold">{error.message}</div>
                      {errorId && <div className="opacity-75 mt-1">ID: {errorId}</div>}
                    </div>
                  )}
                  <div className="mt-3 space-x-2">
                    <Button onClick={this.handleRetry} size="sm" variant="outline">
                      Retry
                    </Button>
                    <Button onClick={this.handleReload} size="sm" variant="outline">
                      Reload Page
                    </Button>
                  </div>
                </div>
              </div>
            </Alert>
          </div>
        )
      }

      // Component level (default)
      return (
        <div className="p-4 border border-red-200 bg-red-50 rounded-lg">
          <div className="flex items-start space-x-2">
            <div className="flex-shrink-0 text-red-500">
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-red-800">
                Component Error
              </p>
              <p className="text-sm text-red-700 mt-1">
                This component couldn't be rendered due to an error.
              </p>
              {showDetails && error && (
                <div className="mt-2 font-mono text-xs bg-red-100 p-2 rounded border">
                  <div className="font-bold">{error.message}</div>
                  {errorId && <div className="opacity-75 mt-1">ID: {errorId}</div>}
                </div>
              )}
              <div className="mt-2">
                <Button onClick={this.handleRetry} size="sm" variant="outline" className="text-xs">
                  Retry
                </Button>
              </div>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

// Higher-order component for easier usage
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  errorBoundaryProps?: Omit<Props, 'children'>
) {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <Component {...props} />
    </ErrorBoundary>
  )

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`
  
  return WrappedComponent
}

// Hook for error reporting in functional components
export function useErrorHandler() {
  return (error: Error, errorInfo?: any) => {
    logger.error('ErrorHandler', 'Manual error report', {
      error: error.message,
      stack: error.stack,
      errorInfo,
      timestamp: new Date().toISOString()
    })
  }
}

export default ErrorBoundary
