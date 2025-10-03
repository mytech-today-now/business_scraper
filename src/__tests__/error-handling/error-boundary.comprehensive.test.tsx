/**
 * Error Boundary - Comprehensive Test Suite
 * Tests React error boundaries, fallback UI, error recovery, and logging
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ErrorBoundary, withErrorBoundary, useErrorHandler } from '@/components/ErrorBoundary'
import { logger } from '@/utils/logger'
import { securityTokenErrorLogger } from '@/utils/enhancedErrorLogger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/utils/enhancedErrorLogger')
jest.mock('@/utils/debugConfig', () => ({
  shouldPreventAutoReload: jest.fn(() => false),
  shouldUseEnhancedErrorLogging: jest.fn(() => false),
  safeReload: jest.fn(),
  logEnhancedError: jest.fn(),
}))

const mockLogger = logger as jest.Mocked<typeof logger>
const mockSecurityTokenErrorLogger = securityTokenErrorLogger as jest.Mocked<typeof securityTokenErrorLogger>

// Test components that throw errors
const ThrowingComponent: React.FC<{ shouldThrow?: boolean; errorMessage?: string }> = ({ 
  shouldThrow = true, 
  errorMessage = 'Test error' 
}) => {
  if (shouldThrow) {
    throw new Error(errorMessage)
  }
  return <div data-testid="working-component">Component works!</div>
}

const AsyncThrowingComponent: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = true }) => {
  React.useEffect(() => {
    if (shouldThrow) {
      throw new Error('Async test error')
    }
  }, [shouldThrow])
  
  return <div data-testid="async-component">Async component</div>
}

describe('Error Boundary - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(console, 'group').mockImplementation(() => {})
    jest.spyOn(console, 'groupEnd').mockImplementation(() => {})
    jest.spyOn(console, 'table').mockImplementation(() => {})
    jest.spyOn(console, 'trace').mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Basic Error Catching', () => {
    it('should catch and display error when child component throws', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Component crashed!" />
        </ErrorBoundary>
      )

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
      expect(screen.getByText(/component crashed!/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    })

    it('should render children normally when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent shouldThrow={false} />
        </ErrorBoundary>
      )

      expect(screen.getByTestId('working-component')).toBeInTheDocument()
      expect(screen.getByText('Component works!')).toBeInTheDocument()
    })

    it('should catch errors from multiple child components', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="First error" />
          <ThrowingComponent errorMessage="Second error" />
        </ErrorBoundary>
      )

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
      expect(screen.getByText(/first error/i)).toBeInTheDocument()
    })
  })

  describe('Error Logging', () => {
    it('should log error details when component throws', () => {
      render(
        <ErrorBoundary level="component">
          <ThrowingComponent errorMessage="Logged error" />
        </ErrorBoundary>
      )

      expect(mockLogger.error).toHaveBeenCalledWith(
        'ErrorBoundary',
        expect.stringContaining('React Error Boundary caught error'),
        expect.objectContaining({
          errorId: expect.any(String),
          error: expect.objectContaining({
            name: 'Error',
            message: 'Logged error',
            stack: expect.any(String),
          }),
          errorInfo: expect.objectContaining({
            componentStack: expect.any(String),
          }),
          level: 'component',
          retryCount: 0,
        })
      )
    })

    it('should generate unique error IDs for different errors', () => {
      const { rerender } = render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="First error" />
        </ErrorBoundary>
      )

      const firstCall = mockLogger.error.mock.calls[0]
      const firstErrorId = firstCall[2].errorId

      // Clear the error and throw a new one
      fireEvent.click(screen.getByRole('button', { name: /retry/i }))
      
      rerender(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Second error" />
        </ErrorBoundary>
      )

      const secondCall = mockLogger.error.mock.calls[1]
      const secondErrorId = secondCall[2].errorId

      expect(firstErrorId).not.toBe(secondErrorId)
    })

    it('should call custom error handler when provided', () => {
      const customErrorHandler = jest.fn()

      render(
        <ErrorBoundary onError={customErrorHandler}>
          <ThrowingComponent errorMessage="Custom handler test" />
        </ErrorBoundary>
      )

      expect(customErrorHandler).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          componentStack: expect.any(String),
        })
      )
    })
  })

  describe('Error Recovery', () => {
    it('should allow retry after error occurs', async () => {
      let shouldThrow = true
      const TestComponent = () => {
        if (shouldThrow) {
          throw new Error('Retryable error')
        }
        return <div data-testid="recovered-component">Recovered!</div>
      }

      render(
        <ErrorBoundary>
          <TestComponent />
        </ErrorBoundary>
      )

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()

      // Fix the component and retry
      shouldThrow = false
      fireEvent.click(screen.getByRole('button', { name: /retry/i }))

      await waitFor(() => {
        expect(screen.getByTestId('recovered-component')).toBeInTheDocument()
      })
    })

    it('should limit retry attempts', () => {
      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Persistent error" />
        </ErrorBoundary>
      )

      // Try to retry multiple times
      for (let i = 0; i < 5; i++) {
        if (screen.queryByRole('button', { name: /retry/i })) {
          fireEvent.click(screen.getByRole('button', { name: /retry/i }))
        }
      }

      // Should still show error after max retries
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
    })

    it('should provide reload option when retry fails', () => {
      const mockReload = jest.fn()
      Object.defineProperty(window, 'location', {
        value: { reload: mockReload },
        writable: true,
      })

      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Reload test" />
        </ErrorBoundary>
      )

      const reloadButton = screen.getByRole('button', { name: /reload page/i })
      fireEvent.click(reloadButton)

      expect(mockReload).toHaveBeenCalled()
    })
  })

  describe('Fallback UI Customization', () => {
    it('should render custom fallback component when provided', () => {
      const CustomFallback = () => <div data-testid="custom-fallback">Custom error UI</div>

      render(
        <ErrorBoundary fallback={<CustomFallback />}>
          <ThrowingComponent />
        </ErrorBoundary>
      )

      expect(screen.getByTestId('custom-fallback')).toBeInTheDocument()
      expect(screen.getByText('Custom error UI')).toBeInTheDocument()
    })

    it('should show different UI based on error level', () => {
      render(
        <ErrorBoundary level="page">
          <ThrowingComponent errorMessage="Page level error" />
        </ErrorBoundary>
      )

      expect(screen.getByText(/page level error/i)).toBeInTheDocument()
      expect(mockLogger.error).toHaveBeenCalledWith(
        'ErrorBoundary',
        expect.any(String),
        expect.objectContaining({
          level: 'page',
        })
      )
    })

    it('should show error details when showDetails is true', () => {
      render(
        <ErrorBoundary showDetails={true}>
          <ThrowingComponent errorMessage="Detailed error" />
        </ErrorBoundary>
      )

      expect(screen.getByText(/detailed error/i)).toBeInTheDocument()
      expect(screen.getByText(/error id:/i)).toBeInTheDocument()
    })
  })

  describe('Higher-Order Component', () => {
    it('should wrap component with error boundary using HOC', () => {
      const WrappedComponent = withErrorBoundary(ThrowingComponent, {
        level: 'component',
        showDetails: true,
      })

      render(<WrappedComponent errorMessage="HOC test error" />)

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
      expect(screen.getByText(/hoc test error/i)).toBeInTheDocument()
    })

    it('should preserve component display name in HOC', () => {
      const TestComponent = () => <div>Test</div>
      TestComponent.displayName = 'TestComponent'

      const WrappedComponent = withErrorBoundary(TestComponent)

      expect(WrappedComponent.displayName).toBe('withErrorBoundary(TestComponent)')
    })

    it('should work with functional components', () => {
      const FunctionalComponent = ({ shouldThrow }: { shouldThrow: boolean }) => {
        if (shouldThrow) {
          throw new Error('Functional component error')
        }
        return <div data-testid="functional-component">Functional works</div>
      }

      const WrappedComponent = withErrorBoundary(FunctionalComponent)

      const { rerender } = render(<WrappedComponent shouldThrow={true} />)
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()

      rerender(<WrappedComponent shouldThrow={false} />)
      expect(screen.getByTestId('functional-component')).toBeInTheDocument()
    })
  })

  describe('Error Handler Hook', () => {
    it('should provide error handler function', () => {
      const TestComponent = () => {
        const handleError = useErrorHandler()
        
        const triggerError = () => {
          try {
            throw new Error('Hook test error')
          } catch (error) {
            handleError(error as Error)
          }
        }

        return <button onClick={triggerError} data-testid="trigger-error">Trigger Error</button>
      }

      expect(() => {
        render(
          <ErrorBoundary>
            <TestComponent />
          </ErrorBoundary>
        )
        
        fireEvent.click(screen.getByTestId('trigger-error'))
      }).toThrow('Hook test error')
    })
  })

  describe('Enhanced Error Logging', () => {
    it('should use enhanced logging when enabled', () => {
      const { shouldUseEnhancedErrorLogging } = require('@/utils/debugConfig')
      shouldUseEnhancedErrorLogging.mockReturnValue(true)

      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Enhanced logging test" />
        </ErrorBoundary>
      )

      expect(mockSecurityTokenErrorLogger.logComponentError).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          componentName: 'Unknown',
          errorBoundary: 'ErrorBoundary',
        }),
        expect.objectContaining({
          errorInfo: expect.any(Object),
          errorId: expect.any(String),
          retryCount: 0,
          level: 'component',
        })
      )
    })
  })

  describe('Production Error Reporting', () => {
    it('should report errors to external service in production', () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation()

      render(
        <ErrorBoundary>
          <ThrowingComponent errorMessage="Production error" />
        </ErrorBoundary>
      )

      expect(consoleSpy).toHaveBeenCalledWith(
        'Error reported to tracking service:',
        expect.objectContaining({
          error: expect.any(Error),
          errorInfo: expect.any(Object),
          errorId: expect.any(String),
        })
      )

      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Edge Cases and Error Scenarios', () => {
    it('should handle null or undefined children gracefully', () => {
      render(
        <ErrorBoundary>
          {null}
          {undefined}
        </ErrorBoundary>
      )

      // Should not crash and should not show error UI
      expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument()
    })

    it('should handle errors in error boundary itself', () => {
      const BuggyErrorBoundary = () => {
        throw new Error('Error boundary error')
      }

      expect(() => {
        render(<BuggyErrorBoundary />)
      }).toThrow('Error boundary error')
    })

    it('should handle very long error messages', () => {
      const longErrorMessage = 'A'.repeat(1000)

      render(
        <ErrorBoundary showDetails={true}>
          <ThrowingComponent errorMessage={longErrorMessage} />
        </ErrorBoundary>
      )

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
      // Should truncate or handle long messages gracefully
    })

    it('should handle errors with circular references', () => {
      const CircularErrorComponent = () => {
        const obj: any = {}
        obj.self = obj
        const error = new Error('Circular error')
        ;(error as any).circular = obj
        throw error
      }

      render(
        <ErrorBoundary>
          <CircularErrorComponent />
        </ErrorBoundary>
      )

      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
      expect(mockLogger.error).toHaveBeenCalled()
    })
  })
})
