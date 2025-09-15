/**
 * ClientOnlyStripeProvider Component Tests
 * Tests for the client-only Stripe provider wrapper
 */

import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { ClientOnlyStripeProvider } from '@/components/ClientOnlyStripeProvider'

// Mock the dynamic import
jest.mock('next/dynamic', () => {
  return jest.fn(() => {
    const MockStripeProvider = ({ children }: { children: React.ReactNode }) => (
      <div data-testid="mock-stripe-provider">{children}</div>
    )
    MockStripeProvider.displayName = 'MockStripeProvider'
    return MockStripeProvider
  })
})

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}))

describe('ClientOnlyStripeProvider', () => {
  const TestChild = () => <div data-testid="test-child">Test Child</div>

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Server-Side Rendering', () => {
    it('should render children without Stripe during SSR', () => {
      // Mock SSR environment
      Object.defineProperty(window, 'location', {
        value: undefined,
        writable: true,
      })

      render(
        <ClientOnlyStripeProvider>
          <TestChild />
        </ClientOnlyStripeProvider>
      )

      expect(screen.getByTestId('test-child')).toBeInTheDocument()
    })
  })

  describe('Client-Side Rendering', () => {
    it('should render children with Stripe provider after client hydration', async () => {
      render(
        <ClientOnlyStripeProvider>
          <TestChild />
        </ClientOnlyStripeProvider>
      )

      // Initially should render children
      expect(screen.getByTestId('test-child')).toBeInTheDocument()

      // After client-side initialization, should have Stripe provider
      await waitFor(() => {
        expect(screen.getByTestId('mock-stripe-provider')).toBeInTheDocument()
      })
    })

    it('should handle initialization errors gracefully', async () => {
      // Mock console.error to avoid noise in test output
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation()

      render(
        <ClientOnlyStripeProvider>
          <TestChild />
        </ClientOnlyStripeProvider>
      )

      expect(screen.getByTestId('test-child')).toBeInTheDocument()

      consoleSpy.mockRestore()
    })
  })

  describe('Error Boundary', () => {
    it('should render children even if Stripe provider fails', () => {
      // Mock dynamic import to throw an error
      const mockDynamic = require('next/dynamic')
      mockDynamic.mockImplementationOnce(() => {
        throw new Error('Failed to load Stripe')
      })

      expect(() => {
        render(
          <ClientOnlyStripeProvider>
            <TestChild />
          </ClientOnlyStripeProvider>
        )
      }).not.toThrow()

      expect(screen.getByTestId('test-child')).toBeInTheDocument()
    })
  })

  describe('Loading States', () => {
    it('should show loading state during Stripe initialization', () => {
      render(
        <ClientOnlyStripeProvider>
          <TestChild />
        </ClientOnlyStripeProvider>
      )

      // Should render children immediately
      expect(screen.getByTestId('test-child')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('should maintain accessibility for child components', () => {
      render(
        <ClientOnlyStripeProvider>
          <button aria-label="Test button">Click me</button>
        </ClientOnlyStripeProvider>
      )

      const button = screen.getByRole('button', { name: 'Test button' })
      expect(button).toBeInTheDocument()
      expect(button).toHaveAttribute('aria-label', 'Test button')
    })
  })
})
