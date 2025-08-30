/**
 * PaymentForm Component Tests
 * Comprehensive unit tests for PaymentForm component
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'
import { PaymentForm } from '@/view/components/payments/PaymentForm'

// Mock Stripe hooks
const mockStripe = {
  confirmPayment: jest.fn(),
  createPaymentMethod: jest.fn(),
}

const mockElements = {
  submit: jest.fn(),
  getElement: jest.fn(),
}

jest.mock('@stripe/react-stripe-js', () => ({
  PaymentElement: ({ options }: { options?: any }) => (
    <div data-testid="payment-element" data-options={JSON.stringify(options)}>
      Payment Element Mock
    </div>
  ),
  useStripe: () => mockStripe,
  useElements: () => mockElements,
}))

// Mock UI components
jest.mock('@/view/components/ui/Button', () => ({
  Button: ({ children, onClick, disabled, className, size, type }: any) => (
    <button
      onClick={onClick}
      disabled={disabled}
      className={className}
      data-size={size}
      type={type}
      data-testid="payment-button"
    >
      {children}
    </button>
  ),
}))

jest.mock('@/view/components/ui/Alert', () => ({
  Alert: ({ children, variant }: { children: React.ReactNode; variant: string }) => (
    <div data-testid="alert" data-variant={variant}>
      {children}
    </div>
  ),
}))

jest.mock('@/view/components/ui/Spinner', () => ({
  Spinner: ({ className }: { className?: string }) => (
    <div data-testid="spinner" className={className}>
      Loading...
    </div>
  ),
}))

describe('PaymentForm', () => {
  const defaultProps = {
    amount: 2999, // $29.99
    currency: 'usd',
    description: 'Test payment for premium subscription',
    onSuccess: jest.fn(),
    onError: jest.fn(),
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockElements.submit.mockResolvedValue({ error: null })
    mockStripe.confirmPayment.mockResolvedValue({
      error: null,
      paymentIntent: { status: 'succeeded', id: 'pi_test_123' },
    })
  })

  describe('Rendering', () => {
    it('should render payment form with correct amount and description', () => {
      render(<PaymentForm {...defaultProps} />)

      expect(screen.getByText('Payment Details')).toBeInTheDocument()
      expect(screen.getByText(defaultProps.description)).toBeInTheDocument()
      expect(screen.getByText('$29.99')).toBeInTheDocument()
      expect(screen.getByTestId('payment-element')).toBeInTheDocument()
      expect(screen.getByTestId('payment-button')).toBeInTheDocument()
    })

    it('should render with different currency', () => {
      render(<PaymentForm {...defaultProps} currency="eur" amount={3500} />)

      expect(screen.getByText('€35.00')).toBeInTheDocument()
    })

    it('should render PaymentElement with correct options', () => {
      render(<PaymentForm {...defaultProps} />)

      const paymentElement = screen.getByTestId('payment-element')
      const options = JSON.parse(paymentElement.getAttribute('data-options') || '{}')
      expect(options.layout).toBe('tabs')
    })

    it('should show correct button text with formatted amount', () => {
      render(<PaymentForm {...defaultProps} />)

      expect(screen.getByText('Pay $29.99')).toBeInTheDocument()
    })
  })

  describe('Form Submission', () => {
    it('should handle successful payment submission', async () => {
      const user = userEvent.setup()
      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      await waitFor(() => {
        expect(mockElements.submit).toHaveBeenCalled()
        expect(mockStripe.confirmPayment).toHaveBeenCalledWith({
          elements: mockElements,
          confirmParams: {
            return_url: `${window.location.origin}/payment/success`,
          },
          redirect: 'if_required',
        })
        expect(defaultProps.onSuccess).toHaveBeenCalledWith({
          status: 'succeeded',
          id: 'pi_test_123',
        })
      })
    })

    it('should handle payment submission errors', async () => {
      const user = userEvent.setup()
      mockElements.submit.mockResolvedValueOnce({
        error: { message: 'Invalid payment method' },
      })

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      await waitFor(() => {
        expect(screen.getByTestId('alert')).toBeInTheDocument()
        expect(screen.getByText('Invalid payment method')).toBeInTheDocument()
      })
    })

    it('should handle payment confirmation errors', async () => {
      const user = userEvent.setup()
      mockStripe.confirmPayment.mockResolvedValueOnce({
        error: { message: 'Your card was declined' },
        paymentIntent: null,
      })

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      await waitFor(() => {
        expect(screen.getByTestId('alert')).toBeInTheDocument()
        expect(screen.getByText('Your card was declined')).toBeInTheDocument()
        expect(defaultProps.onError).toHaveBeenCalledWith('Your card was declined')
      })
    })

    it('should handle unexpected errors', async () => {
      const user = userEvent.setup()
      mockElements.submit.mockRejectedValueOnce(new Error('Network error'))

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      await waitFor(() => {
        expect(screen.getByTestId('alert')).toBeInTheDocument()
        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument()
        expect(defaultProps.onError).toHaveBeenCalledWith('An unexpected error occurred')
      })
    })
  })

  describe('Loading States', () => {
    it('should show loading state during payment processing', async () => {
      const user = userEvent.setup()
      mockElements.submit.mockImplementationOnce(
        () => new Promise(resolve => setTimeout(() => resolve({ error: null }), 100))
      )

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      expect(screen.getByTestId('spinner')).toBeInTheDocument()
      expect(screen.getByText('Processing Payment...')).toBeInTheDocument()
      expect(submitButton).toBeDisabled()
    })

    it('should disable button when Stripe is not loaded', () => {
      jest.doMock('@stripe/react-stripe-js', () => ({
        PaymentElement: () => <div data-testid="payment-element" />,
        useStripe: () => null,
        useElements: () => mockElements,
      }))

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      expect(submitButton).toBeDisabled()
    })

    it('should disable button when Elements is not loaded', () => {
      jest.doMock('@stripe/react-stripe-js', () => ({
        PaymentElement: () => <div data-testid="payment-element" />,
        useStripe: () => mockStripe,
        useElements: () => null,
      }))

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      expect(submitButton).toBeDisabled()
    })
  })

  describe('Currency Formatting', () => {
    it('should format USD currency correctly', () => {
      render(<PaymentForm {...defaultProps} amount={1234} currency="usd" />)
      expect(screen.getByText('$12.34')).toBeInTheDocument()
    })

    it('should format EUR currency correctly', () => {
      render(<PaymentForm {...defaultProps} amount={5678} currency="eur" />)
      expect(screen.getByText('€56.78')).toBeInTheDocument()
    })

    it('should handle zero amount', () => {
      render(<PaymentForm {...defaultProps} amount={0} />)
      expect(screen.getByText('$0.00')).toBeInTheDocument()
    })

    it('should handle large amounts', () => {
      render(<PaymentForm {...defaultProps} amount={999999} />)
      expect(screen.getByText('$9,999.99')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('should have proper form structure', () => {
      render(<PaymentForm {...defaultProps} />)

      const form = screen.getByRole('form') || screen.getByTestId('payment-button').closest('form')
      expect(form).toBeInTheDocument()
    })

    it('should have accessible button', () => {
      render(<PaymentForm {...defaultProps} />)

      const button = screen.getByTestId('payment-button')
      expect(button).toHaveAttribute('type', 'submit')
    })

    it('should show error messages accessibly', async () => {
      const user = userEvent.setup()
      mockElements.submit.mockResolvedValueOnce({
        error: { message: 'Test error' },
      })

      render(<PaymentForm {...defaultProps} />)

      const submitButton = screen.getByTestId('payment-button')
      await user.click(submitButton)

      await waitFor(() => {
        const alert = screen.getByTestId('alert')
        expect(alert).toHaveAttribute('data-variant', 'error')
      })
    })
  })
})
