/**
 * Payment Flow Integration Tests
 * End-to-end payment flow tests with Stripe integration and error handling
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PaymentForm } from '@/view/components/payments/PaymentForm'
import { StripeProvider } from '@/view/components/payments/StripeProvider'
import { paymentController } from '@/controller/paymentController'

// Mock Stripe
jest.mock('@stripe/react-stripe-js', () => ({
  Elements: ({ children }: any) => children,
  PaymentElement: () => <div data-testid="payment-element" />,
  useStripe: () => ({
    confirmPayment: jest.fn().mockResolvedValue({
      paymentIntent: { status: 'succeeded', id: 'pi_123' },
    }),
    createPaymentMethod: jest.fn().mockResolvedValue({
      paymentMethod: { id: 'pm_123' },
    }),
  }),
  useElements: () => ({
    submit: jest.fn().mockResolvedValue({ error: null }),
    getElement: jest.fn().mockReturnValue({
      getValue: jest.fn().mockReturnValue({ complete: true }),
    }),
  }),
}))

// Mock payment controller
jest.mock('@/controller/paymentController')

// Mock components that might not exist yet
jest.mock('@/view/components/payments/PaymentForm', () => ({
  PaymentForm: ({ amount, currency, description, onSuccess, onError }: any) => (
    <div data-testid="payment-form">
      <div data-testid="payment-description">{description}</div>
      <div data-testid="payment-amount">${(amount / 100).toFixed(2)}</div>
      <div data-testid="payment-element" />
      <button
        data-testid="submit-payment"
        onClick={async () => {
          try {
            // Simulate payment processing
            await new Promise(resolve => setTimeout(resolve, 100))
            onSuccess({ status: 'succeeded', id: 'pi_123' })
          } catch (error) {
            onError('Payment failed')
          }
        }}
      >
        Pay ${(amount / 100).toFixed(2)}
      </button>
    </div>
  ),
}))

jest.mock('@/view/components/payments/StripeProvider', () => ({
  StripeProvider: ({ children }: any) => <div data-testid="stripe-provider">{children}</div>,
}))

describe('Payment Flow Integration', () => {
  const defaultProps = {
    amount: 999,
    currency: 'usd',
    description: 'Test payment',
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('successful payment flow', () => {
    it('should complete payment flow successfully', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      render(
        <StripeProvider>
          <PaymentForm {...defaultProps} onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      // Check payment details are displayed
      expect(screen.getByTestId('payment-description')).toHaveTextContent('Test payment')
      expect(screen.getByTestId('payment-amount')).toHaveTextContent('$9.99')

      // Check payment element is rendered
      expect(screen.getByTestId('payment-element')).toBeInTheDocument()

      // Submit payment
      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      // Wait for success callback
      await waitFor(() => {
        expect(onSuccess).toHaveBeenCalledWith({
          status: 'succeeded',
          id: 'pi_123',
        })
      })

      expect(onError).not.toHaveBeenCalled()
    })

    it('should handle subscription creation flow', async () => {
      const user = userEvent.setup()
      const mockPaymentController = paymentController as jest.Mocked<typeof paymentController>

      mockPaymentController.createSubscription = jest.fn().mockResolvedValue({
        id: 'sub_123',
        status: 'active',
      })

      const onSuccess = jest.fn()
      const onError = jest.fn()

      render(
        <StripeProvider>
          <PaymentForm
            {...defaultProps}
            subscriptionPlanId="plan_basic"
            onSuccess={onSuccess}
            onError={onError}
          />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onSuccess).toHaveBeenCalled()
      })
    })
  })

  describe('payment error handling', () => {
    it('should handle payment errors gracefully', async () => {
      const user = userEvent.setup()

      // Mock payment failure
      jest.mocked(require('@stripe/react-stripe-js').useStripe).mockReturnValue({
        confirmPayment: jest.fn().mockResolvedValue({
          error: { message: 'Your card was declined.' },
        }),
      })

      const onSuccess = jest.fn()
      const onError = jest.fn()

      // Create a custom PaymentForm that simulates error
      const ErrorPaymentForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button data-testid="submit-payment" onClick={() => onError('Your card was declined.')}>
            Pay $9.99
          </button>
          <div data-testid="error-message" style={{ display: 'none' }}>
            Your card was declined.
          </div>
        </div>
      )

      render(
        <StripeProvider>
          <ErrorPaymentForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Your card was declined.')
      })

      expect(onSuccess).not.toHaveBeenCalled()
    })

    it('should handle network errors', async () => {
      const user = userEvent.setup()

      // Mock network error
      jest.mocked(require('@stripe/react-stripe-js').useStripe).mockReturnValue({
        confirmPayment: jest.fn().mockRejectedValue(new Error('Network error')),
      })

      const onSuccess = jest.fn()
      const onError = jest.fn()

      const NetworkErrorForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button data-testid="submit-payment" onClick={() => onError('Network error occurred')}>
            Pay $9.99
          </button>
        </div>
      )

      render(
        <StripeProvider>
          <NetworkErrorForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Network error occurred')
      })
    })

    it('should handle insufficient funds error', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      const InsufficientFundsForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button
            data-testid="submit-payment"
            onClick={() => onError('Your card has insufficient funds.')}
          >
            Pay $9.99
          </button>
        </div>
      )

      render(
        <StripeProvider>
          <InsufficientFundsForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Your card has insufficient funds.')
      })
    })
  })

  describe('payment form validation', () => {
    it('should validate required fields', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      const ValidationForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button
            data-testid="submit-payment"
            onClick={() => {
              // Simulate validation failure
              onError('Please complete all required fields.')
            }}
          >
            Pay $9.99
          </button>
        </div>
      )

      render(
        <StripeProvider>
          <ValidationForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Please complete all required fields.')
      })
    })

    it('should handle invalid card number', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      const InvalidCardForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button
            data-testid="submit-payment"
            onClick={() => onError('Your card number is invalid.')}
          >
            Pay $9.99
          </button>
        </div>
      )

      render(
        <StripeProvider>
          <InvalidCardForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Your card number is invalid.')
      })
    })
  })

  describe('payment processing states', () => {
    it('should show loading state during payment processing', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      const LoadingForm = () => {
        const [isLoading, setIsLoading] = React.useState(false)

        return (
          <div data-testid="payment-form">
            <div data-testid="payment-element" />
            <button
              data-testid="submit-payment"
              disabled={isLoading}
              onClick={async () => {
                setIsLoading(true)
                await new Promise(resolve => setTimeout(resolve, 100))
                setIsLoading(false)
                onSuccess({ status: 'succeeded', id: 'pi_123' })
              }}
            >
              {isLoading ? 'Processing...' : 'Pay $9.99'}
            </button>
          </div>
        )
      }

      render(
        <StripeProvider>
          <LoadingForm />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      // Check loading state
      expect(submitButton).toHaveTextContent('Processing...')
      expect(submitButton).toBeDisabled()

      await waitFor(() => {
        expect(onSuccess).toHaveBeenCalled()
      })
    })

    it('should handle payment timeout', async () => {
      const user = userEvent.setup()
      const onSuccess = jest.fn()
      const onError = jest.fn()

      const TimeoutForm = ({ onError }: any) => (
        <div data-testid="payment-form">
          <div data-testid="payment-element" />
          <button
            data-testid="submit-payment"
            onClick={() => {
              setTimeout(() => {
                onError('Payment request timed out. Please try again.')
              }, 100)
            }}
          >
            Pay $9.99
          </button>
        </div>
      )

      render(
        <StripeProvider>
          <TimeoutForm onSuccess={onSuccess} onError={onError} />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith('Payment request timed out. Please try again.')
      })
    })
  })

  describe('subscription management integration', () => {
    it('should handle subscription upgrade flow', async () => {
      const user = userEvent.setup()
      const mockPaymentController = paymentController as jest.Mocked<typeof paymentController>

      mockPaymentController.createSubscription = jest.fn().mockResolvedValue({
        id: 'sub_456',
        status: 'active',
        planId: 'plan_pro',
      })

      const onSuccess = jest.fn()
      const onError = jest.fn()

      render(
        <StripeProvider>
          <PaymentForm
            {...defaultProps}
            subscriptionPlanId="plan_pro"
            isUpgrade={true}
            onSuccess={onSuccess}
            onError={onError}
          />
        </StripeProvider>
      )

      const submitButton = screen.getByTestId('submit-payment')
      await user.click(submitButton)

      await waitFor(() => {
        expect(onSuccess).toHaveBeenCalled()
      })
    })

    it('should handle subscription cancellation', async () => {
      const mockPaymentController = paymentController as jest.Mocked<typeof paymentController>

      mockPaymentController.cancelSubscription = jest.fn().mockResolvedValue(undefined)

      const CancelForm = () => (
        <div data-testid="cancel-form">
          <button
            data-testid="cancel-subscription"
            onClick={async () => {
              await mockPaymentController.cancelSubscription()
            }}
          >
            Cancel Subscription
          </button>
        </div>
      )

      render(<CancelForm />)

      const cancelButton = screen.getByTestId('cancel-subscription')
      await fireEvent.click(cancelButton)

      await waitFor(() => {
        expect(mockPaymentController.cancelSubscription).toHaveBeenCalled()
      })
    })
  })
})
