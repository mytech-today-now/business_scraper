import React, { useState } from 'react'
import {
  PaymentElement,
  useStripe,
  useElements
} from '@stripe/react-stripe-js'
import { Button } from '@/view/components/ui/Button'
import { Alert } from '@/view/components/ui/Alert'
import { Spinner } from '@/view/components/ui/Spinner'

interface PaymentFormProps {
  onSuccess?: (paymentIntent: any) => void
  onError?: (error: string) => void
  amount: number
  currency?: string
  description: string
}

export const PaymentForm: React.FC<PaymentFormProps> = ({
  onSuccess,
  onError,
  amount,
  currency = 'usd',
  description
}) => {
  const stripe = useStripe()
  const elements = useElements()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()

    if (!stripe || !elements) {
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const { error: submitError } = await elements.submit()
      if (submitError) {
        setError(submitError.message || 'Payment submission failed')
        setIsLoading(false)
        return
      }

      const { error: confirmError, paymentIntent } = await stripe.confirmPayment({
        elements,
        confirmParams: {
          return_url: `${window.location.origin}/payment/success`
        },
        redirect: 'if_required'
      })

      if (confirmError) {
        setError(confirmError.message || 'Payment confirmation failed')
        onError?.(confirmError.message || 'Payment failed')
      } else if (paymentIntent?.status === 'succeeded') {
        onSuccess?.(paymentIntent)
      }
    } catch (err) {
      setError('An unexpected error occurred')
      onError?.('An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const formatAmount = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase()
    }).format(cents / 100)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="bg-gray-50 p-4 rounded-lg">
        <h3 className="font-semibold text-lg mb-2">Payment Details</h3>
        <p className="text-gray-600 mb-2">{description}</p>
        <p className="text-2xl font-bold text-blue-600">
          {formatAmount(amount)}
        </p>
      </div>

      <div className="space-y-4">
        <PaymentElement
          options={{
            layout: 'tabs'
          }}
        />
      </div>

      {error && (
        <Alert variant="error">
          {error}
        </Alert>
      )}

      <Button
        type="submit"
        disabled={!stripe || !elements || isLoading}
        className="w-full"
        size="lg"
      >
        {isLoading ? (
          <>
            <Spinner className="mr-2" />
            Processing Payment...
          </>
        ) : (
          `Pay ${formatAmount(amount)}`
        )}
      </Button>
    </form>
  )
}
