'use client'

import React from 'react'
import { Elements } from '@stripe/react-stripe-js'
import { loadStripe } from '@stripe/stripe-js'
import { getConfig } from '@/lib/config'

const config = getConfig()
const stripePromise = loadStripe(config.payments.stripePublishableKey)

interface StripeProviderProps {
  children: React.ReactNode
  clientSecret?: string
}

export const StripeProvider: React.FC<StripeProviderProps> = ({ children, clientSecret }) => {
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

  return (
    <Elements stripe={stripePromise} options={clientSecret ? options : undefined}>
      {children}
    </Elements>
  )
}
