/**
 * Payment System Initializer Component
 * Initializes the payment system when the application loads
 */

'use client'

import React, { useEffect } from 'react'
import { paymentController } from '@/controller/paymentController'
import { logger } from '@/utils/logger'

/**
 * Payment System Initializer Component
 * This component runs once when the app loads to initialize the payment system
 */
export function PaymentSystemInitializer(): JSX.Element | null {
  useEffect(() => {
    const initializePayments = async () => {
      try {
        logger.info('PaymentSystemInitializer', 'Initializing payment system')
        await paymentController.initializePaymentSystem()
        logger.info('PaymentSystemInitializer', 'Payment system initialized successfully')
      } catch (error) {
        logger.error('PaymentSystemInitializer', 'Failed to initialize payment system', error)
        // Don't throw error to prevent app crash - payment system is optional
      }
    }

    initializePayments()
  }, [])

  // This component doesn't render anything
  return null
}
