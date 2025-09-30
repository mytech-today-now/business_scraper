/**
 * Payment Success Page
 * Displays confirmation after successful payment
 */

'use client'

import React, { useEffect, useState, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/view/components/ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { CheckCircle, ArrowRight, Download, Settings } from 'lucide-react'
import { logger } from '@/utils/logger'
import { usePaymentController } from '@/controller/paymentController'

/**
 * Success Animation Component
 */
function SuccessAnimation(): JSX.Element {
  return (
    <div className="flex items-center justify-center mb-6">
      <div className="relative">
        <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center animate-pulse">
          <CheckCircle className="w-12 h-12 text-green-600" />
        </div>
        <div className="absolute inset-0 w-20 h-20 bg-green-200 rounded-full animate-ping opacity-20"></div>
      </div>
    </div>
  )
}

/**
 * Next Steps Component
 */
function NextSteps(): JSX.Element {
  const router = useRouter()

  const steps = [
    {
      icon: <Settings className="w-5 h-5" />,
      title: 'Configure Your Settings',
      description: 'Set up your scraping preferences and search criteria',
      action: () => router.push('/dashboard/settings'),
      buttonText: 'Go to Settings',
    },
    {
      icon: <ArrowRight className="w-5 h-5" />,
      title: 'Start Your First Scrape',
      description: 'Begin collecting business data with our powerful tools',
      action: () => router.push('/dashboard'),
      buttonText: 'Start Scraping',
    },
    {
      icon: <Download className="w-5 h-5" />,
      title: 'Download Your Data',
      description: 'Export your results in multiple formats',
      action: () => router.push('/dashboard/exports'),
      buttonText: 'View Exports',
    },
  ]

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-center mb-6">What's Next?</h3>
      <div className="grid gap-4">
        {steps.map((step, index) => (
          <Card key={index} className="border-l-4 border-l-primary">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <div className="bg-primary/10 p-2 rounded-lg">{step.icon}</div>
                <div className="flex-1">
                  <h4 className="font-medium mb-1">{step.title}</h4>
                  <p className="text-sm text-muted-foreground mb-3">{step.description}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={step.action}
                    className="w-full sm:w-auto"
                  >
                    {step.buttonText}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

/**
 * Subscription Details Component
 */
interface SubscriptionDetailsProps {
  planName?: string
  amount?: string
  interval?: string
}

function SubscriptionDetails({
  planName,
  amount,
  interval,
}: SubscriptionDetailsProps): JSX.Element {
  if (!planName) return <></>

  return (
    <Card className="bg-muted/50">
      <CardHeader>
        <CardTitle className="text-lg">Subscription Details</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex justify-between">
          <span className="text-muted-foreground">Plan:</span>
          <span className="font-medium">{planName}</span>
        </div>
        {amount && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">Amount:</span>
            <span className="font-medium">{amount}</span>
          </div>
        )}
        {interval && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">Billing:</span>
            <span className="font-medium">Every {interval}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-muted-foreground">Status:</span>
          <span className="font-medium text-green-600">Active</span>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * Payment Success Content Component (with search params)
 */
function PaymentSuccessContent(): JSX.Element {
  const searchParams = useSearchParams()
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(true)
  const [subscriptionDetails, setSubscriptionDetails] = useState<{
    planName?: string
    amount?: string
    interval?: string
  }>({})

  const { loadCurrentSubscription, getCurrentPlan } = usePaymentController() as any

  // Extract URL parameters
  const sessionId = searchParams?.get('session_id')
  const paymentIntent = searchParams?.get('payment_intent')
  const planId = searchParams?.get('plan_id')

  useEffect(() => {
    // Log successful payment
    logger.info('PaymentSuccess', 'Payment success page loaded', {
      sessionId,
      paymentIntent,
      planId,
    })

    // Load subscription details
    loadSubscriptionData()
  }, [sessionId, paymentIntent, planId])

  const loadSubscriptionData = async () => {
    try {
      setIsLoading(true)

      // Reload current subscription
      await loadCurrentSubscription()

      // Get current plan details
      const currentPlan = getCurrentPlan()
      if (currentPlan) {
        setSubscriptionDetails({
          planName: currentPlan.name,
          amount: `$${(currentPlan.priceCents / 100).toFixed(2)}`,
          interval: currentPlan.interval,
        })
      }
    } catch (error) {
      logger.error('PaymentSuccess', 'Failed to load subscription data', error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleContinueToDashboard = () => {
    router.push('/dashboard')
  }

  const handleManageSubscription = () => {
    router.push('/dashboard/billing')
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-8">
        {/* Success Header */}
        <div className="text-center">
          <SuccessAnimation />
          <h1 className="text-3xl font-bold mb-2">Payment Successful!</h1>
          <p className="text-muted-foreground text-lg">
            Welcome to Business Scraper! Your subscription is now active.
          </p>
        </div>

        {/* Subscription Details */}
        {!isLoading && (
          <SubscriptionDetails
            planName={subscriptionDetails.planName}
            amount={subscriptionDetails.amount}
            interval={subscriptionDetails.interval}
          />
        )}

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button onClick={handleContinueToDashboard} size="lg" className="flex items-center gap-2">
            <ArrowRight className="w-4 h-4" />
            Go to Dashboard
          </Button>
          <Button onClick={handleManageSubscription} variant="outline" size="lg">
            Manage Subscription
          </Button>
        </div>

        {/* Next Steps */}
        <NextSteps />

        {/* Support Information */}
        <Card className="bg-blue-50 border-blue-200">
          <CardContent className="p-6 text-center">
            <h3 className="font-semibold mb-2">Need Help Getting Started?</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Our support team is here to help you make the most of your subscription.
            </p>
            <div className="flex flex-col sm:flex-row gap-2 justify-center">
              <Button variant="outline" size="sm">
                View Documentation
              </Button>
              <Button variant="outline" size="sm">
                Contact Support
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center text-sm text-muted-foreground">
          <p>
            You will receive a confirmation email shortly. If you have any questions, please don't
            hesitate to contact our support team.
          </p>
        </div>
      </div>
    </div>
  )
}

/**
 * Main Payment Success Page Component with Suspense
 */
export default function PaymentSuccessPage(): JSX.Element {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
            <p>Loading payment confirmation...</p>
          </div>
        </div>
      }
    >
      <PaymentSuccessContent />
    </Suspense>
  )
}
