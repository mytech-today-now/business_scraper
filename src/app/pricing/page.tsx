/**
 * Pricing Page
 * Displays subscription plans and handles plan selection
 */

'use client'

import React, { useState, useEffect } from 'react'
import { SubscriptionPlan } from '@/model/types/payment'
import { usePaymentController } from '@/controller/paymentController'
import { Button } from '@/view/components/ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Check, Star, Zap, Shield } from 'lucide-react'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'
import { formatCurrency, centsTodollars } from '@/model/types/payment'

/**
 * Plan Card Component
 */
interface PlanCardProps {
  plan: SubscriptionPlan
  isPopular?: boolean
  onSelectPlan: (plan: SubscriptionPlan) => void
  isLoading?: boolean
}

function PlanCard({ plan, isPopular, onSelectPlan, isLoading }: PlanCardProps): JSX.Element {
  const monthlyPrice =
    plan.interval === 'year'
      ? centsTodollars(plan.priceCents) / 12
      : centsTodollars(plan.priceCents)

  const yearlyDiscount = plan.interval === 'year' ? '17% off' : null

  return (
    <Card
      className={`relative ${isPopular ? 'border-primary shadow-lg scale-105' : 'border-border'}`}
    >
      {isPopular && (
        <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
          <div className="bg-primary text-primary-foreground px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
            <Star className="h-3 w-3" />
            Most Popular
          </div>
        </div>
      )}

      <CardHeader className="text-center pb-4">
        <CardTitle className="text-xl font-bold">{plan.name}</CardTitle>
        <div className="mt-2">
          <div className="text-3xl font-bold">{formatCurrency(plan.priceCents, plan.currency)}</div>
          <div className="text-sm text-muted-foreground">
            per {plan.interval}
            {plan.interval === 'year' && (
              <span className="ml-2 text-green-600 font-medium">({yearlyDiscount})</span>
            )}
          </div>
          {plan.interval === 'year' && (
            <div className="text-xs text-muted-foreground mt-1">
              ${monthlyPrice.toFixed(2)}/month when billed annually
            </div>
          )}
        </div>
        <p className="text-sm text-muted-foreground mt-2">{plan.description}</p>
      </CardHeader>

      <CardContent className="space-y-4">
        <ul className="space-y-2">
          {plan.features.map((feature, index) => (
            <li key={index} className="flex items-start gap-2">
              <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm">{feature}</span>
            </li>
          ))}
        </ul>

        <Button
          onClick={() => onSelectPlan(plan)}
          disabled={isLoading}
          className={`w-full ${isPopular ? 'bg-primary hover:bg-primary/90' : ''}`}
          variant={isPopular ? 'default' : 'outline'}
        >
          {isLoading ? 'Processing...' : 'Get Started'}
        </Button>
      </CardContent>
    </Card>
  )
}

/**
 * Pricing Toggle Component
 */
interface PricingToggleProps {
  interval: 'month' | 'year'
  onIntervalChange: (interval: 'month' | 'year') => void
}

function PricingToggle({ interval, onIntervalChange }: PricingToggleProps): JSX.Element {
  return (
    <div className="flex items-center justify-center gap-4 mb-8">
      <span className={`text-sm ${interval === 'month' ? 'font-medium' : 'text-muted-foreground'}`}>
        Monthly
      </span>
      <button
        onClick={() => onIntervalChange(interval === 'month' ? 'year' : 'month')}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          interval === 'year' ? 'bg-primary' : 'bg-gray-200'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            interval === 'year' ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
      <span className={`text-sm ${interval === 'year' ? 'font-medium' : 'text-muted-foreground'}`}>
        Yearly
        <span className="ml-1 text-green-600 text-xs">(Save 17%)</span>
      </span>
    </div>
  )
}

/**
 * Main Pricing Page Component
 */
export default function PricingPage(): JSX.Element {
  const [selectedInterval, setSelectedInterval] = useState<'month' | 'year'>('month')
  const [plans, setPlans] = useState<SubscriptionPlan[]>([])
  const [loading, setLoading] = useState(true)
  const [processingPlan, setProcessingPlan] = useState<string | null>(null)

  const {
    isLoading: paymentLoading,
    createSubscription,
    hasActiveSubscription,
    getCurrentPlan,
  } = usePaymentController()

  // Load plans on component mount
  useEffect(() => {
    loadPlans()
  }, [])

  const loadPlans = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/payments/plans')
      const data = await response.json()

      if (data.success) {
        setPlans(data.plans)
        logger.info('PricingPage', 'Plans loaded successfully', { count: data.plans.length })
      } else {
        throw new Error(data.message || 'Failed to load plans')
      }
    } catch (error) {
      logger.error('PricingPage', 'Failed to load plans', error)
      toast.error('Failed to load pricing plans')
    } finally {
      setLoading(false)
    }
  }

  const handleSelectPlan = async (plan: SubscriptionPlan) => {
    try {
      setProcessingPlan(plan.id)

      // Check if user already has an active subscription
      if (hasActiveSubscription()) {
        const currentPlan = getCurrentPlan()
        if (currentPlan?.id === plan.id) {
          toast.success('You already have this plan!')
          return
        }

        // TODO: Handle plan upgrades/downgrades
        toast.info('Plan changes will be available soon. Please contact support.')
        return
      }

      // Create subscription
      await createSubscription(plan.id)

      toast.success('Subscription created successfully!')
      logger.info('PricingPage', 'Plan selected and subscription created', { planId: plan.id })
    } catch (error) {
      logger.error('PricingPage', 'Failed to create subscription', error)
      toast.error('Failed to create subscription. Please try again.')
    } finally {
      setProcessingPlan(null)
    }
  }

  // Filter plans by selected interval
  const filteredPlans = plans.filter(plan => plan.interval === selectedInterval)

  // Determine popular plan (middle tier for monthly, professional for yearly)
  const getPopularPlanId = () => {
    if (selectedInterval === 'month') {
      return 'professional'
    }
    return 'professional-yearly'
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading pricing plans...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="container mx-auto px-4 py-16 text-center">
        <h1 className="text-4xl font-bold mb-4">Choose Your Plan</h1>
        <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
          Start scraping business data with our powerful tools. Upgrade or downgrade at any time.
        </p>

        <PricingToggle interval={selectedInterval} onIntervalChange={setSelectedInterval} />
      </div>

      {/* Pricing Cards */}
      <div className="container mx-auto px-4 pb-16">
        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {filteredPlans.map(plan => (
            <PlanCard
              key={plan.id}
              plan={plan}
              isPopular={plan.id === getPopularPlanId()}
              onSelectPlan={handleSelectPlan}
              isLoading={processingPlan === plan.id || paymentLoading}
            />
          ))}
        </div>
      </div>

      {/* Features Comparison */}
      <div className="bg-muted/50 py-16">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Why Choose Business Scraper?</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Our platform provides everything you need to find and connect with potential
              customers.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center">
              <div className="bg-primary/10 w-12 h-12 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Zap className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Lightning Fast</h3>
              <p className="text-sm text-muted-foreground">
                Advanced scraping technology that delivers results in minutes, not hours.
              </p>
            </div>

            <div className="text-center">
              <div className="bg-primary/10 w-12 h-12 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Reliable & Secure</h3>
              <p className="text-sm text-muted-foreground">
                Enterprise-grade security with 99.9% uptime guarantee.
              </p>
            </div>

            <div className="text-center">
              <div className="bg-primary/10 w-12 h-12 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Check className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Easy to Use</h3>
              <p className="text-sm text-muted-foreground">
                Intuitive interface that gets you started in minutes with no technical knowledge
                required.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
