/**
 * Subscription Plans API Route
 * Handles fetching available subscription plans
 */

import { NextRequest, NextResponse } from 'next/server'
import { withApiSecurity } from '@/lib/api-security'
import { logger } from '@/utils/logger'
import { SubscriptionPlan } from '@/model/types/payment'

// Predefined subscription plans
const SUBSCRIPTION_PLANS: SubscriptionPlan[] = [
  {
    id: 'starter',
    stripePriceId: process.env.STRIPE_STARTER_PRICE_ID || 'price_starter',
    name: 'Starter',
    description: 'Perfect for small businesses getting started with web scraping',
    priceCents: 2900, // $29.00
    currency: 'USD',
    interval: 'month',
    features: [
      'Up to 1,000 business records per month',
      'Basic search filters',
      'CSV export',
      'Email support',
      '30-day data retention',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
  {
    id: 'professional',
    stripePriceId: process.env.STRIPE_PROFESSIONAL_PRICE_ID || 'price_professional',
    name: 'Professional',
    description: 'Ideal for growing businesses with advanced scraping needs',
    priceCents: 7900, // $79.00
    currency: 'USD',
    interval: 'month',
    features: [
      'Up to 10,000 business records per month',
      'Advanced search filters',
      'Multiple export formats (CSV, XLSX, PDF, JSON)',
      'Priority email support',
      '90-day data retention',
      'API access',
      'Custom industry categories',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
  {
    id: 'enterprise',
    stripePriceId: process.env.STRIPE_ENTERPRISE_PRICE_ID || 'price_enterprise',
    name: 'Enterprise',
    description: 'For large organizations with unlimited scraping requirements',
    priceCents: 19900, // $199.00
    currency: 'USD',
    interval: 'month',
    features: [
      'Unlimited business records',
      'All search filters and features',
      'All export formats',
      'Priority phone and email support',
      '1-year data retention',
      'Full API access',
      'Custom integrations',
      'Dedicated account manager',
      'SLA guarantee',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
  {
    id: 'starter-yearly',
    stripePriceId: process.env.STRIPE_STARTER_YEARLY_PRICE_ID || 'price_starter_yearly',
    name: 'Starter (Yearly)',
    description: 'Starter plan with annual billing - 2 months free!',
    priceCents: 29000, // $290.00 (10 months price)
    currency: 'USD',
    interval: 'year',
    features: [
      'Up to 1,000 business records per month',
      'Basic search filters',
      'CSV export',
      'Email support',
      '30-day data retention',
      '2 months free with annual billing',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
  {
    id: 'professional-yearly',
    stripePriceId: process.env.STRIPE_PROFESSIONAL_YEARLY_PRICE_ID || 'price_professional_yearly',
    name: 'Professional (Yearly)',
    description: 'Professional plan with annual billing - 2 months free!',
    priceCents: 79000, // $790.00 (10 months price)
    currency: 'USD',
    interval: 'year',
    features: [
      'Up to 10,000 business records per month',
      'Advanced search filters',
      'Multiple export formats (CSV, XLSX, PDF, JSON)',
      'Priority email support',
      '90-day data retention',
      'API access',
      'Custom industry categories',
      '2 months free with annual billing',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
  {
    id: 'enterprise-yearly',
    stripePriceId: process.env.STRIPE_ENTERPRISE_YEARLY_PRICE_ID || 'price_enterprise_yearly',
    name: 'Enterprise (Yearly)',
    description: 'Enterprise plan with annual billing - 2 months free!',
    priceCents: 199000, // $1,990.00 (10 months price)
    currency: 'USD',
    interval: 'year',
    features: [
      'Unlimited business records',
      'All search filters and features',
      'All export formats',
      'Priority phone and email support',
      '1-year data retention',
      'Full API access',
      'Custom integrations',
      'Dedicated account manager',
      'SLA guarantee',
      '2 months free with annual billing',
    ],
    isActive: true,
    createdAt: new Date('2024-01-01'),
  },
]

/**
 * GET /api/payments/plans
 * Fetch available subscription plans
 */
async function handleGetPlans(request: NextRequest): Promise<NextResponse> {
  try {
    logger.info('PaymentsAPI', 'Fetching subscription plans')

    // Filter active plans
    const activePlans = SUBSCRIPTION_PLANS.filter(plan => plan.isActive)

    // Sort plans by price (ascending)
    const sortedPlans = activePlans.sort((a, b) => {
      // Group by interval first, then by price
      if (a.interval !== b.interval) {
        return a.interval === 'month' ? -1 : 1
      }
      return a.priceCents - b.priceCents
    })

    return NextResponse.json({
      success: true,
      plans: sortedPlans,
      count: sortedPlans.length,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to fetch subscription plans', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch subscription plans',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * GET /api/payments/plans?id=planId
 * Fetch specific subscription plan by ID
 */
async function handleGetPlanById(planId: string): Promise<NextResponse> {
  try {
    logger.info('PaymentsAPI', 'Fetching subscription plan by ID', { planId })

    const plan = SUBSCRIPTION_PLANS.find(p => p.id === planId && p.isActive)

    if (!plan) {
      return NextResponse.json(
        {
          success: false,
          error: 'Plan not found',
          message: `No active plan found with ID: ${planId}`,
        },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      plan,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to fetch subscription plan', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch subscription plan',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Main route handler
 */
export const GET = withApiSecurity(
  async (request: NextRequest): Promise<NextResponse> => {
    const { searchParams } = new URL(request.url)
    const planId = searchParams.get('id')

    if (planId) {
      return handleGetPlanById(planId)
    } else {
      return handleGetPlans(request)
    }
  },
  {
    requireAuth: false,
    rateLimit: 'general',
    logRequests: true,
  }
)

// Export plan data for use in other modules
export { SUBSCRIPTION_PLANS }
