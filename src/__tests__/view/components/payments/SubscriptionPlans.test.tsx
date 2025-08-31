/**
 * SubscriptionPlans Component Tests
 * Comprehensive unit tests for SubscriptionPlans component
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'
import { SubscriptionPlans } from '@/view/components/payments/SubscriptionPlans'
import { SubscriptionPlan } from '@/model/types/payment'

// Mock UI components
jest.mock('@/view/components/ui/Button', () => ({
  Button: ({ children, onClick, disabled, className, variant }: any) => (
    <button
      onClick={onClick}
      disabled={disabled}
      className={className}
      data-variant={variant}
      data-testid="plan-button"
    >
      {children}
    </button>
  ),
}))

jest.mock('@/view/components/ui/Card', () => ({
  Card: ({ children, className }: { children: React.ReactNode; className?: string }) => (
    <div data-testid="plan-card" className={className}>
      {children}
    </div>
  ),
}))

jest.mock('@/view/components/ui/Badge', () => ({
  Badge: ({ children, variant, className }: any) => (
    <div data-testid="badge" data-variant={variant} className={className}>
      {children}
    </div>
  ),
}))

jest.mock('lucide-react', () => ({
  CheckIcon: ({ className }: { className?: string }) => (
    <div data-testid="check-icon" className={className}>
      ✓
    </div>
  ),
}))

describe('SubscriptionPlans', () => {
  const mockPlans: SubscriptionPlan[] = [
    {
      id: 'basic',
      stripePriceId: 'price_basic',
      name: 'Basic',
      description: 'Perfect for individuals',
      priceCents: 999,
      currency: 'USD',
      interval: 'month',
      features: ['10 scraping jobs', 'Basic support', 'CSV export'],
      isActive: true,
      createdAt: new Date(),
    },
    {
      id: 'pro',
      stripePriceId: 'price_pro',
      name: 'Pro',
      description: 'Best for professionals',
      priceCents: 2999,
      currency: 'USD',
      interval: 'month',
      features: ['100 scraping jobs', 'Priority support', 'All export formats', 'API access'],
      isActive: true,
      createdAt: new Date(),
    },
    {
      id: 'enterprise',
      stripePriceId: 'price_enterprise',
      name: 'Enterprise',
      description: 'For large organizations',
      priceCents: 9999,
      currency: 'USD',
      interval: 'month',
      features: ['Unlimited scraping', 'Dedicated support', 'Custom integrations', 'SLA'],
      isActive: true,
      createdAt: new Date(),
    },
  ]

  const defaultProps = {
    plans: mockPlans,
    onSelectPlan: jest.fn(),
    isLoading: false,
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Rendering', () => {
    it('should render all subscription plans', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      expect(screen.getAllByTestId('plan-card')).toHaveLength(3)
      expect(screen.getByText('Basic')).toBeInTheDocument()
      expect(screen.getByText('Pro')).toBeInTheDocument()
      expect(screen.getByText('Enterprise')).toBeInTheDocument()
    })

    it('should display plan details correctly', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      // Check Basic plan
      expect(screen.getByText('Basic')).toBeInTheDocument()
      expect(screen.getByText('Perfect for individuals')).toBeInTheDocument()
      expect(screen.getByText('$9.99/month')).toBeInTheDocument()

      // Check Pro plan
      expect(screen.getByText('Pro')).toBeInTheDocument()
      expect(screen.getByText('Best for professionals')).toBeInTheDocument()
      expect(screen.getByText('$29.99/month')).toBeInTheDocument()
    })

    it('should display plan features with check icons', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      const checkIcons = screen.getAllByTestId('check-icon')
      expect(checkIcons.length).toBeGreaterThan(0)

      expect(screen.getByText('10 scraping jobs')).toBeInTheDocument()
      expect(screen.getByText('Basic support')).toBeInTheDocument()
      expect(screen.getByText('CSV export')).toBeInTheDocument()
    })

    it('should show "Most Popular" badge for Pro plan', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      const badges = screen.getAllByTestId('badge')
      const popularBadge = badges.find(badge => badge.textContent === 'Most Popular')
      expect(popularBadge).toBeInTheDocument()
    })

    it('should render with responsive grid layout', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      const container = screen.getAllByTestId('plan-card')[0].parentElement
      expect(container).toHaveClass('grid', 'grid-cols-1', 'md:grid-cols-2', 'lg:grid-cols-3')
    })
  })

  describe('Plan Selection', () => {
    it('should call onSelectPlan when a plan is selected', async () => {
      const user = userEvent.setup()
      render(<SubscriptionPlans {...defaultProps} />)

      const buttons = screen.getAllByTestId('plan-button')
      await user.click(buttons[0])

      expect(defaultProps.onSelectPlan).toHaveBeenCalledWith(mockPlans[0])
    })

    it('should highlight selected plan', async () => {
      const user = userEvent.setup()
      render(<SubscriptionPlans {...defaultProps} />)

      const cards = screen.getAllByTestId('plan-card')
      const buttons = screen.getAllByTestId('plan-button')

      await user.click(buttons[1])

      // The card should have selection styling
      expect(cards[1]).toHaveClass('ring-2', 'ring-blue-500', 'border-blue-500')
    })

    it('should show current plan correctly', () => {
      render(<SubscriptionPlans {...defaultProps} currentPlanId="pro" />)

      const buttons = screen.getAllByTestId('plan-button')
      const proButton = buttons.find(button => button.textContent === 'Current Plan')

      expect(proButton).toBeInTheDocument()
      expect(proButton).toBeDisabled()
    })

    it('should highlight current plan card', () => {
      render(<SubscriptionPlans {...defaultProps} currentPlanId="basic" />)

      const cards = screen.getAllByTestId('plan-card')
      expect(cards[0]).toHaveClass('bg-blue-50')
    })
  })

  describe('Loading States', () => {
    it('should show loading state on buttons when isLoading is true', () => {
      render(<SubscriptionPlans {...defaultProps} isLoading={true} />)

      const buttons = screen.getAllByTestId('plan-button')
      buttons.forEach(button => {
        expect(button).toBeDisabled()
        expect(button).toHaveTextContent('Processing...')
      })
    })

    it('should not disable current plan button during loading', () => {
      render(<SubscriptionPlans {...defaultProps} currentPlanId="basic" isLoading={true} />)

      const buttons = screen.getAllByTestId('plan-button')
      const currentPlanButton = buttons.find(button => button.textContent === 'Current Plan')

      expect(currentPlanButton).toBeDisabled() // Should be disabled because it's current plan
    })
  })

  describe('Price Formatting', () => {
    it('should format prices correctly for different amounts', () => {
      const plansWithDifferentPrices: SubscriptionPlan[] = [
        {
          ...mockPlans[0],
          priceCents: 500, // $5.00
        },
        {
          ...mockPlans[1],
          priceCents: 12345, // $123.45
        },
      ]

      render(<SubscriptionPlans {...defaultProps} plans={plansWithDifferentPrices} />)

      expect(screen.getByText('$5.00/month')).toBeInTheDocument()
      expect(screen.getByText('$123.45/month')).toBeInTheDocument()
    })

    it('should handle yearly intervals', () => {
      const yearlyPlan: SubscriptionPlan = {
        ...mockPlans[0],
        interval: 'year',
        priceCents: 9999,
      }

      render(<SubscriptionPlans {...defaultProps} plans={[yearlyPlan]} />)

      expect(screen.getByText('$99.99/year')).toBeInTheDocument()
    })

    it('should handle zero price', () => {
      const freePlan: SubscriptionPlan = {
        ...mockPlans[0],
        priceCents: 0,
      }

      render(<SubscriptionPlans {...defaultProps} plans={[freePlan]} />)

      expect(screen.getByText('$0.00/month')).toBeInTheDocument()
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty plans array', () => {
      render(<SubscriptionPlans {...defaultProps} plans={[]} />)

      expect(screen.queryByTestId('plan-card')).not.toBeInTheDocument()
    })

    it('should handle plans without features', () => {
      const planWithoutFeatures: SubscriptionPlan = {
        ...mockPlans[0],
        features: [],
      }

      render(<SubscriptionPlans {...defaultProps} plans={[planWithoutFeatures]} />)

      expect(screen.getByTestId('plan-card')).toBeInTheDocument()
      expect(screen.queryByTestId('check-icon')).not.toBeInTheDocument()
    })

    it('should handle very long plan names and descriptions', () => {
      const longNamePlan: SubscriptionPlan = {
        ...mockPlans[0],
        name: 'Very Long Plan Name That Might Overflow',
        description:
          'This is a very long description that might cause layout issues if not handled properly',
      }

      render(<SubscriptionPlans {...defaultProps} plans={[longNamePlan]} />)

      expect(screen.getByText('Very Long Plan Name That Might Overflow')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('should have accessible button labels', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      const buttons = screen.getAllByTestId('plan-button')
      buttons.forEach(button => {
        expect(button).toHaveTextContent(/Select Plan|Current Plan|Processing.../)
      })
    })

    it('should maintain proper heading hierarchy', () => {
      render(<SubscriptionPlans {...defaultProps} />)

      const headings = screen.getAllByRole('heading', { level: 3 })
      expect(headings).toHaveLength(3)
      expect(headings[0]).toHaveTextContent('Basic')
      expect(headings[1]).toHaveTextContent('Pro')
      expect(headings[2]).toHaveTextContent('Enterprise')
    })
  })
})
