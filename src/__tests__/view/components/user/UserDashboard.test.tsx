/**
 * Unit Tests for User Dashboard Component
 * Comprehensive testing of user dashboard functionality, subscription management, and usage tracking
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import UserDashboard from '@/view/components/user/UserDashboard'
import { User, createDefaultUsageQuotas } from '@/model/types/user'
import { userPaymentService } from '@/model/userPaymentService'

// Mock dependencies
jest.mock('@/model/userPaymentService')
jest.mock('@/utils/logger')

const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>

describe('UserDashboard', () => {
  const mockOnUpdateUser = jest.fn()

  const baseUser: User = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    emailVerified: true,
    subscriptionStatus: 'free',
    usageQuotas: createDefaultUsageQuotas('free'),
    isActive: true,
    loginAttempts: 0,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01')
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(null)
  })

  describe('Account Overview Section', () => {
    test('should display user information correctly', async () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Test User')).toBeInTheDocument()
      expect(screen.getByText('test@example.com')).toBeInTheDocument()
      expect(screen.getByText('Free')).toBeInTheDocument()
      expect(screen.getByText('Active')).toBeInTheDocument()
      expect(screen.getByText('1/1/2024')).toBeInTheDocument()
    })

    test('should show email verification warning for unverified users', () => {
      const unverifiedUser = { ...baseUser, emailVerified: false }
      render(<UserDashboard user={unverifiedUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Email not verified')).toBeInTheDocument()
    })

    test('should display last login when available', () => {
      const userWithLastLogin = {
        ...baseUser,
        lastLoginAt: new Date('2024-01-15')
      }
      render(<UserDashboard user={userWithLastLogin} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Last Login')).toBeInTheDocument()
      expect(screen.getByText('1/15/2024')).toBeInTheDocument()
    })

    test('should show inactive status for inactive users', () => {
      const inactiveUser = { ...baseUser, isActive: false }
      render(<UserDashboard user={inactiveUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Inactive')).toBeInTheDocument()
    })
  })

  describe('Usage Quotas Section', () => {
    test('should display usage quotas correctly', () => {
      const userWithUsage = {
        ...baseUser,
        usageQuotas: {
          ...baseUser.usageQuotas,
          scrapingRequests: { used: 5, limit: 10, resetDate: new Date('2024-02-01') },
          exports: { used: 2, limit: 5, resetDate: new Date('2024-02-01') }
        }
      }

      render(<UserDashboard user={userWithUsage} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Scraping Requests')).toBeInTheDocument()
      expect(screen.getByText('Data Exports')).toBeInTheDocument()
      expect(screen.getByText('Advanced Searches')).toBeInTheDocument()
      expect(screen.getByText('API Calls')).toBeInTheDocument()
    })

    test('should show quota reset date', () => {
      const userWithQuotas = {
        ...baseUser,
        usageQuotas: {
          ...baseUser.usageQuotas,
          scrapingRequests: { used: 0, limit: 10, resetDate: new Date('2024-02-01') }
        }
      }

      render(<UserDashboard user={userWithQuotas} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText(/Quotas reset on:/)).toBeInTheDocument()
      expect(screen.getByText(/2\/1\/2024/)).toBeInTheDocument()
    })

    test('should handle unlimited quotas correctly', () => {
      const enterpriseUser = {
        ...baseUser,
        subscriptionPlan: 'enterprise',
        usageQuotas: createDefaultUsageQuotas('enterprise')
      }

      render(<UserDashboard user={enterpriseUser} onUpdateUser={mockOnUpdateUser} />)

      // Should show unlimited usage
      expect(screen.getAllByText(/Unlimited/)).toHaveLength(4)
    })
  })

  describe('Payment Information Section', () => {
    test('should display payment method when available', () => {
      const userWithPayment = {
        ...baseUser,
        stripeCustomerId: 'cus_123',
        paymentMethodLast4: '1234',
        paymentMethodBrand: 'visa'
      }

      render(<UserDashboard user={userWithPayment} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Payment Information')).toBeInTheDocument()
      expect(screen.getByText('visa ending in 1234')).toBeInTheDocument()
    })

    test('should display billing address when available', () => {
      const userWithBilling = {
        ...baseUser,
        stripeCustomerId: 'cus_123',
        billingAddress: {
          line1: '123 Main St',
          city: 'Anytown',
          state: 'CA',
          postalCode: '12345',
          country: 'US'
        }
      }

      render(<UserDashboard user={userWithBilling} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Billing Address')).toBeInTheDocument()
      expect(screen.getByText('123 Main St')).toBeInTheDocument()
      expect(screen.getByText('Anytown, CA 12345')).toBeInTheDocument()
      expect(screen.getByText('US')).toBeInTheDocument()
    })

    test('should not show payment section for users without Stripe customer', () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.queryByText('Payment Information')).not.toBeInTheDocument()
    })
  })

  describe('Subscription Management Section', () => {
    test('should show subscription management for active subscribers', () => {
      const activeSubscriber = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro',
        subscriptionEndsAt: new Date('2024-12-31')
      }

      render(<UserDashboard user={activeSubscriber} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Subscription Management')).toBeInTheDocument()
      expect(screen.getByText('pro')).toBeInTheDocument()
      expect(screen.getByText('12/31/2024')).toBeInTheDocument()
      expect(screen.getByText('Change Plan')).toBeInTheDocument()
      expect(screen.getByText('Update Payment Method')).toBeInTheDocument()
      expect(screen.getByText('Cancel Subscription')).toBeInTheDocument()
    })

    test('should handle subscription cancellation', async () => {
      const activeSubscriber = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro'
      }

      // Mock window.confirm
      const originalConfirm = window.confirm
      window.confirm = jest.fn(() => true)

      render(<UserDashboard user={activeSubscriber} onUpdateUser={mockOnUpdateUser} />)

      const cancelButton = screen.getByText('Cancel Subscription')
      fireEvent.click(cancelButton)

      await waitFor(() => {
        expect(mockOnUpdateUser).toHaveBeenCalledWith(
          expect.objectContaining({
            subscriptionStatus: 'canceled'
          })
        )
      })

      // Restore original confirm
      window.confirm = originalConfirm
    })

    test('should not cancel subscription if user declines confirmation', () => {
      const activeSubscriber = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro'
      }

      // Mock window.confirm to return false
      const originalConfirm = window.confirm
      window.confirm = jest.fn(() => false)

      render(<UserDashboard user={activeSubscriber} onUpdateUser={mockOnUpdateUser} />)

      const cancelButton = screen.getByText('Cancel Subscription')
      fireEvent.click(cancelButton)

      expect(mockOnUpdateUser).not.toHaveBeenCalled()

      // Restore original confirm
      window.confirm = originalConfirm
    })

    test('should not show subscription management for free users', () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.queryByText('Subscription Management')).not.toBeInTheDocument()
    })
  })

  describe('Upgrade Prompt Section', () => {
    test('should show upgrade prompt for free users', () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('Upgrade Your Account')).toBeInTheDocument()
      expect(screen.getByText('Get access to advanced features and higher usage limits with a paid plan.')).toBeInTheDocument()
      expect(screen.getByText('View Plans')).toBeInTheDocument()
    })

    test('should show upgrade benefits', () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByText('✓ Unlimited scraping requests')).toBeInTheDocument()
      expect(screen.getByText('✓ Advanced search capabilities')).toBeInTheDocument()
      expect(screen.getByText('✓ API access')).toBeInTheDocument()
      expect(screen.getByText('✓ Priority support')).toBeInTheDocument()
    })

    test('should not show upgrade prompt for paid users', () => {
      const paidUser = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro'
      }

      render(<UserDashboard user={paidUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.queryByText('Upgrade Your Account')).not.toBeInTheDocument()
    })
  })

  describe('Error Handling', () => {
    test('should display error message when data loading fails', async () => {
      mockUserPaymentService.getUserPaymentProfile.mockRejectedValue(
        new Error('Network error')
      )

      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      await waitFor(() => {
        expect(screen.getByText('Failed to load user data')).toBeInTheDocument()
      })
    })

    test('should handle subscription cancellation errors', async () => {
      const activeSubscriber = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro'
      }

      // Mock window.confirm
      const originalConfirm = window.confirm
      window.confirm = jest.fn(() => true)

      // Mock console.error to avoid test output noise
      const originalError = console.error
      console.error = jest.fn()

      render(<UserDashboard user={activeSubscriber} onUpdateUser={mockOnUpdateUser} />)

      // Simulate error in onUpdateUser
      mockOnUpdateUser.mockImplementation(() => {
        throw new Error('Update failed')
      })

      const cancelButton = screen.getByText('Cancel Subscription')
      fireEvent.click(cancelButton)

      await waitFor(() => {
        expect(screen.getByText('Failed to cancel subscription')).toBeInTheDocument()
      })

      // Restore mocks
      window.confirm = originalConfirm
      console.error = originalError
    })
  })

  describe('Subscription Status Badges', () => {
    test('should display correct badge variants for different statuses', () => {
      const statuses = [
        { status: 'free', expectedText: 'Free' },
        { status: 'active', expectedText: 'Active' },
        { status: 'past_due', expectedText: 'Past Due' },
        { status: 'canceled', expectedText: 'Canceled' },
        { status: 'incomplete', expectedText: 'Incomplete' }
      ]

      statuses.forEach(({ status, expectedText }) => {
        const userWithStatus = {
          ...baseUser,
          subscriptionStatus: status as any
        }

        const { unmount } = render(
          <UserDashboard user={userWithStatus} onUpdateUser={mockOnUpdateUser} />
        )

        expect(screen.getByText(expectedText)).toBeInTheDocument()
        unmount()
      })
    })
  })

  describe('Accessibility', () => {
    test('should have proper heading structure', () => {
      render(<UserDashboard user={baseUser} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByRole('heading', { name: 'Account Overview' })).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: 'Usage This Month' })).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: 'Upgrade Your Account' })).toBeInTheDocument()
    })

    test('should have accessible buttons', () => {
      const activeSubscriber = {
        ...baseUser,
        subscriptionStatus: 'active' as const,
        subscriptionPlan: 'pro'
      }

      render(<UserDashboard user={activeSubscriber} onUpdateUser={mockOnUpdateUser} />)

      expect(screen.getByRole('button', { name: 'Change Plan' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Update Payment Method' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Cancel Subscription' })).toBeInTheDocument()
    })
  })
})
