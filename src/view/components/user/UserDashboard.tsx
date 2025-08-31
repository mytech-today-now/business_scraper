/**
 * User Dashboard Component
 * Comprehensive user dashboard with account overview, usage tracking, and subscription management
 */

import React, { useState, useEffect } from 'react'
import { User, hasActiveSubscription, getUserDisplayName } from '@/model/types/user'
import { userPaymentService } from '@/model/userPaymentService'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { UsageProgress } from '@/view/components/ui/ProgressBar'
import { Badge } from '@/view/components/ui/Badge'
import { logger } from '@/utils/logger'

interface UserDashboardProps {
  user: User
  onUpdateUser: (user: User) => void
}

export const UserDashboard: React.FC<UserDashboardProps> = ({ user, onUpdateUser }) => {
  const [subscription, setSubscription] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadUserData()
  }, [user.id])

  const loadUserData = async () => {
    try {
      setError(null)
      // Load user subscription data
      const userProfile = await userPaymentService.getUserPaymentProfile(user.id)
      setSubscription(userProfile)
    } catch (error) {
      logger.error('UserDashboard', 'Failed to load user data', error)
      setError('Failed to load user data')
    }
  }

  const handleCancelSubscription = async () => {
    if (!confirm('Are you sure you want to cancel your subscription?')) return

    setLoading(true)
    try {
      // This would integrate with the payment controller when available
      // For now, we'll update the user status
      const updatedUser = {
        ...user,
        subscriptionStatus: 'canceled' as const,
        updatedAt: new Date(),
      }

      onUpdateUser(updatedUser)
      await loadUserData()

      logger.info('UserDashboard', `Subscription canceled for user: ${user.id}`)
    } catch (error) {
      logger.error('UserDashboard', 'Failed to cancel subscription', error)
      setError('Failed to cancel subscription')
    } finally {
      setLoading(false)
    }
  }

  const getSubscriptionStatusBadge = (status: string) => {
    const statusMap = {
      free: { variant: 'secondary' as const, label: 'Free' },
      active: { variant: 'success' as const, label: 'Active' },
      past_due: { variant: 'warning' as const, label: 'Past Due' },
      canceled: { variant: 'secondary' as const, label: 'Canceled' },
      incomplete: { variant: 'warning' as const, label: 'Incomplete' },
    }

    const config = statusMap[status as keyof typeof statusMap] || statusMap.free
    return <Badge variant={config.variant}>{config.label}</Badge>
  }

  const formatDate = (date: Date | string | undefined) => {
    if (!date) return 'N/A'
    return new Date(date).toLocaleDateString()
  }

  return (
    <div className="space-y-6 p-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {/* Account Overview */}
      <Card>
        <CardHeader>
          <CardTitle>Account Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Name</p>
                <p className="font-semibold">{getUserDisplayName(user)}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Email</p>
                <p className="font-semibold">{user.email}</p>
                {!user.emailVerified && (
                  <p className="text-sm text-yellow-600">Email not verified</p>
                )}
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Account Status</p>
                <Badge variant={user.isActive ? 'success' : 'secondary'}>
                  {user.isActive ? 'Active' : 'Inactive'}
                </Badge>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Subscription Status</p>
                {getSubscriptionStatusBadge(user.subscriptionStatus)}
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Plan</p>
                <p className="font-semibold capitalize">{user.subscriptionPlan || 'Free'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Member Since</p>
                <p className="font-semibold">{formatDate(user.createdAt)}</p>
              </div>
              {user.lastLoginAt && (
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Last Login</p>
                  <p className="font-semibold">{formatDate(user.lastLoginAt)}</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Usage Quotas */}
      <Card>
        <CardHeader>
          <CardTitle>Usage This Month</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <UsageProgress
              used={user.usageQuotas.scrapingRequests.used}
              limit={user.usageQuotas.scrapingRequests.limit}
              label="Scraping Requests"
            />
            <UsageProgress
              used={user.usageQuotas.exports.used}
              limit={user.usageQuotas.exports.limit}
              label="Data Exports"
            />
            <UsageProgress
              used={user.usageQuotas.advancedSearches.used}
              limit={user.usageQuotas.advancedSearches.limit}
              label="Advanced Searches"
            />
            <UsageProgress
              used={user.usageQuotas.apiCalls.used}
              limit={user.usageQuotas.apiCalls.limit}
              label="API Calls"
            />
          </div>
          <div className="mt-4 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Quotas reset on: {formatDate(user.usageQuotas.scrapingRequests.resetDate)}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Payment Information */}
      {user.stripeCustomerId && (
        <Card>
          <CardHeader>
            <CardTitle>Payment Information</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {user.paymentMethodLast4 && (
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Payment Method</p>
                  <p className="font-semibold">
                    {user.paymentMethodBrand} ending in {user.paymentMethodLast4}
                  </p>
                </div>
              )}
              {user.billingAddress && (
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Billing Address</p>
                  <div className="text-sm">
                    <p>{user.billingAddress.line1}</p>
                    {user.billingAddress.line2 && <p>{user.billingAddress.line2}</p>}
                    <p>
                      {user.billingAddress.city}, {user.billingAddress.state}{' '}
                      {user.billingAddress.postalCode}
                    </p>
                    <p>{user.billingAddress.country}</p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Subscription Management */}
      {hasActiveSubscription(user) && (
        <Card>
          <CardHeader>
            <CardTitle>Subscription Management</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Current Plan</p>
                <p className="font-semibold text-lg capitalize">{user.subscriptionPlan}</p>
              </div>
              {user.subscriptionEndsAt && (
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Next Billing Date</p>
                  <p className="font-semibold">{formatDate(user.subscriptionEndsAt)}</p>
                </div>
              )}
              <div className="flex flex-wrap gap-4">
                <Button variant="outline">Change Plan</Button>
                <Button variant="outline">Update Payment Method</Button>
                <Button variant="destructive" onClick={handleCancelSubscription} disabled={loading}>
                  {loading ? 'Canceling...' : 'Cancel Subscription'}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Upgrade Prompt for Free Users */}
      {user.subscriptionStatus === 'free' && (
        <Card className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20">
          <CardHeader>
            <CardTitle>Upgrade Your Account</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Get access to advanced features and higher usage limits with a paid plan.
            </p>
            <div className="space-y-2 mb-4">
              <p className="text-sm">✓ Unlimited scraping requests</p>
              <p className="text-sm">✓ Advanced search capabilities</p>
              <p className="text-sm">✓ API access</p>
              <p className="text-sm">✓ Priority support</p>
            </div>
            <Button>View Plans</Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default UserDashboard
