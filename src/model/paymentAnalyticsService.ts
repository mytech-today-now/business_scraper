/**
 * Payment Analytics Service
 * Implements payment analytics and reporting functionality
 */

import { storage } from './storage'
import { userPaymentService } from './userPaymentService'
import { stripeService } from './stripeService'
import { logger } from '@/utils/logger'
import {
  PaymentAnalytics,
  PaymentTransaction,
  Invoice,
  UserPaymentProfile,
  ServiceResponse,
  PaginatedResponse,
} from '@/types/payment'

export class PaymentAnalyticsService {
  /**
   * Generate payment analytics for a user
   */
  async generateUserAnalytics(
    userId: string,
    startDate: Date,
    endDate: Date
  ): Promise<ServiceResponse<PaymentAnalytics>> {
    try {
      const profile = await userPaymentService.getUserPaymentProfile(userId)
      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      // Get transactions and invoices for the period
      const transactions = await this.getTransactionsForPeriod(userId, startDate, endDate)
      const invoices = await this.getInvoicesForPeriod(userId, startDate, endDate)

      // Calculate metrics
      const metrics = this.calculateMetrics(transactions, invoices, startDate, endDate)
      const subscriptionMetrics = await this.calculateSubscriptionMetrics(
        userId,
        startDate,
        endDate
      )

      const analytics: PaymentAnalytics = {
        userId,
        period: { start: startDate, end: endDate },
        metrics,
        subscriptionMetrics,
      }

      // Save analytics
      await storage.savePaymentAnalytics(analytics)

      logger.info('PaymentAnalyticsService', `Generated analytics for user: ${userId}`)
      return { success: true, data: analytics }
    } catch (error) {
      logger.error(
        'PaymentAnalyticsService',
        `Failed to generate analytics for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'ANALYTICS_GENERATION_FAILED',
      }
    }
  }

  /**
   * Get revenue analytics for a specific period
   */
  async getRevenueAnalytics(
    startDate: Date,
    endDate: Date
  ): Promise<
    ServiceResponse<{
      totalRevenue: number
      subscriptionRevenue: number
      oneTimeRevenue: number
      refunds: number
      netRevenue: number
      transactionCount: number
      averageTransactionValue: number
    }>
  > {
    try {
      // This would typically aggregate across all users
      // For now, we'll implement a basic version
      const analytics = {
        totalRevenue: 0,
        subscriptionRevenue: 0,
        oneTimeRevenue: 0,
        refunds: 0,
        netRevenue: 0,
        transactionCount: 0,
        averageTransactionValue: 0,
      }

      logger.info('PaymentAnalyticsService', 'Generated revenue analytics')
      return { success: true, data: analytics }
    } catch (error) {
      logger.error('PaymentAnalyticsService', 'Failed to generate revenue analytics', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'REVENUE_ANALYTICS_FAILED',
      }
    }
  }

  /**
   * Get subscription analytics
   */
  async getSubscriptionAnalytics(
    startDate: Date,
    endDate: Date
  ): Promise<
    ServiceResponse<{
      activeSubscriptions: number
      newSubscriptions: number
      canceledSubscriptions: number
      churnRate: number
      mrr: number
      arr: number
      averageRevenuePerUser: number
    }>
  > {
    try {
      // This would typically aggregate subscription data
      const analytics = {
        activeSubscriptions: 0,
        newSubscriptions: 0,
        canceledSubscriptions: 0,
        churnRate: 0,
        mrr: 0,
        arr: 0,
        averageRevenuePerUser: 0,
      }

      logger.info('PaymentAnalyticsService', 'Generated subscription analytics')
      return { success: true, data: analytics }
    } catch (error) {
      logger.error('PaymentAnalyticsService', 'Failed to generate subscription analytics', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'SUBSCRIPTION_ANALYTICS_FAILED',
      }
    }
  }

  /**
   * Get user payment history with pagination
   */
  async getUserPaymentHistory(
    userId: string,
    limit: number = 10,
    offset: number = 0
  ): Promise<PaginatedResponse<PaymentTransaction>> {
    try {
      const allTransactions = await storage.getPaymentTransactionsByUser(userId)

      // Sort by creation date (newest first)
      const sortedTransactions = allTransactions.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime()
      )

      // Apply pagination
      const paginatedTransactions = sortedTransactions.slice(offset, offset + limit)
      const hasMore = offset + limit < sortedTransactions.length

      return {
        data: paginatedTransactions,
        hasMore,
        totalCount: sortedTransactions.length,
      }
    } catch (error) {
      logger.error(
        'PaymentAnalyticsService',
        `Failed to get payment history for user: ${userId}`,
        error
      )
      return {
        data: [],
        hasMore: false,
        totalCount: 0,
      }
    }
  }

  /**
   * Get user invoice history with pagination
   */
  async getUserInvoiceHistory(
    userId: string,
    limit: number = 10,
    offset: number = 0
  ): Promise<PaginatedResponse<Invoice>> {
    try {
      const allInvoices = await storage.getInvoicesByUser(userId)

      // Sort by creation date (newest first)
      const sortedInvoices = allInvoices.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime()
      )

      // Apply pagination
      const paginatedInvoices = sortedInvoices.slice(offset, offset + limit)
      const hasMore = offset + limit < sortedInvoices.length

      return {
        data: paginatedInvoices,
        hasMore,
        totalCount: sortedInvoices.length,
      }
    } catch (error) {
      logger.error(
        'PaymentAnalyticsService',
        `Failed to get invoice history for user: ${userId}`,
        error
      )
      return {
        data: [],
        hasMore: false,
        totalCount: 0,
      }
    }
  }

  /**
   * Calculate customer lifetime value (LTV)
   */
  async calculateCustomerLTV(userId: string): Promise<ServiceResponse<number>> {
    try {
      const transactions = await storage.getPaymentTransactionsByUser(userId)
      const profile = await userPaymentService.getUserPaymentProfile(userId)

      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      // Calculate total revenue from this customer
      const totalRevenue = transactions
        .filter(t => t.status === 'succeeded')
        .reduce((sum, t) => sum + t.amount, 0)

      // Calculate customer lifespan in months
      const customerLifespanMonths = this.calculateCustomerLifespanMonths(profile)

      // Simple LTV calculation: total revenue / lifespan
      const ltv = customerLifespanMonths > 0 ? totalRevenue / customerLifespanMonths : totalRevenue

      return { success: true, data: ltv }
    } catch (error) {
      logger.error('PaymentAnalyticsService', `Failed to calculate LTV for user: ${userId}`, error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'LTV_CALCULATION_FAILED',
      }
    }
  }

  /**
   * Get payment method analytics for a user
   */
  async getPaymentMethodAnalytics(userId: string): Promise<
    ServiceResponse<{
      paymentMethods: Array<{
        type: string
        count: number
        totalAmount: number
        percentage: number
      }>
      preferredMethod: string
    }>
  > {
    try {
      const transactions = await storage.getPaymentTransactionsByUser(userId)

      // Group transactions by payment method
      const methodStats = transactions.reduce(
        (acc, transaction) => {
          const method = transaction.paymentMethod
          if (!acc[method]) {
            acc[method] = { count: 0, totalAmount: 0 }
          }
          acc[method].count++
          acc[method].totalAmount += transaction.amount
          return acc
        },
        {} as Record<string, { count: number; totalAmount: number }>
      )

      const totalTransactions = transactions.length
      const totalAmount = transactions.reduce((sum, t) => sum + t.amount, 0)

      // Convert to analytics format
      const paymentMethods = Object.entries(methodStats).map(([type, stats]) => ({
        type,
        count: stats.count,
        totalAmount: stats.totalAmount,
        percentage: totalTransactions > 0 ? (stats.count / totalTransactions) * 100 : 0,
      }))

      // Find preferred method (most used)
      const preferredMethod =
        paymentMethods.reduce(
          (prev, current) => (prev.count > current.count ? prev : current),
          paymentMethods[0]
        )?.type || 'none'

      return {
        success: true,
        data: {
          paymentMethods,
          preferredMethod,
        },
      }
    } catch (error) {
      logger.error(
        'PaymentAnalyticsService',
        `Failed to get payment method analytics for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'PAYMENT_METHOD_ANALYTICS_FAILED',
      }
    }
  }

  // Private helper methods

  private async getTransactionsForPeriod(
    userId: string,
    startDate: Date,
    endDate: Date
  ): Promise<PaymentTransaction[]> {
    const allTransactions = await storage.getPaymentTransactionsByUser(userId)
    return allTransactions.filter(t => t.createdAt >= startDate && t.createdAt <= endDate)
  }

  private async getInvoicesForPeriod(
    userId: string,
    startDate: Date,
    endDate: Date
  ): Promise<Invoice[]> {
    const allInvoices = await storage.getInvoicesByUser(userId)
    return allInvoices.filter(i => i.createdAt >= startDate && i.createdAt <= endDate)
  }

  private calculateMetrics(
    transactions: PaymentTransaction[],
    invoices: Invoice[],
    startDate: Date,
    endDate: Date
  ) {
    const successfulTransactions = transactions.filter(t => t.status === 'succeeded')
    const failedTransactions = transactions.filter(t => t.status === 'failed')

    const totalRevenue = successfulTransactions.reduce((sum, t) => sum + t.amount, 0)
    const subscriptionRevenue = invoices
      .filter(i => i.status === 'paid')
      .reduce((sum, i) => sum + i.amount, 0)
    const oneTimePayments = totalRevenue - subscriptionRevenue

    // Calculate refunds (negative amounts)
    const refunds = Math.abs(
      successfulTransactions.filter(t => t.amount < 0).reduce((sum, t) => sum + t.amount, 0)
    )

    // Calculate MRR and ARR (simplified)
    const monthsDiff = this.getMonthsDifference(startDate, endDate)
    const mrr = monthsDiff > 0 ? subscriptionRevenue / monthsDiff : 0
    const arr = mrr * 12

    // Calculate churn rate (simplified)
    const churnRate = 0 // Would need more complex calculation

    // Calculate LTV (simplified)
    const ltv = totalRevenue // Would need more complex calculation

    return {
      totalRevenue,
      subscriptionRevenue,
      oneTimePayments,
      refunds,
      chargeBacks: 0, // Would need to track separately
      mrr,
      arr,
      churnRate,
      ltv,
    }
  }

  private async calculateSubscriptionMetrics(userId: string, startDate: Date, endDate: Date) {
    // This would typically involve more complex subscription tracking
    return {
      newSubscriptions: 0,
      canceledSubscriptions: 0,
      upgrades: 0,
      downgrades: 0,
      reactivations: 0,
    }
  }

  private calculateCustomerLifespanMonths(profile: UserPaymentProfile): number {
    const now = new Date()
    const createdAt = profile.createdAt
    return this.getMonthsDifference(createdAt, now)
  }

  private getMonthsDifference(startDate: Date, endDate: Date): number {
    const yearDiff = endDate.getFullYear() - startDate.getFullYear()
    const monthDiff = endDate.getMonth() - startDate.getMonth()
    return yearDiff * 12 + monthDiff
  }
}

// Singleton instance
export const paymentAnalyticsService = new PaymentAnalyticsService()
