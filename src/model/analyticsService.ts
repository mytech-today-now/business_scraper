'use strict'

import { storage } from './storage'
import { logger } from '@/utils/logger'

export interface AnalyticsEvent {
  id: string
  userId?: string
  eventType: string
  eventData: Record<string, any>
  timestamp: Date
  sessionId?: string
  userAgent?: string
  ipAddress?: string
}

export interface RevenueMetrics {
  totalRevenue: number
  monthlyRecurringRevenue: number
  averageRevenuePerUser: number
  churnRate: number
  lifetimeValue: number
  conversionRate: number
}

export interface UserMetrics {
  totalUsers: number
  activeUsers: number
  newUsers: number
  retentionRate: number
  engagementScore: number
}

export interface FeatureUsageData {
  featureUsage: Record<string, number>
  topFeatures: [string, number][]
  totalFeatureUsage: number
}

export class AnalyticsService {
  private sessionId: string
  private userId?: string

  constructor() {
    this.sessionId = this.generateSessionId()
    this.initializeSession()
  }

  /**
   * Initialize analytics session
   */
  private initializeSession(): void {
    try {
      // Generate or retrieve session ID
      if (typeof window !== 'undefined') {
        const existingSession = sessionStorage.getItem('analytics_session_id')
        if (existingSession) {
          this.sessionId = existingSession
        } else {
          sessionStorage.setItem('analytics_session_id', this.sessionId)
        }
      }
      
      logger.info('Analytics', `Session initialized: ${this.sessionId}`)
    } catch (error) {
      logger.error('Analytics', 'Failed to initialize session', error)
    }
  }

  /**
   * Set user ID for tracking
   */
  setUserId(userId: string): void {
    this.userId = userId
    logger.info('Analytics', `User ID set: ${userId}`)
  }

  /**
   * Track user events
   */
  async trackEvent(
    eventType: string,
    eventData: Record<string, any> = {},
    userId?: string
  ): Promise<void> {
    try {
      const event: AnalyticsEvent = {
        id: this.generateEventId(),
        userId: userId || this.userId,
        eventType,
        eventData,
        timestamp: new Date(),
        sessionId: this.sessionId,
        userAgent: typeof window !== 'undefined' ? navigator.userAgent : undefined
      }

      await this.storeEvent(event)
      await this.processEventInRealTime(event)

      logger.info('Analytics', `Event tracked: ${eventType}`, { 
        userId: event.userId, 
        sessionId: event.sessionId,
        eventData 
      })
    } catch (error) {
      logger.error('Analytics', 'Failed to track event', error)
    }
  }

  /**
   * Get revenue metrics for a date range
   */
  async getRevenueMetrics(startDate: Date, endDate: Date): Promise<RevenueMetrics> {
    try {
      const transactions = await this.getTransactionsInPeriod(startDate, endDate)
      const subscriptions = await this.getActiveSubscriptions()

      const totalRevenue = transactions.reduce((sum, t) => sum + t.amountCents, 0) / 100
      const monthlyRecurringRevenue = this.calculateMRR(subscriptions)
      const averageRevenuePerUser = this.calculateARPU(totalRevenue, subscriptions.length)
      const churnRate = await this.calculateChurnRate(startDate, endDate)
      const lifetimeValue = this.calculateLTV(averageRevenuePerUser, churnRate)
      const conversionRate = await this.calculateConversionRate(startDate, endDate)

      return {
        totalRevenue,
        monthlyRecurringRevenue,
        averageRevenuePerUser,
        churnRate,
        lifetimeValue,
        conversionRate
      }
    } catch (error) {
      logger.error('Analytics', 'Failed to get revenue metrics', error)
      throw error
    }
  }

  /**
   * Get user metrics for a date range
   */
  async getUserMetrics(startDate: Date, endDate: Date): Promise<UserMetrics> {
    try {
      const totalUsers = await this.getTotalUsers()
      const activeUsers = await this.getActiveUsers(startDate, endDate)
      const newUsers = await this.getNewUsers(startDate, endDate)
      const retentionRate = await this.calculateRetentionRate(startDate, endDate)
      const engagementScore = await this.calculateEngagementScore(startDate, endDate)

      return {
        totalUsers,
        activeUsers,
        newUsers,
        retentionRate,
        engagementScore
      }
    } catch (error) {
      logger.error('Analytics', 'Failed to get user metrics', error)
      throw error
    }
  }

  /**
   * Get feature usage analytics
   */
  async getFeatureUsageAnalytics(startDate: Date, endDate: Date): Promise<FeatureUsageData> {
    try {
      const events = await this.getEventsInPeriod(startDate, endDate)

      const featureUsage = events.reduce((acc, event) => {
        if (event.eventType.startsWith('feature_')) {
          const feature = event.eventType.replace('feature_', '')
          acc[feature] = (acc[feature] || 0) + 1
        }
        return acc
      }, {} as Record<string, number>)

      const topFeatures = Object.entries(featureUsage)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10) as [string, number][]

      return {
        featureUsage,
        topFeatures,
        totalFeatureUsage: Object.values(featureUsage).reduce((sum, count) => sum + count, 0)
      }
    } catch (error) {
      logger.error('Analytics', 'Failed to get feature usage analytics', error)
      throw error
    }
  }

  /**
   * Calculate Monthly Recurring Revenue
   */
  private calculateMRR(subscriptions: any[]): number {
    return subscriptions.reduce((mrr, sub) => {
      if (sub.status === 'active') {
        const monthlyAmount = sub.interval === 'year'
          ? sub.priceCents / 12
          : sub.priceCents
        return mrr + (monthlyAmount / 100)
      }
      return mrr
    }, 0)
  }

  /**
   * Calculate Average Revenue Per User
   */
  private calculateARPU(totalRevenue: number, userCount: number): number {
    return userCount > 0 ? totalRevenue / userCount : 0
  }

  /**
   * Calculate Customer Lifetime Value
   */
  private calculateLTV(arpu: number, churnRate: number): number {
    return churnRate > 0 ? arpu / churnRate : 0
  }

  /**
   * Calculate churn rate
   */
  private async calculateChurnRate(startDate: Date, endDate: Date): Promise<number> {
    const startUsers = await this.getActiveUsersAtDate(startDate)
    const churnedUsers = await this.getChurnedUsers(startDate, endDate)

    return startUsers > 0 ? churnedUsers / startUsers : 0
  }

  /**
   * Calculate conversion rate
   */
  private async calculateConversionRate(startDate: Date, endDate: Date): Promise<number> {
    const visitors = await this.getUniqueVisitors(startDate, endDate)
    const conversions = await this.getConversions(startDate, endDate)

    return visitors > 0 ? conversions / visitors : 0
  }

  /**
   * Store analytics event
   */
  private async storeEvent(event: AnalyticsEvent): Promise<void> {
    try {
      // Store in IndexedDB using existing storage service
      await storage.saveAnalyticsEvent(event)
    } catch (error) {
      logger.error('Analytics', 'Failed to store event', error)
      throw error
    }
  }

  /**
   * Process event for real-time analytics
   */
  private async processEventInRealTime(event: AnalyticsEvent): Promise<void> {
    try {
      // Update real-time counters and metrics
      await this.updateRealTimeMetrics(event)
    } catch (error) {
      logger.error('Analytics', 'Failed to process real-time event', error)
    }
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  // Helper methods for data retrieval (to be implemented based on actual data sources)
  private async getTransactionsInPeriod(startDate: Date, endDate: Date): Promise<any[]> {
    // Implementation would query payment transactions from storage
    return []
  }

  private async getActiveSubscriptions(): Promise<any[]> {
    // Implementation would query active subscriptions from storage
    return []
  }

  private async getEventsInPeriod(startDate: Date, endDate: Date): Promise<AnalyticsEvent[]> {
    try {
      return await storage.getAnalyticsEvents(startDate, endDate)
    } catch (error) {
      logger.error('Analytics', 'Failed to get events in period', error)
      return []
    }
  }

  private async updateRealTimeMetrics(event: AnalyticsEvent): Promise<void> {
    // Implementation for real-time metric updates
  }

  // Additional helper methods with placeholder implementations
  private async getTotalUsers(): Promise<number> { return 0 }
  private async getActiveUsers(start: Date, end: Date): Promise<number> { return 0 }
  private async getNewUsers(start: Date, end: Date): Promise<number> { return 0 }
  private async calculateRetentionRate(start: Date, end: Date): Promise<number> { return 0 }
  private async calculateEngagementScore(start: Date, end: Date): Promise<number> { return 0 }
  private async getActiveUsersAtDate(date: Date): Promise<number> { return 0 }
  private async getChurnedUsers(start: Date, end: Date): Promise<number> { return 0 }
  private async getUniqueVisitors(start: Date, end: Date): Promise<number> { return 0 }
  private async getConversions(start: Date, end: Date): Promise<number> { return 0 }
}

export const analyticsService = new AnalyticsService()
