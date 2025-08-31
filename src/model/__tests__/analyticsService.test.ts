import { AnalyticsService, AnalyticsEvent, RevenueMetrics, UserMetrics } from '../analyticsService'
import { storage } from '../storage'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('../storage')
jest.mock('@/utils/logger')

const mockStorage = storage as jest.Mocked<typeof storage>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('AnalyticsService', () => {
  let analyticsService: AnalyticsService

  beforeEach(() => {
    jest.clearAllMocks()
    analyticsService = new AnalyticsService()

    // Mock sessionStorage
    Object.defineProperty(window, 'sessionStorage', {
      value: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
        clear: jest.fn(),
      },
      writable: true,
    })

    // Mock navigator
    Object.defineProperty(window, 'navigator', {
      value: {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      writable: true,
    })
  })

  describe('trackEvent', () => {
    it('should track an event successfully', async () => {
      const eventType = 'test_event'
      const eventData = { key: 'value' }
      const userId = 'user123'

      mockStorage.saveAnalyticsEvent.mockResolvedValue()

      await analyticsService.trackEvent(eventType, eventData, userId)

      expect(mockStorage.saveAnalyticsEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType,
          eventData,
          userId,
          timestamp: expect.any(Date),
          sessionId: expect.any(String),
          userAgent: expect.any(String),
        })
      )
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Analytics',
        `Event tracked: ${eventType}`,
        expect.any(Object)
      )
    })

    it('should handle tracking errors gracefully', async () => {
      const eventType = 'test_event'
      const error = new Error('Storage error')

      mockStorage.saveAnalyticsEvent.mockRejectedValue(error)

      await analyticsService.trackEvent(eventType, {})

      expect(mockLogger.error).toHaveBeenCalledWith('Analytics', 'Failed to track event', error)
    })

    it('should generate unique event IDs', async () => {
      mockStorage.saveAnalyticsEvent.mockResolvedValue()

      await analyticsService.trackEvent('event1', {})
      await analyticsService.trackEvent('event2', {})

      const calls = mockStorage.saveAnalyticsEvent.mock.calls
      const event1Id = calls[0][0].id
      const event2Id = calls[1][0].id

      expect(event1Id).not.toBe(event2Id)
      expect(event1Id).toMatch(/^evt_\d+_[a-z0-9]+$/)
      expect(event2Id).toMatch(/^evt_\d+_[a-z0-9]+$/)
    })
  })

  describe('setUserId', () => {
    it('should set user ID for tracking', () => {
      const userId = 'user123'

      analyticsService.setUserId(userId)

      expect(mockLogger.info).toHaveBeenCalledWith('Analytics', `User ID set: ${userId}`)
    })
  })

  describe('getRevenueMetrics', () => {
    it('should calculate revenue metrics correctly', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')

      // Mock private methods by setting up the service with test data
      const mockTransactions = [
        { amountCents: 10000 }, // $100
        { amountCents: 5000 }, // $50
      ]
      const mockSubscriptions = [
        { status: 'active', priceCents: 2000, interval: 'month' }, // $20/month
        { status: 'active', priceCents: 12000, interval: 'year' }, // $120/year = $10/month
      ]

      // Mock the private methods by overriding them
      jest
        .spyOn(analyticsService as any, 'getTransactionsInPeriod')
        .mockResolvedValue(mockTransactions)
      jest
        .spyOn(analyticsService as any, 'getActiveSubscriptions')
        .mockResolvedValue(mockSubscriptions)
      jest.spyOn(analyticsService as any, 'calculateChurnRate').mockResolvedValue(0.05) // 5% churn
      jest.spyOn(analyticsService as any, 'calculateConversionRate').mockResolvedValue(0.15) // 15% conversion

      const metrics = await analyticsService.getRevenueMetrics(startDate, endDate)

      expect(metrics).toEqual({
        totalRevenue: 150, // $100 + $50
        monthlyRecurringRevenue: 30, // $20 + $10
        averageRevenuePerUser: 75, // $150 / 2 subscriptions
        churnRate: 0.05,
        lifetimeValue: 1500, // $75 / 0.05
        conversionRate: 0.15,
      })
    })

    it('should handle errors in revenue metrics calculation', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')
      const error = new Error('Database error')

      jest.spyOn(analyticsService as any, 'getTransactionsInPeriod').mockRejectedValue(error)

      await expect(analyticsService.getRevenueMetrics(startDate, endDate)).rejects.toThrow(
        'Database error'
      )

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Analytics',
        'Failed to get revenue metrics',
        error
      )
    })
  })

  describe('getUserMetrics', () => {
    it('should calculate user metrics correctly', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')

      // Mock private methods
      jest.spyOn(analyticsService as any, 'getTotalUsers').mockResolvedValue(1000)
      jest.spyOn(analyticsService as any, 'getActiveUsers').mockResolvedValue(800)
      jest.spyOn(analyticsService as any, 'getNewUsers').mockResolvedValue(100)
      jest.spyOn(analyticsService as any, 'calculateRetentionRate').mockResolvedValue(0.85)
      jest.spyOn(analyticsService as any, 'calculateEngagementScore').mockResolvedValue(0.75)

      const metrics = await analyticsService.getUserMetrics(startDate, endDate)

      expect(metrics).toEqual({
        totalUsers: 1000,
        activeUsers: 800,
        newUsers: 100,
        retentionRate: 0.85,
        engagementScore: 0.75,
      })
    })

    it('should handle errors in user metrics calculation', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')
      const error = new Error('Database error')

      jest.spyOn(analyticsService as any, 'getTotalUsers').mockRejectedValue(error)

      await expect(analyticsService.getUserMetrics(startDate, endDate)).rejects.toThrow(
        'Database error'
      )

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Analytics',
        'Failed to get user metrics',
        error
      )
    })
  })

  describe('getFeatureUsageAnalytics', () => {
    it('should calculate feature usage analytics correctly', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')

      const mockEvents: AnalyticsEvent[] = [
        {
          id: '1',
          eventType: 'feature_search',
          eventData: {},
          timestamp: new Date(),
          sessionId: 'session1',
        },
        {
          id: '2',
          eventType: 'feature_search',
          eventData: {},
          timestamp: new Date(),
          sessionId: 'session1',
        },
        {
          id: '3',
          eventType: 'feature_export',
          eventData: {},
          timestamp: new Date(),
          sessionId: 'session2',
        },
        {
          id: '4',
          eventType: 'user_login',
          eventData: {},
          timestamp: new Date(),
          sessionId: 'session3',
        },
      ]

      mockStorage.getAnalyticsEvents.mockResolvedValue(mockEvents)

      const analytics = await analyticsService.getFeatureUsageAnalytics(startDate, endDate)

      expect(analytics).toEqual({
        featureUsage: {
          search: 2,
          export: 1,
        },
        topFeatures: [
          ['search', 2],
          ['export', 1],
        ],
        totalFeatureUsage: 3,
      })
    })

    it('should handle errors in feature usage analytics', async () => {
      const startDate = new Date('2023-01-01')
      const endDate = new Date('2023-01-31')
      const error = new Error('Database error')

      mockStorage.getAnalyticsEvents.mockRejectedValue(error)

      await expect(analyticsService.getFeatureUsageAnalytics(startDate, endDate)).rejects.toThrow(
        'Database error'
      )

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Analytics',
        'Failed to get feature usage analytics',
        error
      )
    })
  })

  describe('private calculation methods', () => {
    it('should calculate MRR correctly', () => {
      const subscriptions = [
        { status: 'active', priceCents: 2000, interval: 'month' }, // $20/month
        { status: 'active', priceCents: 12000, interval: 'year' }, // $120/year = $10/month
        { status: 'cancelled', priceCents: 1000, interval: 'month' }, // Should be ignored
      ]

      const mrr = (analyticsService as any).calculateMRR(subscriptions)
      expect(mrr).toBe(30) // $20 + $10
    })

    it('should calculate ARPU correctly', () => {
      const arpu = (analyticsService as any).calculateARPU(150, 2)
      expect(arpu).toBe(75)
    })

    it('should handle zero users in ARPU calculation', () => {
      const arpu = (analyticsService as any).calculateARPU(150, 0)
      expect(arpu).toBe(0)
    })

    it('should calculate LTV correctly', () => {
      const ltv = (analyticsService as any).calculateLTV(75, 0.05)
      expect(ltv).toBe(1500)
    })

    it('should handle zero churn rate in LTV calculation', () => {
      const ltv = (analyticsService as any).calculateLTV(75, 0)
      expect(ltv).toBe(0)
    })
  })
})
