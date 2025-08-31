import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AnalyticsDashboard } from '../AnalyticsDashboard'
import { analyticsService } from '@/model/analyticsService'

// Mock dependencies
jest.mock('@/model/analyticsService')
jest.mock('@/utils/logger')

const mockAnalyticsService = analyticsService as jest.Mocked<typeof analyticsService>

// Mock URL.createObjectURL and related APIs for export functionality
global.URL.createObjectURL = jest.fn(() => 'mock-url')
global.URL.revokeObjectURL = jest.fn()

// Mock document.createElement and related DOM APIs
const mockLink = {
  href: '',
  download: '',
  click: jest.fn(),
}
jest.spyOn(document, 'createElement').mockImplementation(tagName => {
  if (tagName === 'a') {
    return mockLink as any
  }
  return document.createElement(tagName)
})
jest.spyOn(document.body, 'appendChild').mockImplementation(() => mockLink as any)
jest.spyOn(document.body, 'removeChild').mockImplementation(() => mockLink as any)

describe('AnalyticsDashboard', () => {
  const mockRevenueMetrics = {
    totalRevenue: 10000,
    monthlyRecurringRevenue: 2500,
    averageRevenuePerUser: 125,
    churnRate: 0.05,
    lifetimeValue: 2500,
    conversionRate: 0.15,
  }

  const mockUserMetrics = {
    totalUsers: 1000,
    activeUsers: 800,
    newUsers: 150,
    retentionRate: 0.85,
    engagementScore: 0.75,
  }

  const mockFeatureUsage = {
    featureUsage: {
      search: 500,
      export: 200,
      scraping: 300,
    },
    topFeatures: [
      ['search', 500],
      ['scraping', 300],
      ['export', 200],
    ] as [string, number][],
    totalFeatureUsage: 1000,
  }

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup default mock implementations
    mockAnalyticsService.trackEvent.mockResolvedValue()
    mockAnalyticsService.getRevenueMetrics.mockResolvedValue(mockRevenueMetrics)
    mockAnalyticsService.getUserMetrics.mockResolvedValue(mockUserMetrics)
    mockAnalyticsService.getFeatureUsageAnalytics.mockResolvedValue(mockFeatureUsage)
  })

  it('should render loading state initially', () => {
    render(<AnalyticsDashboard />)

    expect(screen.getByText('Loading analytics...')).toBeInTheDocument()
  })

  it('should render analytics dashboard with data', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })

    // Check revenue metrics
    expect(screen.getByText('Total Revenue')).toBeInTheDocument()
    expect(screen.getByText('$10,000.00')).toBeInTheDocument()
    expect(screen.getByText('Monthly Recurring Revenue')).toBeInTheDocument()
    expect(screen.getByText('$2,500.00')).toBeInTheDocument()
    expect(screen.getByText('Average Revenue Per User')).toBeInTheDocument()
    expect(screen.getByText('$125.00')).toBeInTheDocument()
    expect(screen.getByText('Churn Rate')).toBeInTheDocument()
    expect(screen.getByText('5.0%')).toBeInTheDocument()

    // Check user metrics
    expect(screen.getByText('Total Users')).toBeInTheDocument()
    expect(screen.getByText('1,000')).toBeInTheDocument()
    expect(screen.getByText('Active Users')).toBeInTheDocument()
    expect(screen.getByText('800')).toBeInTheDocument()
    expect(screen.getByText('New Users')).toBeInTheDocument()
    expect(screen.getByText('150')).toBeInTheDocument()
    expect(screen.getByText('Retention Rate')).toBeInTheDocument()
    expect(screen.getByText('85.0%')).toBeInTheDocument()

    // Check feature usage
    expect(screen.getByText('Feature Usage')).toBeInTheDocument()
  })

  it('should track analytics dashboard view event', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(mockAnalyticsService.trackEvent).toHaveBeenCalledWith(
        'feature_analytics_dashboard_view',
        expect.objectContaining({
          timeRange: '30d',
          timestamp: expect.any(String),
        })
      )
    })
  })

  it('should handle time range changes', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })

    // Find and click the time range selector
    const timeRangeSelect = screen.getByRole('button', { name: /select time range/i })
    fireEvent.click(timeRangeSelect)

    // Select "Last 7 days"
    const sevenDaysOption = screen.getByText('Last 7 days')
    fireEvent.click(sevenDaysOption)

    await waitFor(() => {
      expect(mockAnalyticsService.getRevenueMetrics).toHaveBeenCalledWith(
        expect.any(Date),
        expect.any(Date)
      )
    })
  })

  it('should handle refresh button click', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })

    // Clear previous calls
    jest.clearAllMocks()
    mockAnalyticsService.getRevenueMetrics.mockResolvedValue(mockRevenueMetrics)
    mockAnalyticsService.getUserMetrics.mockResolvedValue(mockUserMetrics)
    mockAnalyticsService.getFeatureUsageAnalytics.mockResolvedValue(mockFeatureUsage)

    // Click refresh button
    const refreshButton = screen.getByRole('button', { name: '' }) // Refresh button with icon only
    fireEvent.click(refreshButton)

    await waitFor(() => {
      expect(mockAnalyticsService.getRevenueMetrics).toHaveBeenCalled()
      expect(mockAnalyticsService.getUserMetrics).toHaveBeenCalled()
      expect(mockAnalyticsService.getFeatureUsageAnalytics).toHaveBeenCalled()
    })
  })

  it('should handle export functionality', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })

    // Click export button
    const exportButton = screen.getByRole('button', { name: '' }) // Export button with icon only
    fireEvent.click(exportButton)

    await waitFor(() => {
      expect(mockAnalyticsService.trackEvent).toHaveBeenCalledWith(
        'feature_analytics_export',
        expect.objectContaining({
          timeRange: '30d',
          timestamp: expect.any(String),
        })
      )
    })

    expect(global.URL.createObjectURL).toHaveBeenCalled()
    expect(mockLink.click).toHaveBeenCalled()
    expect(global.URL.revokeObjectURL).toHaveBeenCalled()
  })

  it('should display error state when data loading fails', async () => {
    const error = new Error('Failed to load analytics data')
    mockAnalyticsService.getRevenueMetrics.mockRejectedValue(error)

    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText(/Failed to load analytics/)).toBeInTheDocument()
    })

    // Check retry button is present
    expect(screen.getByText('Retry')).toBeInTheDocument()
  })

  it('should handle retry after error', async () => {
    const error = new Error('Failed to load analytics data')
    mockAnalyticsService.getRevenueMetrics.mockRejectedValueOnce(error)
    mockAnalyticsService.getRevenueMetrics.mockResolvedValue(mockRevenueMetrics)

    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText(/Failed to load analytics/)).toBeInTheDocument()
    })

    // Click retry button
    const retryButton = screen.getByText('Retry')
    fireEvent.click(retryButton)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })
  })

  it('should format currency values correctly', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('$10,000.00')).toBeInTheDocument()
      expect(screen.getByText('$2,500.00')).toBeInTheDocument()
      expect(screen.getByText('$125.00')).toBeInTheDocument()
    })
  })

  it('should format percentage values correctly', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('5.0%')).toBeInTheDocument()
      expect(screen.getByText('85.0%')).toBeInTheDocument()
    })
  })

  it('should format number values correctly', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('1,000')).toBeInTheDocument()
      expect(screen.getByText('800')).toBeInTheDocument()
      expect(screen.getByText('150')).toBeInTheDocument()
    })
  })

  it('should display last updated timestamp', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText(/Last updated:/)).toBeInTheDocument()
    })
  })

  it('should handle different time ranges correctly', async () => {
    render(<AnalyticsDashboard />)

    await waitFor(() => {
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument()
    })

    // Test different time ranges
    const timeRanges = ['7d', '90d', '1y']

    for (const range of timeRanges) {
      jest.clearAllMocks()
      mockAnalyticsService.getRevenueMetrics.mockResolvedValue(mockRevenueMetrics)

      const timeRangeSelect = screen.getByRole('button', { name: /select time range/i })
      fireEvent.click(timeRangeSelect)

      const option = screen.getByText(
        range === '7d' ? 'Last 7 days' : range === '90d' ? 'Last 90 days' : 'Last year'
      )
      fireEvent.click(option)

      await waitFor(() => {
        expect(mockAnalyticsService.getRevenueMetrics).toHaveBeenCalled()
      })
    }
  })
})
