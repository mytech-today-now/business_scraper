/**
 * Tests for useBusinessInsights Hook
 */

import { renderHook, act } from '@testing-library/react'
import { useBusinessInsights } from '@/hooks/useBusinessInsights'
import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'

// Mock chart helpers
jest.mock('@/utils/chartHelpers', () => ({
  generateIndustryDistribution: jest.fn(() => [
    { name: 'Technology', value: 10, color: '#3B82F6' },
    { name: 'Healthcare', value: 5, color: '#10B981' }
  ]),
  generateScoreDistribution: jest.fn(() => [
    { name: '81-100', value: 8, color: '#10B981' },
    { name: '61-80', value: 5, color: '#F59E0B' },
    { name: '41-60', value: 2, color: '#F97316' }
  ]),
  generateGeographicDistribution: jest.fn(() => [
    { state: 'CA', count: 8, averageScore: 75, coordinates: { lat: 36.7783, lng: -119.4179 } },
    { state: 'NY', count: 7, averageScore: 72, coordinates: { lat: 43.2994, lng: -74.2179 } }
  ]),
  generateTrendData: jest.fn(() => [
    { date: '2024-01-01', value: 5 },
    { date: '2024-01-02', value: 8 },
    { date: '2024-01-03', value: 12 }
  ]),
  generateConversionPrediction: jest.fn(() => [
    { name: 'High Quality', value: 8, color: '#10B981' },
    { name: 'Medium Quality', value: 5, color: '#F59E0B' }
  ]),
  calculateROIPredictions: jest.fn(() => [
    { category: 'High', leads: 8, predictedRevenue: 12000, roi: 2.4 },
    { category: 'Medium', leads: 5, predictedRevenue: 4000, roi: 0.8 }
  ])
}))

describe('useBusinessInsights', () => {
  let mockBusinesses: BusinessRecord[]
  let mockScores: Map<string, LeadScore>

  beforeEach(() => {
    mockBusinesses = [
      {
        id: 'business-1',
        businessName: 'Tech Company A',
        email: ['contact@techcompanya.com'],
        websiteUrl: 'https://techcompanya.com',
        address: {
          street: '123 Tech St',
          city: 'San Francisco',
          state: 'CA',
          zipCode: '94105'
        },
        industry: 'Technology',
        scrapedAt: new Date('2024-01-15T10:00:00Z')
      },
      {
        id: 'business-2',
        businessName: 'Healthcare Corp B',
        email: ['info@healthcareb.com'],
        websiteUrl: 'https://healthcareb.com',
        address: {
          street: '456 Health Ave',
          city: 'New York',
          state: 'NY',
          zipCode: '10001'
        },
        industry: 'Healthcare',
        scrapedAt: new Date('2024-01-16T11:00:00Z')
      }
    ]

    mockScores = new Map([
      ['business-1', {
        score: 85,
        confidence: 0.9,
        factors: {
          dataCompleteness: 90,
          contactQuality: 85,
          businessSize: 80,
          industryRelevance: 95,
          geographicDesirability: 90,
          webPresence: 85
        },
        recommendations: ['High-quality lead - prioritize for immediate contact']
      }],
      ['business-2', {
        score: 72,
        confidence: 0.8,
        factors: {
          dataCompleteness: 85,
          contactQuality: 75,
          businessSize: 70,
          industryRelevance: 85,
          geographicDesirability: 80,
          webPresence: 75
        },
        recommendations: ['Good lead - suitable for standard follow-up process']
      }]
    ])
  })

  it('should initialize with default state', () => {
    const { result } = renderHook(() => 
      useBusinessInsights([], new Map(), { autoRefresh: false })
    )

    expect(result.current.insights).toBeNull()
    expect(result.current.isLoading).toBe(false)
    expect(result.current.error).toBeNull()
    expect(result.current.lastUpdated).toBeNull()
  })

  it('should generate insights when data is provided', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    expect(result.current.insights).not.toBeNull()
    expect(result.current.insights?.summary.totalBusinesses).toBe(2)
    expect(result.current.insights?.summary.averageScore).toBeGreaterThan(0)
    expect(result.current.lastUpdated).not.toBeNull()
  })

  it('should handle empty data gracefully', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights([], new Map(), { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    expect(result.current.error).toBe('No business data available')
    expect(result.current.insights).toBeNull()
  })

  it('should calculate summary statistics correctly', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    const summary = result.current.insights?.summary
    expect(summary?.totalBusinesses).toBe(2)
    expect(summary?.averageScore).toBe(Math.round((85 + 72) / 2))
    expect(summary?.highQualityLeads).toBe(1) // Only business-1 has score >= 70
    expect(summary?.topIndustry).toBe('Technology')
    expect(summary?.topState).toBe('CA')
  })

  it('should generate recommendations based on data', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    const recommendations = result.current.insights?.summary.recommendations
    expect(recommendations).toBeInstanceOf(Array)
    expect(recommendations?.length).toBeGreaterThan(0)
  })

  it('should export insights in JSON format', async () => {
    // Mock URL.createObjectURL and document.createElement
    const mockCreateObjectURL = jest.fn(() => 'mock-url')
    const mockClick = jest.fn()
    const mockRevokeObjectURL = jest.fn()

    Object.defineProperty(window, 'URL', {
      value: {
        createObjectURL: mockCreateObjectURL,
        revokeObjectURL: mockRevokeObjectURL
      }
    })

    const mockLink = {
      href: '',
      download: '',
      click: mockClick
    }
    jest.spyOn(document, 'createElement').mockReturnValue(mockLink as any)

    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    act(() => {
      result.current.exportInsights('json')
    })

    expect(mockCreateObjectURL).toHaveBeenCalled()
    expect(mockClick).toHaveBeenCalled()
    expect(mockRevokeObjectURL).toHaveBeenCalled()
  })

  it('should export insights in CSV format', async () => {
    // Mock URL.createObjectURL and document.createElement
    const mockCreateObjectURL = jest.fn(() => 'mock-url')
    const mockClick = jest.fn()
    const mockRevokeObjectURL = jest.fn()

    Object.defineProperty(window, 'URL', {
      value: {
        createObjectURL: mockCreateObjectURL,
        revokeObjectURL: mockRevokeObjectURL
      }
    })

    const mockLink = {
      href: '',
      download: '',
      click: mockClick
    }
    jest.spyOn(document, 'createElement').mockReturnValue(mockLink as any)

    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    act(() => {
      result.current.exportInsights('csv')
    })

    expect(mockCreateObjectURL).toHaveBeenCalled()
    expect(mockClick).toHaveBeenCalled()
    expect(mockRevokeObjectURL).toHaveBeenCalled()
  })

  it('should handle auto-refresh when enabled', async () => {
    jest.useFakeTimers()

    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { 
        autoRefresh: true, 
        refreshInterval: 1000 
      })
    )

    // Initial refresh should happen
    expect(result.current.isLoading).toBe(true)

    // Fast-forward time
    act(() => {
      jest.advanceTimersByTime(1000)
    })

    // Should trigger another refresh
    expect(result.current.lastUpdated).not.toBeNull()

    jest.useRealTimers()
  })

  it('should include ROI predictions when enabled', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { 
        autoRefresh: false,
        includeROI: true,
        averageOrderValue: 1500
      })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    expect(result.current.insights?.roiPredictions).toBeInstanceOf(Array)
    expect(result.current.insights?.roiPredictions.length).toBeGreaterThan(0)
  })

  it('should exclude ROI predictions when disabled', async () => {
    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { 
        autoRefresh: false,
        includeROI: false
      })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    expect(result.current.insights?.roiPredictions).toEqual([])
  })

  it('should handle errors during insight generation', async () => {
    // Mock an error in chart helpers
    const { generateIndustryDistribution } = require('@/utils/chartHelpers')
    generateIndustryDistribution.mockImplementationOnce(() => {
      throw new Error('Chart generation failed')
    })

    const { result } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { autoRefresh: false })
    )

    await act(async () => {
      result.current.refreshInsights()
    })

    expect(result.current.error).toBe('Chart generation failed')
    expect(result.current.insights).toBeNull()
  })

  it('should clean up intervals on unmount', () => {
    jest.useFakeTimers()
    const clearIntervalSpy = jest.spyOn(global, 'clearInterval')

    const { unmount } = renderHook(() => 
      useBusinessInsights(mockBusinesses, mockScores, { 
        autoRefresh: true, 
        refreshInterval: 1000 
      })
    )

    unmount()

    expect(clearIntervalSpy).toHaveBeenCalled()

    jest.useRealTimers()
  })
})
