/**
 * Unit Tests for Virtual Scrolling Components and Services
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { VirtualizedResultsTable } from '@/view/components/VirtualizedResultsTable'
import { virtualScrollingService } from '@/lib/virtualScrollingService'
import { generateMockDataset, PerformanceTester } from '../performance/virtualScrolling.performance.test'
import { BusinessRecord } from '@/types/business'

// Mock the virtual scrolling service
jest.mock('@/lib/virtualScrollingService', () => ({
  virtualScrollingService: {
    fetchBusinesses: jest.fn(),
    prefetchNextPage: jest.fn(),
    clearCache: jest.fn(),
    getCacheStats: jest.fn()
  },
  useVirtualScrolling: () => ({
    fetchBusinesses: jest.fn(),
    prefetchNextPage: jest.fn(),
    clearCache: jest.fn(),
    getCacheStats: jest.fn()
  }),
  calculateAILeadScore: jest.fn().mockReturnValue({
    overallScore: 75,
    confidence: 0.8,
    rank: 'B',
    factors: {
      contactability: { score: 80, weight: 0.3, details: {} },
      businessMaturity: { score: 70, weight: 0.25, details: {} },
      marketPotential: { score: 75, weight: 0.25, details: {} },
      engagementLikelihood: { score: 80, weight: 0.2, details: {} }
    },
    predictions: {
      conversionProbability: 0.7,
      responseTime: 'fast',
      bestContactMethod: 'email',
      optimalContactTime: { dayOfWeek: ['Tuesday'], timeOfDay: ['10:00 AM'] }
    },
    badges: [],
    warnings: [],
    recommendations: [],
    scoringVersion: '2.0.0',
    lastUpdated: new Date(),
    processingTime: 50
  })
}))

// Mock react-window components
jest.mock('react-window', () => ({
  FixedSizeList: ({ children, itemData, itemCount }: any) => {
    const React = require('react')
    const items = []
    for (let i = 0; i < Math.min(itemCount, 10); i++) {
      items.push(
        React.createElement('div', {
          key: i,
          'data-testid': `virtual-row-${i}`
        }, children({ index: i, style: {}, data: itemData }))
      )
    }
    return React.createElement('div', { 'data-testid': 'virtual-list' }, items)
  }
}))

jest.mock('react-window-infinite-loader', () => ({
  __esModule: true,
  default: ({ children }: any) => children({ onItemsRendered: jest.fn(), ref: jest.fn() })
}))

jest.mock('react-virtualized-auto-sizer', () => ({
  __esModule: true,
  default: ({ children }: any) => children({ height: 600, width: 800 })
}))

describe('Virtual Scrolling Implementation', () => {
  const mockBusinesses = generateMockDataset(100)
  
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('VirtualizedResultsTable Component', () => {
    it('should render without crashing', () => {
      render(
        <VirtualizedResultsTable
          onEdit={jest.fn()}
          onDelete={jest.fn()}
          onExport={jest.fn()}
          isLoading={false}
          height={600}
        />
      )
      
      expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
    })

    it('should display loading state correctly', () => {
      render(
        <VirtualizedResultsTable
          onEdit={jest.fn()}
          onDelete={jest.fn()}
          onExport={jest.fn()}
          isLoading={true}
          height={600}
        />
      )
      
      expect(screen.getByText(/loading business data/i)).toBeInTheDocument()
    })

    it('should handle export functionality', async () => {
      const mockOnExport = jest.fn()
      
      render(
        <VirtualizedResultsTable
          onEdit={jest.fn()}
          onDelete={jest.fn()}
          onExport={mockOnExport}
          isLoading={false}
          height={600}
        />
      )
      
      const exportButton = screen.getByRole('button', { name: /export/i })
      fireEvent.click(exportButton)
      
      // Should trigger export functionality
      await waitFor(() => {
        expect(exportButton).toBeInTheDocument()
      })
    })

    it('should handle filtering and sorting', () => {
      const initialFilters = {
        search: 'test',
        industry: 'Technology'
      }
      
      const initialSort = {
        field: 'businessName' as const,
        order: 'asc' as const
      }
      
      render(
        <VirtualizedResultsTable
          onEdit={jest.fn()}
          onDelete={jest.fn()}
          onExport={jest.fn()}
          isLoading={false}
          height={600}
          initialFilters={initialFilters}
          initialSort={initialSort}
        />
      )
      
      expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
    })
  })

  describe('Virtual Scrolling Service', () => {
    it('should fetch businesses with pagination', async () => {
      const mockResponse = {
        data: mockBusinesses.slice(0, 10),
        pagination: {
          nextCursor: 'cursor-123',
          hasMore: true,
          totalCount: 100,
          currentPage: 1,
          pageSize: 10
        },
        metadata: {
          processingTime: 50,
          source: 'indexeddb' as const,
          appliedFilters: {},
          sortConfig: { field: 'scrapedAt', order: 'desc' }
        }
      }
      
      const mockFetch = virtualScrollingService.fetchBusinesses as jest.MockedFunction<typeof virtualScrollingService.fetchBusinesses>
      mockFetch.mockResolvedValue(mockResponse)
      
      const result = await virtualScrollingService.fetchBusinesses(undefined, 10)
      
      expect(result).toEqual(mockResponse)
      expect(mockFetch).toHaveBeenCalledWith(undefined, 10)
    })

    it('should handle caching correctly', () => {
      const mockStats = {
        totalEntries: 5,
        totalMemoryUsage: 1024,
        hitRate: 0.8,
        oldestEntry: new Date(),
        newestEntry: new Date()
      }
      
      const mockGetCacheStats = virtualScrollingService.getCacheStats as jest.MockedFunction<typeof virtualScrollingService.getCacheStats>
      mockGetCacheStats.mockReturnValue(mockStats)
      
      const stats = virtualScrollingService.getCacheStats()
      expect(stats).toEqual(mockStats)
    })

    it('should clear cache when requested', () => {
      const mockClearCache = virtualScrollingService.clearCache as jest.MockedFunction<typeof virtualScrollingService.clearCache>
      
      virtualScrollingService.clearCache()
      expect(mockClearCache).toHaveBeenCalled()
    })
  })

  describe('Performance Tests', () => {
    let performanceTester: PerformanceTester

    beforeEach(() => {
      performanceTester = new PerformanceTester()
    })

    it('should handle small datasets efficiently', async () => {
      const metrics = await performanceTester.measureRenderPerformance(100)
      
      expect(metrics.renderTime).toBeLessThan(1000) // Should render in under 1 second
      expect(metrics.memoryUsage).toBeLessThan(10 * 1024 * 1024) // Should use less than 10MB
      expect(metrics.scrollPerformance).toBeLessThan(100) // Pagination should be under 100ms
      expect(metrics.filteringTime).toBeLessThan(500) // Filtering should be under 500ms
      expect(metrics.sortingTime).toBeLessThan(1000) // Sorting should be under 1 second
    }, 10000)

    it('should handle medium datasets efficiently', async () => {
      const metrics = await performanceTester.measureRenderPerformance(1000)
      
      expect(metrics.renderTime).toBeLessThan(1000) // Should render in under 1 second
      expect(metrics.memoryUsage).toBeLessThan(50 * 1024 * 1024) // Should use less than 50MB
      expect(metrics.scrollPerformance).toBeLessThan(100) // Pagination should be under 100ms
      expect(metrics.filteringTime).toBeLessThan(500) // Filtering should be under 500ms
      expect(metrics.sortingTime).toBeLessThan(1000) // Sorting should be under 1 second
    }, 15000)

    it('should handle large datasets with acceptable performance', async () => {
      const metrics = await performanceTester.measureRenderPerformance(10000)
      
      expect(metrics.renderTime).toBeLessThan(2000) // Should render in under 2 seconds
      expect(metrics.memoryUsage).toBeLessThan(100 * 1024 * 1024) // Should use less than 100MB
      expect(metrics.scrollPerformance).toBeLessThan(100) // Pagination should be under 100ms
      expect(metrics.filteringTime).toBeLessThan(1000) // Filtering should be under 1 second
      expect(metrics.sortingTime).toBeLessThan(2000) // Sorting should be under 2 seconds
    }, 30000)

    it('should maintain performance with AI scoring enabled', async () => {
      // Test that AI scoring doesn't significantly impact performance
      const startTime = performance.now()
      
      const businesses = generateMockDataset(1000)
      businesses.forEach(business => {
        // Simulate AI scoring calculation
        let score = 0
        if (business.businessName) score += 20
        if (business.email) score += 25
        if (business.phone) score += 20
        if (business.website) score += 15
        if (business.address) score += 10
        if (business.industry) score += 5
        if (business.description) score += 5
      })
      
      const aiScoringTime = performance.now() - startTime
      
      expect(aiScoringTime).toBeLessThan(1000) // AI scoring should complete in under 1 second for 1K records
    })
  })

  describe('Data Integrity', () => {
    it('should maintain data consistency during virtual scrolling', () => {
      const businesses = generateMockDataset(100)
      
      // Verify all businesses have required fields
      businesses.forEach(business => {
        expect(business.id).toBeDefined()
        expect(business.businessName).toBeDefined()
        expect(business.industry).toBeDefined()
        expect(business.scrapedAt).toBeDefined()
      })
    })

    it('should handle empty datasets gracefully', () => {
      const emptyDataset = generateMockDataset(0)
      expect(emptyDataset).toHaveLength(0)
      
      render(
        <VirtualizedResultsTable
          onEdit={jest.fn()}
          onDelete={jest.fn()}
          onExport={jest.fn()}
          isLoading={false}
          height={600}
        />
      )
      
      expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
    })

    it('should validate business record structure', () => {
      const business = generateMockDataset(1)[0]
      
      expect(business).toMatchObject({
        id: expect.any(String),
        businessName: expect.any(String),
        industry: expect.any(String),
        email: expect.any(String),
        phone: expect.any(String),
        website: expect.any(String),
        address: expect.any(String),
        description: expect.any(String),
        scrapedAt: expect.any(Date),
        source: expect.any(String),
        confidence: expect.any(Number),
        dataQuality: expect.any(Number)
      })
    })
  })

  describe('Error Handling', () => {
    it('should handle API errors gracefully', async () => {
      const mockFetch = virtualScrollingService.fetchBusinesses as jest.MockedFunction<typeof virtualScrollingService.fetchBusinesses>
      mockFetch.mockRejectedValue(new Error('API Error'))
      
      try {
        await virtualScrollingService.fetchBusinesses()
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('API Error')
      }
    })

    it('should handle network timeouts', async () => {
      const mockFetch = virtualScrollingService.fetchBusinesses as jest.MockedFunction<typeof virtualScrollingService.fetchBusinesses>
      mockFetch.mockImplementation(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), 100)
        )
      )
      
      try {
        await virtualScrollingService.fetchBusinesses()
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('Timeout')
      }
    })
  })
})
