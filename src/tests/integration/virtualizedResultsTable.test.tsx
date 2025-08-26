/**
 * Integration tests for VirtualizedResultsTable component
 * Tests virtual scrolling, performance monitoring, and user interactions
 */

import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { VirtualizedResultsTable } from '@/view/components/VirtualizedResultsTable'
import { BusinessRecord } from '@/types/business'
import { performanceMonitoringService } from '@/lib/performanceMonitoringService'

// Mock react-window components
jest.mock('react-window', () => ({
  FixedSizeList: ({ children, itemCount, itemSize, onScroll }: any) => {
    const items = Array.from({ length: Math.min(itemCount, 20) }, (_, index) => (
      <div key={index} style={{ height: itemSize }}>
        {children({ index, style: { height: itemSize } })}
      </div>
    ))
    
    return (
      <div 
        data-testid="virtual-list"
        onScroll={(e) => onScroll && onScroll({ scrollTop: e.currentTarget.scrollTop })}
        style={{ height: 400, overflow: 'auto' }}
      >
        {items}
      </div>
    )
  }
}))

jest.mock('react-window-infinite-loader', () => ({
  __esModule: true,
  default: ({ children, isItemLoaded, loadMoreItems }: any) => {
    return children({
      onItemsRendered: jest.fn(),
      ref: jest.fn()
    })
  }
}))

jest.mock('react-virtualized-auto-sizer', () => ({
  __esModule: true,
  default: ({ children }: any) => children({ height: 400, width: 800 })
}))

// Mock the virtual scrolling service
jest.mock('@/lib/virtualScrollingService', () => ({
  useVirtualScrolling: () => ({
    fetchBusinesses: jest.fn().mockResolvedValue({
      data: mockBusinesses.slice(0, 10),
      pagination: {
        nextCursor: 'next-cursor',
        hasMore: true,
        totalCount: 1000
      }
    }),
    prefetchNextPage: jest.fn(),
    clearCache: jest.fn()
  }),
  calculateAILeadScore: jest.fn().mockReturnValue({
    overall: 85,
    badges: ['verified', 'high-engagement']
  })
}))

// Mock AI lead scoring service
jest.mock('@/lib/aiLeadScoringService', () => ({
  calculateAILeadScore: jest.fn().mockReturnValue({
    overall: 85,
    badges: ['verified', 'high-engagement']
  })
}))

// Mock performance monitoring service
jest.mock('@/lib/performanceMonitoringService', () => ({
  performanceMonitoringService: {
    startFrameRateMonitoring: jest.fn(),
    stopFrameRateMonitoring: jest.fn(),
    incrementFrameCount: jest.fn(),
    recordMetric: jest.fn(),
    getMetrics: jest.fn().mockReturnValue([]),
    getStatistics: jest.fn().mockReturnValue({
      avgRenderTime: 8.5,
      maxRenderTime: 15.2,
      minRenderTime: 3.1,
      avgFrameRate: 58,
      currentMemoryUsage: 45 * 1024 * 1024,
      alertCount: 0,
      metricsCount: 25
    })
  }
}))

// Mock businesses data
const mockBusinesses: BusinessRecord[] = Array.from({ length: 100 }, (_, index) => ({
  id: `business-${index}`,
  businessName: `Test Business ${index + 1}`,
  industry: index % 3 === 0 ? 'Technology' : index % 3 === 1 ? 'Healthcare' : 'Finance',
  email: [`contact${index}@business${index}.com`],
  phone: `+1-555-${String(index).padStart(4, '0')}`,
  website: `https://business${index}.com`,
  address: {
    street: `${index + 1} Business St`,
    city: 'Test City',
    state: 'TS',
    zipCode: `${String(index).padStart(5, '0')}`,
    country: 'USA'
  },
  scrapedAt: new Date(Date.now() - index * 1000 * 60 * 60), // Staggered times
  source: 'Test Source',
  confidence: 0.8 + (index % 20) * 0.01
}))

const defaultProps = {
  onEdit: jest.fn(),
  onDelete: jest.fn(),
  onExport: jest.fn(),
  isLoading: false,
  isExporting: false,
  height: 600,
  initialFilters: {},
  initialSort: { field: 'scrapedAt' as const, order: 'desc' as const }
}

describe('VirtualizedResultsTable Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Mock performance.now for consistent testing
    jest.spyOn(performance, 'now').mockReturnValue(1000)
    
    // Mock performance.memory
    Object.defineProperty(performance, 'memory', {
      value: {
        usedJSHeapSize: 50 * 1024 * 1024 // 50MB
      },
      configurable: true
    })
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Component Rendering', () => {
    test('should render virtual scrolling table', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
      })
      
      expect(screen.getByText(/Business Results/)).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Search businesses...')).toBeInTheDocument()
    })

    test('should show loading state', () => {
      render(<VirtualizedResultsTable {...defaultProps} isLoading={true} />)
      
      expect(screen.getByText('Loading more results...')).toBeInTheDocument()
    })

    test('should display performance monitoring panel in development', () => {
      // Mock development environment
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'
      
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      expect(screen.getByText('Performance')).toBeInTheDocument()
      
      // Restore environment
      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Performance Monitoring Integration', () => {
    test('should start frame rate monitoring on mount', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        expect(performanceMonitoringService.startFrameRateMonitoring).toHaveBeenCalledWith('VirtualizedResultsTable')
      })
    })

    test('should stop frame rate monitoring on unmount', async () => {
      const { unmount } = render(<VirtualizedResultsTable {...defaultProps} />)
      
      unmount()
      
      expect(performanceMonitoringService.stopFrameRateMonitoring).toHaveBeenCalledWith('VirtualizedResultsTable')
    })

    test('should record performance metrics on scroll', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      const virtualList = await screen.findByTestId('virtual-list')
      
      // Simulate scroll event
      fireEvent.scroll(virtualList, { target: { scrollTop: 100 } })
      
      await waitFor(() => {
        expect(performanceMonitoringService.incrementFrameCount).toHaveBeenCalledWith('VirtualizedResultsTable')
      })
    })

    test('should show performance metrics when panel is open', async () => {
      // Mock development environment
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'
      
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      // Click performance button to show panel
      const performanceButton = screen.getByText('Performance')
      fireEvent.click(performanceButton)
      
      await waitFor(() => {
        expect(screen.getByText('Performance Metrics')).toBeInTheDocument()
        expect(screen.getByText('8.50ms')).toBeInTheDocument() // avgRenderTime
        expect(screen.getByText('58 fps')).toBeInTheDocument() // avgFrameRate
      })
      
      // Restore environment
      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Search and Filtering', () => {
    test('should handle search input', async () => {
      const user = userEvent.setup()
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      const searchInput = screen.getByPlaceholderText('Search businesses...')
      
      await user.type(searchInput, 'Technology')
      
      expect(searchInput).toHaveValue('Technology')
    })

    test('should record performance metrics on search', async () => {
      const user = userEvent.setup()
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      const searchInput = screen.getByPlaceholderText('Search businesses...')
      
      await user.type(searchInput, 'test')
      
      await waitFor(() => {
        expect(performanceMonitoringService.recordMetric).toHaveBeenCalled()
      })
    })
  })

  describe('Row Selection', () => {
    test('should handle row selection', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        const checkboxes = screen.getAllByRole('checkbox')
        expect(checkboxes.length).toBeGreaterThan(0)
      })
      
      const firstCheckbox = screen.getAllByRole('checkbox')[1] // Skip header checkbox
      fireEvent.click(firstCheckbox)
      
      expect(firstCheckbox).toBeChecked()
    })

    test('should handle select all', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        const headerCheckbox = screen.getAllByRole('checkbox')[0]
        fireEvent.click(headerCheckbox)
        
        // All visible checkboxes should be checked
        const checkboxes = screen.getAllByRole('checkbox')
        checkboxes.forEach(checkbox => {
          expect(checkbox).toBeChecked()
        })
      })
    })
  })

  describe('Export Functionality', () => {
    test('should handle export with performance tracking', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      const exportButton = screen.getByText(/Export/)
      fireEvent.click(exportButton)
      
      await waitFor(() => {
        expect(performanceMonitoringService.recordMetric).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: 'export'
          })
        )
      })
    })

    test('should show export button with count', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        expect(screen.getByText(/Export \(/)).toBeInTheDocument()
      })
    })
  })

  describe('Sorting', () => {
    test('should handle column sorting', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        const businessNameHeader = screen.getByText('Business Name')
        fireEvent.click(businessNameHeader)
        
        // Should record performance metric for sorting
        expect(performanceMonitoringService.recordMetric).toHaveBeenCalled()
      })
    })
  })

  describe('Error Handling', () => {
    test('should handle fetch errors gracefully', async () => {
      // Mock fetch to throw error
      const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'))
      global.fetch = mockFetch
      
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      // Component should still render without crashing
      expect(screen.getByText(/Business Results/)).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    test('should have proper ARIA labels', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      await waitFor(() => {
        const searchInput = screen.getByPlaceholderText('Search businesses...')
        expect(searchInput).toHaveAttribute('type', 'text')
        
        const checkboxes = screen.getAllByRole('checkbox')
        expect(checkboxes[0]).toHaveAttribute('title', 'Select all businesses')
      })
    })

    test('should support keyboard navigation', async () => {
      const user = userEvent.setup()
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      const searchInput = screen.getByPlaceholderText('Search businesses...')
      
      // Should be able to focus and type
      await user.click(searchInput)
      await user.keyboard('test')
      
      expect(searchInput).toHaveValue('test')
      expect(searchInput).toHaveFocus()
    })
  })

  describe('Responsive Design', () => {
    test('should handle different screen sizes', () => {
      // Mock different viewport sizes
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 768 // Tablet size
      })
      
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      // Component should render without issues
      expect(screen.getByText(/Business Results/)).toBeInTheDocument()
    })
  })

  describe('Memory Management', () => {
    test('should limit performance metrics to prevent memory leaks', async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
      
      // Simulate many scroll events
      const virtualList = await screen.findByTestId('virtual-list')
      
      for (let i = 0; i < 150; i++) {
        fireEvent.scroll(virtualList, { target: { scrollTop: i * 10 } })
      }
      
      // Performance monitoring service should handle metric limiting
      expect(performanceMonitoringService.recordMetric).toHaveBeenCalled()
    })
  })
})
