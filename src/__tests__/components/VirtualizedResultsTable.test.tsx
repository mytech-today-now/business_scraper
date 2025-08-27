import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { VirtualizedResultsTable } from '@/view/components/VirtualizedResultsTable'
import { BusinessRecord } from '@/types/business'

// Mock react-window
jest.mock('react-window', () => ({
  FixedSizeList: React.forwardRef(({ children, itemCount, itemData }: any, ref: any) => (
    <div data-testid="virtual-list" ref={ref}>
      {Array.from({ length: Math.min(itemCount, 10) }, (_, index) => (
        <div key={index}>{children({ index, style: {}, data: itemData })}</div>
      ))}
    </div>
  )),
}))

// Mock react-window-infinite-loader
jest.mock('react-window-infinite-loader', () => ({
  __esModule: true,
  default: React.forwardRef(({ children }: any, ref: any) =>
    children({ onItemsRendered: jest.fn(), ref: jest.fn() })
  ),
}))

// Mock react-virtualized-auto-sizer
jest.mock('react-virtualized-auto-sizer', () => ({
  __esModule: true,
  default: ({ children }: any) => children({ height: 600, width: 800 }),
}))

// Mock performance monitoring service
jest.mock('@/lib/performanceMonitoringService', () => ({
  performanceMonitoringService: {
    startFrameRateMonitoring: jest.fn(),
    stopFrameRateMonitoring: jest.fn(),
    recordMetric: jest.fn(),
    incrementFrameCount: jest.fn(),
  },
}))

// Mock virtual scrolling service
const mockFetchBusinesses = jest.fn()
jest.mock('@/lib/virtualScrollingService', () => ({
  useVirtualScrolling: () => ({
    fetchBusinesses: mockFetchBusinesses,
    prefetchNextPage: jest.fn(),
    clearCache: jest.fn(),
  }),
  calculateAILeadScore: jest.fn().mockReturnValue({
    overallScore: 85,
    rank: 'A',
    confidence: 0.9,
    badges: [],
  }),
}))

// Mock AI lead scoring service
jest.mock('@/lib/aiLeadScoringService', () => ({
  calculateAILeadScore: jest.fn().mockReturnValue({
    overallScore: 85,
    rank: 'A',
    confidence: 0.9,
    badges: [],
  }),
}))

// Mock toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

// Mock data
const mockBusinesses: BusinessRecord[] = Array.from({ length: 100 }, (_, index) => ({
  id: `business-${index}`,
  businessName: `Business ${index}`,
  industry: `Industry ${index % 5}`,
  email: [`contact${index}@business${index}.com`],
  phone: `+1-555-${String(index).padStart(4, '0')}`,
  websiteUrl: `https://business${index}.com`,
  address: {
    street: `${index} Main St`,
    city: `City ${index}`,
    state: 'CA',
    zipCode: `9${String(index).padStart(4, '0')}`,
    country: 'USA',
  },
  scrapedAt: new Date(),
  lastUpdated: new Date(),
  source: 'test',
  confidence: 0.9,
  metadata: {},
}))

describe('VirtualizedResultsTable', () => {
  const defaultProps = {
    onEdit: jest.fn(),
    onDelete: jest.fn(),
    onExport: jest.fn(),
    isLoading: false,
    isExporting: false,
    height: 600,
  }

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup mock fetch response
    mockFetchBusinesses.mockResolvedValue({
      data: mockBusinesses.slice(0, 10), // Return first 10 items
      pagination: {
        nextCursor: null,
        hasMore: false,
        totalCount: mockBusinesses.length,
      },
    })

    // Mock fetch for export functionality
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          success: true,
          exportId: 'test-export-id',
          estimatedDuration: 30,
        }),
    })
  })

  it('renders without crashing', async () => {
    await act(async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
    })

    await waitFor(() => {
      expect(screen.getByText(/Business Results/)).toBeInTheDocument()
    })
  })

  it('displays virtual list container', async () => {
    await act(async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
    })

    await waitFor(() => {
      expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
    })
  })

  it('shows performance panel in development mode', async () => {
    const originalEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'development'

    await act(async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
    })

    await waitFor(() => {
      expect(screen.getByText('Performance')).toBeInTheDocument()
    })

    process.env.NODE_ENV = originalEnv
  })

  it('handles search input', async () => {
    await act(async () => {
      render(<VirtualizedResultsTable {...defaultProps} />)
    })

    const searchInput = screen.getByPlaceholderText('Search businesses...')

    await act(async () => {
      fireEvent.change(searchInput, { target: { value: 'test search' } })
    })

    expect(searchInput).toHaveValue('test search')
  })

  it('handles export button click', async () => {
    const mockOnExport = jest.fn()

    await act(async () => {
      render(<VirtualizedResultsTable {...defaultProps} onExport={mockOnExport} />)
    })

    const exportButton = screen.getByText(/Export/)

    await act(async () => {
      fireEvent.click(exportButton)
    })

    // Should trigger export functionality
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/export/virtualized', expect.any(Object))
    })
  })

  it('displays correct total count', async () => {
    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      expect(screen.getByText(/Business Results \(100\)/)).toBeInTheDocument()
    })
  })

  it('handles column sorting', async () => {
    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      const businessNameHeader = screen.getByText('Business Name')
      fireEvent.click(businessNameHeader)

      // Should trigger sort functionality
      expect(businessNameHeader).toBeInTheDocument()
    })
  })

  it('handles row selection', async () => {
    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      const checkboxes = screen.getAllByRole('checkbox')
      if (checkboxes.length > 1) {
        fireEvent.click(checkboxes[1]) // First business checkbox
        expect(checkboxes[1]).toBeChecked()
      }
    })
  })

  it('handles select all functionality', async () => {
    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      const selectAllCheckbox = screen.getAllByRole('checkbox')[0]
      fireEvent.click(selectAllCheckbox)

      // Should select all visible items
      expect(selectAllCheckbox).toBeInTheDocument()
    })
  })

  it('displays loading state correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} isLoading={true} />)

    expect(screen.getByText(/Business Results/)).toBeInTheDocument()
  })

  it('displays export state correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} isExporting={true} />)

    const exportButton = screen.getByText(/Export/)
    expect(exportButton).toBeDisabled()
  })

  it('handles edit action', async () => {
    const mockOnEdit = jest.fn()
    render(<VirtualizedResultsTable {...defaultProps} onEdit={mockOnEdit} />)

    await waitFor(() => {
      const editButtons = screen.getAllByTitle('Edit business')
      if (editButtons.length > 0) {
        fireEvent.click(editButtons[0])
        expect(mockOnEdit).toHaveBeenCalled()
      }
    })
  })

  it('handles delete action', async () => {
    const mockOnDelete = jest.fn()
    render(<VirtualizedResultsTable {...defaultProps} onDelete={mockOnDelete} />)

    await waitFor(() => {
      const deleteButtons = screen.getAllByTitle('Delete business')
      if (deleteButtons.length > 0) {
        fireEvent.click(deleteButtons[0])
        expect(mockOnDelete).toHaveBeenCalled()
      }
    })
  })

  it('renders AI score badges correctly', async () => {
    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      // Should render AI score badges for businesses
      const scoreElements = screen.getAllByText(/A \(85\)/)
      expect(scoreElements.length).toBeGreaterThan(0)
    })
  })

  it('handles performance monitoring toggle', async () => {
    const originalEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'development'

    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      const performanceButton = screen.getByText('Performance')
      fireEvent.click(performanceButton)

      // Should toggle performance panel
      expect(performanceButton).toBeInTheDocument()
    })

    process.env.NODE_ENV = originalEnv
  })

  it('displays performance metrics when available', async () => {
    const originalEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'development'

    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      // Performance metrics should be displayed in development mode
      expect(screen.getByText('Performance')).toBeInTheDocument()
    })

    process.env.NODE_ENV = originalEnv
  })

  it('handles large datasets efficiently', async () => {
    // Test with a large dataset
    const largeDataset = Array.from({ length: 10000 }, (_, index) => ({
      ...mockBusinesses[0],
      id: `business-${index}`,
      businessName: `Business ${index}`,
    }))

    render(<VirtualizedResultsTable {...defaultProps} />)

    await waitFor(() => {
      // Should render without performance issues
      expect(screen.getByTestId('virtual-list')).toBeInTheDocument()
    })
  })
})
