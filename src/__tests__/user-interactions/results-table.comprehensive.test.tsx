/**
 * Results Table - Comprehensive User Interaction Tests
 * 
 * Tests all results table user interactions including:
 * - Table display and rendering
 * - Row selection and editing
 * - Sorting and filtering
 * - Pagination controls
 * - Virtualization and performance
 */

import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ResultsTable } from '@/view/components/ResultsTable'
import { PaginatedResultsTable } from '@/view/components/PaginatedResultsTable'
import { VirtualizedResultsTable } from '@/view/components/VirtualizedResultsTable'
import { useVirtualScroll } from '@/hooks/useVirtualScroll'

// Mock dependencies
jest.mock('@/hooks/useVirtualScroll')
jest.mock('@/utils/logger')
jest.mock('@/lib/dataValidationPipeline')

const mockUseVirtualScroll = useVirtualScroll as jest.MockedFunction<typeof useVirtualScroll>

// Sample test data
const sampleBusinessData = [
  {
    id: '1',
    name: 'Test Restaurant',
    address: '123 Main St',
    phone: '555-1234',
    email: 'test@restaurant.com',
    website: 'https://testrestaurant.com',
    category: 'Restaurant',
    leadScore: 85,
  },
  {
    id: '2',
    name: 'Another Business',
    address: '456 Oak Ave',
    phone: '555-5678',
    email: 'info@anotherbusiness.com',
    website: 'https://anotherbusiness.com',
    category: 'Retail',
    leadScore: 72,
  },
  {
    id: '3',
    name: 'Service Company',
    address: '789 Pine St',
    phone: '555-9012',
    email: 'contact@servicecompany.com',
    website: 'https://servicecompany.com',
    category: 'Services',
    leadScore: 91,
  },
]

describe('Results Table - Comprehensive User Interaction Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default virtual scroll hook mock
    mockUseVirtualScroll.mockReturnValue({
      containerRef: { current: null },
      visibleItems: sampleBusinessData,
      scrollToIndex: jest.fn(),
      scrollToTop: jest.fn(),
      isScrolling: false,
    })
  })

  describe('Basic Table Rendering', () => {
    it('should render table with business data', () => {
      render(<ResultsTable data={sampleBusinessData} />)
      
      expect(screen.getByText('Test Restaurant')).toBeInTheDocument()
      expect(screen.getByText('Another Business')).toBeInTheDocument()
      expect(screen.getByText('Service Company')).toBeInTheDocument()
    })

    it('should display table headers', () => {
      render(<ResultsTable data={sampleBusinessData} />)
      
      expect(screen.getByText('Business Name')).toBeInTheDocument()
      expect(screen.getByText('Address')).toBeInTheDocument()
      expect(screen.getByText('Phone')).toBeInTheDocument()
      expect(screen.getByText('Email')).toBeInTheDocument()
      expect(screen.getByText('Website')).toBeInTheDocument()
      expect(screen.getByText('Category')).toBeInTheDocument()
      expect(screen.getByText('Lead Score')).toBeInTheDocument()
    })

    it('should handle empty data', () => {
      render(<ResultsTable data={[]} />)
      
      expect(screen.getByText(/no results found/i)).toBeInTheDocument()
    })

    it('should display loading state', () => {
      render(<ResultsTable data={[]} loading={true} />)
      
      expect(screen.getByText(/loading/i)).toBeInTheDocument()
      expect(screen.getByRole('progressbar')).toBeInTheDocument()
    })
  })

  describe('Row Selection', () => {
    it('should handle single row selection', async () => {
      const handleSelectionChange = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onSelectionChange={handleSelectionChange}
          selectable={true}
        />
      )

      const firstRowCheckbox = screen.getByLabelText(/select test restaurant/i)
      await user.click(firstRowCheckbox)

      expect(firstRowCheckbox).toBeChecked()
      expect(handleSelectionChange).toHaveBeenCalledWith(['1'])
    })

    it('should handle multiple row selection', async () => {
      const handleSelectionChange = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onSelectionChange={handleSelectionChange}
          selectable={true}
        />
      )

      const firstRowCheckbox = screen.getByLabelText(/select test restaurant/i)
      const secondRowCheckbox = screen.getByLabelText(/select another business/i)

      await user.click(firstRowCheckbox)
      await user.click(secondRowCheckbox)

      expect(firstRowCheckbox).toBeChecked()
      expect(secondRowCheckbox).toBeChecked()
      expect(handleSelectionChange).toHaveBeenLastCalledWith(['1', '2'])
    })

    it('should handle select all', async () => {
      const handleSelectionChange = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onSelectionChange={handleSelectionChange}
          selectable={true}
        />
      )

      const selectAllCheckbox = screen.getByLabelText(/select all/i)
      await user.click(selectAllCheckbox)

      expect(selectAllCheckbox).toBeChecked()
      expect(handleSelectionChange).toHaveBeenCalledWith(['1', '2', '3'])
    })

    it('should handle deselect all', async () => {
      const handleSelectionChange = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onSelectionChange={handleSelectionChange}
          selectable={true}
          selectedRows={['1', '2', '3']}
        />
      )

      const selectAllCheckbox = screen.getByLabelText(/select all/i)
      await user.click(selectAllCheckbox)

      expect(selectAllCheckbox).not.toBeChecked()
      expect(handleSelectionChange).toHaveBeenCalledWith([])
    })
  })

  describe('Row Editing', () => {
    it('should enable inline editing', async () => {
      const handleRowUpdate = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onRowUpdate={handleRowUpdate}
          editable={true}
        />
      )

      const editButton = screen.getByRole('button', { name: /edit test restaurant/i })
      await user.click(editButton)

      const nameInput = screen.getByDisplayValue('Test Restaurant')
      await user.clear(nameInput)
      await user.type(nameInput, 'Updated Restaurant Name')

      const saveButton = screen.getByRole('button', { name: /save/i })
      await user.click(saveButton)

      expect(handleRowUpdate).toHaveBeenCalledWith('1', expect.objectContaining({
        name: 'Updated Restaurant Name'
      }))
    })

    it('should cancel editing', async () => {
      const handleRowUpdate = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onRowUpdate={handleRowUpdate}
          editable={true}
        />
      )

      const editButton = screen.getByRole('button', { name: /edit test restaurant/i })
      await user.click(editButton)

      const nameInput = screen.getByDisplayValue('Test Restaurant')
      await user.clear(nameInput)
      await user.type(nameInput, 'Updated Restaurant Name')

      const cancelButton = screen.getByRole('button', { name: /cancel/i })
      await user.click(cancelButton)

      expect(handleRowUpdate).not.toHaveBeenCalled()
      expect(screen.getByText('Test Restaurant')).toBeInTheDocument()
    })

    it('should validate edited data', async () => {
      const handleRowUpdate = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          onRowUpdate={handleRowUpdate}
          editable={true}
        />
      )

      const editButton = screen.getByRole('button', { name: /edit test restaurant/i })
      await user.click(editButton)

      const emailInput = screen.getByDisplayValue('test@restaurant.com')
      await user.clear(emailInput)
      await user.type(emailInput, 'invalid-email')

      const saveButton = screen.getByRole('button', { name: /save/i })
      await user.click(saveButton)

      expect(screen.getByText(/invalid email format/i)).toBeInTheDocument()
      expect(handleRowUpdate).not.toHaveBeenCalled()
    })
  })

  describe('Sorting and Filtering', () => {
    it('should handle column sorting', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} sortable={true} />)

      const nameHeader = screen.getByRole('button', { name: /sort by business name/i })
      await user.click(nameHeader)

      // Check if data is sorted (assuming ascending order)
      const rows = screen.getAllByRole('row')
      expect(rows[1]).toHaveTextContent('Another Business')
      expect(rows[2]).toHaveTextContent('Service Company')
      expect(rows[3]).toHaveTextContent('Test Restaurant')
    })

    it('should toggle sort direction', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} sortable={true} />)

      const nameHeader = screen.getByRole('button', { name: /sort by business name/i })
      
      // First click - ascending
      await user.click(nameHeader)
      
      // Second click - descending
      await user.click(nameHeader)

      const rows = screen.getAllByRole('row')
      expect(rows[1]).toHaveTextContent('Test Restaurant')
      expect(rows[2]).toHaveTextContent('Service Company')
      expect(rows[3]).toHaveTextContent('Another Business')
    })

    it('should handle column filtering', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} filterable={true} />)

      const categoryFilter = screen.getByLabelText(/filter by category/i)
      await user.selectOptions(categoryFilter, 'Restaurant')

      expect(screen.getByText('Test Restaurant')).toBeInTheDocument()
      expect(screen.queryByText('Another Business')).not.toBeInTheDocument()
      expect(screen.queryByText('Service Company')).not.toBeInTheDocument()
    })

    it('should handle search filtering', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} searchable={true} />)

      const searchInput = screen.getByPlaceholderText(/search businesses/i)
      await user.type(searchInput, 'restaurant')

      expect(screen.getByText('Test Restaurant')).toBeInTheDocument()
      expect(screen.queryByText('Another Business')).not.toBeInTheDocument()
      expect(screen.queryByText('Service Company')).not.toBeInTheDocument()
    })
  })

  describe('Pagination', () => {
    it('should display pagination controls', () => {
      render(
        <PaginatedResultsTable 
          data={sampleBusinessData} 
          pageSize={2}
          totalItems={10}
        />
      )

      expect(screen.getByText(/page 1 of 5/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /previous page/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /next page/i })).toBeInTheDocument()
    })

    it('should handle page navigation', async () => {
      const handlePageChange = jest.fn()
      const user = userEvent.setup()

      render(
        <PaginatedResultsTable 
          data={sampleBusinessData} 
          pageSize={2}
          totalItems={10}
          currentPage={1}
          onPageChange={handlePageChange}
        />
      )

      const nextButton = screen.getByRole('button', { name: /next page/i })
      await user.click(nextButton)

      expect(handlePageChange).toHaveBeenCalledWith(2)
    })

    it('should handle page size change', async () => {
      const handlePageSizeChange = jest.fn()
      const user = userEvent.setup()

      render(
        <PaginatedResultsTable 
          data={sampleBusinessData} 
          pageSize={10}
          onPageSizeChange={handlePageSizeChange}
        />
      )

      const pageSizeSelect = screen.getByLabelText(/items per page/i)
      await user.selectOptions(pageSizeSelect, '25')

      expect(handlePageSizeChange).toHaveBeenCalledWith(25)
    })
  })

  describe('Virtualization', () => {
    it('should render virtualized table for large datasets', () => {
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        id: `${i + 1}`,
        name: `Business ${i + 1}`,
        address: `${i + 1} Main St`,
        phone: `555-${String(i + 1).padStart(4, '0')}`,
        email: `business${i + 1}@example.com`,
        website: `https://business${i + 1}.com`,
        category: 'Business',
        leadScore: Math.floor(Math.random() * 100),
      }))

      render(<VirtualizedResultsTable data={largeDataset} />)

      // Should only render visible items
      expect(screen.getByText('Business 1')).toBeInTheDocument()
      expect(screen.queryByText('Business 500')).not.toBeInTheDocument()
    })

    it('should handle scroll to index', async () => {
      const mockScrollToIndex = jest.fn()
      mockUseVirtualScroll.mockReturnValue({
        containerRef: { current: null },
        visibleItems: sampleBusinessData,
        scrollToIndex: mockScrollToIndex,
        scrollToTop: jest.fn(),
        isScrolling: false,
      })

      const user = userEvent.setup()

      render(<VirtualizedResultsTable data={sampleBusinessData} />)

      const scrollToButton = screen.getByRole('button', { name: /scroll to row 100/i })
      await user.click(scrollToButton)

      expect(mockScrollToIndex).toHaveBeenCalledWith(100)
    })
  })

  describe('Table Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<ResultsTable data={sampleBusinessData} />)

      const table = screen.getByRole('table')
      expect(table).toHaveAttribute('aria-label', 'Business results table')
    })

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} selectable={true} />)

      const firstCheckbox = screen.getByLabelText(/select test restaurant/i)
      const secondCheckbox = screen.getByLabelText(/select another business/i)

      await user.click(firstCheckbox)
      expect(firstCheckbox).toHaveFocus()

      await user.tab()
      expect(secondCheckbox).toHaveFocus()
    })

    it('should announce sort changes to screen readers', async () => {
      const user = userEvent.setup()

      render(<ResultsTable data={sampleBusinessData} sortable={true} />)

      const nameHeader = screen.getByRole('button', { name: /sort by business name/i })
      await user.click(nameHeader)

      const statusRegion = screen.getByRole('status')
      expect(statusRegion).toHaveTextContent(/sorted by business name ascending/i)
    })
  })

  describe('Table Performance', () => {
    it('should handle large datasets efficiently', () => {
      const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
        id: `${i + 1}`,
        name: `Business ${i + 1}`,
        address: `${i + 1} Main St`,
        phone: `555-${String(i + 1).padStart(4, '0')}`,
        email: `business${i + 1}@example.com`,
        website: `https://business${i + 1}.com`,
        category: 'Business',
        leadScore: Math.floor(Math.random() * 100),
      }))

      const startTime = performance.now()
      render(<VirtualizedResultsTable data={largeDataset} />)
      const endTime = performance.now()

      // Should render quickly even with large dataset
      expect(endTime - startTime).toBeLessThan(1000)
    })

    it('should debounce search input', async () => {
      const handleSearch = jest.fn()
      const user = userEvent.setup()

      render(
        <ResultsTable 
          data={sampleBusinessData} 
          searchable={true}
          onSearch={handleSearch}
        />
      )

      const searchInput = screen.getByPlaceholderText(/search businesses/i)
      
      // Type rapidly
      await user.type(searchInput, 'restaurant')

      // Should debounce the search
      await waitFor(() => {
        expect(handleSearch).toHaveBeenCalledTimes(1)
      }, { timeout: 1000 })
    })
  })
})
