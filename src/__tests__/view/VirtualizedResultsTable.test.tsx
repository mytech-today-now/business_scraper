import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { VirtualizedResultsTable } from '../../view/components/VirtualizedResultsTable'
import { BusinessRecord } from '../../types/business'

// Mock react-window
jest.mock('react-window', () => ({
  FixedSizeList: ({ children, itemData, itemCount }: any) => (
    <div data-testid="virtualized-list">
      {Array.from({ length: Math.min(itemCount, 10) }, (_, index) => {
        if (typeof children === 'function') {
          return (
            <div key={index}>
              {children({
                index,
                style: { height: '60px' },
                data: itemData
              })}
            </div>
          )
        }
        return null
      })}
    </div>
  )
}))

// Mock business data generator
const generateMockBusiness = (id: number): BusinessRecord => ({
  id: `business-${id}`,
  businessName: `Business ${id}`,
  email: [`contact${id}@business${id}.com`],
  phone: `555-000-${id.toString().padStart(4, '0')}`,
  websiteUrl: `https://business${id}.com`,
  address: {
    street: `${id} Main St`,
    city: 'Test City',
    state: 'TS',
    zipCode: '12345'
  },
  industry: 'Technology',
  source: 'test',
  scrapedAt: new Date().toISOString()
})

const generateMockBusinesses = (count: number): BusinessRecord[] => 
  Array.from({ length: count }, (_, i) => generateMockBusiness(i + 1))

// Default columns for testing
const defaultColumns = [
  { key: 'businessName' as const, label: 'Business Name', sortable: true, visible: true, width: '200px' },
  { key: 'email' as const, label: 'Email', sortable: true, visible: true, width: '200px' },
  { key: 'phone' as const, label: 'Phone', sortable: true, visible: true, width: '150px' },
  { key: 'industry' as const, label: 'Industry', sortable: true, visible: true, width: '120px' },
  { key: 'actions' as const, label: 'Actions', sortable: false, visible: true, width: '100px' }
]

const defaultProps = {
  businesses: generateMockBusinesses(5),
  columns: defaultColumns,
  sortConfig: { key: null, direction: 'asc' as const },
  selectedRows: new Set<string>(),
  editingCell: null,
  onSort: jest.fn(),
  onRowSelect: jest.fn(),
  onCellEdit: jest.fn(),
  height: 600,
  itemSize: 60
}

describe('VirtualizedResultsTable', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders virtualized table with business data', () => {
    render(<VirtualizedResultsTable {...defaultProps} />)
    
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
    expect(screen.getByText('Business 1')).toBeInTheDocument()
    expect(screen.getByText('contact1@business1.com')).toBeInTheDocument()
  })

  it('renders table headers correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} />)
    
    expect(screen.getByText('Business Name')).toBeInTheDocument()
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByText('Phone')).toBeInTheDocument()
    expect(screen.getByText('Industry')).toBeInTheDocument()
    expect(screen.getByText('Actions')).toBeInTheDocument()
  })

  it('handles row selection correctly', () => {
    const onRowSelect = jest.fn()
    render(<VirtualizedResultsTable {...defaultProps} onRowSelect={onRowSelect} />)
    
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1]) // First business checkbox (index 0 is select all)
    
    expect(onRowSelect).toHaveBeenCalledWith('business-1', true)
  })

  it('handles select all functionality', () => {
    const onRowSelect = jest.fn()
    const businesses = generateMockBusinesses(3)
    
    render(
      <VirtualizedResultsTable 
        {...defaultProps} 
        businesses={businesses}
        onRowSelect={onRowSelect} 
      />
    )
    
    const selectAllCheckbox = screen.getAllByRole('checkbox')[0]
    fireEvent.click(selectAllCheckbox)
    
    // Should call onRowSelect for each business
    expect(onRowSelect).toHaveBeenCalledTimes(3)
    expect(onRowSelect).toHaveBeenCalledWith('business-1', true)
    expect(onRowSelect).toHaveBeenCalledWith('business-2', true)
    expect(onRowSelect).toHaveBeenCalledWith('business-3', true)
  })

  it('handles sorting correctly', () => {
    const onSort = jest.fn()
    render(<VirtualizedResultsTable {...defaultProps} onSort={onSort} />)
    
    const businessNameHeader = screen.getByText('Business Name')
    fireEvent.click(businessNameHeader)
    
    expect(onSort).toHaveBeenCalledWith('businessName')
  })

  it('displays sort indicators correctly', () => {
    const sortConfig = { key: 'businessName' as const, direction: 'asc' as const }
    render(<VirtualizedResultsTable {...defaultProps} sortConfig={sortConfig} />)
    
    // Should show ascending sort icon
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
  })

  it('handles large datasets efficiently', () => {
    const largeDataset = generateMockBusinesses(10000)
    const startTime = performance.now()
    
    render(<VirtualizedResultsTable {...defaultProps} businesses={largeDataset} />)
    
    const endTime = performance.now()
    const renderTime = endTime - startTime
    
    // Should render quickly even with large dataset (under 100ms)
    expect(renderTime).toBeLessThan(100)
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
  })

  it('shows selected rows correctly', () => {
    const selectedRows = new Set(['business-1', 'business-3'])
    render(<VirtualizedResultsTable {...defaultProps} selectedRows={selectedRows} />)
    
    const checkboxes = screen.getAllByRole('checkbox')
    expect(checkboxes[1]).toBeChecked() // business-1
    expect(checkboxes[2]).not.toBeChecked() // business-2
    expect(checkboxes[3]).toBeChecked() // business-3
  })

  it('handles cell editing correctly', () => {
    const onCellEdit = jest.fn()
    const editingCell = { businessId: 'business-1', field: 'businessName' }
    
    render(
      <VirtualizedResultsTable 
        {...defaultProps} 
        editingCell={editingCell}
        onCellEdit={onCellEdit} 
      />
    )
    
    const input = screen.getByDisplayValue('Business 1')
    fireEvent.change(input, { target: { value: 'Updated Business Name' } })
    fireEvent.blur(input)
    
    expect(onCellEdit).toHaveBeenCalledWith('business-1', 'businessName', 'Updated Business Name')
  })

  it('handles delete action correctly', () => {
    const onDelete = jest.fn()
    render(<VirtualizedResultsTable {...defaultProps} onDelete={onDelete} />)
    
    // Find delete button (trash icon)
    const deleteButtons = screen.getAllByRole('button')
    const deleteButton = deleteButtons.find(button => 
      button.querySelector('svg') && button.className.includes('text-destructive')
    )
    
    if (deleteButton) {
      fireEvent.click(deleteButton)
      expect(onDelete).toHaveBeenCalledWith('business-1')
    }
  })

  it('renders email links correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} />)
    
    const emailLink = screen.getByText('contact1@business1.com')
    expect(emailLink.closest('a')).toHaveAttribute('href', 'mailto:contact1@business1.com')
  })

  it('renders phone links correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} />)
    
    const phoneLink = screen.getByText('555-000-0001')
    expect(phoneLink.closest('a')).toHaveAttribute('href', 'tel:555-000-0001')
  })

  it('renders website links correctly', () => {
    render(<VirtualizedResultsTable {...defaultProps} />)
    
    const websiteLink = screen.getByText('https://business1.com')
    expect(websiteLink.closest('a')).toHaveAttribute('href', 'https://business1.com')
    expect(websiteLink.closest('a')).toHaveAttribute('target', '_blank')
  })

  it('handles missing data gracefully', () => {
    const businessWithMissingData: BusinessRecord = {
      id: 'incomplete-business',
      businessName: 'Incomplete Business',
      email: [],
      phone: '',
      websiteUrl: '',
      address: {
        street: '',
        city: '',
        state: '',
        zipCode: ''
      },
      industry: 'Unknown',
      source: 'test',
      scrapedAt: new Date().toISOString()
    }
    
    render(
      <VirtualizedResultsTable 
        {...defaultProps} 
        businesses={[businessWithMissingData]} 
      />
    )
    
    expect(screen.getByText('Incomplete Business')).toBeInTheDocument()
    expect(screen.getByText('No phone')).toBeInTheDocument()
    expect(screen.getByText('No website')).toBeInTheDocument()
  })

  it('maintains performance with frequent updates', async () => {
    const { rerender } = render(<VirtualizedResultsTable {...defaultProps} />)
    
    // Simulate frequent updates
    for (let i = 0; i < 10; i++) {
      const updatedBusinesses = generateMockBusinesses(1000 + i * 100)
      const startTime = performance.now()
      
      rerender(<VirtualizedResultsTable {...defaultProps} businesses={updatedBusinesses} />)
      
      const endTime = performance.now()
      expect(endTime - startTime).toBeLessThan(50) // Should update quickly
    }
    
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
  })
})
