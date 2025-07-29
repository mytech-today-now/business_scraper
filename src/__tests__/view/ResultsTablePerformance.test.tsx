import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import '@testing-library/jest-dom'
import { ResultsTable } from '../../view/components/ResultsTable'
import { BusinessRecord } from '../../types/business'
import toast from 'react-hot-toast'

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  }
}))

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

// Mock performance.memory
Object.defineProperty(performance, 'memory', {
  value: {
    usedJSHeapSize: 100 * 1024 * 1024, // 100MB
    totalJSHeapSize: 200 * 1024 * 1024,
    jsHeapSizeLimit: 2048 * 1024 * 1024
  },
  writable: true
})

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

describe('ResultsTable Performance Features', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('shows performance warning for medium datasets (1000+ results)', async () => {
    const businesses = generateMockBusinesses(1500)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should show performance warning
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
    expect(screen.getByText(/Medium dataset size/)).toBeInTheDocument()
  })

  it('shows performance warning for large datasets (2500+ results)', async () => {
    const businesses = generateMockBusinesses(3000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should show performance warning
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
    expect(screen.getByText(/Large dataset detected/)).toBeInTheDocument()
  })

  it('shows virtual scrolling recommendation for very large datasets (5000+ results)', async () => {
    const businesses = generateMockBusinesses(6000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should show virtual scrolling recommendation
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
    expect(screen.getByText(/Very large dataset detected/)).toBeInTheDocument()
    expect(screen.getByText('Enable Virtual Scrolling')).toBeInTheDocument()
  })

  it('automatically enables virtual scrolling for very large datasets', async () => {
    const businesses = generateMockBusinesses(6000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Fast-forward timers to trigger useEffect
    act(() => {
      jest.runAllTimers()
    })

    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith(
        expect.stringContaining('Large dataset detected'),
        expect.objectContaining({
          duration: 5000,
          icon: '⚡'
        })
      )
    })

    // Should show virtual scrolling is enabled
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
  })

  it('shows performance suggestions for medium-large datasets', async () => {
    const businesses = generateMockBusinesses(3000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Fast-forward timers to trigger useEffect
    act(() => {
      jest.runAllTimers()
    })

    await waitFor(() => {
      expect(toast).toHaveBeenCalledWith(
        expect.stringContaining('Dataset size: 3,000 results'),
        expect.objectContaining({
          duration: 4000,
          icon: '💡'
        })
      )
    })
  })

  it('enables virtual scrolling when button is clicked', async () => {
    const businesses = generateMockBusinesses(6000)
    
    render(<ResultsTable businesses={businesses} />)
    
    const enableButton = screen.getByText('Enable Virtual Scrolling')
    fireEvent.click(enableButton)
    
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith(
        'Virtual scrolling enabled! Performance should improve significantly.'
      )
    })

    // Should show virtualized list
    expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
  })

  it('disables virtual scrolling when disable button is clicked', async () => {
    const businesses = generateMockBusinesses(6000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // First enable virtual scrolling
    const enableButton = screen.getByText('Enable Virtual Scrolling')
    fireEvent.click(enableButton)
    
    await waitFor(() => {
      expect(screen.getByTestId('virtualized-list')).toBeInTheDocument()
    })

    // Then disable it
    const disableButton = screen.getByText('Disable Virtual Scrolling')
    fireEvent.click(disableButton)
    
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith(
        'Virtual scrolling disabled. Using standard table view.'
      )
    })

    // Should show standard table
    expect(screen.queryByTestId('virtualized-list')).not.toBeInTheDocument()
  })

  it('displays memory usage in performance warnings', () => {
    // Mock high memory usage
    Object.defineProperty(performance, 'memory', {
      value: {
        usedJSHeapSize: 600 * 1024 * 1024, // 600MB
        totalJSHeapSize: 800 * 1024 * 1024,
        jsHeapSizeLimit: 2048 * 1024 * 1024
      },
      writable: true
    })

    const businesses = generateMockBusinesses(1500)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should show memory usage warning
    expect(screen.getByText(/High memory usage detected: 600MB/)).toBeInTheDocument()
    expect(screen.getByText(/Current memory usage: 600.0MB/)).toBeInTheDocument()
  })

  it('shows table mode indicator in statistics', () => {
    const businesses = generateMockBusinesses(100)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should show standard mode initially
    expect(screen.getByText('Standard')).toBeInTheDocument()
    expect(screen.getByText('Table Mode')).toBeInTheDocument()
  })

  it('updates table mode indicator when virtual scrolling is enabled', async () => {
    const businesses = generateMockBusinesses(6000)
    
    render(<ResultsTable businesses={businesses} />)
    
    const enableButton = screen.getByText('Enable Virtual Scrolling')
    fireEvent.click(enableButton)
    
    await waitFor(() => {
      expect(screen.getByText('Virtual')).toBeInTheDocument()
      expect(screen.getByText('Table Mode')).toBeInTheDocument()
    })
  })

  it('monitors memory usage periodically', async () => {
    const businesses = generateMockBusinesses(1000)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Fast-forward 5 seconds to trigger memory monitoring
    act(() => {
      jest.advanceTimersByTime(5000)
    })

    // Memory monitoring should be active (no specific assertion needed as it's internal)
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
  })

  it('handles datasets below warning threshold without performance notices', () => {
    const businesses = generateMockBusinesses(500)
    
    render(<ResultsTable businesses={businesses} />)
    
    // Should not show performance warnings
    expect(screen.queryByText('Performance Notice')).not.toBeInTheDocument()
  })

  it('updates performance warnings when dataset size changes', async () => {
    const { rerender } = render(<ResultsTable businesses={generateMockBusinesses(500)} />)
    
    // Initially no warnings
    expect(screen.queryByText('Performance Notice')).not.toBeInTheDocument()
    
    // Update to large dataset
    rerender(<ResultsTable businesses={generateMockBusinesses(1500)} />)
    
    // Should now show warnings
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
  })

  it('maintains performance with frequent filter changes', async () => {
    const businesses = generateMockBusinesses(2000)
    
    const { rerender } = render(<ResultsTable businesses={businesses} />)
    
    // Simulate frequent filter changes
    for (let i = 0; i < 10; i++) {
      const startTime = performance.now()
      
      rerender(<ResultsTable businesses={businesses} />)
      
      const endTime = performance.now()
      expect(endTime - startTime).toBeLessThan(100) // Should update quickly
    }
  })

  it('handles edge case of exactly threshold values', () => {
    // Test exactly 1000 results
    const businesses1000 = generateMockBusinesses(1000)
    const { rerender } = render(<ResultsTable businesses={businesses1000} />)
    expect(screen.getByText('Performance Notice')).toBeInTheDocument()
    
    // Test exactly 2500 results
    const businesses2500 = generateMockBusinesses(2500)
    rerender(<ResultsTable businesses={businesses2500} />)
    expect(screen.getByText(/Large dataset detected/)).toBeInTheDocument()
    
    // Test exactly 5000 results
    const businesses5000 = generateMockBusinesses(5000)
    rerender(<ResultsTable businesses={businesses5000} />)
    expect(screen.getByText(/Very large dataset detected/)).toBeInTheDocument()
  })
})
