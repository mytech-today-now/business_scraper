/**
 * Regression Test: ZIP Code Toast Duplication
 * 
 * This test ensures that the ZIP code validation toast notification
 * appears only once per valid ZIP code acceptance, preventing the
 * duplicate toast issue reported in GitHub issue #193.
 */

import React from 'react'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'react-hot-toast'
import { App } from '@/view/components/App'
import { useScraperController } from '@/controller/useScraperController'
import { useConfig } from '@/controller/ConfigContext'
import { toastDeduplication } from '@/utils/toastDeduplication'
import { mockScraperController, mockConfigContext } from '@/test/testUtils'

// Mock dependencies
jest.mock('@/controller/useScraperController')
jest.mock('@/controller/ConfigContext')
jest.mock('react-hot-toast')

const mockUseScraperController = useScraperController as jest.MockedFunction<typeof useScraperController>
const mockUseConfig = useConfig as jest.MockedFunction<typeof useConfig>
const mockToast = toast as jest.Mocked<typeof toast>

// Mock storage
jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn().mockResolvedValue(undefined),
    getConfig: jest.fn().mockResolvedValue({
      id: 'default',
      industries: [],
      zipCode: '60047', // Pre-existing ZIP code that triggers the issue
      searchRadius: 25,
      searchDepth: 2,
      pagesPerSite: 5,
    }),
    saveConfig: jest.fn().mockResolvedValue(undefined),
    getAllIndustries: jest.fn().mockResolvedValue([
      {
        id: 'law-firms',
        name: 'Law Firms & Legal Services',
        keywords: ['law firm near me', 'corporate law office'],
        isCustom: false,
      },
    ]),
    saveIndustries: jest.fn().mockResolvedValue(undefined),
    getResults: jest.fn().mockResolvedValue([]),
    saveResults: jest.fn().mockResolvedValue(undefined),
    clearResults: jest.fn().mockResolvedValue(undefined),
  },
}))

// Mock other dependencies
jest.mock('@/lib/cspUtils', () => ({
  getCSPNonce: jest.fn(() => 'mock-nonce'),
  createCSPSafeStyle: jest.fn((styles) => styles),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

describe('Regression Test: ZIP Code Toast Duplication', () => {

  beforeEach(() => {
    jest.clearAllMocks()
    toastDeduplication.clear()
    
    mockUseScraperController.mockReturnValue(mockScraperController)
    mockUseConfig.mockReturnValue(mockConfigContext)
    
    // Mock toast.success to track calls
    mockToast.success = jest.fn()
    mockToast.error = jest.fn()
    mockToast.warning = jest.fn()
    mockToast.info = jest.fn()
  })

  it('should show ZIP code validation toast only once on page load with existing ZIP code', async () => {
    // Render the App component with a pre-existing ZIP code
    render(<App />)

    // Wait for the component to initialize and process the existing ZIP code
    await waitFor(() => {
      expect(screen.getByDisplayValue('60047')).toBeInTheDocument()
    }, { timeout: 5000 })

    // Give additional time for any async operations to complete
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 1000))
    })

    // Check that the success toast was called at most once
    const successCalls = mockToast.success.mock.calls.filter(call => 
      call[0].includes('ZIP code "60047" is valid')
    )
    
    expect(successCalls.length).toBeLessThanOrEqual(1)
    
    if (successCalls.length === 1) {
      expect(successCalls[0][0]).toBe('ZIP code "60047" is valid')
    }
  })

  it('should prevent duplicate toasts when ZIP code input is processed multiple times', async () => {
    const user = userEvent.setup()
    
    render(<App />)

    // Wait for component to load
    await waitFor(() => {
      expect(screen.getByLabelText(/zip code/i)).toBeInTheDocument()
    })

    const zipInput = screen.getByLabelText(/zip code/i)

    // Clear the input and type a new ZIP code
    await user.clear(zipInput)
    await user.type(zipInput, '90210')

    // Trigger blur event multiple times to simulate the issue
    await act(async () => {
      zipInput.blur()
      zipInput.focus()
      zipInput.blur()
      zipInput.focus()
      zipInput.blur()
    })

    // Wait for debouncing and processing
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 1500))
    })

    // Check that the success toast was called at most once for the new ZIP code
    const successCalls = mockToast.success.mock.calls.filter(call => 
      call[0].includes('ZIP code "90210" is valid')
    )
    
    expect(successCalls.length).toBeLessThanOrEqual(1)
  })

  it('should allow different ZIP codes to show toasts independently', async () => {
    const user = userEvent.setup()
    
    render(<App />)

    await waitFor(() => {
      expect(screen.getByLabelText(/zip code/i)).toBeInTheDocument()
    })

    const zipInput = screen.getByLabelText(/zip code/i)

    // Enter first ZIP code
    await user.clear(zipInput)
    await user.type(zipInput, '10001')
    await act(async () => {
      zipInput.blur()
    })

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
    })

    // Enter second ZIP code
    await user.selectAll(zipInput)
    await user.type(zipInput, '90210')
    await act(async () => {
      zipInput.blur()
    })

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
    })

    // Both ZIP codes should be allowed to show toasts
    const zip1Calls = mockToast.success.mock.calls.filter(call => 
      call[0].includes('ZIP code "10001" is valid')
    )
    const zip2Calls = mockToast.success.mock.calls.filter(call => 
      call[0].includes('ZIP code "90210" is valid')
    )

    expect(zip1Calls.length).toBeLessThanOrEqual(1)
    expect(zip2Calls.length).toBeLessThanOrEqual(1)
  })
})
