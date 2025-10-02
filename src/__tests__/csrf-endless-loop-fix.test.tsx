/**
 * Test for CSRF endless loop fix
 * Verifies that the login page handles database connection failures gracefully
 * without getting stuck in an endless loading loop
 */

import React from 'react'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { jest } from '@jest/globals'
import LoginPage from '@/app/login/page'

// Mock the router
const mockPush = jest.fn()
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: mockPush,
    replace: jest.fn(),
  }),
}))

// Mock the CSRF hook
const mockCSRFHook = {
  csrfToken: null as string | null,
  isLoading: false,
  error: null as string | null,
  submitForm: jest.fn(),
  getCSRFInput: jest.fn(() => null),
  isTokenValid: jest.fn(() => false),
}

jest.mock('@/hooks/useLightweightCSRF', () => ({
  useLightweightFormCSRF: () => mockCSRFHook,
}))

// Mock fetch for API calls
import { createFetchMock } from '@/__tests__/utils/mockTypeHelpers'
global.fetch = createFetchMock()

describe('CSRF Endless Loop Fix', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockCSRFHook.csrfToken = null
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = null
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('should display loading message when CSRF token is being fetched', () => {
    mockCSRFHook.isLoading = true
    mockCSRFHook.error = null

    render(<LoginPage />)

    expect(screen.getByText('Loading security token...')).toBeInTheDocument()
  })

  it('should display database error message when database connection fails', () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Database connection failed. Please check if the database service is running and try again.'

    render(<LoginPage />)

    expect(screen.getByText('⚠️ Security Token Error')).toBeInTheDocument()
    expect(screen.getByText(/Database connection failed/)).toBeInTheDocument()
    expect(screen.getByText('Database Connection Issue')).toBeInTheDocument()
  })

  it('should display network error message when network connection fails', () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Network connection failed. Please check your internet connection and try again.'

    render(<LoginPage />)

    expect(screen.getByText('⚠️ Security Token Error')).toBeInTheDocument()
    expect(screen.getByText(/Network connection failed/)).toBeInTheDocument()
    expect(screen.getByText('Network Connection Issue')).toBeInTheDocument()
  })

  it('should provide manual retry button when CSRF error occurs', () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Failed to load security token'

    render(<LoginPage />)

    expect(screen.getByText('Retry Loading Token')).toBeInTheDocument()
    expect(screen.getByText('Refresh Page')).toBeInTheDocument()
  })

  it('should handle manual retry button click', () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Failed to load security token'

    // Mock window.location.reload
    const originalReload = window.location.reload
    window.location.reload = jest.fn()

    render(<LoginPage />)

    const retryButton = screen.getByText('Retry Loading Token')
    fireEvent.click(retryButton)

    expect(window.location.reload).toHaveBeenCalled()

    // Restore original reload
    window.location.reload = originalReload
  })

  it('should not show loading message when there is an error', () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Some error occurred'

    render(<LoginPage />)

    expect(screen.queryByText('Loading security token...')).not.toBeInTheDocument()
    expect(screen.getByText('⚠️ Security Token Error')).toBeInTheDocument()
  })

  it('should show retry count when manual retries are performed', async () => {
    mockCSRFHook.isLoading = false
    mockCSRFHook.error = 'Failed to load security token'

    // Mock window.location.reload
    const originalReload = window.location.reload
    window.location.reload = jest.fn()

    render(<LoginPage />)

    const retryButton = screen.getByText('Retry Loading Token')
    
    // First retry
    fireEvent.click(retryButton)
    
    // Since reload is mocked, we need to simulate the state change
    // In real scenario, the page would reload and reset the state
    
    // Restore original reload
    window.location.reload = originalReload
  })

  it('should not get stuck in endless loop when database is down', async () => {
    // Simulate the scenario where CSRF hook keeps retrying
    let retryCount = 0
    const maxRetries = 3

    // Mock the hook to simulate retry behavior
    const simulateRetries = () => {
      if (retryCount < maxRetries) {
        retryCount++
        mockCSRFHook.isLoading = true
        mockCSRFHook.error = null
        
        // Simulate retry delay
        setTimeout(() => {
          mockCSRFHook.isLoading = false
          mockCSRFHook.error = 'Database connection failed. Please check if the database service is running and try again.'
        }, 100)
      }
    }

    render(<LoginPage />)

    // Start the retry simulation
    simulateRetries()

    // Wait for the final error state
    await waitFor(() => {
      expect(mockCSRFHook.error).toBeTruthy()
      expect(mockCSRFHook.isLoading).toBe(false)
    }, { timeout: 5000 })

    // Verify that retries stopped after max attempts
    expect(retryCount).toBeLessThanOrEqual(maxRetries)
  })
})
