import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiConfigurationPage } from '../../src/view/components/ApiConfigurationPage'

// Mock the secure storage utilities
jest.mock('../../src/utils/secureStorage', () => ({
  storeApiCredentials: jest.fn(),
  retrieveApiCredentials: jest.fn(),
  clearApiCredentials: jest.fn(),
  hasStoredCredentials: jest.fn(),
  getCredentialsTimestamp: jest.fn(),
  validateApiCredentials: jest.fn(),
  testApiCredentials: jest.fn(),
  testApiCredentialsDetailed: jest.fn(),
  exportCredentials: jest.fn(),
  importCredentials: jest.fn(),
}))

// Mock the storage
jest.mock('../../src/model/storage', () => ({
  storage: {
    getDomainBlacklist: jest.fn().mockResolvedValue([]),
    setDomainBlacklist: jest.fn().mockResolvedValue(undefined),
  },
}))

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  toast: {
    error: jest.fn(),
    success: jest.fn(),
  },
}))

// Mock logger
jest.mock('../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
  },
}))

describe('ApiConfigurationPage Real-time Validation', () => {
  const mockOnClose = jest.fn()
  const mockOnCredentialsUpdated = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should show real-time validation for Google Search API key', async () => {
    const user = userEvent.setup()

    render(
      <ApiConfigurationPage onClose={mockOnClose} onCredentialsUpdated={mockOnCredentialsUpdated} />
    )

    const apiKeyInput = screen.getByLabelText(/Google Search.*API Key/i)

    // Initially should not show validation
    expect(screen.queryByText(/Google Search API key is required/i)).not.toBeInTheDocument()

    // Type invalid short key
    await user.type(apiKeyInput, 'short')

    // Should show validation error after debounce
    await waitFor(
      () => {
        expect(screen.getByText(/Google Search API key is required/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )

    // Clear and type valid key
    await user.clear(apiKeyInput)
    await user.type(apiKeyInput, 'valid-api-key-12345')

    // Should show success state
    await waitFor(
      () => {
        expect(screen.getByText(/Valid input/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )
  })

  it('should show real-time validation for Google Search Engine ID', async () => {
    const user = userEvent.setup()

    render(
      <ApiConfigurationPage onClose={mockOnClose} onCredentialsUpdated={mockOnCredentialsUpdated} />
    )

    const engineIdInput = screen.getByLabelText(/Search Engine ID/i)

    // Type invalid short ID
    await user.type(engineIdInput, 'ab')

    // Should show validation error
    await waitFor(
      () => {
        expect(screen.getByText(/Google Search Engine ID is required/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )

    // Clear and type valid ID
    await user.clear(engineIdInput)
    await user.type(engineIdInput, 'valid-engine-id')

    // Should show success state
    await waitFor(
      () => {
        expect(screen.getByText(/Valid input/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )
  })

  it('should maintain accessibility attributes', async () => {
    const user = userEvent.setup()

    render(
      <ApiConfigurationPage onClose={mockOnClose} onCredentialsUpdated={mockOnCredentialsUpdated} />
    )

    const apiKeyInput = screen.getByLabelText(/Google Search.*API Key/i)

    // Type invalid input
    await user.type(apiKeyInput, 'short')

    // Should have proper ARIA attributes
    await waitFor(
      () => {
        expect(apiKeyInput).toHaveAttribute('aria-invalid', 'true')
        expect(apiKeyInput).toHaveAttribute('aria-describedby')
      },
      { timeout: 1000 }
    )

    // Error message should have proper role
    const errorMessage = screen.getByText(/Google Search API key is required/i)
    expect(errorMessage).toHaveAttribute('role', 'alert')
    expect(errorMessage).toHaveAttribute('aria-live', 'polite')
  })

  it('should clear validation errors when input changes', async () => {
    const user = userEvent.setup()

    render(
      <ApiConfigurationPage onClose={mockOnClose} onCredentialsUpdated={mockOnCredentialsUpdated} />
    )

    const apiKeyInput = screen.getByLabelText(/Google Search.*API Key/i)

    // Type invalid input
    await user.type(apiKeyInput, 'short')

    // Wait for error to appear
    await waitFor(
      () => {
        expect(screen.getByText(/Google Search API key is required/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )

    // Clear input
    await user.clear(apiKeyInput)

    // Type valid input
    await user.type(apiKeyInput, 'valid-api-key-12345')

    // Error should be gone and success should appear
    await waitFor(
      () => {
        expect(screen.queryByText(/Google Search API key is required/i)).not.toBeInTheDocument()
        expect(screen.getByText(/Valid input/i)).toBeInTheDocument()
      },
      { timeout: 1000 }
    )
  })
})
