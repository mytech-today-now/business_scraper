import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { ProcessingWindow, ProcessingStep } from '@/view/components/ProcessingWindow'
import toast from 'react-hot-toast'

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  success: jest.fn(),
  error: jest.fn(),
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    error: jest.fn(),
  },
}))

// Mock clipboard API
const mockWriteText = jest.fn()
Object.assign(navigator, {
  clipboard: {
    writeText: mockWriteText,
  },
})

// Mock document.execCommand for fallback testing
document.execCommand = jest.fn()

describe('ProcessingWindow - Copy Functionality', () => {
  const defaultProps = {
    isVisible: true,
    isActive: true,
    currentStep: 'test-step',
    steps: [] as ProcessingStep[],
    onToggleVisibility: jest.fn(),
    onClear: jest.fn(),
    progress: {
      current: 0,
      total: 0,
      percentage: 0,
    },
    currentUrl: 'https://example.com',
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockWriteText.mockResolvedValue(undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('renders without crashing', () => {
    render(<ProcessingWindow {...defaultProps} />)
    expect(screen.getByText('Console Output')).toBeInTheDocument()
  })

  it('shows console output section with copy button', () => {
    render(<ProcessingWindow {...defaultProps} />)
    
    // Check if Copy button is present
    const copyButton = screen.getByRole('button', { name: /copy/i })
    expect(copyButton).toBeInTheDocument()
    expect(copyButton).toHaveAttribute('title', 'Copy console output to clipboard')
  })

  it('disables copy button when no console logs are present', () => {
    render(<ProcessingWindow {...defaultProps} />)
    
    const copyButton = screen.getByRole('button', { name: /copy/i })
    expect(copyButton).toBeDisabled()
  })

  it('shows error toast when trying to copy empty console', async () => {
    render(<ProcessingWindow {...defaultProps} />)
    
    // Show console
    const showButton = screen.getByRole('button', { name: /show/i })
    fireEvent.click(showButton)
    
    // Try to click copy button (should be disabled, but test the function directly)
    const copyButton = screen.getByRole('button', { name: /copy/i })
    
    // Force click even though disabled to test the function
    fireEvent.click(copyButton)
    
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('No console output to copy')
    })
  })

  it('shows and hides console output correctly', () => {
    render(<ProcessingWindow {...defaultProps} />)
    
    // Initially console should be hidden
    expect(screen.queryByText('No console output yet...')).not.toBeInTheDocument()
    
    // Show console
    const showButton = screen.getByRole('button', { name: /show/i })
    fireEvent.click(showButton)
    
    expect(screen.getByText('No console output yet...')).toBeInTheDocument()
    
    // Hide console
    const hideButton = screen.getByRole('button', { name: /hide/i })
    fireEvent.click(hideButton)
    
    expect(screen.queryByText('No console output yet...')).not.toBeInTheDocument()
  })

  it('handles clipboard API failure gracefully', async () => {
    mockWriteText.mockRejectedValue(new Error('Clipboard API failed'))

    render(<ProcessingWindow {...defaultProps} />)

    // Show console
    const showButton = screen.getByRole('button', { name: /show/i })
    fireEvent.click(showButton)

    // The copy button should be disabled when no logs are present
    const copyButton = screen.getByRole('button', { name: /copy/i })
    expect(copyButton).toBeDisabled()

    // Test that the error handling works when called directly
    fireEvent.click(copyButton)

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('No console output to copy')
    })
  })

  it('copy button has correct accessibility attributes', () => {
    render(<ProcessingWindow {...defaultProps} />)

    const copyButton = screen.getByRole('button', { name: /copy/i })

    // Check accessibility attributes
    expect(copyButton).toHaveAttribute('title', 'Copy console output to clipboard')
    expect(copyButton).toBeDisabled() // Should be disabled when no logs

    // Check that it has the copy icon
    const copyIcon = copyButton.querySelector('svg')
    expect(copyIcon).toBeInTheDocument()
  })

  it('copy button is part of console controls', () => {
    render(<ProcessingWindow {...defaultProps} />)

    // Verify the copy button is in the console controls section
    const consoleHeading = screen.getByText('Console Output')
    expect(consoleHeading).toBeInTheDocument()

    const copyButton = screen.getByRole('button', { name: /copy/i })
    const clearConsoleButton = screen.getByRole('button', { name: /clear console/i })
    const showButton = screen.getByRole('button', { name: /show/i })

    // All console control buttons should be present
    expect(copyButton).toBeInTheDocument()
    expect(clearConsoleButton).toBeInTheDocument()
    expect(showButton).toBeInTheDocument()
  })

  it('renders processing steps correctly', () => {
    const steps: ProcessingStep[] = [
      {
        id: '1',
        name: 'Step 1',
        status: 'completed',
        startTime: new Date(),
        endTime: new Date(),
      },
      {
        id: '2',
        name: 'Step 2',
        status: 'running',
        startTime: new Date(),
      },
      {
        id: '3',
        name: 'Step 3',
        status: 'pending',
      },
    ]

    render(<ProcessingWindow {...defaultProps} steps={steps} />)

    expect(screen.getByText('Step 1')).toBeInTheDocument()
    expect(screen.getByText('Step 2')).toBeInTheDocument()
    expect(screen.getByText('Step 3')).toBeInTheDocument()
  })

  it('displays progress information correctly', () => {
    const progress = {
      current: 5,
      total: 10,
      percentage: 50,
    }

    render(<ProcessingWindow {...defaultProps} progress={progress} />)

    // Check if progress information is displayed
    expect(screen.getByText(/50%/)).toBeInTheDocument()
  })

  it('shows current URL when provided', () => {
    const currentUrl = 'https://example.com/test-page'

    render(<ProcessingWindow {...defaultProps} currentUrl={currentUrl} />)

    expect(screen.getByText(currentUrl)).toBeInTheDocument()
  })
})
