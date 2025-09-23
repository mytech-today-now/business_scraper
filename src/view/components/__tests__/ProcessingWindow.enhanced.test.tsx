/**
 * Enhanced tests for ProcessingWindow component
 * Tests the console filtering improvements made for Issue #190
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ProcessingWindow } from '../ProcessingWindow'
import toast from 'react-hot-toast'

// Mock dependencies
jest.mock('react-hot-toast')
jest.mock('@/utils/logger')

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: jest.fn().mockResolvedValue(undefined),
  },
})

const mockProps = {
  isVisible: true,
  isActive: true,
  currentStep: 'Processing...',
  steps: [
    {
      id: '1',
      name: 'Step 1',
      status: 'completed' as const,
      timestamp: new Date(),
      duration: 1000,
    },
    {
      id: '2',
      name: 'Step 2',
      status: 'active' as const,
      timestamp: new Date(),
    },
  ],
  onToggleVisibility: jest.fn(),
  onClear: jest.fn(),
  progress: {
    current: 50,
    total: 100,
    percentage: 50,
  },
  currentUrl: 'https://example.com',
}

describe('ProcessingWindow Enhanced Console Filtering', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Reset console methods
    const originalConsole = {
      log: console.log,
      info: console.info,
      warn: console.warn,
      error: console.error,
      debug: console.debug,
    }
    
    console.log = originalConsole.log
    console.info = originalConsole.info
    console.warn = originalConsole.warn
    console.error = originalConsole.error
    console.debug = originalConsole.debug
  })

  describe('Console Log Filtering', () => {
    it('should filter out debug messages by default', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate debug messages
      console.debug('[05:48:41 AM] <Monitoring> DEBUG: Metric stored')
      console.info('[05:48:41 AM] <ScraperController> INFO: Scraper initialized')
      
      await waitFor(() => {
        // Debug message should be filtered out
        expect(screen.queryByText(/Metric stored/)).not.toBeInTheDocument()
        
        // Info message should be visible
        expect(screen.getByText(/Scraper initialized/)).toBeInTheDocument()
      })
    })

    it('should filter out monitoring messages when hideMonitoring is enabled', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate monitoring messages
      console.info('[05:48:41 AM] <Monitoring> INFO: Metric recorded: memory_heap_used = 149601132 bytes')
      console.info('[05:48:41 AM] <ScraperController> INFO: Normal message')
      
      await waitFor(() => {
        // Monitoring message should be filtered out
        expect(screen.queryByText(/Metric recorded/)).not.toBeInTheDocument()
        
        // Normal message should be visible
        expect(screen.getByText(/Normal message/)).toBeInTheDocument()
      })
    })

    it('should show debug messages when debug filter is enabled', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Enable debug filter
      const debugCheckbox = screen.getByLabelText(/Debug/)
      fireEvent.click(debugCheckbox)
      
      // Simulate debug message
      console.debug('[05:48:41 AM] <TestComponent> DEBUG: Test debug message')
      
      await waitFor(() => {
        expect(screen.getByText(/Test debug message/)).toBeInTheDocument()
      })
    })

    it('should show monitoring messages when monitoring filter is enabled', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Enable monitoring filter
      const monitoringCheckbox = screen.getByLabelText(/Monitoring/)
      fireEvent.click(monitoringCheckbox)
      
      // Simulate monitoring message
      console.info('[05:48:41 AM] <Monitoring> INFO: Metric stored')
      
      await waitFor(() => {
        expect(screen.getByText(/Metric stored/)).toBeInTheDocument()
      })
    })

    it('should display correct filter counts', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate various log messages
      console.debug('[05:48:41 AM] <Monitoring> DEBUG: Debug message')
      console.info('[05:48:41 AM] <Monitoring> INFO: Monitoring message')
      console.info('[05:48:41 AM] <ScraperController> INFO: Normal message')
      console.warn('[05:48:41 AM] <TestComponent> WARN: Warning message')
      
      await waitFor(() => {
        // Should show filtered count (debug and monitoring filtered out by default)
        expect(screen.getByText(/\(2\/4 shown\)/)).toBeInTheDocument()
      })
    })
  })

  describe('Console Filter Controls', () => {
    it('should render all filter controls', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Check all filter controls are present
      expect(screen.getByLabelText(/Error/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Warn/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Info/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Debug/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Monitoring/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Streaming/)).toBeInTheDocument()
    })

    it('should toggle filters correctly', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate info message
      console.info('[05:48:41 AM] <TestComponent> INFO: Test message')
      
      await waitFor(() => {
        expect(screen.getByText(/Test message/)).toBeInTheDocument()
      })
      
      // Disable info filter
      const infoCheckbox = screen.getByLabelText(/Info/)
      fireEvent.click(infoCheckbox)
      
      await waitFor(() => {
        expect(screen.queryByText(/Test message/)).not.toBeInTheDocument()
      })
    })
  })

  describe('Component Extraction', () => {
    it('should extract component names from log messages', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate message with component
      console.info('[05:48:41 AM] <ScraperController> INFO: Test message')
      
      await waitFor(() => {
        expect(screen.getByText('<ScraperController>')).toBeInTheDocument()
        expect(screen.getByText(/Test message/)).toBeInTheDocument()
      })
    })

    it('should handle messages without component names', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate message without component
      console.info('Simple log message without component')
      
      await waitFor(() => {
        expect(screen.getByText(/Simple log message/)).toBeInTheDocument()
        expect(screen.queryByText(/<.*>/)).not.toBeInTheDocument()
      })
    })
  })

  describe('Copy Functionality', () => {
    it('should copy filtered logs to clipboard', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate log messages
      console.info('[05:48:41 AM] <ScraperController> INFO: Test message')
      console.debug('[05:48:41 AM] <Monitoring> DEBUG: Debug message')
      
      // Click copy button
      const copyButton = screen.getByText('Copy')
      fireEvent.click(copyButton)
      
      await waitFor(() => {
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
          expect.stringContaining('Test message')
        )
        
        // Should not include debug message (filtered out by default)
        expect(navigator.clipboard.writeText).not.toHaveBeenCalledWith(
          expect.stringContaining('Debug message')
        )
      })
    })

    it('should show error when no logs to copy', async () => {
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Click copy button without any logs
      const copyButton = screen.getByText('Copy')
      fireEvent.click(copyButton)
      
      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith('No console output to copy')
      })
    })
  })

  describe('Auto-scroll Functionality', () => {
    it('should auto-scroll when new filtered logs are added', async () => {
      // Mock scrollTop property
      const mockScrollTop = jest.fn()
      Object.defineProperty(HTMLElement.prototype, 'scrollTop', {
        set: mockScrollTop,
        get: () => 0,
        configurable: true,
      })
      
      Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
        get: () => 1000,
        configurable: true,
      })
      
      render(<ProcessingWindow {...mockProps} />)
      
      // Show console
      const showButton = screen.getByText('Show')
      fireEvent.click(showButton)
      
      // Simulate new log message
      console.info('[05:48:41 AM] <ScraperController> INFO: New message')
      
      await waitFor(() => {
        expect(mockScrollTop).toHaveBeenCalledWith(1000)
      })
    })
  })
})
