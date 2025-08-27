/**
 * Performance Context Tests
 * Tests for the Smart Performance Mode Auto-Detection system
 */

import React from 'react'
import { render, screen, act, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PerformanceProvider, usePerformance } from '@/controller/PerformanceContext'
import { DEFAULT_PERFORMANCE_THRESHOLDS } from '@/types/performance'

// Mock localStorage
const mockLocalStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
})

// Mock performance.memory
Object.defineProperty(window, 'performance', {
  value: {
    ...window.performance,
    memory: {
      usedJSHeapSize: 100 * 1024 * 1024, // 100MB
      totalJSHeapSize: 200 * 1024 * 1024, // 200MB
      jsHeapSizeLimit: 2 * 1024 * 1024 * 1024, // 2GB
    },
  },
})

// Test component that uses performance context
function TestComponent({ datasetSize = 0 }: { datasetSize?: number }) {
  const {
    mode,
    metrics,
    showAdvisoryBanner,
    showPaginationPrompt,
    preferences,
    updatePreferences,
    setMode,
    dismissAdvisoryBanner,
    acceptPagination,
    declinePagination,
  } = usePerformance()

  return (
    <div>
      <div data-testid="mode">{mode}</div>
      <div data-testid="dataset-size">{metrics.datasetSize}</div>
      <div data-testid="memory-usage">{metrics.memoryUsage}</div>
      <div data-testid="performance-score">{metrics.performanceScore}</div>
      <div data-testid="show-advisory">{showAdvisoryBanner.toString()}</div>
      <div data-testid="show-pagination-prompt">{showPaginationPrompt.toString()}</div>
      <div data-testid="auto-detection">{preferences.autoDetection.toString()}</div>

      <button onClick={() => updatePreferences({ autoDetection: false })}>
        Disable Auto Detection
      </button>
      <button onClick={() => setMode('virtualized')}>Set Virtualized</button>
      <button onClick={dismissAdvisoryBanner}>Dismiss Advisory</button>
      <button onClick={acceptPagination}>Accept Pagination</button>
      <button onClick={declinePagination}>Decline Pagination</button>
    </div>
  )
}

describe('PerformanceContext', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockLocalStorage.getItem.mockReturnValue(null)
  })

  describe('Auto-detection', () => {
    it('should start in normal mode for small datasets', () => {
      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      expect(screen.getByTestId('mode')).toHaveTextContent('normal')
      expect(screen.getByTestId('show-advisory')).toHaveTextContent('false')
      expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('false')
    })

    it('should show advisory banner for medium datasets', async () => {
      render(
        <PerformanceProvider datasetSize={1500}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('advisory')
        expect(screen.getByTestId('show-advisory')).toHaveTextContent('true')
      })
    })

    it('should prompt for pagination for large datasets', async () => {
      render(
        <PerformanceProvider datasetSize={3000}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('pagination')
        expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('true')
      })
    })

    it('should auto-switch to virtualization for very large datasets', async () => {
      render(
        <PerformanceProvider datasetSize={6000}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('virtualized')
      })
    })
  })

  describe('User interactions', () => {
    it('should allow disabling auto-detection', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={1500}>
          <TestComponent />
        </PerformanceProvider>
      )

      await user.click(screen.getByText('Disable Auto Detection'))

      await waitFor(() => {
        expect(screen.getByTestId('auto-detection')).toHaveTextContent('false')
      })
    })

    it('should allow manual mode switching', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      await user.click(screen.getByText('Set Virtualized'))

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('virtualized')
      })
    })

    it('should allow dismissing advisory banner', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={1500}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('show-advisory')).toHaveTextContent('true')
      })

      await user.click(screen.getByText('Dismiss Advisory'))

      await waitFor(() => {
        expect(screen.getByTestId('show-advisory')).toHaveTextContent('false')
      })
    })

    it('should handle pagination acceptance', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={3000}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('true')
      })

      await user.click(screen.getByText('Accept Pagination'))

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('pagination')
        expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('false')
      })
    })

    it('should handle pagination decline', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={3000}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('true')
      })

      await user.click(screen.getByText('Decline Pagination'))

      await waitFor(() => {
        expect(screen.getByTestId('show-pagination-prompt')).toHaveTextContent('false')
      })
    })
  })

  describe('Preferences persistence', () => {
    it('should save preferences to localStorage', async () => {
      const user = userEvent.setup()

      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      await user.click(screen.getByText('Disable Auto Detection'))

      await waitFor(() => {
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
          'performancePreferences',
          expect.stringContaining('"autoDetection":false')
        )
      })
    })

    it('should load preferences from localStorage', () => {
      const savedPreferences = {
        autoDetection: false,
        pageSize: 100,
        enableMonitoring: false,
      }

      mockLocalStorage.getItem.mockReturnValue(JSON.stringify(savedPreferences))

      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      expect(screen.getByTestId('auto-detection')).toHaveTextContent('false')
    })
  })

  describe('Memory monitoring', () => {
    it('should track memory usage', async () => {
      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('memory-usage')).toHaveTextContent('104857600') // 100MB in bytes
      })
    })

    it('should calculate performance score', async () => {
      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        const score = parseInt(screen.getByTestId('performance-score').textContent || '0')
        expect(score).toBeGreaterThan(0)
        expect(score).toBeLessThanOrEqual(100)
      })
    })
  })

  describe('Custom thresholds', () => {
    it('should respect custom thresholds', async () => {
      const customPreferences = {
        autoDetection: true,
        customThresholds: {
          advisory: 500,
          pagination: 1000,
          virtualization: 2000,
          memoryThreshold: 200 * 1024 * 1024,
        },
      }

      mockLocalStorage.getItem.mockReturnValue(JSON.stringify(customPreferences))

      render(
        <PerformanceProvider datasetSize={800}>
          <TestComponent />
        </PerformanceProvider>
      )

      await waitFor(() => {
        expect(screen.getByTestId('mode')).toHaveTextContent('advisory')
      })
    })
  })

  describe('Error handling', () => {
    it('should handle localStorage errors gracefully', () => {
      mockLocalStorage.getItem.mockImplementation(() => {
        throw new Error('localStorage error')
      })

      expect(() => {
        render(
          <PerformanceProvider datasetSize={100}>
            <TestComponent />
          </PerformanceProvider>
        )
      }).not.toThrow()
    })

    it('should handle missing performance.memory gracefully', () => {
      // Temporarily remove performance.memory
      const originalMemory = (window.performance as any).memory
      delete (window.performance as any).memory

      render(
        <PerformanceProvider datasetSize={100}>
          <TestComponent />
        </PerformanceProvider>
      )

      expect(screen.getByTestId('memory-usage')).toHaveTextContent('0')

      // Restore performance.memory
      ;(window.performance as any).memory = originalMemory
    })
  })
})
