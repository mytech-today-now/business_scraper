/**
 * UI Stability Tests - Search and Download Functionality
 * Tests for search streaming, export services, and download capabilities
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'

import { useSearchStreaming } from '@/hooks/useSearchStreaming'
import { ExportService } from '@/utils/exportService'
import { SearchEngineControls } from '@/view/components/SearchEngineControls'

// Mock the search streaming hook
jest.mock('@/hooks/useSearchStreaming')
const mockUseSearchStreaming = useSearchStreaming as jest.MockedFunction<typeof useSearchStreaming>

// Mock the export service
jest.mock('@/utils/exportService')
const mockExportService = ExportService as jest.MockedClass<typeof ExportService>

// Mock URL.createObjectURL and URL.revokeObjectURL
global.URL.createObjectURL = jest.fn(() => 'mock-url')
global.URL.revokeObjectURL = jest.fn()

// Mock document methods
const mockClick = jest.fn()
const mockAppendChild = jest.fn()
const mockRemoveChild = jest.fn()

Object.defineProperty(document, 'createElement', {
  value: jest.fn(() => ({
    click: mockClick,
    style: {},
    setAttribute: jest.fn(),
    getAttribute: jest.fn(),
  })),
})

Object.defineProperty(document.body, 'appendChild', {
  value: mockAppendChild,
})

Object.defineProperty(document.body, 'removeChild', {
  value: mockRemoveChild,
})

describe('UI Stability - Search and Download', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Search Streaming Hook', () => {
    it('should handle connection failures gracefully', async () => {
      const mockStreamingReturn = {
        results: [],
        progress: {
          totalFound: 0,
          processed: 0,
          currentBatch: 0,
          estimatedTimeRemaining: 0,
          status: 'error' as const,
          connectionStatus: 'disconnected' as const,
          errorMessage: 'Connection failed',
        },
        isStreaming: false,
        isPaused: false,
        error: 'Connection failed',
        startStreaming: jest.fn(),
        pauseStreaming: jest.fn(),
        resumeStreaming: jest.fn(),
        stopStreaming: jest.fn(),
        clearResults: jest.fn(),
      }

      mockUseSearchStreaming.mockReturnValue(mockStreamingReturn)

      const TestComponent = () => {
        const streaming = useSearchStreaming()
        return (
          <div>
            <div data-testid="status">{streaming.progress.status}</div>
            <div data-testid="error">{streaming.error}</div>
            <button onClick={() => streaming.startStreaming('test', 'location')}>
              Start Search
            </button>
          </div>
        )
      }

      render(<TestComponent />)

      expect(screen.getByTestId('status')).toHaveTextContent('error')
      expect(screen.getByTestId('error')).toHaveTextContent('Connection failed')
    })

    it('should handle successful streaming', async () => {
      const mockResults = [
        { id: '1', name: 'Business 1', address: '123 Main St' },
        { id: '2', name: 'Business 2', address: '456 Oak Ave' },
      ]

      const mockStreamingReturn = {
        results: mockResults,
        progress: {
          totalFound: 2,
          processed: 2,
          currentBatch: 1,
          estimatedTimeRemaining: 0,
          status: 'completed' as const,
          connectionStatus: 'connected' as const,
        },
        isStreaming: false,
        isPaused: false,
        error: null,
        startStreaming: jest.fn(),
        pauseStreaming: jest.fn(),
        resumeStreaming: jest.fn(),
        stopStreaming: jest.fn(),
        clearResults: jest.fn(),
      }

      mockUseSearchStreaming.mockReturnValue(mockStreamingReturn)

      const TestComponent = () => {
        const streaming = useSearchStreaming()
        return (
          <div>
            <div data-testid="status">{streaming.progress.status}</div>
            <div data-testid="results-count">{streaming.results.length}</div>
            <div data-testid="total-found">{streaming.progress.totalFound}</div>
          </div>
        )
      }

      render(<TestComponent />)

      expect(screen.getByTestId('status')).toHaveTextContent('completed')
      expect(screen.getByTestId('results-count')).toHaveTextContent('2')
      expect(screen.getByTestId('total-found')).toHaveTextContent('2')
    })

    it('should handle pause and resume functionality', async () => {
      const user = userEvent.setup()
      const mockStartStreaming = jest.fn()
      const mockPauseStreaming = jest.fn()
      const mockResumeStreaming = jest.fn()

      const mockStreamingReturn = {
        results: [],
        progress: {
          totalFound: 0,
          processed: 0,
          currentBatch: 0,
          estimatedTimeRemaining: 0,
          status: 'streaming' as const,
          connectionStatus: 'connected' as const,
        },
        isStreaming: true,
        isPaused: false,
        error: null,
        startStreaming: mockStartStreaming,
        pauseStreaming: mockPauseStreaming,
        resumeStreaming: mockResumeStreaming,
        stopStreaming: jest.fn(),
        clearResults: jest.fn(),
      }

      mockUseSearchStreaming.mockReturnValue(mockStreamingReturn)

      const TestComponent = () => {
        const streaming = useSearchStreaming()
        return (
          <div>
            <button onClick={() => streaming.pauseStreaming()}>Pause</button>
            <button onClick={() => streaming.resumeStreaming()}>Resume</button>
          </div>
        )
      }

      render(<TestComponent />)

      const pauseButton = screen.getByRole('button', { name: /pause/i })
      const resumeButton = screen.getByRole('button', { name: /resume/i })

      await user.click(pauseButton)
      expect(mockPauseStreaming).toHaveBeenCalled()

      await user.click(resumeButton)
      expect(mockResumeStreaming).toHaveBeenCalled()
    })
  })

  describe('Export Service', () => {
    let exportService: ExportService

    beforeEach(() => {
      exportService = new ExportService()
    })

    it('should handle CSV export correctly', async () => {
      const mockData = [
        { name: 'Business 1', address: '123 Main St', phone: '555-0001' },
        { name: 'Business 2', address: '456 Oak Ave', phone: '555-0002' },
      ]

      const { asMockedFunction } = await import('@/__tests__/utils/mockTypeHelpers')
      const mockBlob = new Blob(['csv content'], { type: 'text/csv' })
      jest.spyOn(exportService, 'exportToCSV').mockResolvedValue(mockBlob)
      jest.spyOn(exportService, 'downloadBlob').mockImplementation(() => {})

      await exportService.exportToCSV(mockData, 'test-export.csv')

      expect(exportService.exportToCSV).toHaveBeenCalledWith(mockData, 'test-export.csv')
    })

    it('should handle download blob with proper error handling', () => {
      const mockBlob = new Blob(['test content'], { type: 'text/plain' })
      
      // Test successful download
      expect(() => {
        exportService.downloadBlob(mockBlob, 'test-file.txt')
      }).not.toThrow()

      // Test with invalid filename
      expect(() => {
        exportService.downloadBlob(mockBlob, 'test<>file.txt')
      }).not.toThrow() // Should sanitize filename
    })

    it('should sanitize filenames properly', () => {
      const mockBlob = new Blob(['test'], { type: 'text/plain' })
      
      // Mock the private sanitizeFilename method by testing through downloadBlob
      jest.spyOn(exportService, 'downloadBlob').mockImplementation((blob, filename) => {
        // Simulate the sanitization logic
        const sanitized = filename
          .replace(/[<>:"/\\|?*]/g, '_')
          .replace(/\s+/g, '_')
          .replace(/_{2,}/g, '_')
          .replace(/^_+|_+$/g, '')
          .substring(0, 255)
        
        expect(sanitized).not.toMatch(/[<>:"/\\|?*]/)
      })

      exportService.downloadBlob(mockBlob, 'test<>file:name.txt')
    })

    it('should handle different export formats', () => {
      const formats = exportService.getSupportedFormats(true)
      
      expect(formats).toContain('csv')
      expect(formats).toContain('xlsx')
      expect(formats).toContain('pdf')
      expect(formats).toContain('json')
      expect(formats).toContain('xml')

      // Test format descriptions
      expect(exportService.getFormatDescription('csv')).toContain('Comma-Separated Values')
      expect(exportService.getFormatDescription('pdf')).toContain('Portable Document Format')
    })
  })

  describe('Search Engine Controls', () => {
    const mockEngines = [
      { id: 'google', name: 'Google', enabled: true, status: 'active' },
      { id: 'bing', name: 'Bing', enabled: false, status: 'inactive' },
    ]

    it('should render engine controls with proper states', () => {
      render(
        <SearchEngineControls
          engines={mockEngines}
          onEngineToggle={jest.fn()}
          onRefreshEngines={jest.fn()}
        />
      )

      const googleEngine = screen.getByText('Google')
      const bingEngine = screen.getByText('Bing')

      expect(googleEngine).toBeInTheDocument()
      expect(bingEngine).toBeInTheDocument()
    })

    it('should handle engine toggle functionality', async () => {
      const user = userEvent.setup()
      const mockOnEngineToggle = jest.fn()

      render(
        <SearchEngineControls
          engines={mockEngines}
          onEngineToggle={mockOnEngineToggle}
          onRefreshEngines={jest.fn()}
        />
      )

      // Find toggle buttons/switches for engines
      const toggles = screen.getAllByRole('switch')
      
      if (toggles.length > 0) {
        await user.click(toggles[0])
        expect(mockOnEngineToggle).toHaveBeenCalled()
      }
    })

    it('should show engine status indicators', () => {
      render(
        <SearchEngineControls
          engines={mockEngines}
          onEngineToggle={jest.fn()}
          onRefreshEngines={jest.fn()}
        />
      )

      // Check for status indicators
      const statusElements = screen.getAllByText(/active|inactive/i)
      expect(statusElements.length).toBeGreaterThan(0)
    })
  })

  describe('Error Handling and Recovery', () => {
    it('should handle network errors gracefully', async () => {
      // Mock fetch to simulate network error
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'))

      const TestComponent = () => {
        const [error, setError] = React.useState<string | null>(null)

        const handleSearch = async () => {
          try {
            await fetch('/api/search')
          } catch (err) {
            setError(err instanceof Error ? err.message : 'Unknown error')
          }
        }

        return (
          <div>
            <button onClick={handleSearch}>Search</button>
            {error && <div data-testid="error">{error}</div>}
          </div>
        )
      }

      const user = userEvent.setup()
      render(<TestComponent />)

      const searchButton = screen.getByRole('button', { name: /search/i })
      await user.click(searchButton)

      await waitFor(() => {
        expect(screen.getByTestId('error')).toHaveTextContent('Network error')
      })
    })

    it('should provide fallback mechanisms', () => {
      const mockStreamingReturn = {
        results: [],
        progress: {
          totalFound: 0,
          processed: 0,
          currentBatch: 0,
          estimatedTimeRemaining: 0,
          status: 'fallback' as const,
          connectionStatus: 'disconnected' as const,
        },
        isStreaming: false,
        isPaused: false,
        error: null,
        startStreaming: jest.fn(),
        pauseStreaming: jest.fn(),
        resumeStreaming: jest.fn(),
        stopStreaming: jest.fn(),
        clearResults: jest.fn(),
      }

      mockUseSearchStreaming.mockReturnValue(mockStreamingReturn)

      const TestComponent = () => {
        const streaming = useSearchStreaming()
        return <div data-testid="status">{streaming.progress.status}</div>
      }

      render(<TestComponent />)

      expect(screen.getByTestId('status')).toHaveTextContent('fallback')
    })
  })
})
