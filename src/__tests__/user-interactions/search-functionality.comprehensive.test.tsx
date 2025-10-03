/**
 * Search Functionality - Comprehensive User Interaction Tests
 * 
 * Tests all search-related user interactions including:
 * - Search input and query handling
 * - Real-time search suggestions
 * - Search filters and sorting
 * - Search results display and pagination
 * - Search state management
 */

import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SearchEngineControls } from '@/view/components/SearchEngineControls'
import { CategorySelector } from '@/view/components/CategorySelector'
import { useSearchStreaming } from '@/hooks/useSearchStreaming'
import { useScraperController } from '@/controller/useScraperController'

// Mock dependencies
jest.mock('@/hooks/useSearchStreaming')
jest.mock('@/controller/useScraperController')
jest.mock('@/utils/logger')
jest.mock('@/lib/scraperService')

const mockUseSearchStreaming = useSearchStreaming as jest.MockedFunction<typeof useSearchStreaming>
const mockUseScraperController = useScraperController as jest.MockedFunction<typeof useScraperController>

describe('Search Functionality - Comprehensive User Interaction Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default search streaming hook mock
    mockUseSearchStreaming.mockReturnValue({
      isSearching: false,
      searchResults: [],
      searchError: null,
      searchProgress: 0,
      startSearch: jest.fn(),
      stopSearch: jest.fn(),
      clearResults: jest.fn(),
      retrySearch: jest.fn(),
    })

    // Default scraper controller mock
    mockUseScraperController.mockReturnValue({
      scrapingState: {
        isRunning: false,
        results: [],
        errors: [],
        progress: 0,
        currentStep: '',
        processingSteps: [],
        searchQuery: '',
        zipCode: '',
        selectedCategories: [],
      },
      startScraping: jest.fn(),
      stopScraping: jest.fn(),
      stopEarly: jest.fn(),
      clearResults: jest.fn(),
      loadPreviousResults: jest.fn(),
      removeBusiness: jest.fn(),
      updateBusiness: jest.fn(),
      canStartScraping: true,
      hasResults: false,
      hasErrors: false,
      clearProcessingSteps: jest.fn(),
      shouldShowResults: false,
    })
  })

  describe('Search Input Interactions', () => {
    it('should handle search query input', async () => {
      const mockStartSearch = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: null,
        searchProgress: 0,
        startSearch: mockStartSearch,
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      await user.type(searchInput, 'restaurants')

      expect(searchInput).toHaveValue('restaurants')
    })

    it('should trigger search on Enter key', async () => {
      const mockStartSearch = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: null,
        searchProgress: 0,
        startSearch: mockStartSearch,
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      await user.type(searchInput, 'restaurants{enter}')

      expect(mockStartSearch).toHaveBeenCalledWith(
        expect.objectContaining({
          query: 'restaurants'
        })
      )
    })

    it('should handle search button click', async () => {
      const mockStartSearch = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: null,
        searchProgress: 0,
        startSearch: mockStartSearch,
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      const searchButton = screen.getByRole('button', { name: /search/i })

      await user.type(searchInput, 'restaurants')
      await user.click(searchButton)

      expect(mockStartSearch).toHaveBeenCalled()
    })

    it('should clear search results', async () => {
      const mockClearResults = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [
          { id: '1', name: 'Test Restaurant', address: '123 Main St' }
        ],
        searchError: null,
        searchProgress: 0,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: mockClearResults,
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const clearButton = screen.getByRole('button', { name: /clear/i })
      await user.click(clearButton)

      expect(mockClearResults).toHaveBeenCalled()
    })
  })

  describe('Category Selection', () => {
    it('should render category selector', () => {
      render(<CategorySelector />)
      
      expect(screen.getByText(/select categories/i)).toBeInTheDocument()
    })

    it('should handle category selection', async () => {
      const user = userEvent.setup()

      render(<CategorySelector />)

      // Assuming categories are rendered as checkboxes
      const restaurantCategory = screen.getByLabelText(/restaurants/i)
      await user.click(restaurantCategory)

      expect(restaurantCategory).toBeChecked()
    })

    it('should handle select all categories', async () => {
      const user = userEvent.setup()

      render(<CategorySelector />)

      const selectAllButton = screen.getByRole('button', { name: /select all/i })
      await user.click(selectAllButton)

      // Verify all categories are selected
      const categoryCheckboxes = screen.getAllByRole('checkbox')
      categoryCheckboxes.forEach(checkbox => {
        expect(checkbox).toBeChecked()
      })
    })

    it('should handle deselect all categories', async () => {
      const user = userEvent.setup()

      render(<CategorySelector />)

      const selectAllButton = screen.getByRole('button', { name: /select all/i })
      const deselectAllButton = screen.getByRole('button', { name: /deselect all/i })

      // First select all
      await user.click(selectAllButton)
      
      // Then deselect all
      await user.click(deselectAllButton)

      // Verify all categories are deselected
      const categoryCheckboxes = screen.getAllByRole('checkbox')
      categoryCheckboxes.forEach(checkbox => {
        expect(checkbox).not.toBeChecked()
      })
    })
  })

  describe('Search State Management', () => {
    it('should show loading state during search', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: true,
        searchResults: [],
        searchError: null,
        searchProgress: 50,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      expect(screen.getByText(/searching/i)).toBeInTheDocument()
      expect(screen.getByRole('progressbar')).toBeInTheDocument()
    })

    it('should display search progress', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: true,
        searchResults: [],
        searchError: null,
        searchProgress: 75,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      const progressBar = screen.getByRole('progressbar')
      expect(progressBar).toHaveAttribute('aria-valuenow', '75')
    })

    it('should handle search errors', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: 'Network error occurred',
        searchProgress: 0,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      expect(screen.getByText(/network error occurred/i)).toBeInTheDocument()
    })

    it('should handle search retry', async () => {
      const mockRetrySearch = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: 'Network error occurred',
        searchProgress: 0,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: mockRetrySearch,
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const retryButton = screen.getByRole('button', { name: /retry/i })
      await user.click(retryButton)

      expect(mockRetrySearch).toHaveBeenCalled()
    })
  })

  describe('Search Results Display', () => {
    it('should display search results', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [
          { id: '1', name: 'Test Restaurant', address: '123 Main St', phone: '555-1234' },
          { id: '2', name: 'Another Restaurant', address: '456 Oak Ave', phone: '555-5678' }
        ],
        searchError: null,
        searchProgress: 100,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      expect(screen.getByText('Test Restaurant')).toBeInTheDocument()
      expect(screen.getByText('Another Restaurant')).toBeInTheDocument()
      expect(screen.getByText('123 Main St')).toBeInTheDocument()
      expect(screen.getByText('456 Oak Ave')).toBeInTheDocument()
    })

    it('should handle empty search results', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: null,
        searchProgress: 100,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      expect(screen.getByText(/no results found/i)).toBeInTheDocument()
    })
  })

  describe('Search Filters and Sorting', () => {
    it('should handle location filter', async () => {
      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const locationInput = screen.getByPlaceholderText(/enter zip code/i)
      await user.type(locationInput, '90210')

      expect(locationInput).toHaveValue('90210')
    })

    it('should validate ZIP code format', async () => {
      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const locationInput = screen.getByPlaceholderText(/enter zip code/i)
      await user.type(locationInput, 'invalid')
      await user.tab()

      expect(screen.getByText(/invalid zip code format/i)).toBeInTheDocument()
    })

    it('should handle search radius selection', async () => {
      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const radiusSelect = screen.getByLabelText(/search radius/i)
      await user.selectOptions(radiusSelect, '25')

      expect(radiusSelect).toHaveValue('25')
    })
  })

  describe('Search Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      expect(searchInput).toHaveAttribute('aria-label')
    })

    it('should announce search status to screen readers', () => {
      mockUseSearchStreaming.mockReturnValue({
        isSearching: true,
        searchResults: [],
        searchError: null,
        searchProgress: 50,
        startSearch: jest.fn(),
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      render(<SearchEngineControls />)

      const statusRegion = screen.getByRole('status')
      expect(statusRegion).toHaveTextContent(/searching/i)
    })

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      const searchButton = screen.getByRole('button', { name: /search/i })

      await user.click(searchInput)
      expect(searchInput).toHaveFocus()

      await user.tab()
      expect(searchButton).toHaveFocus()
    })
  })

  describe('Search Performance', () => {
    it('should debounce search input', async () => {
      const mockStartSearch = jest.fn()
      mockUseSearchStreaming.mockReturnValue({
        isSearching: false,
        searchResults: [],
        searchError: null,
        searchProgress: 0,
        startSearch: mockStartSearch,
        stopSearch: jest.fn(),
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      
      // Type rapidly
      await user.type(searchInput, 'rest')
      await user.type(searchInput, 'aurant')

      // Should not trigger search immediately
      expect(mockStartSearch).not.toHaveBeenCalled()

      // Wait for debounce
      await waitFor(() => {
        expect(mockStartSearch).toHaveBeenCalledTimes(1)
      }, { timeout: 1000 })
    })

    it('should cancel previous search when starting new one', async () => {
      const mockStopSearch = jest.fn()
      const mockStartSearch = jest.fn()
      
      mockUseSearchStreaming.mockReturnValue({
        isSearching: true,
        searchResults: [],
        searchError: null,
        searchProgress: 50,
        startSearch: mockStartSearch,
        stopSearch: mockStopSearch,
        clearResults: jest.fn(),
        retrySearch: jest.fn(),
      })

      const user = userEvent.setup()

      render(<SearchEngineControls />)

      const searchInput = screen.getByPlaceholderText(/search for businesses/i)
      await user.type(searchInput, 'new search{enter}')

      expect(mockStopSearch).toHaveBeenCalled()
      expect(mockStartSearch).toHaveBeenCalled()
    })
  })
})
