/**
 * Test suite for App component scraping lock functionality
 */

import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '@/view/components/App'
import { ConfigProvider } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'

// Mock the scraper controller
jest.mock('@/controller/useScraperController')
const mockUseScraperController = useScraperController as jest.MockedFunction<typeof useScraperController>

// Mock other dependencies
jest.mock('@/model/storage', () => ({
  storage: {
    getConfig: jest.fn().mockResolvedValue({
      id: 'default',
      industries: [],
      zipCode: '90210',
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
        isCustom: false
      }
    ]),
    saveIndustries: jest.fn().mockResolvedValue(undefined),
  }
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  }
}))

jest.mock('@/model/clientScraperService', () => ({
  clientScraperService: {
    refreshCredentials: jest.fn().mockResolvedValue(undefined),
  }
}))

jest.mock('@/utils/exportService', () => ({
  ExportService: jest.fn().mockImplementation(() => ({
    exportBusinesses: jest.fn().mockResolvedValue({ blob: new Blob(), filename: 'test.csv' }),
  })),
  ExportFormat: {},
  ExportTemplate: {},
}))

// Mock toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
    loading: jest.fn(),
  }
}))

// Mock error handling hook
jest.mock('@/hooks/useErrorHandling', () => ({
  useErrorHandling: jest.fn().mockReturnValue({
    handleError: jest.fn(),
    clearError: jest.fn(),
    error: null,
  })
}))

const renderWithProvider = (component: React.ReactElement) => {
  return render(
    <ConfigProvider>
      {component}
    </ConfigProvider>
  )
}

describe('App Component - Scraping Lock Functionality', () => {
  const mockScrapingState = {
    isScrapingActive: false,
    results: [],
    errors: [],
    progress: { current: 0, total: 0, percentage: 0 },
    currentUrl: '',
    processingSteps: []
  }

  const mockScraperController = {
    scrapingState: mockScrapingState,
    startScraping: jest.fn(),
    stopScraping: jest.fn(),
    clearResults: jest.fn(),
    removeBusiness: jest.fn(),
    updateBusiness: jest.fn(),
    loadPreviousResults: jest.fn(),
    addProcessingStep: jest.fn(),
    updateProcessingStep: jest.fn(),
    clearProcessingSteps: jest.fn(),
    canStartScraping: true,
    hasResults: false,
    hasErrors: false,
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockUseScraperController.mockReturnValue(mockScraperController)
  })

  describe('when scraping is not active', () => {
    it('should allow navigation to configuration tab', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Configuration')).toBeInTheDocument()
      })

      const configButton = screen.getByRole('button', { name: /configuration/i })
      expect(configButton).not.toBeDisabled()
      expect(configButton).not.toHaveClass('opacity-50')
    })

    it('should allow editing configuration fields', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByLabelText(/zip code/i)).toBeInTheDocument()
      })

      const zipInput = screen.getByLabelText(/zip code/i)
      expect(zipInput).not.toBeDisabled()
    })

    it('should not show scraping lock banner', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Configuration')).toBeInTheDocument()
      })

      expect(screen.queryByText(/Configuration Locked - Scraping in Progress/)).not.toBeInTheDocument()
    })
  })

  describe('when scraping is active', () => {
    beforeEach(() => {
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true
        }
      })
    })

    it('should disable navigation to configuration tab', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Configuration')).toBeInTheDocument()
      })

      const configButton = screen.getByRole('button', { name: /configuration/i })
      expect(configButton).toBeDisabled()
      expect(configButton).toHaveClass('opacity-50')
    })

    it('should show lock icon on configuration tab', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('🔒')).toBeInTheDocument()
      })
    })

    it('should show tooltip explaining why configuration is locked', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Configuration')).toBeInTheDocument()
      })

      const configButton = screen.getByRole('button', { name: /configuration/i })
      expect(configButton).toHaveAttribute('title', 'Configuration cannot be changed while scraping is active. Please stop scraping first.')
    })

    it('should show scraping lock banner when on configuration tab', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText(/Configuration Locked - Scraping in Progress/)).toBeInTheDocument()
      })

      expect(screen.getByText(/Configuration settings are locked while scraping is active/)).toBeInTheDocument()
    })

    it('should disable configuration input fields', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByLabelText(/zip code/i)).toBeInTheDocument()
      })

      const zipInput = screen.getByLabelText(/zip code/i)
      const radiusInput = screen.getByLabelText(/search radius/i)
      const depthInput = screen.getByLabelText(/search depth/i)
      const pagesInput = screen.getByLabelText(/pages per site/i)

      expect(zipInput).toBeDisabled()
      expect(radiusInput).toBeDisabled()
      expect(depthInput).toBeDisabled()
      expect(pagesInput).toBeDisabled()
    })

    it('should show lock messages on configuration sections', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText(/Configuration is locked while scraping is active/)).toBeInTheDocument()
      })

      expect(screen.getByText(/Settings cannot be changed during active scraping/)).toBeInTheDocument()
      expect(screen.getByText(/Industry selection is locked during scraping/)).toBeInTheDocument()
    })

    it('should disable industry selection buttons', async () => {
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Select All')).toBeInTheDocument()
      })

      const selectAllButton = screen.getByRole('button', { name: /select all/i })
      const addCustomButton = screen.getByRole('button', { name: /add custom/i })

      expect(selectAllButton).toBeDisabled()
      expect(addCustomButton).toBeDisabled()
    })

    it('should prevent clicking on industry items', async () => {
      const user = userEvent.setup()
      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Industry Categories')).toBeInTheDocument()
      })

      // Industry items should have cursor-not-allowed class and be non-interactive
      const industryItems = screen.getAllByText(/law firm|restaurant|medical/i)
      if (industryItems.length > 0) {
        const firstIndustry = industryItems[0].closest('div')
        expect(firstIndustry).toHaveClass('cursor-not-allowed')
      }
    })
  })

  describe('navigation behavior during scraping', () => {
    it('should allow navigation to scraping tab when scraping is active', async () => {
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true
        }
      })

      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Scraping')).toBeInTheDocument()
      })

      const scrapingButton = screen.getByRole('button', { name: /scraping/i })
      expect(scrapingButton).not.toBeDisabled()
    })

    it('should prevent navigation back to configuration during scraping', async () => {
      const user = userEvent.setup()
      
      // Start with scraping active
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true
        }
      })

      renderWithProvider(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Configuration')).toBeInTheDocument()
      })

      // Try to click configuration tab - should be disabled
      const configButton = screen.getByRole('button', { name: /configuration/i })
      expect(configButton).toBeDisabled()
      
      // Click should not work
      await user.click(configButton)
      
      // Should still show the scraping lock banner (indicating we're on config tab but locked)
      expect(screen.getByText(/Configuration Locked - Scraping in Progress/)).toBeInTheDocument()
    })
  })
})
