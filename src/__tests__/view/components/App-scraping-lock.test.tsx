/**
 * Test suite for App component scraping lock functionality
 */

import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '@/view/components/App'
import { useScraperController } from '@/controller/useScraperController'
import { useConfig } from '@/controller/ConfigContext'
import {
  mockConfigContext,
  setupBrowserMocks
} from '@/test/testUtils'

// Mock the scraper controller
jest.mock('@/controller/useScraperController')
const mockUseScraperController = useScraperController as jest.MockedFunction<
  typeof useScraperController
>

// Mock the config hook
jest.mock('@/controller/ConfigContext', () => ({
  ...jest.requireActual('@/controller/ConfigContext'),
  useConfig: jest.fn(),
}))
const mockUseConfig = useConfig as jest.MockedFunction<typeof useConfig>

// Mock storage
jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn().mockResolvedValue(undefined),
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
        isCustom: false,
      },
    ]),
    saveIndustries: jest.fn().mockResolvedValue(undefined),
    getAllSubCategories: jest.fn().mockResolvedValue([]),
    saveSubCategory: jest.fn().mockResolvedValue(undefined),
    getAllBusinesses: jest.fn().mockResolvedValue([]),
    saveBusiness: jest.fn().mockResolvedValue(undefined),
    deleteBusiness: jest.fn().mockResolvedValue(undefined),
    clearAllBusinesses: jest.fn().mockResolvedValue(undefined),
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/model/clientScraperService', () => ({
  clientScraperService: {
    refreshCredentials: jest.fn().mockResolvedValue(undefined),
  },
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
  },
}))

// Mock error handling hook
jest.mock('@/hooks/useErrorHandling', () => ({
  useErrorHandling: jest.fn().mockReturnValue({
    handleError: jest.fn(),
    clearError: jest.fn(),
    error: null,
  }),
}))

// Browser mocks are handled by test utilities

describe('App Component - Scraping Lock Functionality', () => {
  const mockScrapingState = {
    isScrapingActive: false,
    results: [],
    errors: [],
    progress: { current: 0, total: 0, percentage: 0 },
    currentUrl: '',
    processingSteps: [],
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
    setupBrowserMocks()
    mockUseScraperController.mockReturnValue(mockScraperController)
    mockUseConfig.mockReturnValue(mockConfigContext)
  })

  describe('when scraping is not active', () => {
    it('should allow navigation to configuration tab', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getAllByText('Configuration')).toHaveLength(4) // Header button, breadcrumb, title, etc.
      })

      // Get the specific navigation button in the header
      const configButtons = screen.getAllByRole('button', { name: /configuration/i })
      const headerConfigButton = configButtons.find(button =>
        button.closest('header') !== null
      )

      expect(headerConfigButton).not.toBeDisabled()
      expect(headerConfigButton).not.toHaveClass('opacity-50')
    })

    it('should allow editing configuration fields', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getByLabelText(/zip code/i)).toBeInTheDocument()
      })

      const zipInput = screen.getByLabelText(/zip code/i)
      expect(zipInput).not.toBeDisabled()
    })

    it('should not show scraping lock banner', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getAllByText('Configuration')).toHaveLength(4)
      })

      expect(
        screen.queryByText(/Configuration Locked - Scraping in Progress/)
      ).not.toBeInTheDocument()
    })
  })

  describe('when scraping is active', () => {
    beforeEach(() => {
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true,
        },
      })
    })

    it('should disable navigation to configuration tab', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getAllByText('Configuration')).toHaveLength(4)
      })

      // Get the specific navigation button in the header that should be disabled
      const configButtons = screen.getAllByRole('button', { name: /configuration/i })
      const headerConfigButton = configButtons.find(button =>
        button.closest('header') !== null && button.hasAttribute('disabled')
      )

      expect(headerConfigButton).toBeDisabled()
      expect(headerConfigButton).toHaveClass('opacity-50')
    })

    it('should show lock icon on configuration tab', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getByText('🔒')).toBeInTheDocument()
      })
    })

    it('should show tooltip explaining why configuration is locked', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getAllByText('Configuration')).toHaveLength(4)
      })

      // Get the specific disabled navigation button in the header
      const configButtons = screen.getAllByRole('button', { name: /configuration/i })
      const disabledHeaderButton = configButtons.find(button =>
        button.closest('header') !== null && button.hasAttribute('disabled')
      )

      expect(disabledHeaderButton).toHaveAttribute(
        'title',
        'Configuration cannot be changed while scraping is active. Please stop scraping first.'
      )
    })

    it('should show scraping lock banner when on configuration tab', async () => {
      render(<App />)

      await waitFor(() => {
        expect(screen.getByText(/Configuration Locked - Scraping in Progress/)).toBeInTheDocument()
      })

      expect(
        screen.getByText(/Configuration settings are locked while scraping is active/)
      ).toBeInTheDocument()
    })

    it('should disable configuration input fields', async () => {
      render(<App />)

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
      render(<App />)

      await waitFor(() => {
        expect(
          screen.getByText(/Configuration Locked - Scraping in Progress/)
        ).toBeInTheDocument()
      })

      // Check for multiple instances of the lock message
      const lockMessages = screen.getAllByText(/Settings cannot be changed during active scraping/)
      expect(lockMessages).toHaveLength(2) // Should appear in both sections

      expect(screen.getByText(/Industry selection is locked during scraping/)).toBeInTheDocument()
    })

    it('should disable industry selection buttons', async () => {
      render(<App />)

      await waitFor(() => {
        const selectAllButtons = screen.getAllByText('Select All')
        expect(selectAllButtons).toHaveLength(2) // One in each section
      })

      // Find the disabled Select All button
      const selectAllButtons = screen.getAllByRole('button', { name: /select all/i })
      const disabledSelectAllButton = selectAllButtons.find(button => button.hasAttribute('disabled'))

      const addCustomButton = screen.getByRole('button', { name: /add custom/i })

      expect(disabledSelectAllButton).toBeDisabled()
      expect(addCustomButton).toBeDisabled()
    })

    it('should prevent clicking on industry items', async () => {
      const user = userEvent.setup()
      render(<App />)

      await waitFor(() => {
        expect(screen.getByText(/Industry selection is locked during scraping/)).toBeInTheDocument()
      })

      // Industry items should have cursor-not-allowed class and be non-interactive
      const industryItems = screen.getAllByText(/Law Firms/i)
      if (industryItems.length > 0) {
        const firstIndustryContainer = industryItems[0].closest('[class*="cursor-not-allowed"]')
        expect(firstIndustryContainer).toBeInTheDocument()
      }
    })
  })

  describe('navigation behavior during scraping', () => {
    it('should allow navigation to scraping tab when scraping is active', async () => {
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true,
        },
      })

      render(<App />)

      await waitFor(() => {
        const scrapingButtons = screen.getAllByText('Scraping')
        expect(scrapingButtons).toHaveLength(2) // Header button and breadcrumb
      })

      // Get the specific navigation button in the header
      const scrapingButtons = screen.getAllByRole('button', { name: /scraping/i })
      const headerScrapingButton = scrapingButtons.find(button =>
        button.closest('header') !== null
      )

      expect(headerScrapingButton).not.toBeDisabled()
    })

    it('should prevent navigation back to configuration during scraping', async () => {
      const user = userEvent.setup()

      // Start with scraping active
      mockUseScraperController.mockReturnValue({
        ...mockScraperController,
        scrapingState: {
          ...mockScrapingState,
          isScrapingActive: true,
        },
      })

      render(<App />)

      await waitFor(() => {
        expect(screen.getAllByText('Configuration')).toHaveLength(4)
      })

      // Get the specific disabled navigation button in the header
      const configButtons = screen.getAllByRole('button', { name: /configuration/i })
      const disabledHeaderButton = configButtons.find(button =>
        button.closest('header') !== null && button.hasAttribute('disabled')
      )

      expect(disabledHeaderButton).toBeDisabled()

      // Click should not work (disabled buttons don't trigger click events)
      await user.click(disabledHeaderButton!)

      // Should still show the scraping lock banner (indicating we're on config tab but locked)
      expect(screen.getByText(/Configuration Locked - Scraping in Progress/)).toBeInTheDocument()
    })
  })
})
