/**
 * Comprehensive Business Rule Tests for Scraper Controller
 * Tests complete business workflows, state management, and process orchestration
 */

import { renderHook, act } from '@testing-library/react'
import { useScraperController, ScrapingState, ScrapingStats } from '@/controller/useScraperController'
import { useConfig } from '@/controller/useConfig'
import { scraperService } from '@/model/scraperService'
import { searchEngineManager } from '@/model/searchEngineManager'
import { storage } from '@/model/storage'
import { BusinessRecord } from '@/types/business'
import { ProcessingStep } from '@/view/components/ProcessingWindow'

// Mock dependencies
jest.mock('@/controller/useConfig')
jest.mock('@/model/scraperService')
jest.mock('@/model/searchEngineManager')
jest.mock('@/model/storage')
jest.mock('@/utils/logger')
jest.mock('react-hot-toast')

// Mock WebSocket
global.WebSocket = jest.fn().mockImplementation(() => ({
  close: jest.fn(),
  send: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  readyState: 1,
}))

// Mock fetch for WebSocket API
global.fetch = jest.fn()

describe('Scraper Controller - Business Process Workflows', () => {
  let mockUseConfig: jest.MockedFunction<typeof useConfig>
  let mockScraperService: jest.Mocked<typeof scraperService>
  let mockSearchEngineManager: jest.Mocked<typeof searchEngineManager>
  let mockStorage: jest.Mocked<typeof storage>

  const mockConfigState = {
    searchQuery: 'restaurants',
    zipCode: '12345',
    selectedIndustries: ['restaurants', 'retail'],
    searchDepth: 2,
    pagesPerSite: 3,
    maxResults: 50,
    isStreamingEnabled: true,
  }

  const mockBusinessRecords: BusinessRecord[] = [
    {
      id: 'business-1',
      name: 'Test Restaurant',
      address: '123 Main St',
      phone: '555-0123',
      email: 'test@restaurant.com',
      website: 'https://testrestaurant.com',
      industry: 'restaurants',
      description: 'A test restaurant',
      coordinates: { lat: 40.7128, lng: -74.0060 },
      socialMedia: {},
      businessHours: {},
      services: [],
      reviews: [],
      images: [],
      lastUpdated: new Date(),
      dataSource: 'scraped',
      confidence: 0.95,
    },
  ]

  beforeEach(() => {
    // Mock useConfig
    mockUseConfig = useConfig as jest.MockedFunction<typeof useConfig>
    mockUseConfig.mockReturnValue({
      state: mockConfigState,
      getSelectedIndustryNames: jest.fn().mockReturnValue(['restaurants', 'retail']),
      isConfigValid: jest.fn().mockReturnValue(true),
      updateConfig: jest.fn(),
      resetConfig: jest.fn(),
    })

    // Mock scraperService
    mockScraperService = scraperService as jest.Mocked<typeof scraperService>
    mockScraperService.searchForWebsites.mockResolvedValue([
      'https://restaurant1.com',
      'https://restaurant2.com',
    ])
    mockScraperService.scrapeWebsite.mockResolvedValue(mockBusinessRecords)
    mockScraperService.cleanup.mockResolvedValue()

    // Mock searchEngineManager
    mockSearchEngineManager = searchEngineManager as jest.Mocked<typeof searchEngineManager>
    mockSearchEngineManager.hasAvailableEngines.mockReturnValue(true)
    mockSearchEngineManager.startSession.mockResolvedValue()
    mockSearchEngineManager.endSession.mockResolvedValue()

    // Mock storage
    mockStorage = storage as jest.Mocked<typeof storage>
    mockStorage.saveBusinesses.mockResolvedValue()
    mockStorage.loadBusinesses.mockResolvedValue(mockBusinessRecords)

    // Mock fetch for WebSocket
    ;(global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue({ success: true }),
    })

    jest.clearAllMocks()
  })

  describe('Workflow State Management', () => {
    test('should initialize with correct default state', () => {
      const { result } = renderHook(() => useScraperController())

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(result.current.scrapingState.results).toEqual([])
      expect(result.current.scrapingState.errors).toEqual([])
      expect(result.current.scrapingState.processingSteps).toEqual([])
      expect(result.current.scrapingState.progress.current).toBe(0)
      expect(result.current.scrapingState.progress.total).toBe(0)
      expect(result.current.scrapingState.progress.percentage).toBe(0)
      expect(result.current.scrapingState.hasCompletedScraping).toBe(false)
      expect(result.current.canStartScraping).toBe(true)
      expect(result.current.hasResults).toBe(false)
      expect(result.current.hasErrors).toBe(false)
    })

    test('should transition to active state when scraping starts', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(true)
      expect(result.current.scrapingState.sessionId).toBeDefined()
      expect(result.current.scrapingState.sessionId).toMatch(/^session_\d+_[a-z0-9]+$/)
      expect(result.current.canStartScraping).toBe(false)
    })

    test('should handle state transitions during scraping workflow', async () => {
      const { result } = renderHook(() => useScraperController())

      // Initial state
      expect(result.current.scrapingState.isScrapingActive).toBe(false)

      // Start scraping
      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(true)
      expect(result.current.scrapingState.results.length).toBeGreaterThan(0)

      // Stop scraping
      act(() => {
        result.current.stopScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(result.current.scrapingState.hasCompletedScraping).toBe(true)
    })

    test('should manage processing steps throughout workflow', async () => {
      const { result } = renderHook(() => useScraperController())

      // Add processing step
      act(() => {
        result.current.addProcessingStep({
          name: 'Test Step',
          status: 'running',
          url: 'https://test.com',
          details: 'Testing step management',
        })
      })

      expect(result.current.scrapingState.processingSteps).toHaveLength(1)
      expect(result.current.scrapingState.processingSteps[0].name).toBe('Test Step')
      expect(result.current.scrapingState.processingSteps[0].status).toBe('running')

      // Update processing step
      const stepId = result.current.scrapingState.processingSteps[0].id
      act(() => {
        result.current.updateProcessingStep(stepId, {
          status: 'completed',
          details: 'Step completed successfully',
          businessesFound: 5,
        })
      })

      expect(result.current.scrapingState.processingSteps[0].status).toBe('completed')
      expect(result.current.scrapingState.processingSteps[0].businessesFound).toBe(5)

      // Clear processing steps
      act(() => {
        result.current.clearProcessingSteps()
      })

      expect(result.current.scrapingState.processingSteps).toHaveLength(0)
    })
  })

  describe('Complete Scraping Workflow', () => {
    test('should execute complete scraping workflow successfully', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Verify workflow execution
      expect(mockSearchEngineManager.hasAvailableEngines).toHaveBeenCalled()
      expect(mockSearchEngineManager.startSession).toHaveBeenCalled()
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledWith(
        'restaurants',
        '12345',
        expect.any(Number)
      )
      expect(mockScraperService.scrapeWebsite).toHaveBeenCalled()
      expect(mockStorage.saveBusinesses).toHaveBeenCalled()
      expect(mockSearchEngineManager.endSession).toHaveBeenCalled()
      expect(mockScraperService.cleanup).toHaveBeenCalled()

      // Verify final state
      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(result.current.scrapingState.hasCompletedScraping).toBe(true)
      expect(result.current.hasResults).toBe(true)
      expect(result.current.shouldShowResults).toBe(true)
    })

    test('should handle multiple industry workflow', async () => {
      mockUseConfig.mockReturnValue({
        state: { ...mockConfigState, selectedIndustries: ['restaurants', 'retail', 'healthcare'] },
        getSelectedIndustryNames: jest.fn().mockReturnValue(['restaurants', 'retail', 'healthcare']),
        isConfigValid: jest.fn().mockReturnValue(true),
        updateConfig: jest.fn(),
        resetConfig: jest.fn(),
      })

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Should call search for each industry
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledTimes(3)
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledWith('restaurants', '12345', expect.any(Number))
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledWith('retail', '12345', expect.any(Number))
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledWith('healthcare', '12345', expect.any(Number))
    })

    test('should handle workflow with streaming enabled', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Should attempt to start WebSocket server
      expect(global.fetch).toHaveBeenCalledWith('/api/websocket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start' }),
      })

      expect(result.current.scrapingState.isStreamingEnabled).toBe(true)
    })

    test('should handle early stopping workflow', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Enable early stopping
      expect(result.current.scrapingState.canStopEarly).toBe(false)

      // Simulate early stop
      act(() => {
        result.current.stopEarly()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
    })
  })

  describe('Business Data Management', () => {
    test('should manage business records throughout workflow', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.results).toHaveLength(mockBusinessRecords.length)
      expect(result.current.hasResults).toBe(true)

      // Remove business
      act(() => {
        result.current.removeBusiness('business-1')
      })

      expect(result.current.scrapingState.results).toHaveLength(0)

      // Add business back for update test
      act(() => {
        result.current.scrapingState.results.push(mockBusinessRecords[0])
      })

      // Update business
      act(() => {
        result.current.updateBusiness('business-1', { name: 'Updated Restaurant' })
      })

      const updatedBusiness = result.current.scrapingState.results.find(b => b.id === 'business-1')
      expect(updatedBusiness?.name).toBe('Updated Restaurant')

      // Clear results
      act(() => {
        result.current.clearResults()
      })

      expect(result.current.scrapingState.results).toHaveLength(0)
      expect(result.current.hasResults).toBe(false)
    })

    test('should load previous results', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.loadPreviousResults()
      })

      expect(mockStorage.loadBusinesses).toHaveBeenCalled()
      expect(result.current.scrapingState.results).toEqual(mockBusinessRecords)
      expect(result.current.hasResults).toBe(true)
    })
  })

  describe('Error Handling and Recovery', () => {
    test('should handle configuration validation errors', async () => {
      mockUseConfig.mockReturnValue({
        state: mockConfigState,
        getSelectedIndustryNames: jest.fn().mockReturnValue([]),
        isConfigValid: jest.fn().mockReturnValue(false),
        updateConfig: jest.fn(),
        resetConfig: jest.fn(),
      })

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(mockScraperService.searchForWebsites).not.toHaveBeenCalled()
    })

    test('should handle search engine unavailability', async () => {
      mockSearchEngineManager.hasAvailableEngines.mockReturnValue(false)

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(mockScraperService.searchForWebsites).not.toHaveBeenCalled()
    })

    test('should handle scraping service failures', async () => {
      mockScraperService.searchForWebsites.mockRejectedValue(new Error('Search service failed'))

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(result.current.scrapingState.errors.length).toBeGreaterThan(0)
      expect(result.current.hasErrors).toBe(true)
    })

    test('should handle WebSocket connection failures gracefully', async () => {
      ;(global.fetch as jest.Mock).mockRejectedValue(new Error('WebSocket server failed'))

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Should continue scraping even if WebSocket fails
      expect(result.current.scrapingState.isScrapingActive).toBe(false) // Completed
      expect(result.current.hasResults).toBe(true)
    })

    test('should handle storage failures', async () => {
      mockStorage.saveBusinesses.mockRejectedValue(new Error('Storage failed'))

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      // Should complete scraping even if storage fails
      expect(result.current.scrapingState.isScrapingActive).toBe(false)
      expect(result.current.hasResults).toBe(true)
    })
  })

  describe('Progress Tracking and Statistics', () => {
    test('should track progress throughout workflow', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.progress.total).toBeGreaterThan(0)
      expect(result.current.scrapingState.progress.percentage).toBeGreaterThanOrEqual(0)
      expect(result.current.scrapingState.progress.percentage).toBeLessThanOrEqual(100)
    })

    test('should generate scraping statistics', async () => {
      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      const stats = result.current.scrapingState.stats
      expect(stats).toBeDefined()
      expect(stats?.totalSites).toBeGreaterThan(0)
      expect(stats?.totalBusinesses).toBeGreaterThan(0)
      expect(stats?.startTime).toBeInstanceOf(Date)
      expect(stats?.endTime).toBeInstanceOf(Date)
      expect(stats?.duration).toBeGreaterThan(0)
    })
  })

  describe('Concurrent Operations and Race Conditions', () => {
    test('should prevent concurrent scraping operations', async () => {
      const { result } = renderHook(() => useScraperController())

      // Start first scraping operation
      const firstScraping = act(async () => {
        await result.current.startScraping()
      })

      // Try to start second operation while first is running
      await act(async () => {
        await result.current.startScraping()
      })

      await firstScraping

      // Should only call search once (second call should be rejected)
      expect(mockScraperService.searchForWebsites).toHaveBeenCalledTimes(2) // Once per industry
    })

    test('should handle rapid state changes', async () => {
      const { result } = renderHook(() => useScraperController())

      // Rapid operations
      await act(async () => {
        result.current.addProcessingStep({ name: 'Step 1', status: 'running' })
        result.current.addProcessingStep({ name: 'Step 2', status: 'pending' })
        result.current.addProcessingStep({ name: 'Step 3', status: 'running' })
      })

      expect(result.current.scrapingState.processingSteps).toHaveLength(3)

      // Rapid updates
      const stepIds = result.current.scrapingState.processingSteps.map(s => s.id)
      act(() => {
        stepIds.forEach(id => {
          result.current.updateProcessingStep(id, { status: 'completed' })
        })
      })

      result.current.scrapingState.processingSteps.forEach(step => {
        expect(step.status).toBe('completed')
      })
    })
  })

  describe('Performance and Efficiency', () => {
    test('should complete workflow within reasonable time', async () => {
      const { result } = renderHook(() => useScraperController())

      const startTime = Date.now()
      await act(async () => {
        await result.current.startScraping()
      })
      const endTime = Date.now()

      const processingTime = endTime - startTime
      expect(processingTime).toBeLessThan(5000) // Should complete within 5 seconds for mocked operations
    })

    test('should handle large datasets efficiently', async () => {
      const largeDataset = Array(100).fill(0).map((_, i) => ({
        ...mockBusinessRecords[0],
        id: `business-${i}`,
        name: `Business ${i}`,
      }))

      mockScraperService.scrapeWebsite.mockResolvedValue(largeDataset)

      const { result } = renderHook(() => useScraperController())

      await act(async () => {
        await result.current.startScraping()
      })

      expect(result.current.scrapingState.results).toHaveLength(largeDataset.length * 2) // 2 industries
      expect(result.current.hasResults).toBe(true)
    })
  })
})
