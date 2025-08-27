'use client'

import { useState, useCallback, useRef, useEffect } from 'react'
import { BusinessRecord } from '@/types/business'
import { clientScraperService } from '@/model/clientScraperService'

// Create a local alias for compatibility - some code expects 'scraperService' to be available
const scraperService = clientScraperService
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { useConfig } from './ConfigContext'
import toast from 'react-hot-toast'
import type { ProcessingStep } from '@/view/components/ProcessingWindow'
import { searchEngineManager } from '@/lib/searchEngineManager'

/**
 * Scraping statistics interface
 */
export interface ScrapingStats {
  totalSites: number
  successfulScrapes: number
  failedScrapes: number
  totalBusinesses: number
  startTime: Date
  endTime?: Date
  duration?: number
}

/**
 * Scraping state interface
 */
export interface ScrapingState {
  isScrapingActive: boolean
  currentUrl: string
  progress: {
    current: number
    total: number
    percentage: number
  }
  results: BusinessRecord[]
  stats: ScrapingStats | null
  errors: string[]
  processingSteps: ProcessingStep[]
  sessionId: string
  isStreamingEnabled: boolean
  canStopEarly: boolean
  hasCompletedScraping: boolean
}

/**
 * Scraper controller hook
 * Manages scraping operations and state
 */
export function useScraperController(): {
  scrapingState: ScrapingState
  startScraping: () => Promise<void>
  stopScraping: () => void
  stopEarly: () => void
  clearResults: () => void
  removeBusiness: (id: string) => void
  updateBusiness: (id: string, updates: Partial<BusinessRecord>) => void
  loadPreviousResults: () => Promise<void>
  addProcessingStep: (step: Omit<ProcessingStep, 'id' | 'startTime'>) => void
  updateProcessingStep: (id: string, updates: Partial<ProcessingStep>) => void
  clearProcessingSteps: () => void
  canStartScraping: boolean
  hasResults: boolean
  hasErrors: boolean
  shouldShowResults: boolean
} {
  const { state: configState, getSelectedIndustryNames, isConfigValid } = useConfig()

  // Scraping state
  const [scrapingState, setScrapingState] = useState<ScrapingState>({
    isScrapingActive: false,
    currentUrl: '',
    progress: { current: 0, total: 0, percentage: 0 },
    results: [],
    stats: null,
    errors: [],
    processingSteps: [],
    sessionId: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    isStreamingEnabled: true,
    canStopEarly: false,
    hasCompletedScraping: false,
  })

  // Refs for managing scraping process
  const abortControllerRef = useRef<AbortController | null>(null)
  const sessionIdRef = useRef<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const isStoppedEarlyRef = useRef<boolean>(false)

  /**
   * Initialize scraper service when component mounts
   */
  useEffect(() => {
    // Scraper service is always in real mode now
    logger.info('ScraperController', 'Scraper service initialized in real mode')
  }, [])

  /**
   * Update scraping progress
   */
  const updateProgress = useCallback((current: number, total: number, currentUrl: string = '') => {
    const percentage = total > 0 ? Math.round((current / total) * 100) : 0
    setScrapingState(prev => ({
      ...prev,
      currentUrl,
      progress: { current, total, percentage },
    }))
  }, [])

  /**
   * Add error to error list
   */
  const addError = useCallback((error: string) => {
    setScrapingState(prev => ({
      ...prev,
      errors: [...prev.errors, error],
    }))
    logger.error('ScraperController', error)
  }, [])

  /**
   * Add a new processing step
   */
  const addProcessingStep = useCallback((step: Omit<ProcessingStep, 'id' | 'startTime'>) => {
    const newStep: ProcessingStep = {
      ...step,
      id: `step-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      startTime: new Date(),
      dataSource: step.dataSource || 'real',
    }

    setScrapingState(prev => ({
      ...prev,
      processingSteps: [...prev.processingSteps, newStep],
    }))

    logger.info('ScraperController', `Processing step added: ${step.name}`, newStep)
  }, [])

  /**
   * Update an existing processing step
   */
  const updateProcessingStep = useCallback((stepId: string, updates: Partial<ProcessingStep>) => {
    setScrapingState(prev => ({
      ...prev,
      processingSteps: prev.processingSteps.map(step =>
        step.id === stepId
          ? {
              ...step,
              ...updates,
              endTime:
                updates.status === 'completed' || updates.status === 'failed'
                  ? new Date()
                  : step.endTime,
              duration:
                updates.status === 'completed' || updates.status === 'failed'
                  ? new Date().getTime() - (step.startTime?.getTime() || 0)
                  : step.duration,
            }
          : step
      ),
    }))
  }, [])

  /**
   * Clear all processing steps
   */
  const clearProcessingSteps = useCallback(() => {
    setScrapingState(prev => ({
      ...prev,
      processingSteps: [],
    }))
  }, [])

  /**
   * Add business results
   */
  const addResults = useCallback((newResults: BusinessRecord[]) => {
    setScrapingState(prev => ({
      ...prev,
      results: [...prev.results, ...newResults],
    }))
  }, [])

  /**
   * Connect to WebSocket for real-time streaming
   */
  const connectWebSocket = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    try {
      const wsUrl = `ws://localhost:3001/ws/streaming?sessionId=${scrapingState.sessionId}`
      wsRef.current = new WebSocket(wsUrl)

      wsRef.current.onopen = () => {
        logger.info('ScraperController', 'WebSocket connected for real-time streaming')
      }

      wsRef.current.onmessage = event => {
        try {
          const data = JSON.parse(event.data)
          handleRealtimeUpdate(data)
        } catch (error) {
          logger.error('ScraperController', 'Failed to parse WebSocket message', error)
        }
      }

      wsRef.current.onclose = () => {
        logger.info('ScraperController', 'WebSocket disconnected')
      }

      wsRef.current.onerror = error => {
        logger.error('ScraperController', 'WebSocket error', error)
      }
    } catch (error) {
      logger.error('ScraperController', 'Failed to connect WebSocket', error)
    }
  }, [scrapingState.sessionId])

  /**
   * Handle real-time updates from WebSocket
   */
  const handleRealtimeUpdate = useCallback((data: any) => {
    switch (data.type) {
      case 'result':
        if (data.data) {
          // Add single result immediately
          setScrapingState(prev => ({
            ...prev,
            results: [...prev.results, data.data],
            canStopEarly: true, // Enable stop early once we have results
          }))
          logger.info('ScraperController', `Received real-time result: ${data.data.businessName}`)
        }
        break

      case 'progress':
        if (data.progress) {
          setScrapingState(prev => ({
            ...prev,
            progress: {
              current: data.progress.processed || prev.progress.current,
              total: data.progress.totalFound || prev.progress.total,
              percentage: data.progress.percentage || prev.progress.percentage,
            },
            currentUrl: data.progress.currentUrl || prev.currentUrl,
          }))
        }
        break

      case 'error':
        if (data.error) {
          setScrapingState(prev => ({
            ...prev,
            errors: [...prev.errors, data.error],
          }))
        }
        break

      case 'complete':
        setScrapingState(prev => ({
          ...prev,
          isScrapingActive: false,
          canStopEarly: false,
        }))
        toast.success('Scraping completed!')
        break

      case 'stopped':
        setScrapingState(prev => ({
          ...prev,
          isScrapingActive: false,
          canStopEarly: false,
        }))
        toast.info('Scraping stopped by user')
        break
    }
  }, [])

  /**
   * Disconnect WebSocket
   */
  const disconnectWebSocket = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
  }, [])

  /**
   * Start scraping process
   */
  const startScraping = useCallback(async () => {
    if (!isConfigValid()) {
      toast.error('Please configure all required settings before starting')
      return
    }

    if (scrapingState.isScrapingActive) {
      toast.error('Scraping is already in progress')
      return
    }

    try {
      // Check if search engines are available
      if (!searchEngineManager.hasAvailableEngines()) {
        toast.error(
          'No search engines are available. Please enable at least one search engine in the API settings.'
        )
        return
      }

      // Initialize scraping state
      const newSessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      setScrapingState(prev => ({
        ...prev,
        isScrapingActive: true,
        currentUrl: '',
        progress: { current: 0, total: 0, percentage: 0 },
        results: [],
        stats: null,
        errors: [],
        processingSteps: [],
        sessionId: newSessionId,
        canStopEarly: false,
      }))

      // Start search engine session
      searchEngineManager.startSession(newSessionId)

      // Create abort controller
      abortControllerRef.current = new AbortController()

      // Create session
      sessionIdRef.current = newSessionId

      // Add initialization step
      addProcessingStep({
        name: 'Initializing Scraper',
        status: 'running',
        details: 'Connecting to live web services',
      })

      // Start WebSocket server
      try {
        const wsResponse = await fetch('/api/websocket', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'start' }),
        })

        if (!wsResponse.ok) {
          throw new Error('Failed to start WebSocket server')
        }

        // Connect to WebSocket for real-time streaming
        connectWebSocket()

        // Wait a moment for connection to establish
        await new Promise(resolve => setTimeout(resolve, 1000))
      } catch (error) {
        logger.warn(
          'ScraperController',
          'Failed to start WebSocket server, continuing without real-time streaming',
          error
        )
      }

      // Set session ID on scraper service
      scraperService.setSessionId(newSessionId)

      // Initialize scraper service
      await scraperService.initialize()
      scraperService.resetStats()

      // Update initialization step
      const initStepId = scrapingState.processingSteps[scrapingState.processingSteps.length - 1]?.id
      if (initStepId) {
        updateProcessingStep(initStepId, {
          status: 'completed',
          details: 'Connected to live web services',
        })
      }

      const { config, selectedIndustries } = configState
      const industryNames = getSelectedIndustryNames()

      // Get the actual selected industry objects with their keywords
      const selectedIndustryObjects = selectedIndustries
        .map(id => configState.industries.find(industry => industry.id === id))
        .filter(Boolean)

      logger.info('ScraperController', 'Starting scraping process', {
        industries: industryNames,
        zipCode: config.zipCode,
        searchRadius: config.searchRadius,
      })

      toast.success('Scraping started!')

      // Process each industry completely before moving to the next
      for (let industryIndex = 0; industryIndex < selectedIndustryObjects.length; industryIndex++) {
        if (abortControllerRef.current?.signal.aborted) break

        const industryObject = selectedIndustryObjects.at(industryIndex)
        if (!industryObject) {
          logger.error('ScraperController', `Industry object not found at index ${industryIndex}`)
          continue
        }
        const industryName = industryObject.name

        logger.info(
          'ScraperController',
          `Starting complete processing for industry: ${industryName}`
        )

        // Update overall progress
        updateProgress(
          industryIndex,
          selectedIndustryObjects.length,
          `Processing ${industryName} businesses...`
        )

        // Step 1: Search for websites for this industry using individual keywords
        addProcessingStep({
          name: `Searching ${industryName} Businesses`,
          status: 'running',
          details: `Processing ${industryObject.keywords.length} keywords individually in ${config.zipCode}`,
        })

        let industryUrls: string[] = []

        try {
          // Process each keyword individually with ZIP code
          logger.info(
            'ScraperController',
            `Processing ${industryObject.keywords.length} keywords for ${industryName}`
          )

          for (let i = 0; i < industryObject.keywords.length; i++) {
            // Safe array access to prevent object injection
            const keyword = industryObject.keywords[i]
            if (typeof keyword !== 'string') continue

            // Add individual keyword search step
            addProcessingStep({
              name: `Searching "${keyword}"`,
              status: 'running',
              details: `Searching for "${keyword} ${config.zipCode}"`,
            })

            try {
              // Search for this specific keyword with ZIP code
              const keywordUrls = await scraperService.searchForWebsites(
                keyword,
                config.zipCode,
                10 // Get up to 10 results per keyword
              )

              industryUrls.push(...keywordUrls)

              logger.info(
                'ScraperController',
                `Found ${keywordUrls.length} URLs for keyword "${keyword}"`
              )

              // Update keyword search step as completed
              const keywordSearchSteps = scrapingState.processingSteps.filter(s =>
                s.name.includes(`Searching "${keyword}"`)
              )
              const latestKeywordStep = keywordSearchSteps[keywordSearchSteps.length - 1]
              if (latestKeywordStep) {
                updateProcessingStep(latestKeywordStep.id, {
                  status: 'completed',
                  details: `Found ${keywordUrls.length} websites for "${keyword} ${config.zipCode}"`,
                  businessesFound: keywordUrls.length,
                  dataSource: 'real',
                })
              }

              // Add small delay between keyword searches to avoid rate limiting
              if (i < industryObject.keywords.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000))
              }
            } catch (keywordError) {
              logger.error(
                'ScraperController',
                `Failed to search for keyword "${keyword}": ${keywordError}`
              )

              // Update keyword search step as failed
              const keywordSearchSteps = scrapingState.processingSteps.filter(s =>
                s.name.includes(`Searching "${keyword}"`)
              )
              const latestKeywordStep = keywordSearchSteps[keywordSearchSteps.length - 1]
              if (latestKeywordStep) {
                updateProcessingStep(latestKeywordStep.id, {
                  status: 'failed',
                  details: `Failed to search for "${keyword}": ${keywordError}`,
                  businessesFound: 0,
                  dataSource: 'real',
                })
              }
            }
          }

          // Remove duplicates from combined results
          industryUrls = [...new Set(industryUrls)]

          logger.info(
            'ScraperController',
            `Found ${industryUrls.length} unique URLs for ${industryName} after processing all keywords`
          )

          // Update main search step as completed
          const searchSteps = scrapingState.processingSteps.filter(s =>
            s.name.includes(`Searching ${industryName}`)
          )
          const latestSearchStep = searchSteps[searchSteps.length - 1]
          if (latestSearchStep) {
            updateProcessingStep(latestSearchStep.id, {
              status: 'completed',
              details: `Found ${industryUrls.length} unique websites from ${industryObject.keywords.length} keywords`,
              businessesFound: industryUrls.length,
              dataSource: 'real',
            })
          }
        } catch (error) {
          const errorMsg = `Failed to search for ${industryName} businesses: ${error}`
          addError(errorMsg)

          // Update search step as failed
          const searchSteps = scrapingState.processingSteps.filter(s =>
            s.name.includes(`Searching ${industryName}`)
          )
          const latestSearchStep = searchSteps[searchSteps.length - 1]
          if (latestSearchStep) {
            updateProcessingStep(latestSearchStep.id, {
              status: 'failed',
              error: errorMsg,
            })
          }
          continue // Move to next industry
        }

        // Step 2: Scrape all websites for this industry completely
        if (industryUrls.length > 0) {
          // Remove duplicates for this industry
          const uniqueIndustryUrls = Array.from(new Set(industryUrls))

          addProcessingStep({
            name: `Scraping ${industryName} Websites`,
            status: 'running',
            details: `Processing ${uniqueIndustryUrls.length} websites with ${config.pagesPerSite} pages each`,
          })

          const batchSize = 3 // Process in batches to avoid overwhelming
          const totalBatches = Math.ceil(uniqueIndustryUrls.length / batchSize)
          let scrapedCount = 0

          for (let batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
            if (abortControllerRef.current?.signal.aborted) break

            const batchStart = batchIndex * batchSize
            const batchEnd = Math.min(batchStart + batchSize, uniqueIndustryUrls.length)
            const batchUrls = uniqueIndustryUrls.slice(batchStart, batchEnd)

            // Process batch in parallel
            const batchPromises = batchUrls.map(async (url, index) => {
              if (abortControllerRef.current?.signal.aborted) return []

              // Add scraping step for this specific URL
              addProcessingStep({
                name: `Scraping Website`,
                status: 'running',
                url: url,
                details: `Extracting business data from ${url} (${config.pagesPerSite} pages)`,
              })

              try {
                updateProgress(
                  industryIndex + (scrapedCount + index) / uniqueIndustryUrls.length,
                  selectedIndustryObjects.length,
                  `Scraping ${industryName}: ${url} (${config.pagesPerSite} pages)...`
                )

                // Skip scraping directory/search pages
                if (isDirectoryOrSearchPage(url)) {
                  logger.warn('ScraperController', `Skipping directory/search page: ${url}`)
                  return []
                }

                // Scrape this website with the configured number of pages
                const businesses = await scraperService.scrapeWebsite(
                  url,
                  config.searchDepth,
                  config.pagesPerSite
                )

                // Set industry for scraped businesses
                const businessesWithIndustry = businesses.map(business => ({
                  ...business,
                  industry: industryName, // Use the current industry being processed
                }))

                // Update scraping step as completed
                const scrapingSteps = scrapingState.processingSteps.filter(
                  s => s.url === url && s.name === 'Scraping Website'
                )
                const latestScrapingStep = scrapingSteps[scrapingSteps.length - 1]
                if (latestScrapingStep) {
                  updateProcessingStep(latestScrapingStep.id, {
                    status: 'completed',
                    details: `Found ${businessesWithIndustry.length} businesses`,
                    businessesFound: businessesWithIndustry.length,
                    dataSource: 'real',
                  })
                }

                if (businessesWithIndustry.length > 0) {
                  addResults(businessesWithIndustry)

                  // Save to storage
                  await storage.saveBusinesses(businessesWithIndustry)

                  logger.info(
                    'ScraperController',
                    `Scraped ${businessesWithIndustry.length} businesses from ${url} for ${industryName}`
                  )
                }

                return businessesWithIndustry
              } catch (error) {
                const errorMsg = `Failed to scrape ${url}: ${error}`
                addError(errorMsg)

                // Update scraping step as failed
                const scrapingSteps = scrapingState.processingSteps.filter(
                  s => s.url === url && s.name === 'Scraping Website'
                )
                const latestScrapingStep = scrapingSteps[scrapingSteps.length - 1]
                if (latestScrapingStep) {
                  updateProcessingStep(latestScrapingStep.id, {
                    status: 'failed',
                    error: errorMsg,
                  })
                }

                return []
              }
            })

            // Wait for batch to complete
            await Promise.all(batchPromises)
            scrapedCount += batchUrls.length

            // Small delay between batches
            await new Promise(resolve => setTimeout(resolve, 1000))
          }

          // Update scraping step for this industry
          const scrapingSteps = scrapingState.processingSteps.filter(s =>
            s.name.includes(`Scraping ${industryName}`)
          )
          const latestScrapingStep = scrapingSteps[scrapingSteps.length - 1]
          if (latestScrapingStep) {
            updateProcessingStep(latestScrapingStep.id, {
              status: 'completed',
              details: `Completed scraping ${uniqueIndustryUrls.length} websites for ${industryName}`,
            })
          }

          logger.info('ScraperController', `Completed processing industry: ${industryName}`)
        }
      }

      // Final progress update
      updateProgress(industryNames.length, industryNames.length, 'Scraping completed!')

      // Add completion step
      addProcessingStep({
        name: 'Scraping Complete',
        status: 'completed',
        details: `Successfully processed ${industryNames.length} industries and found ${scrapingState.results.length} businesses`,
        businessesFound: scrapingState.results.length,
      })

      // Get final stats
      const finalStats = scraperService.getStats()
      setScrapingState(prev => ({
        ...prev,
        stats: finalStats,
      }))

      // Save session
      if (sessionIdRef.current && scrapingState.results.length > 0) {
        await storage.saveSession({
          id: sessionIdRef.current,
          name: `Scraping Session - ${new Date().toLocaleDateString()}`,
          businesses: scrapingState.results.map(b => b.id),
          createdAt: new Date(),
          updatedAt: new Date(),
        })
      }

      toast.success(`Scraping completed! Found ${scrapingState.results.length} businesses`)
      logger.info('ScraperController', 'Scraping process completed successfully', {
        totalBusinesses: scrapingState.results.length,
        totalErrors: scrapingState.errors.length,
      })
    } catch (error) {
      const errorMsg = `Scraping failed: ${error}`
      addError(errorMsg)
      toast.error(errorMsg)
      logger.error('ScraperController', 'Scraping process failed', error)
    } finally {
      // End search engine session
      searchEngineManager.endSession()

      // Cleanup
      await scraperService.cleanup()
      setScrapingState(prev => ({
        ...prev,
        isScrapingActive: false,
        currentUrl: '',
        hasCompletedScraping: true,
      }))
      abortControllerRef.current = null
    }
  }, [
    configState,
    getSelectedIndustryNames,
    isConfigValid,
    scrapingState.isScrapingActive,
    scrapingState.results.length,
    scrapingState.errors.length,
    updateProgress,
    addError,
    addResults,
    updateProcessingStep,
    addProcessingStep,
  ])

  /**
   * Stop scraping process
   */
  const stopScraping = useCallback(() => {
    if (abortControllerRef.current && scrapingState.isScrapingActive) {
      // Immediately update UI state to show stopping
      setScrapingState(prev => ({
        ...prev,
        isScrapingActive: false,
        currentUrl: 'Stopping scraping...',
      }))

      // Add processing step for stopping
      const stoppingStepId = `stopping-${Date.now()}`
      addProcessingStep({
        name: 'Stopping Scraper',
        status: 'running',
        details: 'Cancelling active operations and cleaning up resources',
      })

      // Abort the scraping process
      abortControllerRef.current.abort()

      // Show immediate feedback
      toast.success('Scraping stopped by user')

      logger.info('ScraperController', 'Scraping stopped by user - immediate UI update applied')

      // Update the stopping step after a brief delay to show completion
      setTimeout(() => {
        setScrapingState(prev => ({
          ...prev,
          currentUrl: '',
          processingSteps: prev.processingSteps.map(step =>
            step.name === 'Stopping Scraper' && step.status === 'running'
              ? {
                  ...step,
                  status: 'completed' as const,
                  details: 'Scraping stopped successfully',
                  endTime: new Date(),
                }
              : step
          ),
        }))
      }, 1500)
    }
  }, [scrapingState.isScrapingActive, addProcessingStep, updateProcessingStep])

  /**
   * Stop scraping early (user satisfaction with current results)
   */
  const stopEarly = useCallback(() => {
    if (scrapingState.isScrapingActive && scrapingState.canStopEarly) {
      isStoppedEarlyRef.current = true

      // Send stop signal via WebSocket
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(
          JSON.stringify({
            type: 'stop_session',
            sessionId: scrapingState.sessionId,
          })
        )
      }

      // Update UI state
      setScrapingState(prev => ({
        ...prev,
        isScrapingActive: false,
        canStopEarly: false,
        currentUrl: 'Stopped early by user',
      }))

      // Abort the scraping process
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }

      // Disconnect WebSocket
      disconnectWebSocket()

      toast.success(`Scraping stopped early. Found ${scrapingState.results.length} results.`)
      logger.info(
        'ScraperController',
        `Scraping stopped early by user with ${scrapingState.results.length} results`
      )
    }
  }, [
    scrapingState.isScrapingActive,
    scrapingState.canStopEarly,
    scrapingState.sessionId,
    scrapingState.results.length,
    disconnectWebSocket,
  ])

  /**
   * Clear results
   */
  const clearResults = useCallback(() => {
    setScrapingState(prev => ({
      ...prev,
      results: [],
      errors: [],
      stats: null,
      progress: { current: 0, total: 0, percentage: 0 },
      processingSteps: [],
      hasCompletedScraping: false,
    }))
    logger.info('ScraperController', 'Results cleared')
  }, [])

  /**
   * Remove specific business from results
   */
  const removeBusiness = useCallback(async (businessId: string) => {
    try {
      setScrapingState(prev => ({
        ...prev,
        results: prev.results.filter(b => b.id !== businessId),
      }))

      await storage.deleteBusiness(businessId)
      toast.success('Business removed')
      logger.info('ScraperController', 'Business removed', { businessId })
    } catch (error) {
      toast.error('Failed to remove business')
      logger.error('ScraperController', 'Failed to remove business', error)
    }
  }, [])

  /**
   * Update business information
   */
  const updateBusiness = useCallback(
    async (businessId: string, updates: Partial<BusinessRecord>) => {
      try {
        setScrapingState(prev => ({
          ...prev,
          results: prev.results.map(business =>
            business.id === businessId ? { ...business, ...updates } : business
          ),
        }))

        // Get updated business and save to storage
        const updatedBusiness = scrapingState.results.find(b => b.id === businessId)
        if (updatedBusiness) {
          await storage.saveBusiness({ ...updatedBusiness, ...updates })
        }

        toast.success('Business updated')
        logger.info('ScraperController', 'Business updated', { businessId, updates })
      } catch (error) {
        toast.error('Failed to update business')
        logger.error('ScraperController', 'Failed to update business', error)
      }
    },
    [scrapingState.results]
  )

  /**
   * Load previous results from storage
   */
  const loadPreviousResults = useCallback(async () => {
    try {
      const businesses = await storage.getAllBusinesses()
      setScrapingState(prev => ({
        ...prev,
        results: businesses,
      }))

      if (businesses.length > 0) {
        toast.success(`Loaded ${businesses.length} previous results`)
        logger.info('ScraperController', 'Previous results loaded', { count: businesses.length })
      }
    } catch (error) {
      toast.error('Failed to load previous results')
      logger.error('ScraperController', 'Failed to load previous results', error)
    }
  }, [])

  return {
    // State
    scrapingState,

    // Actions
    startScraping,
    stopScraping,
    stopEarly,
    clearResults,
    removeBusiness,
    updateBusiness,
    loadPreviousResults,

    // Processing step actions
    addProcessingStep,
    updateProcessingStep,
    clearProcessingSteps,

    // Computed values
    canStartScraping: !scrapingState.isScrapingActive && isConfigValid(),
    hasResults: scrapingState.results.length > 0,
    hasErrors: scrapingState.errors.length > 0,
    shouldShowResults: scrapingState.hasCompletedScraping || scrapingState.results.length > 0,
  }
}

/**
 * Check if a URL is a directory or search page that shouldn't be scraped
 */
function isDirectoryOrSearchPage(url: string): boolean {
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase()
    const pathname = urlObj.pathname.toLowerCase()
    const search = urlObj.search.toLowerCase()

    // Directory sites that shouldn't be scraped
    const directorySites = [
      'yelp.com',
      'yellowpages.com',
      'bbb.org',
      'google.com',
      'bing.com',
      'duckduckgo.com',
      'facebook.com',
      'linkedin.com',
      'twitter.com',
      'instagram.com',
      'foursquare.com',
      'citysearch.com',
      'superpages.com',
    ]

    // Check if it's a directory site
    if (directorySites.some(site => hostname.includes(site))) {
      return true
    }

    // Check for search/directory patterns in URL
    const searchPatterns = [
      '/search',
      '/directory',
      '/find',
      '/results',
      '/listings',
      'find_desc=',
      'find_loc=',
      'q=',
      'query=',
      'search=',
    ]

    if (searchPatterns.some(pattern => pathname.includes(pattern) || search.includes(pattern))) {
      return true
    }

    return false
  } catch (error) {
    // If URL parsing fails, assume it's not a directory page
    return false
  }
}
