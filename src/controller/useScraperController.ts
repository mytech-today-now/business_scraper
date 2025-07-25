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
}

/**
 * Scraper controller hook
 * Manages scraping operations and state
 */
export function useScraperController() {
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
  })
  
  // Refs for managing scraping process
  const abortControllerRef = useRef<AbortController | null>(null)
  const sessionIdRef = useRef<string | null>(null)

  /**
   * Update scraper service demo mode when configuration changes
   */
  useEffect(() => {
    scraperService.setDemoMode(configState.isDemoMode)
  }, [configState.isDemoMode])

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
      dataSource: step.dataSource || (scraperService.isDemoMode() ? 'demo' : 'real')
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
              endTime: updates.status === 'completed' || updates.status === 'failed' ? new Date() : step.endTime,
              duration: updates.status === 'completed' || updates.status === 'failed'
                ? (new Date().getTime() - (step.startTime?.getTime() || 0))
                : step.duration
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
      // Initialize scraping state
      setScrapingState({
        isScrapingActive: true,
        currentUrl: '',
        progress: { current: 0, total: 0, percentage: 0 },
        results: [],
        stats: null,
        errors: [],
        processingSteps: [],
      })

      // Create abort controller
      abortControllerRef.current = new AbortController()

      // Create session
      sessionIdRef.current = `session-${Date.now()}`

      // Add initialization step
      addProcessingStep({
        name: 'Initializing Scraper',
        status: 'running',
        details: configState.isDemoMode ? 'Setting up demo data source' : 'Connecting to live web services'
      })

      // Initialize scraper service
      await scraperService.initialize()
      scraperService.resetStats()

      // Update initialization step
      const initStepId = scrapingState.processingSteps[scrapingState.processingSteps.length - 1]?.id
      if (initStepId) {
        updateProcessingStep(initStepId, {
          status: 'completed',
          details: configState.isDemoMode ? 'Demo data source ready' : 'Connected to live web services'
        })
      }

      const { config, selectedIndustries } = configState
      const industryNames = getSelectedIndustryNames()
      
      logger.info('ScraperController', 'Starting scraping process', {
        industries: industryNames,
        zipCode: config.zipCode,
        searchRadius: config.searchRadius,
      })

      toast.success('Scraping started!')

      // Search for websites for each industry
      const allUrls: string[] = []

      for (let i = 0; i < industryNames.length; i++) {
        if (abortControllerRef.current?.signal.aborted) break

        const industry = industryNames[i]

        if (!industry) {
          continue
        }

        updateProgress(i, industryNames.length, `Searching for ${industry} businesses...`)

        // Add search step
        addProcessingStep({
          name: `Searching ${industry} Businesses`,
          status: 'running',
          details: `Query: "${industry}" in ${config.zipCode}`
        })

        try {
          // Pass the industry name directly - let the search engine handle expansion
          const query: string = industry
          const urls = await scraperService.searchForWebsites(
            query,
            config.zipCode,
            Math.ceil(50 / industryNames.length) // Distribute search results
          )

          allUrls.push(...urls)
          logger.info('ScraperController', `Found ${urls.length} URLs for ${industry}`)

          // Update search step as completed
          const searchSteps = scrapingState.processingSteps.filter(s => s.name.includes(`Searching ${industry}`))
          const latestSearchStep = searchSteps[searchSteps.length - 1]
          if (latestSearchStep) {
            // Check if we're actually using demo mode (fallback)
            const isUsingDemo = scraperService.isDemoMode() || urls.some(url => url.includes('demo') || url.includes('example'))
            updateProcessingStep(latestSearchStep.id, {
              status: 'completed',
              details: `Found ${urls.length} websites${isUsingDemo ? ' (using demo data)' : ''}`,
              businessesFound: urls.length,
              dataSource: isUsingDemo ? 'demo' : 'real'
            })
          }
        } catch (error) {
          const errorMsg = `Failed to search for ${industry} businesses: ${error}`
          addError(errorMsg)

          // Update search step as failed
          const searchSteps = scrapingState.processingSteps.filter(s => s.name.includes(`Searching ${industry}`))
          const latestSearchStep = searchSteps[searchSteps.length - 1]
          if (latestSearchStep) {
            updateProcessingStep(latestSearchStep.id, {
              status: 'failed',
              error: errorMsg
            })
          }
        }
      }

      if (allUrls.length === 0) {
        throw new Error('No websites found to scrape')
      }

      // Remove duplicates
      const uniqueUrls = Array.from(new Set(allUrls))
      logger.info('ScraperController', `Found ${uniqueUrls.length} unique websites to scrape`)

      // Scrape each website
      const batchSize = 3 // Process in batches to avoid overwhelming
      const totalBatches = Math.ceil(uniqueUrls.length / batchSize)
      
      for (let batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
        if (abortControllerRef.current?.signal.aborted) break
        
        const batchStart = batchIndex * batchSize
        const batchEnd = Math.min(batchStart + batchSize, uniqueUrls.length)
        const batchUrls = uniqueUrls.slice(batchStart, batchEnd)
        
        updateProgress(
          batchStart,
          uniqueUrls.length,
          `Scraping batch ${batchIndex + 1}/${totalBatches}...`
        )

        // Process batch in parallel
        const batchPromises = batchUrls.map(async (url, index) => {
          // Add scraping step
          addProcessingStep({
            name: `Scraping Website`,
            status: 'running',
            url: url,
            details: `Extracting business data from ${url}`
          })

          try {
            updateProgress(
              batchStart + index,
              uniqueUrls.length,
              `Scraping ${url}...`
            )

            // Skip scraping directory/search pages
            if (isDirectoryOrSearchPage(url)) {
              logger.warn('ScraperController', `Skipping directory/search page: ${url}`)
              return []
            }

            const businesses = await scraperService.scrapeWebsite(url, config.searchDepth)

            // Set industry for scraped businesses
            const businessesWithIndustry = businesses.map(business => ({
              ...business,
              industry: industryNames.find(name =>
                business.businessName.toLowerCase().includes(name.toLowerCase()) ||
                business.websiteUrl.toLowerCase().includes(name.toLowerCase())
              ) || 'General',
            }))

            // Update scraping step as completed
            const scrapingSteps = scrapingState.processingSteps.filter(s => s.url === url && s.name === 'Scraping Website')
            const latestScrapingStep = scrapingSteps[scrapingSteps.length - 1]
            if (latestScrapingStep) {
              // Check if we're using demo mode
              const isUsingDemo = scraperService.isDemoMode() || url.includes('demo') || url.includes('example') || url.includes('bellavista') || url.includes('techflow')
              updateProcessingStep(latestScrapingStep.id, {
                status: 'completed',
                details: `Found ${businessesWithIndustry.length} businesses${isUsingDemo ? ' (demo data)' : ''}`,
                businessesFound: businessesWithIndustry.length,
                dataSource: isUsingDemo ? 'demo' : 'real'
              })
            }

            if (businessesWithIndustry.length > 0) {
              addResults(businessesWithIndustry)
              
              // Save to storage
              await storage.saveBusinesses(businessesWithIndustry)
              
              logger.info('ScraperController', `Scraped ${businessesWithIndustry.length} businesses from ${url}`)
            }
            
            return businessesWithIndustry
          } catch (error) {
            const errorMsg = `Failed to scrape ${url}: ${error}`
            addError(errorMsg)

            // Update scraping step as failed
            const scrapingSteps = scrapingState.processingSteps.filter(s => s.url === url && s.name === 'Scraping Website')
            const latestScrapingStep = scrapingSteps[scrapingSteps.length - 1]
            if (latestScrapingStep) {
              updateProcessingStep(latestScrapingStep.id, {
                status: 'failed',
                error: errorMsg
              })
            }

            return []
          }
        })

        await Promise.all(batchPromises)
        
        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 1000))
      }

      // Final progress update
      updateProgress(uniqueUrls.length, uniqueUrls.length, 'Scraping completed!')

      // Add completion step
      addProcessingStep({
        name: 'Scraping Complete',
        status: 'completed',
        details: `Successfully processed ${uniqueUrls.length} websites and found ${scrapingState.results.length} businesses`,
        businessesFound: scrapingState.results.length
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
      // Cleanup
      await scraperService.cleanup()
      setScrapingState(prev => ({
        ...prev,
        isScrapingActive: false,
        currentUrl: '',
      }))
      abortControllerRef.current = null
    }
  }, [configState, getSelectedIndustryNames, isConfigValid, scrapingState.isScrapingActive, scrapingState.results.length, scrapingState.errors.length, updateProgress, addError, addResults])

  /**
   * Stop scraping process
   */
  const stopScraping = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      toast('Scraping stopped by user')
      logger.info('ScraperController', 'Scraping stopped by user')
    }
  }, [])

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
  const updateBusiness = useCallback(async (businessId: string, updates: Partial<BusinessRecord>) => {
    try {
      setScrapingState(prev => ({
        ...prev,
        results: prev.results.map(business =>
          business.id === businessId
            ? { ...business, ...updates }
            : business
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
  }, [scrapingState.results])

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
      'superpages.com'
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
      'search='
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
