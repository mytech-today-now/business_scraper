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
      })

      // Create abort controller
      abortControllerRef.current = new AbortController()
      
      // Create session
      sessionIdRef.current = `session-${Date.now()}`
      
      // Initialize scraper service
      await scraperService.initialize()
      scraperService.resetStats()

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
        updateProgress(i, industryNames.length, `Searching for ${industry} businesses...`)
        
        try {
          const query = `${industry} businesses`
          const urls = await scraperService.searchForWebsites(
            query,
            config.zipCode,
            Math.ceil(50 / industryNames.length) // Distribute search results
          )
          
          allUrls.push(...urls)
          logger.info('ScraperController', `Found ${urls.length} URLs for ${industry}`)
        } catch (error) {
          const errorMsg = `Failed to search for ${industry} businesses: ${error}`
          addError(errorMsg)
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
          try {
            updateProgress(
              batchStart + index,
              uniqueUrls.length,
              `Scraping ${url}...`
            )
            
            const businesses = await scraperService.scrapeWebsite(url, config.searchDepth)
            
            // Set industry for scraped businesses
            const businessesWithIndustry = businesses.map(business => ({
              ...business,
              industry: industryNames.find(name => 
                business.businessName.toLowerCase().includes(name.toLowerCase()) ||
                business.websiteUrl.toLowerCase().includes(name.toLowerCase())
              ) || 'General',
            }))
            
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
            return []
          }
        })

        await Promise.all(batchPromises)
        
        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 1000))
      }

      // Final progress update
      updateProgress(uniqueUrls.length, uniqueUrls.length, 'Scraping completed!')
      
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

    // Computed values
    canStartScraping: !scrapingState.isScrapingActive && isConfigValid(),
    hasResults: scrapingState.results.length > 0,
    hasErrors: scrapingState.errors.length > 0,
  }
}
