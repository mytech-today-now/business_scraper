'use strict'

import puppeteer, { Browser, Page } from 'puppeteer'
import axios from 'axios'
import { BusinessRecord, ScrapingConfig } from '@/types/business'
import { geocoder } from './geocoder'
import { searchEngine } from './searchEngine'
import { logger } from '@/utils/logger'
import { CONTACT_KEYWORDS } from '@/lib/industry-config'
import { enhancedScrapingEngine, ScrapingJob } from '@/lib/enhancedScrapingEngine'
import { webSocketServer } from '@/lib/websocket-server'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryCleanup } from '@/lib/memory-cleanup'

/**
 * Interface for scraping statistics
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
 * Interface for search result
 */
export interface SearchResult {
  url: string
  title: string
  snippet: string
}

/**
 * Scraper service configuration
 */
export interface ScraperConfig {
  timeout: number
  maxRetries: number
  retryDelay: number
  userAgent: string
  headless: boolean
  maxConcurrent: number
}

/**
 * Default scraper configuration - Optimized for performance
 */
const DEFAULT_SCRAPER_CONFIG: ScraperConfig = {
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  headless: true,
  maxConcurrent: 6,              // Increased from 3 to 6 for better throughput
}

/**
 * Main scraper service class
 * Handles web scraping operations using Puppeteer
 */
export class ScraperService {
  private config: ScraperConfig
  private browser: Browser | null = null
  private stats: ScrapingStats | null = null
  private demoMode: boolean = false
  private sessionId: string = 'default'

  constructor(config: Partial<ScraperConfig> = {}) {
    this.config = { ...DEFAULT_SCRAPER_CONFIG, ...config }
  }

  /**
   * Set session ID for WebSocket streaming
   */
  setSessionId(sessionId: string): void {
    this.sessionId = sessionId
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.sessionId
  }

  /**
   * Check if demo mode is enabled
   */
  isDemoMode(): boolean {
    return this.demoMode
  }

  /**
   * Set demo mode
   */
  setDemoMode(enabled: boolean): void {
    this.demoMode = enabled
  }

  /**
   * Initialize the browser instance
   */
  async initialize(): Promise<void> {
    if (this.browser) return

    try {
      this.browser = await puppeteer.launch({
        headless: this.config.headless,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu',
        ],
      })
      logger.info('Scraper', 'Browser initialized successfully')

      // Start memory monitoring
      if (!memoryMonitor.isActive()) {
        memoryMonitor.startMonitoring()
        logger.info('Scraper', 'Memory monitoring started')
      }

      // Start auto cleanup
      memoryCleanup.startAutoCleanup()

    } catch (error) {
      logger.error('Scraper', 'Failed to initialize browser', error)
      throw error
    }
  }

  /**
   * Close the browser instance
   */
  async cleanup(): Promise<void> {
    if (this.browser) {
      await this.browser.close()
      this.browser = null
      logger.info('Scraper', 'Browser closed')
    }

    // Stop memory monitoring and cleanup
    memoryMonitor.stopMonitoring()
    memoryCleanup.stopAutoCleanup()

    // Perform final cleanup
    await memoryCleanup.performAutomaticCleanup()

    logger.info('Scraper', 'Memory cleanup completed')
  }

  /**
   * Search for websites based on industry and location
   * @param query - Search query
   * @param zipCode - ZIP code for location-based search
   * @param maxResults - Maximum number of results to return
   * @returns Promise resolving to array of URLs
   */
  async searchForWebsites(
    query: string,
    zipCode: string,
    maxResults: number = 50
  ): Promise<string[]> {
    try {
      logger.info('Scraper', `Searching for websites: ${query} near ${zipCode}`)

      // Use the search engine service
      const searchResults = await searchEngine.searchBusinesses(query, zipCode, maxResults)

      const urls = searchResults
        .map(result => result.url)
        .filter(url => this.isValidBusinessUrl(url))
        .slice(0, maxResults)

      logger.info('Scraper', `Found ${urls.length} potential business websites`)
      return urls
    } catch (error) {
      logger.error('Scraper', 'Failed to search for websites', error)
      return []
    }
  }



  /**
   * Scrape a website for business information
   * @param url - Website URL to scrape
   * @param depth - Maximum depth to crawl
   * @param maxPages - Maximum number of pages to scrape per site
   * @returns Promise resolving to array of business records
   */
  async scrapeWebsite(url: string, depth: number = 2, maxPages: number = 5): Promise<BusinessRecord[]> {
    if (!this.browser) {
      await this.initialize()
    }

    if (!this.browser) {
      throw new Error('Failed to initialize browser')
    }

    const page = await this.browser.newPage()

    try {
      await page.setUserAgent(this.config.userAgent)
      await page.setViewport({ width: 1920, height: 1080 })

      logger.info('Scraper', `Scraping website: ${url}`)

      // Check if URL is accessible
      try {
        // Navigate to the main page
        await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.config.timeout
        })
      } catch (navigationError) {
        logger.warn('Scraper', `Failed to navigate to ${url}`, navigationError)
        // Try with a shorter timeout and different wait condition
        try {
          await page.goto(url, {
            waitUntil: 'domcontentloaded',
            timeout: 15000
          })
        } catch (retryError) {
          logger.error('Scraper', `Navigation failed completely for ${url}`, retryError)
          return []
        }
      }

      // Find contact pages
      const contactUrls = await this.findContactPages(page, url, depth)

      // Limit total pages to maxPages setting (main page + contact pages)
      const allUrls = [url, ...contactUrls]
      const limitedUrls = allUrls.slice(0, maxPages)

      // Scrape business data from limited set of pages
      const businessData = await this.extractBusinessData(page, limitedUrls)

      logger.info('Scraper', `Successfully scraped ${url}, processed ${limitedUrls.length}/${allUrls.length} pages (maxPages: ${maxPages}), found ${businessData.length} business records`)
      return businessData
    } catch (error) {
      logger.error('Scraper', `Failed to scrape ${url}`, error)
      return []
    } finally {
      await page.close()
    }
  }

  /**
   * Find contact pages on a website
   * @param page - Puppeteer page instance
   * @param baseUrl - Base URL of the website
   * @param maxDepth - Maximum crawl depth
   * @returns Promise resolving to array of contact page URLs
   */
  private async findContactPages(page: Page, baseUrl: string, maxDepth: number): Promise<string[]> {
    const contactUrls: Set<string> = new Set()
    const domain = new URL(baseUrl).hostname

    try {
      // Look for contact-related links
      const links = await page.evaluate((keywords) => {
        const allLinks = Array.from(document.querySelectorAll('a[href]'))
        return allLinks
          .map(link => ({
            href: (link as HTMLAnchorElement).href,
            text: link.textContent?.toLowerCase() || '',
          }))
          .filter(link => 
            keywords.some(keyword => 
              link.text.includes(keyword) || 
              link.href.toLowerCase().includes(keyword)
            )
          )
          .map(link => link.href)
      }, CONTACT_KEYWORDS)

      // Filter and normalize URLs
      for (const link of links) {
        try {
          const url = new URL(link, baseUrl)
          if (url.hostname === domain && !contactUrls.has(url.href)) {
            contactUrls.add(url.href)
          }
        } catch {
          // Invalid URL, skip
        }
      }

      logger.info('Scraper', `Found ${contactUrls.size} contact pages for ${baseUrl}`)
      return Array.from(contactUrls).slice(0, maxDepth)
    } catch (error) {
      logger.error('Scraper', `Failed to find contact pages for ${baseUrl}`, error)
      return []
    }
  }

  /**
   * Extract business data from pages
   * @param page - Puppeteer page instance
   * @param urls - URLs to extract data from
   * @returns Promise resolving to array of business records
   */
  private async extractBusinessData(page: Page, urls: string[]): Promise<BusinessRecord[]> {
    const businesses: BusinessRecord[] = []

    for (const url of urls) {
      try {
        await page.goto(url, { 
          waitUntil: 'networkidle2', 
          timeout: this.config.timeout 
        })

        const businessData = await page.evaluate(() => {
          // Extract business name
          const businessName = 
            document.querySelector('h1')?.textContent?.trim() ||
            document.querySelector('title')?.textContent?.trim() ||
            document.querySelector('[class*="company"], [class*="business"]')?.textContent?.trim() ||
            'Unknown Business'

          // Extract emails
          const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
          const pageText = document.body.textContent || ''
          const emails = Array.from(new Set(pageText.match(emailRegex) || []))
            .filter(email => !email.includes('example.com') && !email.includes('placeholder'))

          // Extract phone numbers
          const phoneRegex = /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g
          const phones = Array.from(new Set(pageText.match(phoneRegex) || []))

          // Extract address (simplified)
          const addressRegex = /\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)[,\s]+[A-Za-z\s]+[,\s]+[A-Z]{2}[,\s]+\d{5}(?:-\d{4})?/g
          const addresses = pageText.match(addressRegex) || []

          return {
            businessName,
            emails,
            phones,
            addresses,
            url: window.location.href,
          }
        })

        if (businessData.emails.length > 0 || businessData.phones.length > 0) {
          // Create business record
          const business: BusinessRecord = {
            id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            businessName: businessData.businessName,
            email: businessData.emails,
            phone: businessData.phones[0],
            websiteUrl: url,
            address: this.parseAddress(businessData.addresses[0] || ''),
            industry: 'Unknown', // Will be set by the calling function
            scrapedAt: new Date(),
          }

          // Geocode address if available
          if (businessData.addresses[0]) {
            const coordinates = await geocoder.geocodeAddress(businessData.addresses[0])
            if (coordinates) {
              business.coordinates = coordinates
            }
          }

          businesses.push(business)
          logger.info('Scraper', `Extracted business data from ${url}`)

          // Emit result in real-time via WebSocket
          try {
            webSocketServer.broadcastResult(this.sessionId, business)
          } catch (error) {
            logger.warn('Scraper', 'Failed to broadcast result via WebSocket', error)
          }
        }
      } catch (error) {
        logger.error('Scraper', `Failed to extract data from ${url}`, error)
      }
    }

    return businesses
  }

  /**
   * Parse address string into structured format
   * @param addressString - Raw address string
   * @returns Structured address object
   */
  private parseAddress(addressString: string): BusinessRecord['address'] {
    // Simplified address parsing
    const parts = addressString.split(',').map(part => part.trim())
    
    return {
      street: parts[0] || '',
      city: parts[1] || '',
      state: parts[2]?.split(' ')[0] || '',
      zipCode: parts[2]?.split(' ')[1] || '',
    }
  }

  /**
   * Check if URL is a valid business website
   * @param url - URL to validate
   * @returns Boolean indicating if URL is valid
   */
  private isValidBusinessUrl(url: string): boolean {
    try {
      const urlObj = new URL(url)
      const hostname = urlObj.hostname.toLowerCase()
      
      // Exclude social media, directories, etc.
      const excludedDomains = [
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'yelp.com', 'yellowpages.com', 'google.com', 'youtube.com',
        'wikipedia.org', 'amazon.com', 'ebay.com'
      ]
      
      return !excludedDomains.some(domain => hostname.includes(domain))
    } catch {
      return false
    }
  }

  /**
   * Get scraping statistics
   * @returns Current scraping statistics
   */
  getStats(): ScrapingStats | null {
    return this.stats
  }

  /**
   * Reset scraping statistics
   */
  resetStats(): void {
    this.stats = {
      totalSites: 0,
      successfulScrapes: 0,
      failedScrapes: 0,
      totalBusinesses: 0,
      startTime: new Date(),
    }
  }

  /**
   * Enhanced scraping using the new scraping engine
   * @param urls - Array of URLs to scrape
   * @param depth - Scraping depth
   * @param priority - Job priority
   * @returns Promise resolving to job IDs
   */
  async scrapeUrlsEnhanced(
    urls: string[],
    depth: number = 2,
    priority: number = 1
  ): Promise<string[]> {
    logger.info('ScraperService', `Starting enhanced scraping for ${urls.length} URLs`)

    // Initialize enhanced engine if not already done
    await enhancedScrapingEngine.initialize()

    const jobIds: string[] = []

    for (const url of urls) {
      try {
        const jobId = await enhancedScrapingEngine.addJob(url, depth, priority)
        jobIds.push(jobId)
      } catch (error) {
        logger.error('ScraperService', `Failed to add job for ${url}`, error)
      }
    }

    logger.info('ScraperService', `Added ${jobIds.length} jobs to enhanced scraping queue`)
    return jobIds
  }

  /**
   * Get enhanced scraping job status
   * @param jobId - Job ID
   * @returns Job status or null if not found
   */
  getEnhancedJobStatus(jobId: string): ScrapingJob | null {
    return enhancedScrapingEngine.getJobStatus(jobId)
  }

  /**
   * Get enhanced scraping statistics
   * @returns Enhanced scraping statistics
   */
  getEnhancedStats() {
    return enhancedScrapingEngine.getStats()
  }

  /**
   * Cancel an enhanced scraping job
   * @param jobId - Job ID to cancel
   * @returns True if job was cancelled
   */
  cancelEnhancedJob(jobId: string): boolean {
    return enhancedScrapingEngine.cancelJob(jobId)
  }

  /**
   * Wait for enhanced scraping jobs to complete
   * @param jobIds - Array of job IDs to wait for
   * @param timeout - Timeout in milliseconds
   * @returns Promise resolving to completed jobs
   */
  async waitForEnhancedJobs(
    jobIds: string[],
    timeout: number = 300000
  ): Promise<ScrapingJob[]> {
    const startTime = Date.now()
    const completedJobs: ScrapingJob[] = []

    while (completedJobs.length < jobIds.length && Date.now() - startTime < timeout) {
      for (const jobId of jobIds) {
        if (completedJobs.find(job => job.id === jobId)) continue

        const job = enhancedScrapingEngine.getJobStatus(jobId)
        if (job && (job.status === 'completed' || job.status === 'failed')) {
          completedJobs.push(job)
        }
      }

      if (completedJobs.length < jobIds.length) {
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    }

    return completedJobs
  }

  /**
   * Enhanced website scraping with all advanced features
   * @param url - Website URL to scrape
   * @param depth - Maximum depth to crawl
   * @param maxPages - Maximum number of pages to scrape per site
   * @returns Promise resolving to array of business records
   */
  async scrapeWebsiteEnhanced(url: string, depth: number = 2, maxPages: number = 5): Promise<BusinessRecord[]> {
    logger.info('ScraperService', `Starting enhanced scraping for: ${url}`)

    try {
      // Initialize enhanced engine
      await enhancedScrapingEngine.initialize()

      // Add job with high priority and maxPages limit
      const jobId = await enhancedScrapingEngine.addJob(url, depth, 10, maxPages)

      // Wait for job completion
      const completedJobs = await this.waitForEnhancedJobs([jobId], 120000) // 2 minute timeout

      const firstJob = completedJobs[0]
      if (completedJobs.length > 0 && firstJob?.result) {
        logger.info('ScraperService', `Enhanced scraping completed for ${url}: ${firstJob.result.length} businesses`)
        return firstJob.result
      } else {
        logger.warn('ScraperService', `Enhanced scraping failed or timed out for ${url}`)
        // Fallback to regular scraping
        return await this.scrapeWebsite(url, depth, maxPages)
      }
    } catch (error) {
      logger.error('ScraperService', `Enhanced scraping failed for ${url}`, error)
      // Fallback to regular scraping
      return await this.scrapeWebsite(url, depth, maxPages)
    }
  }
}

/**
 * Default scraper instance
 */
export const scraperService = new ScraperService()
