/**
 * Enhanced Scraping Engine
 * High-performance, concurrent scraping with anti-bot detection bypass
 */

import { browserPool, PageInstance } from './browserPool'
import { contactExtractor, ExtractedContact } from './contactExtractor'
import { antiBotBypass } from './antiBotBypass'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface ScrapingJob {
  id: string
  url: string
  depth: number
  maxPages: number
  priority: number
  retries: number
  maxRetries: number
  createdAt: Date
  startedAt?: Date
  completedAt?: Date
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  result?: BusinessRecord[]
  error?: string
}

export interface ScrapingConfig {
  maxConcurrentJobs: number
  maxRetries: number
  timeout: number
  retryDelay: number
  enableAntiBot: boolean
  enableContactExtraction: boolean
  enablePerformanceMonitoring: boolean
  queueProcessingInterval: number
}

export interface ScrapingStats {
  totalJobs: number
  completedJobs: number
  failedJobs: number
  activeJobs: number
  queuedJobs: number
  averageProcessingTime: number
  successRate: number
  pagesPerMinute: number
}

export interface PerformanceMetrics {
  jobId: string
  url: string
  startTime: number
  endTime: number
  duration: number
  success: boolean
  contactsFound: number
  pagesScraped: number
  retries: number
  error?: string
}

/**
 * Enhanced Scraping Engine with concurrent processing and advanced features
 */
export class EnhancedScrapingEngine {
  private config: ScrapingConfig
  private jobQueue: ScrapingJob[] = []
  private activeJobs: Map<string, ScrapingJob> = new Map()
  private completedJobs: ScrapingJob[] = []
  private performanceMetrics: PerformanceMetrics[] = []
  private isProcessing = false
  private processingInterval?: NodeJS.Timeout

  constructor(config?: Partial<ScrapingConfig>) {
    this.config = {
      maxConcurrentJobs: 8,        // Increased from 3 to 8 for better throughput
      maxRetries: 3,
      timeout: 45000,              // Reduced from 60000 for faster timeouts
      retryDelay: 3000,            // Reduced from 5000 for faster retries
      enableAntiBot: true,
      enableContactExtraction: true,
      enablePerformanceMonitoring: true,
      queueProcessingInterval: 500, // Reduced from 1000 for faster processing
      ...config,
    }
  }

  /**
   * Initialize the scraping engine
   */
  async initialize(): Promise<void> {
    logger.info('EnhancedScrapingEngine', 'Initializing enhanced scraping engine')
    
    await browserPool.initialize()
    this.startQueueProcessing()
    
    logger.info('EnhancedScrapingEngine', 'Enhanced scraping engine initialized')
  }

  /**
   * Add a scraping job to the queue
   */
  async addJob(url: string, depth: number = 2, priority: number = 1, maxPages: number = 5): Promise<string> {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const job: ScrapingJob = {
      id: jobId,
      url,
      depth,
      maxPages,
      priority,
      retries: 0,
      maxRetries: this.config.maxRetries,
      createdAt: new Date(),
      status: 'pending',
    }

    // Insert job in priority order
    const insertIndex = this.jobQueue.findIndex(j => j.priority < priority)
    if (insertIndex === -1) {
      this.jobQueue.push(job)
    } else {
      this.jobQueue.splice(insertIndex, 0, job)
    }

    logger.info('EnhancedScrapingEngine', `Added job ${jobId} for ${url} (priority: ${priority})`)
    return jobId
  }

  /**
   * Cancel a job
   */
  cancelJob(jobId: string): boolean {
    // Remove from queue
    const queueIndex = this.jobQueue.findIndex(job => job.id === jobId)
    if (queueIndex !== -1) {
      const job = this.jobQueue.at(queueIndex)
      if (job) {
        job.status = 'cancelled'
      }
      this.jobQueue.splice(queueIndex, 1)
      return true
    }

    // Cancel active job
    const activeJob = this.activeJobs.get(jobId)
    if (activeJob) {
      activeJob.status = 'cancelled'
      return true
    }

    return false
  }

  /**
   * Get job status
   */
  getJobStatus(jobId: string): ScrapingJob | null {
    // Check active jobs
    const activeJob = this.activeJobs.get(jobId)
    if (activeJob) return activeJob

    // Check queue
    const queuedJob = this.jobQueue.find(job => job.id === jobId)
    if (queuedJob) return queuedJob

    // Check completed jobs
    const completedJob = this.completedJobs.find(job => job.id === jobId)
    if (completedJob) return completedJob

    return null
  }

  /**
   * Get scraping statistics
   */
  getStats(): ScrapingStats {
    const totalJobs = this.completedJobs.length + this.activeJobs.size + this.jobQueue.length
    const completedJobs = this.completedJobs.filter(job => job.status === 'completed').length
    const failedJobs = this.completedJobs.filter(job => job.status === 'failed').length
    const activeJobs = this.activeJobs.size
    const queuedJobs = this.jobQueue.length

    const completedMetrics = this.performanceMetrics.filter(m => m.success)
    const averageProcessingTime = completedMetrics.length > 0
      ? completedMetrics.reduce((sum, m) => sum + m.duration, 0) / completedMetrics.length
      : 0

    const successRate = totalJobs > 0 ? completedJobs / totalJobs : 0

    // Calculate pages per minute from recent metrics
    const recentMetrics = this.performanceMetrics.filter(
      m => Date.now() - m.endTime < 60000 // Last minute
    )
    const pagesPerMinute = recentMetrics.reduce((sum, m) => sum + m.pagesScraped, 0)

    return {
      totalJobs,
      completedJobs,
      failedJobs,
      activeJobs,
      queuedJobs,
      averageProcessingTime,
      successRate,
      pagesPerMinute,
    }
  }

  /**
   * Shutdown the scraping engine
   */
  async shutdown(): Promise<void> {
    logger.info('EnhancedScrapingEngine', 'Shutting down enhanced scraping engine')
    
    this.isProcessing = false
    
    if (this.processingInterval) {
      clearInterval(this.processingInterval)
    }

    // Cancel all pending jobs
    this.jobQueue.forEach(job => {
      job.status = 'cancelled'
    })

    // Wait for active jobs to complete or timeout
    const timeout = 30000 // 30 seconds
    const startTime = Date.now()
    
    while (this.activeJobs.size > 0 && Date.now() - startTime < timeout) {
      await new Promise(resolve => setTimeout(resolve, 1000))
    }

    await browserPool.shutdown()
    
    logger.info('EnhancedScrapingEngine', 'Enhanced scraping engine shutdown complete')
  }

  /**
   * Start queue processing
   */
  private startQueueProcessing(): void {
    this.isProcessing = true
    
    this.processingInterval = setInterval(async () => {
      if (!this.isProcessing) return
      
      await this.processQueue()
    }, this.config.queueProcessingInterval)
  }

  /**
   * Process the job queue
   */
  private async processQueue(): Promise<void> {
    // Check if we can start new jobs
    if (this.activeJobs.size >= this.config.maxConcurrentJobs) {
      return
    }

    // Get next job from queue
    const job = this.jobQueue.find(j => j.status === 'pending')
    if (!job) {
      return
    }

    // Remove from queue and add to active jobs
    const queueIndex = this.jobQueue.indexOf(job)
    this.jobQueue.splice(queueIndex, 1)
    
    job.status = 'running'
    job.startedAt = new Date()
    this.activeJobs.set(job.id, job)

    // Process job asynchronously
    this.processJob(job).catch(error => {
      logger.error('EnhancedScrapingEngine', `Unhandled error processing job ${job.id}`, error)
    })
  }

  /**
   * Process a single scraping job
   */
  private async processJob(job: ScrapingJob): Promise<void> {
    const startTime = Date.now()
    let pageInstance: PageInstance | null = null
    let pagesScraped = 0
    let contactsFound = 0

    try {
      logger.info('EnhancedScrapingEngine', `Processing job ${job.id}: ${job.url}`)

      // Get page from browser pool
      pageInstance = await browserPool.getPage()
      
      // Apply anti-bot bypass measures
      if (this.config.enableAntiBot) {
        await antiBotBypass.applyBypassMeasures(pageInstance.page)
      }

      // Navigate to the URL
      await antiBotBypass.navigateHumanLike(pageInstance.page, job.url)

      // Check for bot detection
      const captchaDetection = await antiBotBypass.detectCaptcha(pageInstance.page)
      if (captchaDetection.detected) {
        throw new Error(`CAPTCHA detected: ${captchaDetection.type}`)
      }

      const isBlocked = await antiBotBypass.isPageBlocked(pageInstance.page)
      if (isBlocked) {
        throw new Error('Page access blocked or rate limited')
      }

      // Wait for page to be ready
      await antiBotBypass.waitForPageReady(pageInstance.page)

      // Extract contact information
      const businesses: BusinessRecord[] = []
      
      if (this.config.enableContactExtraction) {
        const contactInfo = await contactExtractor.extractContactInfo(pageInstance.page, job.url)
        
        if (contactInfo.confidence.overall > 0.3) {
          // Prioritize and format contact information
          const prioritizedEmails = this.prioritizeEmails(contactInfo.emails)
          const formattedPhone = contactInfo.phones.length > 0 && contactInfo.phones[0] ?
            this.formatPhoneNumber(contactInfo.phones[0]) : ''

          const business: BusinessRecord = {
            id: `business-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            businessName: contactInfo.businessName || this.extractDomainName(job.url),
            industry: 'Unknown',
            websiteUrl: job.url,
            email: prioritizedEmails,
            phone: formattedPhone,
            address: this.parseAndFormatAddress(contactInfo.addresses[0]),
            contactPerson: this.extractContactPerson(contactInfo),
            scrapedAt: new Date()
          }

          businesses.push(business)
          contactsFound = contactInfo.emails.length + contactInfo.phones.length
        }
      }

      pagesScraped = 1

      // If depth > 1 and we haven't reached maxPages, find and scrape contact pages
      if (job.depth > 1 && pagesScraped < job.maxPages) {
        const contactPages = await this.findContactPages(pageInstance.page, job.url)

        // Limit contact pages by both depth and maxPages
        const maxContactPages = Math.min(job.depth - 1, job.maxPages - pagesScraped)
        const limitedContactPages = contactPages.slice(0, maxContactPages)

        for (const contactUrl of limitedContactPages) {
          if (job.status === 'cancelled' || pagesScraped >= job.maxPages) break

          pagesScraped++ // Increment page count for each contact page
          
          try {
            await antiBotBypass.navigateHumanLike(pageInstance.page, contactUrl)
            
            const contactInfo = await contactExtractor.extractContactInfo(pageInstance.page, contactUrl)
            
            if (contactInfo.confidence.overall > 0.3) {
              // Merge with existing business or create new one
              if (businesses.length > 0) {
                const business = businesses[0]
                if (business) {
                  // Merge emails (remove duplicates and prioritize)
                  const allEmails = [...business.email, ...contactInfo.emails]
                  business.email = this.prioritizeEmails(Array.from(new Set(allEmails)))

                  // Update phone if better one found
                  if (!business.phone && contactInfo.phones.length > 0 && contactInfo.phones[0]) {
                    business.phone = this.formatPhoneNumber(contactInfo.phones[0])
                  } else if (contactInfo.phones.length > 0) {
                    // Prefer business/main numbers over mobile
                    const businessPhone = contactInfo.phones.find(phone =>
                      phone &&
                      !phone.toLowerCase().includes('mobile') &&
                      !phone.toLowerCase().includes('cell') &&
                      !phone.toLowerCase().includes('fax')
                    )
                    if (businessPhone) {
                      business.phone = this.formatPhoneNumber(businessPhone)
                    }
                  }

                  // Update address if more complete
                  const newAddress = this.parseAndFormatAddress(contactInfo.addresses[0])
                  if (!business.address.street && newAddress.street) {
                    business.address = newAddress
                  } else if (newAddress.street && newAddress.street.length > business.address.street.length) {
                    business.address = newAddress
                  }

                  // Update contact person if found
                  const contactPerson = this.extractContactPerson(contactInfo)
                  if (!business.contactPerson && contactPerson) {
                    business.contactPerson = contactPerson
                  }
                }
              }
            }
            
            pagesScraped++
            contactsFound += contactInfo.emails.length + contactInfo.phones.length
          } catch (error) {
            logger.warn('EnhancedScrapingEngine', `Failed to scrape contact page ${contactUrl}`, error)
          }
        }
      }

      // Job completed successfully
      job.status = 'completed'
      job.completedAt = new Date()
      job.result = businesses

      logger.info('EnhancedScrapingEngine', 
        `Job ${job.id} completed: ${businesses.length} businesses, ${contactsFound} contacts`)

    } catch (error) {
      logger.error('EnhancedScrapingEngine', `Job ${job.id} failed`, error)
      
      job.retries++
      job.error = error instanceof Error ? error.message : String(error)

      if (job.retries < job.maxRetries) {
        // Retry job
        job.status = 'pending'
        
        // Add delay before retry
        setTimeout(() => {
          this.jobQueue.unshift(job) // Add to front of queue
        }, this.config.retryDelay * job.retries)
        
        logger.info('EnhancedScrapingEngine', 
          `Job ${job.id} will be retried (attempt ${job.retries + 1}/${job.maxRetries})`)
      } else {
        // Job failed permanently
        job.status = 'failed'
        job.completedAt = new Date()
        
        logger.error('EnhancedScrapingEngine', 
          `Job ${job.id} failed permanently after ${job.retries} retries`)
      }
    } finally {
      // Release page back to pool
      if (pageInstance) {
        await browserPool.releasePage(pageInstance)
      }

      // Remove from active jobs
      this.activeJobs.delete(job.id)
      
      // Add to completed jobs if not retrying
      if (job.status !== 'pending') {
        this.completedJobs.push(job)
        
        // Keep only recent completed jobs
        if (this.completedJobs.length > 1000) {
          this.completedJobs.splice(0, 100)
        }

        logger.info('EnhancedScrapingEngine', `Scraped ${pagesScraped} pages for ${job.url} (maxPages: ${job.maxPages})`)
      }

      // Record performance metrics
      if (this.config.enablePerformanceMonitoring) {
        const endTime = Date.now()
        const metrics: PerformanceMetrics = {
          jobId: job.id,
          url: job.url,
          startTime,
          endTime,
          duration: endTime - startTime,
          success: job.status === 'completed',
          contactsFound,
          pagesScraped,
          retries: job.retries,
          error: job.error,
        }
        
        this.performanceMetrics.push(metrics)
        
        // Keep only recent metrics
        if (this.performanceMetrics.length > 1000) {
          this.performanceMetrics.splice(0, 100)
        }
      }
    }
  }

  /**
   * Find contact pages on a website
   */
  private async findContactPages(page: any, baseUrl: string): Promise<string[]> {
    try {
      const contactUrls = await page.evaluate((base: string) => {
        const links = Array.from(document.querySelectorAll('a[href]'))
        const contactKeywords = ['contact', 'about', 'team', 'staff', 'location', 'office']
        const urls: string[] = []
        
        links.forEach((link: any) => {
          const href = link.getAttribute('href')
          const text = link.textContent?.toLowerCase() || ''
          
          if (href && contactKeywords.some(keyword => 
            text.includes(keyword) || href.toLowerCase().includes(keyword)
          )) {
            try {
              const url = new URL(href, base)
              if (url.hostname === new URL(base).hostname) {
                urls.push(url.href)
              }
            } catch (error) {
              // Invalid URL, skip
            }
          }
        })
        
        return Array.from(new Set(urls))
      }, baseUrl)
      
      return contactUrls.slice(0, 5) // Limit to 5 contact pages
    } catch (error) {
      logger.warn('EnhancedScrapingEngine', 'Failed to find contact pages', error)
      return []
    }
  }

  /**
   * Extract domain name from URL
   */
  private extractDomainName(url: string): string {
    try {
      const domain = new URL(url).hostname
      return domain.replace('www.', '').split('.')[0] || 'Unknown Business'
    } catch (error) {
      return 'Unknown Business'
    }
  }

  /**
   * Parse and format address into structured components
   */
  private parseAndFormatAddress(rawAddress?: string): BusinessRecord['address'] {
    if (!rawAddress) {
      return { street: '', city: '', state: '', zipCode: '' }
    }

    // Enhanced address parsing logic
    const addressPatterns = {
      // Street address with optional suite/unit
      street: /^([^,]+(?:suite|ste|unit|apt|#)\s*[^,]*)/i,
      // City, State ZIP pattern - ReDoS safe version
      cityStateZip: /([^,]{1,50}),\s*([A-Z]{2})\s*([0-9]{5}(?:-[0-9]{4})?)/i,
      // ZIP code pattern - ReDoS safe version
      zipCode: /\b([0-9]{5}(?:-[0-9]{4})?)\b/,
      // State abbreviation
      state: /\b([A-Z]{2})\b/
    }

    const lines = rawAddress.split(/[,\n]/).map(line => line.trim())

    let street = ''
    let city = ''
    let state = ''
    let zipCode = ''
    let suite = ''

    // Extract ZIP code first
    const zipMatch = rawAddress.match(addressPatterns.zipCode)
    if (zipMatch && zipMatch[1]) {
      zipCode = zipMatch[1]
    }

    // Extract state
    const stateMatch = rawAddress.match(addressPatterns.state)
    if (stateMatch && stateMatch[1]) {
      state = stateMatch[1]
    }

    // Parse city, state, zip line - use cleaned address without newlines
    const cleanedAddress = rawAddress.replace(/\n/g, ', ')
    const cityStateZipMatch = cleanedAddress.match(addressPatterns.cityStateZip)
    if (cityStateZipMatch && cityStateZipMatch[1] && cityStateZipMatch[2] && cityStateZipMatch[3]) {
      city = cityStateZipMatch[1].trim()
      state = cityStateZipMatch[2]
      zipCode = cityStateZipMatch[3]
    }

    // Extract street address (first line typically)
    if (lines.length > 0 && lines[0]) {
      street = lines[0]

      // For comma-separated addresses, check if second element is a suite
      if (lines.length >= 2 && lines[1]) {
        const secondPart = lines[1].trim()
        const suitePattern = /^(suite|ste|unit|apt|apartment|#)\s*(.+)/i
        if (suitePattern.test(secondPart)) {
          suite = secondPart
          // Remove the suite part from lines for further processing
          lines.splice(1, 1)
        }
      }

      // Also check for inline suite format
      const inlineSuiteMatch = street.match(/(.*?)\s+(suite|ste|unit|apt|apartment|#)\s*([^\s,]*)/i)
      if (inlineSuiteMatch && inlineSuiteMatch[1] && inlineSuiteMatch[2] && inlineSuiteMatch[3]) {
        street = inlineSuiteMatch[1].trim()
        suite = `${inlineSuiteMatch[2]} ${inlineSuiteMatch[3]}`.trim()
      }
    }

    // If city not found, try second line (for multiline addresses)
    if (!city && lines.length > 1 && lines[1]) {
      const secondLine = lines[1].trim()
      // Try to parse city, state, zip from the second line - ReDoS safe version
      const cityStateZipMatch2 = secondLine.match(/^([^,]{1,50}),?\s*([A-Z]{2})\s*([0-9]{5}(?:-[0-9]{4})?)?/)
      if (cityStateZipMatch2 && cityStateZipMatch2[1]) {
        city = cityStateZipMatch2[1].trim()
        if (!state && cityStateZipMatch2[2]) {
          state = cityStateZipMatch2[2]
        }
        if (!zipCode && cityStateZipMatch2[3]) {
          zipCode = cityStateZipMatch2[3]
        }
      } else {
        // If no state/zip pattern, just use the line as city
        city = secondLine
      }
    }

    return {
      street: street || '',
      suite: suite || undefined,
      city: city || '',
      state: state || '',
      zipCode: zipCode || ''
    }
  }

  /**
   * Extract contact person from contact information
   */
  private extractContactPerson(contactInfo: ExtractedContact): string | undefined {
    // Look for contact person patterns in structured data
    if (contactInfo.structuredData) {
      for (const data of contactInfo.structuredData) {
        if (data.type === 'Person' && data.data.name) {
          return data.data.name
        }
        if (data.type === 'Organization' && data.data.contactPoint?.name) {
          return data.data.contactPoint.name
        }
      }
    }

    // Look for contact person in business name or other fields
    const businessName = contactInfo.businessName
    if (businessName) {
      // Check if business name contains person indicators
      const personPatterns = [
        /^(Dr\.|Mr\.|Ms\.|Mrs\.|Prof\.)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)/,
        /([A-Z][a-z]+\s+[A-Z][a-z]+)\s+(MD|DDS|PhD|CPA|Esq\.?)/,
        /^([A-Z][a-z]+\s+[A-Z][a-z]+)(?:\s+&|\s+and|\s+,)/
      ]

      for (const pattern of personPatterns) {
        const match = businessName.match(pattern)
        if (match) {
          // For title patterns (Dr. Name), return group 2 (the name)
          // For suffix patterns (Name CPA), return group 1 (the name)
          // For partnership patterns (Name & Name), return group 1 (the first name)
          if (pattern.source.includes('Dr\\.|Mr\\.|Ms\\.|Mrs\\.|Prof\\.')) {
            return match[2] // Title pattern - name is in group 2
          } else {
            return match[1] // Suffix or partnership pattern - name is in group 1
          }
        }
      }
    }

    return undefined
  }

  /**
   * Enhanced email validation and prioritization
   */
  private prioritizeEmails(emails: string[]): string[] {
    const emailPriority = {
      // High priority - business emails
      business: /^(info|contact|sales|support|admin|office|hello|inquiries)@/i,
      // Medium priority - general emails
      general: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      // Low priority - personal or generic
      personal: /^(noreply|no-reply|donotreply|test|example)@/i
    }

    const prioritized = emails
      .filter(email => this.isValidEmail(email))
      .sort((a, b) => {
        // Prioritize business emails
        if (emailPriority.business.test(a) && !emailPriority.business.test(b)) return -1
        if (!emailPriority.business.test(a) && emailPriority.business.test(b)) return 1

        // Deprioritize personal/generic emails
        if (emailPriority.personal.test(a) && !emailPriority.personal.test(b)) return 1
        if (!emailPriority.personal.test(a) && emailPriority.personal.test(b)) return -1

        return 0
      })

    return prioritized
  }

  /**
   * Validate email address
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email) && email.length < 100
  }

  /**
   * Format and validate phone numbers
   */
  private formatPhoneNumber(phone: string): string {
    // Remove all non-digit characters
    const digits = phone.replace(/\D/g, '')

    // Handle US phone numbers
    if (digits.length === 10) {
      return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
    }

    // Return original if can't format
    return phone
  }


}

/**
 * Default enhanced scraping engine instance
 */
export const enhancedScrapingEngine = new EnhancedScrapingEngine()
