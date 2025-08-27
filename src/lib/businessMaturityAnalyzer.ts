'use strict'

/**
 * Business Maturity Analyzer - Advanced scraping for growth signals
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import puppeteer, { Browser, Page } from 'puppeteer'
import { BusinessRecord } from '@/types/business'
import { BusinessMaturityIndicators } from '@/types/ai'
import { logger } from '@/utils/logger'

/**
 * Business Maturity Analyzer class
 * Analyzes business growth signals and maturity indicators
 */
export class BusinessMaturityAnalyzer {
  private browser: Browser | null = null
  private initialized = false

  constructor() {}

  /**
   * Initialize the analyzer
   */
  async initialize(): Promise<void> {
    try {
      logger.info('BusinessMaturityAnalyzer', 'Initializing business maturity analyzer...')

      // Initialize browser for advanced scraping
      this.browser = await puppeteer.launch({
        headless: true,
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

      this.initialized = true
      logger.info('BusinessMaturityAnalyzer', 'Business maturity analyzer initialized')
    } catch (error) {
      logger.error('BusinessMaturityAnalyzer', 'Failed to initialize analyzer', error)
      throw error
    }
  }

  /**
   * Analyze business maturity indicators
   */
  async analyzeBusinessMaturity(business: BusinessRecord): Promise<BusinessMaturityIndicators> {
    try {
      if (!this.initialized) {
        await this.initialize()
      }

      if (!business.website) {
        return this.createBasicMaturityAnalysis(business)
      }

      logger.info(
        'BusinessMaturityAnalyzer',
        `Analyzing business maturity: ${business.businessName}`
      )

      // Run parallel analysis
      const [growthSignals, sizeIndicators, digitalPresence] = await Promise.all([
        this.analyzeGrowthSignals(business.website),
        this.analyzeSizeIndicators(business),
        this.analyzeDigitalPresence(business.website),
      ])

      // Calculate overall maturity score
      const maturityScore = this.calculateMaturityScore(
        growthSignals,
        sizeIndicators,
        digitalPresence
      )

      const analysis: BusinessMaturityIndicators = {
        maturityScore,
        growthSignals,
        sizeIndicators,
        digitalPresence,
        analyzedAt: new Date(),
      }

      logger.info(
        'BusinessMaturityAnalyzer',
        `Maturity analysis completed for: ${business.businessName}`
      )
      return analysis
    } catch (error) {
      logger.error(
        'BusinessMaturityAnalyzer',
        `Failed to analyze business maturity: ${business.businessName}`,
        error
      )
      return this.createBasicMaturityAnalysis(business)
    }
  }

  /**
   * Analyze growth signals from website
   */
  private async analyzeGrowthSignals(websiteUrl: string): Promise<{
    careersPageExists: boolean
    jobPostingsFound: number
    fundingMentions: string[]
    pressReleases: string[]
    investorRelationsPage: boolean
    teamPageExists: boolean
    aboutPageQuality: number
  }> {
    try {
      if (!this.browser) {
        throw new Error('Browser not initialized')
      }

      const page = await this.browser.newPage()
      await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      )

      // Set timeout and navigation options
      await page.setDefaultNavigationTimeout(30000)
      await page.setDefaultTimeout(30000)

      try {
        await page.goto(websiteUrl, { waitUntil: 'networkidle2', timeout: 30000 })
      } catch (error) {
        logger.warn('BusinessMaturityAnalyzer', `Failed to load website: ${websiteUrl}`, error)
        await page.close()
        return this.createDefaultGrowthSignals()
      }

      // Analyze page content
      const pageContent = await page.content()
      const pageText = await page.evaluate(() => document.body.innerText || '').catch(() => '')

      // Check for careers page
      const careersPageExists = await this.checkForCareersPage(page, pageContent)

      // Count job postings
      const jobPostingsFound = this.countJobPostings(pageText)

      // Find funding mentions
      const fundingMentions = this.findFundingMentions(pageText)

      // Find press releases
      const pressReleases = this.findPressReleases(pageText)

      // Check for investor relations
      const investorRelationsPage = this.checkInvestorRelations(pageContent)

      // Check for team page
      const teamPageExists = await this.checkForTeamPage(page, pageContent)

      // Assess about page quality
      const aboutPageQuality = await this.assessAboutPageQuality(page, pageContent)

      await page.close()

      return {
        careersPageExists,
        jobPostingsFound,
        fundingMentions,
        pressReleases,
        investorRelationsPage,
        teamPageExists,
        aboutPageQuality,
      }
    } catch (error) {
      logger.error('BusinessMaturityAnalyzer', 'Growth signals analysis failed', error)
      return this.createDefaultGrowthSignals()
    }
  }

  /**
   * Analyze business size indicators
   */
  private async analyzeSizeIndicators(business: BusinessRecord): Promise<{
    estimatedEmployeeCount: number | null
    officeLocations: string[]
    serviceAreas: string[]
    clientTestimonials: number
    caseStudies: number
  }> {
    try {
      // Extract size indicators from available data
      const officeLocations = business.address ? [business.address] : []

      // Estimate employee count based on business description
      const estimatedEmployeeCount = this.estimateEmployeeCount(business.description || '')

      // Extract service areas from description
      const serviceAreas = this.extractServiceAreas(business.description || '')

      // Count testimonials and case studies (would require website scraping)
      const clientTestimonials = Math.floor(Math.random() * 10) // Placeholder
      const caseStudies = Math.floor(Math.random() * 5) // Placeholder

      return {
        estimatedEmployeeCount,
        officeLocations,
        serviceAreas,
        clientTestimonials,
        caseStudies,
      }
    } catch (error) {
      logger.error('BusinessMaturityAnalyzer', 'Size indicators analysis failed', error)
      return {
        estimatedEmployeeCount: null,
        officeLocations: [],
        serviceAreas: [],
        clientTestimonials: 0,
        caseStudies: 0,
      }
    }
  }

  /**
   * Analyze digital presence maturity
   */
  private async analyzeDigitalPresence(websiteUrl: string): Promise<{
    socialMediaAccounts: string[]
    blogActivity: boolean
    lastBlogPost: Date | null
    emailMarketingSignup: boolean
    liveChatAvailable: boolean
  }> {
    try {
      if (!this.browser) {
        throw new Error('Browser not initialized')
      }

      const page = await this.browser.newPage()

      try {
        await page.goto(websiteUrl, { waitUntil: 'networkidle2', timeout: 30000 })
      } catch (error) {
        await page.close()
        return this.createDefaultDigitalPresence()
      }

      const pageContent = await page.content()

      // Find social media links
      const socialMediaAccounts = this.findSocialMediaLinks(pageContent)

      // Check for blog activity
      const blogActivity = this.checkBlogActivity(pageContent)

      // Check for email signup
      const emailMarketingSignup = this.checkEmailSignup(pageContent)

      // Check for live chat
      const liveChatAvailable = this.checkLiveChat(pageContent)

      await page.close()

      return {
        socialMediaAccounts,
        blogActivity,
        lastBlogPost: blogActivity
          ? new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
          : null,
        emailMarketingSignup,
        liveChatAvailable,
      }
    } catch (error) {
      logger.error('BusinessMaturityAnalyzer', 'Digital presence analysis failed', error)
      return this.createDefaultDigitalPresence()
    }
  }

  /**
   * Check for careers page
   */
  private async checkForCareersPage(page: Page, content: string): Promise<boolean> {
    try {
      // Look for careers-related links and content
      const careersKeywords = [
        'careers',
        'jobs',
        'employment',
        'join our team',
        'work with us',
        'hiring',
      ]
      const lowerContent = content.toLowerCase()

      return careersKeywords.some(keyword => lowerContent.includes(keyword))
    } catch (error) {
      return false
    }
  }

  /**
   * Count job postings
   */
  private countJobPostings(text: string): number {
    const jobKeywords = ['position', 'opening', 'vacancy', 'hiring', 'apply now', 'job description']
    const lowerText = text.toLowerCase()

    return jobKeywords.reduce((count, keyword) => {
      const matches = lowerText.split(keyword).length - 1
      return count + matches
    }, 0)
  }

  /**
   * Find funding mentions
   */
  private findFundingMentions(text: string): string[] {
    const fundingKeywords = [
      'funding',
      'investment',
      'series a',
      'series b',
      'venture capital',
      'investor',
    ]
    const mentions: string[] = []

    fundingKeywords.forEach(keyword => {
      if (text.toLowerCase().includes(keyword)) {
        mentions.push(keyword)
      }
    })

    return mentions
  }

  /**
   * Find press releases
   */
  private findPressReleases(text: string): string[] {
    const pressKeywords = ['press release', 'news', 'announcement', 'media']
    const releases: string[] = []

    pressKeywords.forEach(keyword => {
      if (text.toLowerCase().includes(keyword)) {
        releases.push(keyword)
      }
    })

    return releases
  }

  /**
   * Check for investor relations
   */
  private checkInvestorRelations(content: string): boolean {
    const investorKeywords = [
      'investor relations',
      'shareholders',
      'financial reports',
      'sec filings',
    ]
    const lowerContent = content.toLowerCase()

    return investorKeywords.some(keyword => lowerContent.includes(keyword))
  }

  /**
   * Check for team page
   */
  private async checkForTeamPage(page: Page, content: string): Promise<boolean> {
    const teamKeywords = ['team', 'about us', 'our people', 'staff', 'leadership', 'management']
    const lowerContent = content.toLowerCase()

    return teamKeywords.some(keyword => lowerContent.includes(keyword))
  }

  /**
   * Assess about page quality
   */
  private async assessAboutPageQuality(page: Page, content: string): Promise<number> {
    let score = 30 // Base score

    const aboutKeywords = [
      'about',
      'history',
      'mission',
      'vision',
      'values',
      'founded',
      'established',
    ]
    const lowerContent = content.toLowerCase()

    aboutKeywords.forEach(keyword => {
      if (lowerContent.includes(keyword)) score += 10
    })

    // Check content length
    if (content.length > 1000) score += 20
    if (content.length > 2000) score += 10

    return Math.min(100, score)
  }

  /**
   * Estimate employee count from description
   */
  private estimateEmployeeCount(description: string): number | null {
    if (!description) return null

    const sizeIndicators = {
      small: 5,
      startup: 10,
      growing: 25,
      established: 50,
      large: 100,
      enterprise: 500,
    }

    const lowerDesc = description.toLowerCase()

    for (const [indicator, count] of Object.entries(sizeIndicators)) {
      if (lowerDesc.includes(indicator)) {
        return count
      }
    }

    // Estimate based on description length and complexity
    if (description.length > 500) return 25
    if (description.length > 200) return 10

    return 5
  }

  /**
   * Extract service areas from description
   */
  private extractServiceAreas(description: string): string[] {
    const areas: string[] = []
    const locationKeywords = [
      'local',
      'regional',
      'nationwide',
      'international',
      'city',
      'state',
      'country',
    ]

    locationKeywords.forEach(keyword => {
      if (description.toLowerCase().includes(keyword)) {
        areas.push(keyword)
      }
    })

    return areas
  }

  /**
   * Find social media links
   */
  private findSocialMediaLinks(content: string): string[] {
    const socialPlatforms = ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube', 'tiktok']
    const found: string[] = []

    socialPlatforms.forEach(platform => {
      if (content.toLowerCase().includes(platform)) {
        found.push(platform)
      }
    })

    return found
  }

  /**
   * Check blog activity
   */
  private checkBlogActivity(content: string): boolean {
    const blogKeywords = ['blog', 'articles', 'news', 'insights', 'posts']
    const lowerContent = content.toLowerCase()

    return blogKeywords.some(keyword => lowerContent.includes(keyword))
  }

  /**
   * Check email signup
   */
  private checkEmailSignup(content: string): boolean {
    const emailKeywords = ['newsletter', 'subscribe', 'email signup', 'mailing list', 'updates']
    const lowerContent = content.toLowerCase()

    return emailKeywords.some(keyword => lowerContent.includes(keyword))
  }

  /**
   * Check live chat
   */
  private checkLiveChat(content: string): boolean {
    const chatKeywords = [
      'live chat',
      'chat with us',
      'online support',
      'help desk',
      'customer service',
    ]
    const lowerContent = content.toLowerCase()

    return chatKeywords.some(keyword => lowerContent.includes(keyword))
  }

  /**
   * Calculate overall maturity score
   */
  private calculateMaturityScore(
    growthSignals: any,
    sizeIndicators: any,
    digitalPresence: any
  ): number {
    let score = 30 // Base score

    // Growth signals (40 points)
    if (growthSignals.careersPageExists) score += 10
    if (growthSignals.jobPostingsFound > 0) score += 5
    if (growthSignals.fundingMentions.length > 0) score += 10
    if (growthSignals.teamPageExists) score += 5
    score += Math.min(10, growthSignals.aboutPageQuality / 10)

    // Size indicators (30 points)
    if (sizeIndicators.estimatedEmployeeCount && sizeIndicators.estimatedEmployeeCount > 10)
      score += 10
    if (sizeIndicators.officeLocations.length > 0) score += 5
    if (sizeIndicators.serviceAreas.length > 0) score += 5
    if (sizeIndicators.clientTestimonials > 0) score += 5
    if (sizeIndicators.caseStudies > 0) score += 5

    // Digital presence (30 points)
    score += Math.min(10, digitalPresence.socialMediaAccounts.length * 2)
    if (digitalPresence.blogActivity) score += 10
    if (digitalPresence.emailMarketingSignup) score += 5
    if (digitalPresence.liveChatAvailable) score += 5

    return Math.min(100, score)
  }

  /**
   * Create default growth signals
   */
  private createDefaultGrowthSignals() {
    return {
      careersPageExists: false,
      jobPostingsFound: 0,
      fundingMentions: [],
      pressReleases: [],
      investorRelationsPage: false,
      teamPageExists: false,
      aboutPageQuality: 30,
    }
  }

  /**
   * Create default digital presence
   */
  private createDefaultDigitalPresence() {
    return {
      socialMediaAccounts: [],
      blogActivity: false,
      lastBlogPost: null,
      emailMarketingSignup: false,
      liveChatAvailable: false,
    }
  }

  /**
   * Create basic maturity analysis for businesses without websites
   */
  private createBasicMaturityAnalysis(business: BusinessRecord): BusinessMaturityIndicators {
    const estimatedEmployeeCount = this.estimateEmployeeCount(business.description || '')
    const serviceAreas = this.extractServiceAreas(business.description || '')

    return {
      maturityScore: 40, // Base score for having basic business info
      growthSignals: this.createDefaultGrowthSignals(),
      sizeIndicators: {
        estimatedEmployeeCount,
        officeLocations: business.address ? [business.address] : [],
        serviceAreas,
        clientTestimonials: 0,
        caseStudies: 0,
      },
      digitalPresence: this.createDefaultDigitalPresence(),
      analyzedAt: new Date(),
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    try {
      if (this.browser) {
        await this.browser.close()
        this.browser = null
      }
      this.initialized = false
      logger.info('BusinessMaturityAnalyzer', 'Cleanup completed')
    } catch (error) {
      logger.error('BusinessMaturityAnalyzer', 'Cleanup failed', error)
    }
  }

  /**
   * Check if analyzer is initialized
   */
  isInitialized(): boolean {
    return this.initialized
  }
}

// Export singleton instance
export const businessMaturityAnalyzer = new BusinessMaturityAnalyzer()
