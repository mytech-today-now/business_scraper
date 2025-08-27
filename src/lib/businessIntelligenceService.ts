'use strict'

import { BusinessIntelligence, TechnologyPlatform, SocialMediaProfile } from '@/types/business'
import { logger } from '@/utils/logger'
import { Page } from 'puppeteer'

/**
 * Business Intelligence Enrichment Service
 * Comprehensive business data enrichment including company size, revenue estimation,
 * technology stack detection, and social media presence analysis
 */
export class BusinessIntelligenceService {
  private static instance: BusinessIntelligenceService
  private enrichmentCache = new Map<string, BusinessIntelligence>()
  private technologyCache = new Map<string, TechnologyPlatform[]>()
  private socialMediaCache = new Map<string, SocialMediaProfile[]>()

  // Cache TTL settings
  private readonly CACHE_TTL = 7 * 24 * 60 * 60 * 1000 // 7 days
  private readonly TECH_CACHE_TTL = 30 * 24 * 60 * 60 * 1000 // 30 days

  // Technology detection patterns
  private readonly technologySignatures = new Map([
    // Content Management Systems
    [
      'WordPress',
      {
        patterns: ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
        category: 'cms' as const,
        indicators: ['wp-content', 'wp-admin', 'wp-json'],
      },
    ],
    [
      'Shopify',
      {
        patterns: ['shopify', 'myshopify.com', 'cdn.shopify.com'],
        category: 'ecommerce' as const,
        indicators: ['shopify-section', 'shopify-product'],
      },
    ],
    [
      'Wix',
      {
        patterns: ['wix.com', 'wixstatic.com', 'wix-code'],
        category: 'cms' as const,
        indicators: ['wix-site', 'wix-page'],
      },
    ],
    [
      'Squarespace',
      {
        patterns: ['squarespace.com', 'squarespace-cdn.com'],
        category: 'cms' as const,
        indicators: ['squarespace-config'],
      },
    ],

    // E-commerce Platforms
    [
      'Magento',
      {
        patterns: ['/skin/frontend/', 'mage/cookies', 'magento'],
        category: 'ecommerce' as const,
        indicators: ['mage-', 'magento-'],
      },
    ],
    [
      'WooCommerce',
      {
        patterns: ['woocommerce', 'wc-', '/woocommerce/'],
        category: 'ecommerce' as const,
        indicators: ['woocommerce-page', 'wc-product'],
      },
    ],

    // Analytics & Marketing
    [
      'Google Analytics',
      {
        patterns: ['google-analytics.com', 'gtag(', 'ga('],
        category: 'analytics' as const,
        indicators: ['gtag', 'google-analytics'],
      },
    ],
    [
      'Facebook Pixel',
      {
        patterns: ['facebook.net/tr', 'fbq('],
        category: 'marketing' as const,
        indicators: ['facebook-pixel', 'fbq'],
      },
    ],
    [
      'HubSpot',
      {
        patterns: ['hubspot.com', 'hs-scripts.com'],
        category: 'marketing' as const,
        indicators: ['hubspot-', 'hs-'],
      },
    ],

    // Hosting & Infrastructure
    [
      'Cloudflare',
      {
        patterns: ['cloudflare.com', 'cf-ray'],
        category: 'hosting' as const,
        indicators: ['cloudflare', 'cf-ray'],
      },
    ],
    [
      'AWS',
      {
        patterns: ['amazonaws.com', 'aws.amazon.com'],
        category: 'hosting' as const,
        indicators: ['aws-', 'amazon-'],
      },
    ],
  ])

  // Company size indicators
  private readonly companySizeIndicators = {
    small: ['startup', 'small business', 'family owned', 'local', 'boutique'],
    medium: ['growing', 'expanding', 'regional', 'established', 'mid-size'],
    large: ['enterprise', 'corporation', 'multinational', 'global', 'fortune'],
    enterprise: ['fortune 500', 'publicly traded', 'nasdaq', 'nyse', 'international'],
  }

  // Revenue estimation keywords
  private readonly revenueIndicators = {
    low: ['startup', 'new business', 'small', 'local'],
    medium: ['growing', 'established', 'regional'],
    high: ['enterprise', 'corporation', 'leader', 'major'],
    veryHigh: ['fortune', 'billion', 'multinational', 'global leader'],
  }

  // Social media platform patterns
  private readonly socialMediaPatterns = [
    { platform: 'LinkedIn', patterns: ['linkedin.com/company/', 'linkedin.com/in/'] },
    { platform: 'Facebook', patterns: ['facebook.com/', 'fb.com/'] },
    { platform: 'Twitter', patterns: ['twitter.com/', 'x.com/'] },
    { platform: 'Instagram', patterns: ['instagram.com/'] },
    {
      platform: 'YouTube',
      patterns: ['youtube.com/channel/', 'youtube.com/c/', 'youtube.com/user/'],
    },
    { platform: 'TikTok', patterns: ['tiktok.com/@'] },
  ]

  private constructor() {
    this.initializeEnrichmentData()
  }

  public static getInstance(): BusinessIntelligenceService {
    if (!BusinessIntelligenceService.instance) {
      BusinessIntelligenceService.instance = new BusinessIntelligenceService()
    }
    return BusinessIntelligenceService.instance
  }

  /**
   * Enrich business data with comprehensive intelligence
   */
  public async enrichBusinessData(
    websiteUrl: string,
    businessName: string,
    page?: Page
  ): Promise<BusinessIntelligence> {
    const cacheKey = `${websiteUrl}-${businessName}`

    // Check cache first
    if (this.enrichmentCache.has(cacheKey)) {
      const cached = this.enrichmentCache.get(cacheKey)!
      // Check if cache is still valid
      if (
        cached.companySize?.lastUpdated &&
        Date.now() - new Date(cached.companySize.lastUpdated).getTime() < this.CACHE_TTL
      ) {
        return cached
      }
    }

    const enrichmentData = await this.performBusinessEnrichment(websiteUrl, businessName, page)

    // Cache the result
    this.enrichmentCache.set(cacheKey, enrichmentData)

    return enrichmentData
  }

  /**
   * Perform comprehensive business enrichment
   */
  private async performBusinessEnrichment(
    websiteUrl: string,
    businessName: string,
    page?: Page
  ): Promise<BusinessIntelligence> {
    const timestamp = new Date().toISOString()

    try {
      // 1. Company size estimation
      const companySize = await this.estimateCompanySize(websiteUrl, businessName, page)

      // 2. Revenue estimation
      const revenue = await this.estimateRevenue(websiteUrl, businessName, companySize, page)

      // 3. Business maturity assessment
      const businessMaturity = await this.assessBusinessMaturity(websiteUrl, businessName, page)

      // 4. Technology stack detection
      const technologyStack = await this.detectTechnologyStack(websiteUrl, page)

      // 5. Social media presence analysis
      const socialMediaPresence = await this.analyzeSocialMediaPresence(
        websiteUrl,
        businessName,
        page
      )

      const enrichmentData: BusinessIntelligence = {
        companySize,
        revenue,
        businessMaturity,
        technologyStack,
        socialMediaPresence,
      }

      logger.debug('BusinessIntelligenceService', `Enriched business data for ${businessName}`, {
        companySize: companySize?.employeeRange,
        revenue: revenue?.revenueRange,
        techPlatforms: technologyStack?.platforms?.length || 0,
        socialProfiles: socialMediaPresence?.profiles?.length || 0,
      })

      return enrichmentData
    } catch (error) {
      logger.error('BusinessIntelligenceService', `Enrichment failed for ${businessName}`, error)

      // Return minimal enrichment data on error
      return {
        companySize: {
          confidence: 0,
          source: 'error',
          lastUpdated: timestamp,
        },
        revenue: {
          confidence: 0,
          source: 'error',
          lastUpdated: timestamp,
        },
        businessMaturity: {
          confidence: 0,
          indicators: [],
        },
        technologyStack: {
          platforms: [],
          confidence: 0,
          lastScanned: timestamp,
        },
        socialMediaPresence: {
          profiles: [],
          overallPresence: 0,
        },
      }
    }
  }

  /**
   * Estimate company size based on various indicators
   */
  private async estimateCompanySize(
    websiteUrl: string,
    businessName: string,
    page?: Page
  ): Promise<{
    employeeCount?: number
    employeeRange?: string
    confidence: number
    source?: string
    lastUpdated?: string
  }> {
    const timestamp = new Date().toISOString()
    let confidence = 0
    let employeeRange = ''
    let source = 'website_analysis'

    try {
      if (page) {
        // Analyze website content for size indicators
        const pageContent = await page.content()
        const textContent = await page.evaluate(() => document.body.innerText || '')

        // Look for explicit employee count mentions
        const employeeMatches = textContent.match(/(\d+)\s*(?:\+)?\s*employees?/i)
        if (employeeMatches) {
          const count = parseInt(employeeMatches[1])
          return {
            employeeCount: count,
            employeeRange: this.getEmployeeRange(count),
            confidence: 85,
            source: 'explicit_mention',
            lastUpdated: timestamp,
          }
        }

        // Analyze content for size indicators
        const contentLower = textContent.toLowerCase()

        for (const [size, indicators] of Object.entries(this.companySizeIndicators)) {
          for (const indicator of indicators) {
            if (contentLower.includes(indicator)) {
              confidence += 10
              employeeRange = this.getSizeRangeFromCategory(size)
              source = 'content_analysis'
            }
          }
        }

        // Analyze website complexity as size indicator
        const complexityScore = await this.analyzeWebsiteComplexity(page)
        confidence += complexityScore * 0.3

        if (!employeeRange) {
          employeeRange = this.estimateRangeFromComplexity(complexityScore)
        }
      }

      // Fallback to business name analysis
      if (confidence < 30) {
        const nameAnalysis = this.analyzeBusinessNameForSize(businessName)
        confidence = Math.max(confidence, nameAnalysis.confidence)
        employeeRange = nameAnalysis.range || employeeRange || '1-10'
      }

      return {
        employeeRange,
        confidence: Math.min(100, Math.max(0, Math.round(confidence))),
        source,
        lastUpdated: timestamp,
      }
    } catch (error) {
      logger.debug(
        'BusinessIntelligenceService',
        `Company size estimation failed for ${businessName}`,
        error
      )
      return {
        employeeRange: '1-10',
        confidence: 20,
        source: 'default_estimate',
        lastUpdated: timestamp,
      }
    }
  }

  /**
   * Get employee range from count
   */
  private getEmployeeRange(count: number): string {
    if (count <= 10) return '1-10'
    if (count <= 50) return '11-50'
    if (count <= 200) return '51-200'
    if (count <= 500) return '201-500'
    if (count <= 1000) return '501-1000'
    if (count <= 5000) return '1001-5000'
    return '5000+'
  }

  /**
   * Get size range from category
   */
  private getSizeRangeFromCategory(category: string): string {
    switch (category) {
      case 'small':
        return '1-10'
      case 'medium':
        return '11-50'
      case 'large':
        return '51-200'
      case 'enterprise':
        return '200+'
      default:
        return '1-10'
    }
  }

  /**
   * Analyze website complexity to estimate company size
   */
  private async analyzeWebsiteComplexity(page: Page): Promise<number> {
    try {
      const complexity = await page.evaluate(() => {
        let score = 0

        // Count different types of elements
        score += document.querySelectorAll('script').length * 0.5
        score += document.querySelectorAll('link[rel="stylesheet"]').length * 2
        score += document.querySelectorAll('img').length * 0.1
        score += document.querySelectorAll('a').length * 0.05

        // Check for complex features
        if (document.querySelector('[data-react]') || document.querySelector('[ng-app]')) {
          score += 20 // Modern framework
        }

        if (document.querySelector('form')) {
          score += 10 // Interactive forms
        }

        if (document.querySelector('video, iframe')) {
          score += 15 // Rich media
        }

        return Math.min(100, score)
      })

      return complexity
    } catch (error) {
      return 20 // Default low complexity
    }
  }

  /**
   * Estimate range from website complexity
   */
  private estimateRangeFromComplexity(complexity: number): string {
    if (complexity < 20) return '1-10'
    if (complexity < 40) return '11-50'
    if (complexity < 70) return '51-200'
    return '200+'
  }

  /**
   * Analyze business name for size indicators
   */
  private analyzeBusinessNameForSize(businessName: string): { confidence: number; range?: string } {
    const nameLower = businessName.toLowerCase()

    // Enterprise indicators
    if (
      nameLower.includes('corporation') ||
      nameLower.includes('corp') ||
      nameLower.includes('inc') ||
      nameLower.includes('llc')
    ) {
      return { confidence: 40, range: '11-50' }
    }

    // Small business indicators
    if (
      nameLower.includes('shop') ||
      nameLower.includes('boutique') ||
      nameLower.includes('studio') ||
      nameLower.includes('cafe')
    ) {
      return { confidence: 35, range: '1-10' }
    }

    return { confidence: 20 }
  }

  /**
   * Estimate revenue based on company size and other indicators
   */
  private async estimateRevenue(
    websiteUrl: string,
    businessName: string,
    companySize: any,
    page?: Page
  ): Promise<{
    estimatedRevenue?: number
    revenueRange?: string
    confidence: number
    source?: string
    lastUpdated?: string
  }> {
    const timestamp = new Date().toISOString()
    let confidence = 0
    let revenueRange = ''
    let source = 'estimation'

    try {
      // Base revenue estimation on company size
      if (companySize?.employeeRange) {
        const sizeBasedRevenue = this.estimateRevenueFromSize(companySize.employeeRange)
        confidence += 30
        revenueRange = sizeBasedRevenue.range
      }

      if (page) {
        // Look for explicit revenue mentions
        const textContent = await page.evaluate(() => document.body.innerText || '')
        const revenueMatches = textContent.match(/\$(\d+(?:\.\d+)?)\s*(?:million|billion|M|B)/i)

        if (revenueMatches) {
          const amount = parseFloat(revenueMatches[1])
          const unit = revenueMatches[0].toLowerCase().includes('b') ? 'billion' : 'million'
          const revenue = unit === 'billion' ? amount * 1000000000 : amount * 1000000

          return {
            estimatedRevenue: revenue,
            revenueRange: this.getRevenueRange(revenue),
            confidence: 80,
            source: 'explicit_mention',
            lastUpdated: timestamp,
          }
        }

        // Analyze content for revenue indicators
        const contentLower = textContent.toLowerCase()
        for (const [level, indicators] of Object.entries(this.revenueIndicators)) {
          for (const indicator of indicators) {
            if (contentLower.includes(indicator)) {
              confidence += 5
              revenueRange = this.getRevenueRangeFromLevel(level)
              source = 'content_analysis'
            }
          }
        }
      }

      // Fallback to industry averages
      if (confidence < 40) {
        const industryEstimate = this.estimateRevenueFromIndustry(businessName)
        confidence = Math.max(confidence, 25)
        revenueRange = revenueRange || industryEstimate
      }

      return {
        revenueRange: revenueRange || '$100K-$1M',
        confidence: Math.min(100, Math.max(0, Math.round(confidence))),
        source,
        lastUpdated: timestamp,
      }
    } catch (error) {
      logger.debug(
        'BusinessIntelligenceService',
        `Revenue estimation failed for ${businessName}`,
        error
      )
      return {
        revenueRange: '$100K-$1M',
        confidence: 20,
        source: 'default_estimate',
        lastUpdated: timestamp,
      }
    }
  }

  /**
   * Estimate revenue from company size
   */
  private estimateRevenueFromSize(employeeRange: string): { range: string } {
    switch (employeeRange) {
      case '1-10':
        return { range: '$100K-$1M' }
      case '11-50':
        return { range: '$1M-$10M' }
      case '51-200':
        return { range: '$10M-$50M' }
      case '201-500':
        return { range: '$50M-$100M' }
      case '501-1000':
        return { range: '$100M-$500M' }
      case '1001-5000':
        return { range: '$500M-$1B' }
      case '5000+':
        return { range: '$1B+' }
      default:
        return { range: '$100K-$1M' }
    }
  }

  /**
   * Get revenue range from amount
   */
  private getRevenueRange(amount: number): string {
    if (amount < 1000000) return 'Under $1M'
    if (amount < 10000000) return '$1M-$10M'
    if (amount < 50000000) return '$10M-$50M'
    if (amount < 100000000) return '$50M-$100M'
    if (amount < 500000000) return '$100M-$500M'
    if (amount < 1000000000) return '$500M-$1B'
    return '$1B+'
  }

  /**
   * Get revenue range from level
   */
  private getRevenueRangeFromLevel(level: string): string {
    switch (level) {
      case 'low':
        return '$100K-$1M'
      case 'medium':
        return '$1M-$10M'
      case 'high':
        return '$10M-$100M'
      case 'veryHigh':
        return '$100M+'
      default:
        return '$100K-$1M'
    }
  }

  /**
   * Estimate revenue from industry patterns
   */
  private estimateRevenueFromIndustry(businessName: string): string {
    const nameLower = businessName.toLowerCase()

    // High-revenue industries
    if (
      nameLower.includes('bank') ||
      nameLower.includes('financial') ||
      nameLower.includes('insurance') ||
      nameLower.includes('pharma')
    ) {
      return '$10M-$100M'
    }

    // Medium-revenue industries
    if (
      nameLower.includes('tech') ||
      nameLower.includes('software') ||
      nameLower.includes('consulting') ||
      nameLower.includes('medical')
    ) {
      return '$1M-$10M'
    }

    // Service industries
    if (
      nameLower.includes('restaurant') ||
      nameLower.includes('retail') ||
      nameLower.includes('salon') ||
      nameLower.includes('repair')
    ) {
      return '$100K-$1M'
    }

    return '$100K-$1M'
  }

  /**
   * Assess business maturity
   */
  private async assessBusinessMaturity(
    websiteUrl: string,
    businessName: string,
    page?: Page
  ): Promise<{
    yearsInBusiness?: number
    maturityStage?: 'startup' | 'growth' | 'mature' | 'enterprise'
    confidence: number
    indicators?: string[]
  }> {
    const indicators: string[] = []
    let confidence = 0
    let maturityStage: 'startup' | 'growth' | 'mature' | 'enterprise' = 'startup'

    try {
      if (page) {
        const textContent = await page.evaluate(() => document.body.innerText || '')
        const contentLower = textContent.toLowerCase()

        // Look for explicit founding year
        const yearMatches = textContent.match(/(?:founded|established|since)\s+(\d{4})/i)
        if (yearMatches) {
          const foundingYear = parseInt(yearMatches[1])
          const currentYear = new Date().getFullYear()
          const yearsInBusiness = currentYear - foundingYear

          if (yearsInBusiness > 0) {
            confidence += 70
            indicators.push(`Founded in ${foundingYear}`)

            if (yearsInBusiness < 3) maturityStage = 'startup'
            else if (yearsInBusiness < 10) maturityStage = 'growth'
            else if (yearsInBusiness < 25) maturityStage = 'mature'
            else maturityStage = 'enterprise'

            return {
              yearsInBusiness,
              maturityStage,
              confidence,
              indicators,
            }
          }
        }

        // Analyze content for maturity indicators
        const maturityKeywords = {
          startup: ['startup', 'new', 'launched', 'emerging', 'innovative'],
          growth: ['growing', 'expanding', 'scaling', 'developing'],
          mature: ['established', 'experienced', 'proven', 'trusted', 'leader'],
          enterprise: ['industry leader', 'market leader', 'decades', 'generations'],
        }

        for (const [stage, keywords] of Object.entries(maturityKeywords)) {
          for (const keyword of keywords) {
            if (contentLower.includes(keyword)) {
              confidence += 10
              indicators.push(`Contains "${keyword}"`)
              maturityStage = stage as any
            }
          }
        }
      }

      // Analyze business name for maturity indicators
      const nameAnalysis = this.analyzeBusinessNameForMaturity(businessName)
      confidence = Math.max(confidence, nameAnalysis.confidence)
      if (nameAnalysis.stage) {
        maturityStage = nameAnalysis.stage
      }
      indicators.push(...nameAnalysis.indicators)

      return {
        maturityStage,
        confidence: Math.min(100, Math.max(0, Math.round(confidence))),
        indicators,
      }
    } catch (error) {
      logger.debug(
        'BusinessIntelligenceService',
        `Maturity assessment failed for ${businessName}`,
        error
      )
      return {
        maturityStage: 'startup',
        confidence: 20,
        indicators: ['Default assessment'],
      }
    }
  }

  /**
   * Analyze business name for maturity indicators
   */
  private analyzeBusinessNameForMaturity(businessName: string): {
    confidence: number
    stage?: 'startup' | 'growth' | 'mature' | 'enterprise'
    indicators: string[]
  } {
    const nameLower = businessName.toLowerCase()
    const indicators: string[] = []

    if (
      nameLower.includes('corp') ||
      nameLower.includes('corporation') ||
      nameLower.includes('inc') ||
      nameLower.includes('ltd')
    ) {
      indicators.push('Corporate structure')
      return { confidence: 40, stage: 'mature', indicators }
    }

    if (nameLower.includes('llc') || nameLower.includes('group') || nameLower.includes('company')) {
      indicators.push('Business entity structure')
      return { confidence: 30, stage: 'growth', indicators }
    }

    return { confidence: 20, indicators: ['Name analysis'] }
  }

  /**
   * Detect technology stack used by the website
   */
  private async detectTechnologyStack(
    websiteUrl: string,
    page?: Page
  ): Promise<{
    platforms?: TechnologyPlatform[]
    confidence: number
    lastScanned?: string
  }> {
    const timestamp = new Date().toISOString()
    const platforms: TechnologyPlatform[] = []
    let overallConfidence = 0

    // Check cache first
    if (this.technologyCache.has(websiteUrl)) {
      return {
        platforms: this.technologyCache.get(websiteUrl),
        confidence: 90,
        lastScanned: timestamp,
      }
    }

    try {
      if (page) {
        // Analyze page content for technology signatures
        const [htmlContent, scripts, stylesheets, headers] = await Promise.all([
          page.content(),
          page.evaluate(() =>
            Array.from(document.querySelectorAll('script')).map(s => s.src || s.innerHTML)
          ),
          page.evaluate(() =>
            Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map(l => l.href)
          ),
          page.evaluate(() => {
            const meta = Array.from(document.querySelectorAll('meta')).map(m => ({
              name: m.getAttribute('name') || m.getAttribute('property'),
              content: m.getAttribute('content'),
            }))
            return meta
          }),
        ])

        // Detect technologies based on signatures
        for (const [techName, signature] of this.technologySignatures.entries()) {
          const detection = this.detectTechnology(
            techName,
            signature,
            htmlContent,
            scripts,
            stylesheets,
            headers
          )

          if (detection.detected) {
            platforms.push({
              name: techName,
              category: signature.category,
              confidence: detection.confidence,
              indicators: detection.indicators,
            })
            overallConfidence += detection.confidence
          }
        }

        // Additional technology detection through DOM analysis
        const additionalTech = await this.detectAdditionalTechnologies(page)
        platforms.push(...additionalTech)
        overallConfidence += additionalTech.length * 20
      }

      // Normalize confidence
      overallConfidence = Math.min(
        100,
        Math.max(0, overallConfidence / Math.max(1, platforms.length))
      )

      // Cache the results
      this.technologyCache.set(websiteUrl, platforms)

      return {
        platforms,
        confidence: Math.round(overallConfidence),
        lastScanned: timestamp,
      }
    } catch (error) {
      logger.debug(
        'BusinessIntelligenceService',
        `Technology detection failed for ${websiteUrl}`,
        error
      )
      return {
        platforms: [],
        confidence: 0,
        lastScanned: timestamp,
      }
    }
  }

  /**
   * Detect specific technology based on signatures
   */
  private detectTechnology(
    techName: string,
    signature: any,
    htmlContent: string,
    scripts: string[],
    stylesheets: string[],
    headers: any[]
  ): { detected: boolean; confidence: number; indicators: string[] } {
    const indicators: string[] = []
    let confidence = 0

    // Check HTML content
    for (const pattern of signature.patterns) {
      if (htmlContent.toLowerCase().includes(pattern.toLowerCase())) {
        confidence += 30
        indicators.push(`HTML contains "${pattern}"`)
      }
    }

    // Check scripts
    for (const script of scripts) {
      for (const pattern of signature.patterns) {
        if (script.toLowerCase().includes(pattern.toLowerCase())) {
          confidence += 25
          indicators.push(`Script contains "${pattern}"`)
        }
      }
    }

    // Check stylesheets
    for (const stylesheet of stylesheets) {
      for (const pattern of signature.patterns) {
        if (stylesheet.toLowerCase().includes(pattern.toLowerCase())) {
          confidence += 20
          indicators.push(`Stylesheet contains "${pattern}"`)
        }
      }
    }

    // Check meta tags
    for (const meta of headers) {
      if (meta.name && meta.content) {
        for (const pattern of signature.patterns) {
          if (meta.content.toLowerCase().includes(pattern.toLowerCase())) {
            confidence += 15
            indicators.push(`Meta tag contains "${pattern}"`)
          }
        }
      }
    }

    return {
      detected: confidence > 20,
      confidence: Math.min(100, confidence),
      indicators,
    }
  }

  /**
   * Detect additional technologies through DOM analysis
   */
  private async detectAdditionalTechnologies(page: Page): Promise<TechnologyPlatform[]> {
    try {
      return await page.evaluate(() => {
        const technologies: any[] = []

        // Check for React
        if ((window as any).React || document.querySelector('[data-reactroot]')) {
          technologies.push({
            name: 'React',
            category: 'other',
            confidence: 80,
            indicators: ['React detected in DOM'],
          })
        }

        // Check for Angular
        if ((window as any).angular || document.querySelector('[ng-app]')) {
          technologies.push({
            name: 'Angular',
            category: 'other',
            confidence: 80,
            indicators: ['Angular detected in DOM'],
          })
        }

        // Check for Vue.js
        if ((window as any).Vue || document.querySelector('[data-v-]')) {
          technologies.push({
            name: 'Vue.js',
            category: 'other',
            confidence: 80,
            indicators: ['Vue.js detected in DOM'],
          })
        }

        // Check for jQuery
        if ((window as any).jQuery || (window as any).$) {
          technologies.push({
            name: 'jQuery',
            category: 'other',
            confidence: 70,
            indicators: ['jQuery detected'],
          })
        }

        return technologies
      })
    } catch (error) {
      return []
    }
  }

  /**
   * Analyze social media presence
   */
  private async analyzeSocialMediaPresence(
    websiteUrl: string,
    businessName: string,
    page?: Page
  ): Promise<{
    profiles: SocialMediaProfile[]
    overallPresence: number
    engagement?: {
      totalFollowers?: number
      averageEngagement?: number
      lastActivity?: string
    }
  }> {
    const profiles: SocialMediaProfile[] = []
    let overallPresence = 0

    // Check cache first
    if (this.socialMediaCache.has(websiteUrl)) {
      const cachedProfiles = this.socialMediaCache.get(websiteUrl)!
      return {
        profiles: cachedProfiles,
        overallPresence: cachedProfiles.length * 20,
      }
    }

    try {
      if (page) {
        // Extract social media links from the page
        const socialLinks = await page.evaluate(() => {
          const links = Array.from(document.querySelectorAll('a[href]'))
          return links
            .map(link => ({
              href: link.getAttribute('href') || '',
              text: link.textContent || '',
              title: link.getAttribute('title') || '',
            }))
            .filter(link => link.href)
        })

        // Analyze links for social media platforms
        for (const link of socialLinks) {
          for (const platform of this.socialMediaPatterns) {
            for (const pattern of platform.patterns) {
              if (link.href.includes(pattern)) {
                const profile = this.extractSocialMediaProfile(platform.platform, link.href)
                if (profile) {
                  profiles.push(profile)
                  overallPresence += 20
                }
              }
            }
          }
        }

        // Look for social media widgets or embedded content
        const widgets = await this.detectSocialMediaWidgets(page)
        profiles.push(...widgets)
        overallPresence += widgets.length * 15
      }

      // Remove duplicates
      const uniqueProfiles = this.deduplicateSocialProfiles(profiles)
      overallPresence = Math.min(100, overallPresence)

      // Cache the results
      this.socialMediaCache.set(websiteUrl, uniqueProfiles)

      return {
        profiles: uniqueProfiles,
        overallPresence: Math.round(overallPresence),
      }
    } catch (error) {
      logger.debug(
        'BusinessIntelligenceService',
        `Social media analysis failed for ${websiteUrl}`,
        error
      )
      return {
        profiles: [],
        overallPresence: 0,
      }
    }
  }

  /**
   * Extract social media profile information
   */
  private extractSocialMediaProfile(platform: string, url: string): SocialMediaProfile | null {
    try {
      const urlObj = new URL(url)
      const pathname = urlObj.pathname

      // Extract handle from URL
      let handle = ''
      if (platform === 'LinkedIn') {
        const match = pathname.match(/\/(?:company|in)\/([^\/]+)/)
        handle = match ? match[1] : ''
      } else if (platform === 'Twitter' || platform === 'X') {
        const match = pathname.match(/\/([^\/]+)/)
        handle = match ? `@${match[1]}` : ''
      } else {
        const match = pathname.match(/\/([^\/]+)/)
        handle = match ? match[1] : ''
      }

      if (handle) {
        return {
          platform,
          url,
          handle,
          confidence: 80,
        }
      }
    } catch (error) {
      // Invalid URL
    }

    return null
  }

  /**
   * Detect social media widgets
   */
  private async detectSocialMediaWidgets(page: Page): Promise<SocialMediaProfile[]> {
    try {
      return await page.evaluate(() => {
        const widgets: any[] = []

        // Facebook widgets
        if (document.querySelector('.fb-page, .fb-like, .fb-share-button')) {
          widgets.push({
            platform: 'Facebook',
            url: '',
            confidence: 60,
          })
        }

        // Twitter widgets
        if (document.querySelector('.twitter-timeline, .twitter-tweet')) {
          widgets.push({
            platform: 'Twitter',
            url: '',
            confidence: 60,
          })
        }

        // LinkedIn widgets
        if (document.querySelector('.linkedin-share-button, .IN-widget')) {
          widgets.push({
            platform: 'LinkedIn',
            url: '',
            confidence: 60,
          })
        }

        return widgets
      })
    } catch (error) {
      return []
    }
  }

  /**
   * Remove duplicate social media profiles
   */
  private deduplicateSocialProfiles(profiles: SocialMediaProfile[]): SocialMediaProfile[] {
    const seen = new Set<string>()
    return profiles.filter(profile => {
      const key = `${profile.platform}-${profile.url || profile.handle}`
      if (seen.has(key)) {
        return false
      }
      seen.add(key)
      return true
    })
  }

  /**
   * Clear all caches
   */
  public clearCache(): void {
    this.enrichmentCache.clear()
    this.technologyCache.clear()
    this.socialMediaCache.clear()
    logger.debug('BusinessIntelligenceService', 'All caches cleared')
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): {
    enrichmentCacheSize: number
    technologyCacheSize: number
    socialMediaCacheSize: number
  } {
    return {
      enrichmentCacheSize: this.enrichmentCache.size,
      technologyCacheSize: this.technologyCache.size,
      socialMediaCacheSize: this.socialMediaCache.size,
    }
  }

  /**
   * Initialize enrichment data (placeholder)
   */
  private async initializeEnrichmentData(): Promise<void> {
    logger.debug('BusinessIntelligenceService', 'Initialized business intelligence service')
  }
}
