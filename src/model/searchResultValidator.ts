'use strict'

import axios from 'axios'
import { logger } from '@/utils/logger'

/**
 * Enhanced search result with validation scores
 */
export interface ValidatedSearchResult {
  url: string
  title: string
  snippet: string
  domain: string
  scores: {
    relevance: number      // 0-1: How relevant to the search query
    authority: number      // 0-1: Domain authority and trustworthiness
    business: number       // 0-1: Likelihood of being a legitimate business
    geographic: number     // 0-1: Geographic relevance to search location
    overall: number        // 0-1: Combined weighted score
  }
  metadata: {
    domainAge?: number     // Domain age in years
    hasSSL: boolean        // Has valid SSL certificate
    businessType?: string  // Classified business type
    isDuplicate: boolean   // Marked as duplicate
    confidence: number     // Overall confidence in result quality
  }
}

/**
 * Search result validation configuration
 */
export interface ValidationConfig {
  minRelevanceScore: number
  minAuthorityScore: number
  minBusinessScore: number
  enableDomainAgeCheck: boolean
  enableSSLCheck: boolean
  enableDuplicateDetection: boolean
  maxDuplicatesPerDomain: number
  weights: {
    relevance: number
    authority: number
    business: number
    geographic: number
  }
}

/**
 * Default validation configuration
 */
const DEFAULT_CONFIG: ValidationConfig = {
  minRelevanceScore: 0.1,
  minAuthorityScore: 0.1,
  minBusinessScore: 0.1,
  enableDomainAgeCheck: true,
  enableSSLCheck: true,
  enableDuplicateDetection: true,
  maxDuplicatesPerDomain: 2,
  weights: {
    relevance: 0.35,
    authority: 0.25,
    business: 0.30,
    geographic: 0.10,
  },
}

/**
 * Search result validation and scoring service
 */
export class SearchResultValidator {
  private config: ValidationConfig
  private domainCache: Map<string, any> = new Map()
  private authorityCache: Map<string, number> = new Map()
  private seenDomains: Map<string, number> = new Map()

  constructor(config: Partial<ValidationConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Validate and score search results
   * @param results - Raw search results
   * @param query - Original search query
   * @param location - Search location
   * @returns Validated and scored results
   */
  async validateResults(
    results: Array<{ url: string; title: string; snippet: string; domain: string }>,
    query: string,
    location: string
  ): Promise<ValidatedSearchResult[]> {
    const validatedResults: ValidatedSearchResult[] = []

    for (const result of results) {
      try {
        const validated = await this.validateSingleResult(result, query, location)
        
        // Apply minimum score thresholds
        if (this.meetsMinimumThresholds(validated)) {
          validatedResults.push(validated)
        } else {
          logger.debug('SearchValidator', `Result filtered out due to low scores: ${result.url}`)
        }
      } catch (error) {
        logger.warn('SearchValidator', `Failed to validate result: ${result.url}`, error)
        continue
      }
    }

    // Sort by overall score (highest first)
    validatedResults.sort((a, b) => b.scores.overall - a.scores.overall)

    logger.info('SearchValidator', `Validated ${validatedResults.length} of ${results.length} results`)
    return validatedResults
  }

  /**
   * Validate a single search result
   * @param result - Single search result
   * @param query - Search query
   * @param location - Search location
   * @returns Validated result with scores
   */
  private async validateSingleResult(
    result: { url: string; title: string; snippet: string; domain: string },
    query: string,
    location: string
  ): Promise<ValidatedSearchResult> {
    // Calculate individual scores
    const relevanceScore = this.calculateRelevanceScore(result, query)
    const authorityScore = await this.calculateAuthorityScore(result.domain)
    const businessScore = this.calculateBusinessScore(result)
    const geographicScore = this.calculateGeographicScore(result, location)

    // Calculate overall weighted score
    const overallScore = this.calculateOverallScore({
      relevance: relevanceScore,
      authority: authorityScore,
      business: businessScore,
      geographic: geographicScore,
    })

    // Get domain metadata
    const metadata = await this.getDomainMetadata(result.domain)

    // Check for duplicates
    const isDuplicate = this.checkDuplicate(result.domain)

    return {
      ...result,
      scores: {
        relevance: relevanceScore,
        authority: authorityScore,
        business: businessScore,
        geographic: geographicScore,
        overall: overallScore,
      },
      metadata: {
        ...metadata,
        isDuplicate,
        confidence: overallScore,
      },
    }
  }

  /**
   * Calculate relevance score based on query match
   * @param result - Search result
   * @param query - Search query
   * @returns Relevance score (0-1)
   */
  private calculateRelevanceScore(
    result: { title: string; snippet: string; domain: string },
    query: string
  ): number {
    const queryTerms = query.toLowerCase().split(/\s+/)
    const titleText = result.title.toLowerCase()
    const snippetText = result.snippet.toLowerCase()
    const domainText = result.domain.toLowerCase()

    let score = 0
    let maxScore = queryTerms.length * 3 // Max points per term (title=2, snippet=1, domain=1)

    for (const term of queryTerms) {
      // Title matches are worth more
      if (titleText.includes(term)) {
        score += 2
      }
      
      // Snippet matches
      if (snippetText.includes(term)) {
        score += 1
      }
      
      // Domain matches (business name in domain)
      if (domainText.includes(term)) {
        score += 1
      }
    }

    return Math.min(score / maxScore, 1)
  }

  /**
   * Calculate domain authority score
   * @param domain - Domain name
   * @returns Authority score (0-1)
   */
  private async calculateAuthorityScore(domain: string): Promise<number> {
    // Check cache first
    if (this.authorityCache.has(domain)) {
      return this.authorityCache.get(domain)!
    }

    let score = 0.5 // Default neutral score

    try {
      // Check SSL certificate
      if (this.config.enableSSLCheck) {
        const hasSSL = await this.checkSSL(domain)
        score += hasSSL ? 0.2 : -0.1
      }

      // Check domain age (simplified - in production would use WHOIS API)
      if (this.config.enableDomainAgeCheck) {
        const domainAge = await this.estimateDomainAge(domain)
        if (domainAge > 2) score += 0.2
        else if (domainAge < 0.5) score -= 0.1
      }

      // Check for common business indicators in domain
      const businessIndicators = ['inc', 'llc', 'corp', 'company', 'business', 'services']
      if (businessIndicators.some(indicator => domain.includes(indicator))) {
        score += 0.1
      }

    } catch (error) {
      logger.debug('SearchValidator', `Authority check failed for ${domain}`, error)
    }

    score = Math.max(0, Math.min(1, score))

    // Cache the result
    this.authorityCache.set(domain, score)

    return score
  }

  /**
   * Calculate business legitimacy score
   * @param result - Search result
   * @returns Business score (0-1)
   */
  private calculateBusinessScore(
    result: { title: string; snippet: string; domain: string }
  ): number {
    let score = 0.5 // Start with neutral

    const businessKeywords = [
      'services', 'company', 'business', 'inc', 'llc', 'corp',
      'restaurant', 'shop', 'store', 'clinic', 'office', 'center',
      'solutions', 'consulting', 'professional', 'expert'
    ]

    const directoryKeywords = [
      'directory', 'listing', 'reviews', 'find', 'search',
      'yellow pages', 'white pages', 'business directory'
    ]

    const text = `${result.title} ${result.snippet} ${result.domain}`.toLowerCase()

    // Positive indicators
    const businessMatches = businessKeywords.filter(keyword => text.includes(keyword)).length
    score += Math.min(businessMatches * 0.1, 0.3)

    // Negative indicators (directory sites)
    const directoryMatches = directoryKeywords.filter(keyword => text.includes(keyword)).length
    score -= Math.min(directoryMatches * 0.2, 0.4)

    // Domain structure indicators
    if (result.domain.split('.').length === 2) { // e.g., business.com
      score += 0.1
    }

    return Math.max(0, Math.min(1, score))
  }

  /**
   * Calculate geographic relevance score
   * @param result - Search result
   * @param location - Search location
   * @returns Geographic score (0-1)
   */
  private calculateGeographicScore(
    result: { title: string; snippet: string },
    location: string
  ): number {
    if (!location) return 0.5 // Neutral if no location specified

    const locationTerms = location.toLowerCase().split(/[,\s]+/)
    const text = `${result.title} ${result.snippet}`.toLowerCase()

    let matches = 0
    for (const term of locationTerms) {
      if (term.length > 2 && text.includes(term)) {
        matches++
      }
    }

    return Math.min(matches / locationTerms.length, 1)
  }

  /**
   * Calculate overall weighted score
   * @param scores - Individual scores
   * @returns Overall weighted score
   */
  private calculateOverallScore(scores: {
    relevance: number
    authority: number
    business: number
    geographic: number
  }): number {
    const { weights } = this.config
    
    return (
      scores.relevance * weights.relevance +
      scores.authority * weights.authority +
      scores.business * weights.business +
      scores.geographic * weights.geographic
    )
  }

  /**
   * Check if result meets minimum thresholds
   * @param result - Validated result
   * @returns Boolean indicating if thresholds are met
   */
  private meetsMinimumThresholds(result: ValidatedSearchResult): boolean {
    return (
      result.scores.relevance >= this.config.minRelevanceScore &&
      result.scores.authority >= this.config.minAuthorityScore &&
      result.scores.business >= this.config.minBusinessScore
    )
  }

  /**
   * Check for duplicate domains
   * @param domain - Domain to check
   * @returns Boolean indicating if it's a duplicate
   */
  private checkDuplicate(domain: string): boolean {
    if (!this.config.enableDuplicateDetection) return false

    const count = this.seenDomains.get(domain) || 0
    this.seenDomains.set(domain, count + 1)

    return count >= this.config.maxDuplicatesPerDomain
  }

  /**
   * Get domain metadata
   * @param domain - Domain name
   * @returns Domain metadata
   */
  private async getDomainMetadata(domain: string): Promise<{
    domainAge?: number
    hasSSL: boolean
    businessType?: string
  }> {
    // Check cache first
    if (this.domainCache.has(domain)) {
      return this.domainCache.get(domain)
    }

    const metadata = {
      hasSSL: await this.checkSSL(domain),
      domainAge: await this.estimateDomainAge(domain),
      businessType: this.classifyBusinessType(domain),
    }

    this.domainCache.set(domain, metadata)
    return metadata
  }

  /**
   * Check if domain has SSL certificate
   * @param domain - Domain name
   * @returns Boolean indicating SSL presence
   */
  private async checkSSL(domain: string): Promise<boolean> {
    try {
      const response = await axios.head(`https://${domain}`, {
        timeout: 5000,
        validateStatus: () => true, // Don't throw on HTTP errors
      })
      return response.status < 500 // If we get a response, SSL is working
    } catch (error) {
      return false
    }
  }

  /**
   * Estimate domain age (simplified implementation)
   * @param domain - Domain name
   * @returns Estimated age in years
   */
  private async estimateDomainAge(domain: string): Promise<number> {
    // In a production environment, this would use a WHOIS API
    // For now, return a reasonable default based on domain characteristics
    
    // Shorter domains tend to be older
    if (domain.length < 10) return 5
    if (domain.length < 15) return 3
    return 1
  }

  /**
   * Classify business type based on domain and content
   * @param domain - Domain name
   * @returns Business type classification
   */
  private classifyBusinessType(domain: string): string {
    const classifications = {
      'restaurant': ['restaurant', 'cafe', 'diner', 'bistro', 'eatery'],
      'medical': ['medical', 'clinic', 'doctor', 'health', 'dental'],
      'retail': ['shop', 'store', 'retail', 'boutique', 'market'],
      'services': ['services', 'consulting', 'solutions', 'professional'],
      'technology': ['tech', 'software', 'digital', 'web', 'app'],
    }

    for (const [type, keywords] of Object.entries(classifications)) {
      if (keywords.some(keyword => domain.includes(keyword))) {
        return type
      }
    }

    return 'general'
  }

  /**
   * Clear validation cache
   */
  clearCache(): void {
    this.domainCache.clear()
    this.authorityCache.clear()
    this.seenDomains.clear()
  }

  /**
   * Get validation statistics
   * @returns Validation statistics
   */
  getStats(): {
    cacheSize: number
    domainsProcessed: number
    duplicatesFound: number
  } {
    return {
      cacheSize: this.domainCache.size,
      domainsProcessed: this.seenDomains.size,
      duplicatesFound: Array.from(this.seenDomains.values()).filter(count => count > 1).length,
    }
  }
}

/**
 * Default search result validator instance
 */
export const searchResultValidator = new SearchResultValidator()
