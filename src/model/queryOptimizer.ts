'use strict'

import { logger } from '@/utils/logger'

/**
 * Optimized search query with metadata
 */
export interface OptimizedQuery {
  original: string
  optimized: string
  location: string
  normalizedLocation: string
  industry?: string
  synonyms: string[]
  negativeKeywords: string[]
  templates: string[]
  confidence: number
  estimatedResults: number
}

/**
 * Query performance metrics
 */
export interface QueryPerformance {
  query: string
  location: string
  searchTime: number
  resultCount: number
  relevanceScore: number
  timestamp: Date
  searchProvider: string
}

/**
 * Industry-specific search template
 */
export interface SearchTemplate {
  industry: string
  templates: string[]
  synonyms: string[]
  negativeKeywords: string[]
  locationModifiers: string[]
  businessTypes: string[]
}

/**
 * Location normalization result
 */
export interface NormalizedLocation {
  original: string
  normalized: string
  city?: string
  state?: string
  zipCode?: string
  country: string
  confidence: number
  alternatives: string[]
}

/**
 * Query optimization configuration
 */
export interface QueryOptimizerConfig {
  enableSynonymExpansion: boolean
  enableLocationNormalization: boolean
  enableNegativeKeywords: boolean
  enableIndustryTemplates: boolean
  maxSynonyms: number
  maxTemplates: number
  minConfidenceScore: number
  enableAnalytics: boolean
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: QueryOptimizerConfig = {
  enableSynonymExpansion: true,
  enableLocationNormalization: true,
  enableNegativeKeywords: true,
  enableIndustryTemplates: true,
  maxSynonyms: 5,
  maxTemplates: 10,
  minConfidenceScore: 0.6,
  enableAnalytics: true,
}

/**
 * Query optimization engine for enhanced search performance
 */
export class QueryOptimizer {
  private config: QueryOptimizerConfig
  private performanceMetrics: QueryPerformance[] = []
  private searchTemplates: Map<string, SearchTemplate> = new Map()
  private synonymCache: Map<string, string[]> = new Map()
  private locationCache: Map<string, NormalizedLocation> = new Map()

  constructor(config: Partial<QueryOptimizerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.initializeSearchTemplates()
  }

  /**
   * Optimize a search query for better results
   * @param query - Original search query
   * @param location - Search location
   * @param industry - Optional industry context
   * @returns Optimized query with metadata
   */
  async optimizeQuery(
    query: string,
    location: string,
    industry?: string
  ): Promise<OptimizedQuery> {
    const startTime = Date.now()
    
    try {
      // Normalize and validate inputs
      const cleanQuery = this.cleanQuery(query)
      const normalizedLocation = await this.normalizeLocation(location)
      
      // Generate synonyms
      const synonyms = this.config.enableSynonymExpansion 
        ? await this.generateSynonyms(cleanQuery, industry)
        : []
      
      // Get industry-specific templates
      const templates = this.config.enableIndustryTemplates && industry
        ? this.generateIndustryTemplates(cleanQuery, industry)
        : [cleanQuery]
      
      // Generate negative keywords
      const negativeKeywords = this.config.enableNegativeKeywords
        ? this.generateNegativeKeywords(cleanQuery, industry)
        : []
      
      // Build optimized query
      const optimizedQuery = this.buildOptimizedQuery(
        cleanQuery,
        synonyms,
        negativeKeywords,
        normalizedLocation.normalized
      )
      
      // Calculate confidence score
      const confidence = this.calculateConfidence(
        cleanQuery,
        synonyms,
        templates,
        normalizedLocation.confidence
      )
      
      // Estimate result count
      const estimatedResults = this.estimateResultCount(
        optimizedQuery,
        normalizedLocation.normalized,
        industry
      )
      
      const result: OptimizedQuery = {
        original: query,
        optimized: optimizedQuery,
        location: location,
        normalizedLocation: normalizedLocation.normalized,
        industry,
        synonyms,
        negativeKeywords,
        templates,
        confidence,
        estimatedResults,
      }
      
      const processingTime = Date.now() - startTime
      logger.info('QueryOptimizer', `Query optimized in ${processingTime}ms`, {
        original: query,
        optimized: optimizedQuery,
        confidence,
      })
      
      return result
    } catch (error) {
      logger.error('QueryOptimizer', 'Query optimization failed', error)
      
      // Return basic optimization as fallback
      return {
        original: query,
        optimized: this.cleanQuery(query),
        location: location,
        normalizedLocation: location,
        industry,
        synonyms: [],
        negativeKeywords: [],
        templates: [query],
        confidence: 0.5,
        estimatedResults: 50,
      }
    }
  }

  /**
   * Generate multiple optimized query variations
   * @param query - Original query
   * @param location - Location
   * @param industry - Industry context
   * @returns Array of optimized queries
   */
  async generateQueryVariations(
    query: string,
    location: string,
    industry?: string
  ): Promise<OptimizedQuery[]> {
    const baseOptimization = await this.optimizeQuery(query, location, industry)
    const variations: OptimizedQuery[] = [baseOptimization]
    
    // Generate template-based variations
    if (industry && this.searchTemplates.has(industry)) {
      const template = this.searchTemplates.get(industry)!
      
      for (const templatePattern of template.templates.slice(0, this.config.maxTemplates)) {
        const variationQuery = templatePattern
          .replace('{query}', query)
          .replace('{location}', location)
        
        if (variationQuery !== baseOptimization.optimized) {
          const variation = await this.optimizeQuery(variationQuery, location, industry)
          variations.push(variation)
        }
      }
    }
    
    // Generate synonym-based variations
    for (const synonym of baseOptimization.synonyms.slice(0, 3)) {
      const firstWord = query.split(' ')[0]
      if (firstWord) {
        const synonymQuery = query.replace(
          new RegExp(firstWord, 'gi'),
          synonym
        )

        if (synonymQuery !== query) {
          const variation = await this.optimizeQuery(synonymQuery, location, industry)
          variations.push(variation)
        }
      }
    }
    
    // Sort by confidence score
    variations.sort((a, b) => b.confidence - a.confidence)
    
    return variations.slice(0, this.config.maxTemplates)
  }

  /**
   * Record query performance metrics
   * @param metrics - Performance metrics
   */
  recordPerformance(metrics: QueryPerformance): void {
    if (!this.config.enableAnalytics) return
    
    this.performanceMetrics.push(metrics)
    
    // Keep only recent metrics (last 1000)
    if (this.performanceMetrics.length > 1000) {
      this.performanceMetrics = this.performanceMetrics.slice(-1000)
    }
    
    logger.debug('QueryOptimizer', 'Performance metrics recorded', metrics)
  }

  /**
   * Get query performance analytics
   * @param timeframe - Time period in hours (default: 24)
   * @returns Performance analytics
   */
  getPerformanceAnalytics(timeframe: number = 24): {
    totalQueries: number
    averageSearchTime: number
    averageResultCount: number
    averageRelevanceScore: number
    topPerformingQueries: QueryPerformance[]
    slowestQueries: QueryPerformance[]
    providerPerformance: { [provider: string]: { count: number; avgTime: number } }
  } {
    const cutoffTime = new Date(Date.now() - timeframe * 60 * 60 * 1000)
    const recentMetrics = this.performanceMetrics.filter(m => m.timestamp >= cutoffTime)
    
    if (recentMetrics.length === 0) {
      return {
        totalQueries: 0,
        averageSearchTime: 0,
        averageResultCount: 0,
        averageRelevanceScore: 0,
        topPerformingQueries: [],
        slowestQueries: [],
        providerPerformance: {},
      }
    }
    
    const totalQueries = recentMetrics.length
    const averageSearchTime = recentMetrics.reduce((sum, m) => sum + m.searchTime, 0) / totalQueries
    const averageResultCount = recentMetrics.reduce((sum, m) => sum + m.resultCount, 0) / totalQueries
    const averageRelevanceScore = recentMetrics.reduce((sum, m) => sum + m.relevanceScore, 0) / totalQueries
    
    // Top performing queries (high relevance, good result count)
    const topPerformingQueries = [...recentMetrics]
      .sort((a, b) => (b.relevanceScore * Math.log(b.resultCount + 1)) - (a.relevanceScore * Math.log(a.resultCount + 1)))
      .slice(0, 10)
    
    // Slowest queries
    const slowestQueries = [...recentMetrics]
      .sort((a, b) => b.searchTime - a.searchTime)
      .slice(0, 10)
    
    // Provider performance
    const providerPerformance: { [provider: string]: { count: number; avgTime: number } } = {}
    for (const metric of recentMetrics) {
      if (!providerPerformance[metric.searchProvider]) {
        providerPerformance[metric.searchProvider] = { count: 0, avgTime: 0 }
      }
      const performance = providerPerformance[metric.searchProvider]
      if (performance) {
        performance.count++
        performance.avgTime += metric.searchTime
      }
    }
    
    // Calculate averages
    for (const provider in providerPerformance) {
      const performance = providerPerformance[provider]
      if (performance && performance.count > 0) {
        performance.avgTime /= performance.count
      }
    }
    
    return {
      totalQueries,
      averageSearchTime,
      averageResultCount,
      averageRelevanceScore,
      topPerformingQueries,
      slowestQueries,
      providerPerformance,
    }
  }

  /**
   * Get query suggestions based on performance history
   * @param partialQuery - Partial query input
   * @param location - Location context
   * @param industry - Industry context
   * @returns Array of suggested queries
   */
  getQuerySuggestions(
    partialQuery: string,
    location?: string,
    industry?: string
  ): string[] {
    const suggestions: string[] = []
    const queryLower = partialQuery.toLowerCase()
    
    // Get suggestions from performance history
    const historicalQueries = this.performanceMetrics
      .filter(m => m.query.toLowerCase().includes(queryLower))
      .sort((a, b) => b.relevanceScore - a.relevanceScore)
      .slice(0, 5)
      .map(m => m.query)
    
    suggestions.push(...historicalQueries)
    
    // Get suggestions from industry templates
    if (industry && this.searchTemplates.has(industry)) {
      const template = this.searchTemplates.get(industry)!
      const templateSuggestions = template.businessTypes
        .filter(type => type.toLowerCase().includes(queryLower))
        .slice(0, 3)
      
      suggestions.push(...templateSuggestions)
    }
    
    // Get synonym-based suggestions
    const synonyms = this.getSynonymsFromCache(partialQuery)
    suggestions.push(...synonyms.slice(0, 3))
    
    // Remove duplicates and return
    return Array.from(new Set(suggestions)).slice(0, 10)
  }

  /**
   * Clear performance metrics and caches
   */
  clearCache(): void {
    this.performanceMetrics = []
    this.synonymCache.clear()
    this.locationCache.clear()
    logger.info('QueryOptimizer', 'Cache cleared')
  }

  /**
   * Get optimization statistics
   * @returns Statistics object
   */
  getStats(): {
    performanceMetricsCount: number
    synonymCacheSize: number
    locationCacheSize: number
    searchTemplatesCount: number
  } {
    return {
      performanceMetricsCount: this.performanceMetrics.length,
      synonymCacheSize: this.synonymCache.size,
      locationCacheSize: this.locationCache.size,
      searchTemplatesCount: this.searchTemplates.size,
    }
  }

  /**
   * Initialize industry-specific search templates
   */
  private initializeSearchTemplates(): void {
    const templates: SearchTemplate[] = [
      {
        industry: 'restaurants',
        templates: [
          '{query} restaurants {location}',
          '{query} dining {location}',
          '{query} food service {location}',
          'best {query} {location}',
          '{query} near {location}',
          'local {query} restaurants {location}',
        ],
        synonyms: ['restaurant', 'dining', 'eatery', 'bistro', 'cafe', 'food service'],
        negativeKeywords: ['jobs', 'careers', 'employment', 'reviews', 'delivery'],
        locationModifiers: ['near', 'in', 'around', 'close to'],
        businessTypes: ['restaurant', 'cafe', 'bistro', 'diner', 'pizzeria', 'bakery'],
      },
      {
        industry: 'healthcare',
        templates: [
          '{query} medical {location}',
          '{query} healthcare {location}',
          '{query} clinic {location}',
          '{query} doctors {location}',
          'medical {query} {location}',
          '{query} health services {location}',
        ],
        synonyms: ['medical', 'healthcare', 'clinic', 'hospital', 'doctor', 'physician'],
        negativeKeywords: ['insurance', 'jobs', 'careers', 'reviews', 'ratings'],
        locationModifiers: ['near', 'in', 'serving'],
        businessTypes: ['clinic', 'hospital', 'medical center', 'doctor office', 'urgent care'],
      },
      {
        industry: 'retail',
        templates: [
          '{query} stores {location}',
          '{query} shops {location}',
          '{query} retail {location}',
          '{query} shopping {location}',
          'buy {query} {location}',
          '{query} boutique {location}',
        ],
        synonyms: ['store', 'shop', 'retail', 'boutique', 'outlet', 'marketplace'],
        negativeKeywords: ['online', 'jobs', 'careers', 'wholesale', 'reviews'],
        locationModifiers: ['in', 'near', 'around'],
        businessTypes: ['store', 'shop', 'boutique', 'outlet', 'mall', 'market'],
      },
      {
        industry: 'professional',
        templates: [
          '{query} services {location}',
          '{query} consulting {location}',
          '{query} professionals {location}',
          '{query} firms {location}',
          'professional {query} {location}',
          '{query} experts {location}',
        ],
        synonyms: ['services', 'consulting', 'professional', 'expert', 'specialist', 'firm'],
        negativeKeywords: ['jobs', 'careers', 'training', 'courses', 'reviews'],
        locationModifiers: ['in', 'serving', 'based in'],
        businessTypes: ['consulting', 'law firm', 'accounting', 'financial services', 'insurance'],
      },
      {
        industry: 'construction',
        templates: [
          '{query} contractors {location}',
          '{query} construction {location}',
          '{query} builders {location}',
          '{query} services {location}',
          'construction {query} {location}',
          '{query} companies {location}',
        ],
        synonyms: ['contractor', 'construction', 'builder', 'renovation', 'remodeling', 'repair'],
        negativeKeywords: ['jobs', 'careers', 'materials', 'supplies', 'reviews'],
        locationModifiers: ['in', 'serving', 'near'],
        businessTypes: ['contractor', 'construction company', 'builder', 'renovation', 'plumbing'],
      },
    ]

    for (const template of templates) {
      this.searchTemplates.set(template.industry, template)
    }

    logger.info('QueryOptimizer', `Initialized ${templates.length} search templates`)
  }

  /**
   * Clean and normalize query text
   * @param query - Raw query
   * @returns Cleaned query
   */
  private cleanQuery(query: string): string {
    return query
      .trim()
      .toLowerCase()
      .replace(/[^\w\s-]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
  }

  /**
   * Normalize location for consistent processing
   * @param location - Raw location
   * @returns Normalized location
   */
  private async normalizeLocation(location: string): Promise<NormalizedLocation> {
    const cacheKey = location.toLowerCase().trim()

    if (this.locationCache.has(cacheKey)) {
      return this.locationCache.get(cacheKey)!
    }

    const normalized = this.performLocationNormalization(location)
    this.locationCache.set(cacheKey, normalized)

    return normalized
  }

  /**
   * Perform location normalization logic
   * @param location - Raw location
   * @returns Normalized location result
   */
  private performLocationNormalization(location: string): NormalizedLocation {
    const clean = location.trim()

    // ZIP code pattern
    const zipPattern = /^\d{5}(-\d{4})?$/
    if (zipPattern.test(clean)) {
      return {
        original: location,
        normalized: clean,
        zipCode: clean,
        country: 'US',
        confidence: 0.9,
        alternatives: [],
      }
    }

    // City, State pattern
    const cityStatePattern = /^([^,]+),\s*([A-Z]{2})$/i
    const cityStateMatch = clean.match(cityStatePattern)
    if (cityStateMatch) {
      const [, city, state] = cityStateMatch
      if (city && state) {
        return {
          original: location,
          normalized: `${city.trim()}, ${state.toUpperCase()}`,
          city: city.trim(),
          state: state.toUpperCase(),
          country: 'US',
          confidence: 0.8,
          alternatives: [city.trim(), state.toUpperCase()],
        }
      }
    }

    // Default normalization
    return {
      original: location,
      normalized: clean,
      country: 'US',
      confidence: 0.6,
      alternatives: [],
    }
  }

  /**
   * Generate synonyms for query terms
   * @param query - Search query
   * @param industry - Industry context
   * @returns Array of synonyms
   */
  private async generateSynonyms(query: string, industry?: string): Promise<string[]> {
    const cacheKey = `${query}-${industry || 'general'}`

    if (this.synonymCache.has(cacheKey)) {
      return this.synonymCache.get(cacheKey)!
    }

    const synonyms = this.buildSynonymList(query, industry)
    this.synonymCache.set(cacheKey, synonyms)

    return synonyms
  }

  /**
   * Build synonym list for query
   * @param query - Search query
   * @param industry - Industry context
   * @returns Array of synonyms
   */
  private buildSynonymList(query: string, industry?: string): string[] {
    const synonyms: string[] = []
    const queryTerms = query.split(' ')

    // Industry-specific synonyms
    if (industry && this.searchTemplates.has(industry)) {
      const template = this.searchTemplates.get(industry)!
      synonyms.push(...template.synonyms)
    }

    // General business synonyms
    const generalSynonyms: { [key: string]: string[] } = {
      'business': ['company', 'firm', 'enterprise', 'organization'],
      'service': ['services', 'solutions', 'support', 'assistance'],
      'shop': ['store', 'retail', 'outlet', 'boutique'],
      'office': ['location', 'branch', 'facility', 'center'],
      'professional': ['expert', 'specialist', 'consultant', 'advisor'],
      'local': ['nearby', 'area', 'regional', 'community'],
      'best': ['top', 'leading', 'premier', 'quality'],
      'cheap': ['affordable', 'budget', 'discount', 'low-cost'],
    }

    for (const term of queryTerms) {
      const termSynonyms = generalSynonyms[term.toLowerCase()]
      if (termSynonyms) {
        synonyms.push(...termSynonyms)
      }
    }

    // Remove duplicates and limit
    return Array.from(new Set(synonyms)).slice(0, this.config.maxSynonyms)
  }

  /**
   * Generate industry-specific query templates
   * @param query - Base query
   * @param industry - Industry type
   * @returns Array of template variations
   */
  private generateIndustryTemplates(query: string, industry: string): string[] {
    if (!this.searchTemplates.has(industry)) {
      return [query]
    }

    const template = this.searchTemplates.get(industry)!
    const templates: string[] = []

    for (const templatePattern of template.templates) {
      const generatedQuery = templatePattern.replace('{query}', query)
      templates.push(generatedQuery)
    }

    return templates.slice(0, this.config.maxTemplates)
  }

  /**
   * Generate negative keywords to filter out unwanted results
   * @param query - Search query
   * @param industry - Industry context
   * @returns Array of negative keywords
   */
  private generateNegativeKeywords(query: string, industry?: string): string[] {
    const negativeKeywords: string[] = []

    // Industry-specific negative keywords
    if (industry && this.searchTemplates.has(industry)) {
      const template = this.searchTemplates.get(industry)!
      negativeKeywords.push(...template.negativeKeywords)
    }

    // General negative keywords
    const generalNegative = [
      'jobs', 'careers', 'employment', 'hiring', 'apply',
      'reviews', 'ratings', 'complaints', 'scam',
      'wikipedia', 'wiki', 'definition', 'meaning',
      'news', 'article', 'blog', 'forum',
      'free', 'download', 'software', 'app',
    ]

    negativeKeywords.push(...generalNegative)

    return Array.from(new Set(negativeKeywords))
  }

  /**
   * Build optimized query string
   * @param query - Base query
   * @param synonyms - Synonym terms
   * @param negativeKeywords - Terms to exclude
   * @param location - Normalized location
   * @returns Optimized query string
   */
  private buildOptimizedQuery(
    query: string,
    synonyms: string[],
    negativeKeywords: string[],
    location: string
  ): string {
    let optimized = query

    // Add location if not already present
    if (!optimized.toLowerCase().includes(location.toLowerCase())) {
      optimized += ` ${location}`
    }

    // Add top synonyms as OR terms
    if (synonyms.length > 0) {
      const topSynonyms = synonyms.slice(0, 2)
      optimized += ` (${topSynonyms.join(' OR ')})`
    }

    // Add negative keywords
    for (const negative of negativeKeywords.slice(0, 5)) {
      optimized += ` -${negative}`
    }

    return optimized
  }

  /**
   * Calculate confidence score for optimized query
   * @param query - Original query
   * @param synonyms - Generated synonyms
   * @param templates - Available templates
   * @param locationConfidence - Location normalization confidence
   * @returns Confidence score (0-1)
   */
  private calculateConfidence(
    query: string,
    synonyms: string[],
    templates: string[],
    locationConfidence: number
  ): number {
    let confidence = 0.5 // Base confidence

    // Boost for synonyms
    confidence += Math.min(synonyms.length * 0.1, 0.2)

    // Boost for templates
    confidence += Math.min(templates.length * 0.05, 0.15)

    // Location confidence factor
    confidence *= locationConfidence

    // Query length factor (longer queries tend to be more specific)
    const queryWords = query.split(' ').length
    if (queryWords >= 2) confidence += 0.1
    if (queryWords >= 3) confidence += 0.1

    return Math.min(confidence, 1.0)
  }

  /**
   * Estimate result count for query
   * @param query - Optimized query
   * @param location - Location
   * @param industry - Industry context
   * @returns Estimated result count
   */
  private estimateResultCount(
    query: string,
    location: string,
    industry?: string
  ): number {
    // Base estimate
    let estimate = 100

    // Adjust based on query specificity
    const queryWords = query.split(' ').length
    estimate *= Math.max(0.5, 1 - (queryWords - 2) * 0.1)

    // Adjust based on industry popularity
    const industryMultipliers: { [key: string]: number } = {
      'restaurants': 1.5,
      'retail': 1.3,
      'healthcare': 1.2,
      'professional': 1.0,
      'construction': 0.8,
    }

    if (industry && industryMultipliers[industry]) {
      estimate *= industryMultipliers[industry]
    }

    // Location factor (more populated areas have more businesses)
    if (location.match(/\d{5}/)) { // ZIP code
      estimate *= 1.2
    }

    return Math.round(estimate)
  }

  /**
   * Get synonyms from cache for suggestions
   * @param term - Search term
   * @returns Array of cached synonyms
   */
  private getSynonymsFromCache(term: string): string[] {
    const synonyms: string[] = []

    Array.from(this.synonymCache.entries()).forEach(([key, values]) => {
      if (key.includes(term.toLowerCase())) {
        synonyms.push(...values)
      }
    })

    return Array.from(new Set(synonyms))
  }
}

/**
 * Default query optimizer instance
 */
export const queryOptimizer = new QueryOptimizer()
