/**
 * Enhanced Data Manager with AI Lead Scoring Integration
 * Manages business data with automatic lead scoring and enrichment
 */

import { BusinessRecord } from '@/types/business'
import { aiLeadScoringService, LeadScore } from './aiLeadScoring'
import { dataValidationPipeline } from './dataValidationPipeline'
import { duplicateDetectionSystem } from './duplicateDetection'
import { smartCacheManager } from './smartCacheManager'
import { logger } from '@/utils/logger'

export interface DataProcessingOptions {
  enableLeadScoring?: boolean
  enableValidation?: boolean
  enableDuplicateDetection?: boolean
  enableCaching?: boolean
  batchSize?: number
}

export interface ProcessingResult {
  processed: BusinessRecord[]
  scores: Map<string, LeadScore>
  duplicates: string[]
  errors: string[]
  stats: {
    total: number
    processed: number
    scored: number
    duplicates: number
    errors: number
  }
}

/**
 * Enhanced Data Manager with AI capabilities
 */
export class EnhancedDataManager {
  private isInitialized = false

  constructor() {}

  /**
   * Initialize the data manager and AI services
   */
  async initialize(): Promise<void> {
    try {
      logger.info('EnhancedDataManager', 'Initializing data manager...')

      // Initialize AI lead scoring service
      await aiLeadScoringService.initialize()

      this.isInitialized = true
      logger.info('EnhancedDataManager', 'Data manager initialized successfully')
    } catch (error) {
      logger.error('EnhancedDataManager', 'Failed to initialize data manager', error)
      throw error
    }
  }

  /**
   * Process a batch of business records with AI scoring and validation
   */
  async processBatch(
    businesses: BusinessRecord[],
    options: DataProcessingOptions = {}
  ): Promise<ProcessingResult> {
    if (!this.isInitialized) {
      await this.initialize()
    }

    const {
      enableLeadScoring = true,
      enableValidation = true,
      enableDuplicateDetection = true,
      enableCaching = true,
      batchSize = 10,
    } = options

    const result: ProcessingResult = {
      processed: [],
      scores: new Map(),
      duplicates: [],
      errors: [],
      stats: {
        total: businesses.length,
        processed: 0,
        scored: 0,
        duplicates: 0,
        errors: 0,
      },
    }

    logger.info('EnhancedDataManager', `Processing ${businesses.length} businesses`)

    // Process in batches to avoid overwhelming the system
    for (let i = 0; i < businesses.length; i += batchSize) {
      const batch = businesses.slice(i, i + batchSize)

      for (const business of batch) {
        try {
          let processedBusiness = { ...business }

          // 1. Data validation and cleaning
          if (enableValidation) {
            const validationResult = await dataValidationPipeline.validateAndClean(business)
            if (validationResult.cleanedData) {
              processedBusiness = { ...processedBusiness, ...validationResult.cleanedData }
            }

            // Update data quality score
            processedBusiness.dataQualityScore =
              await dataValidationPipeline.calculateDataQualityScore(business)
          }

          // 2. Duplicate detection
          if (enableDuplicateDetection) {
            const isDuplicate = await this.checkForDuplicate(processedBusiness, result.processed)
            if (isDuplicate) {
              result.duplicates.push(processedBusiness.id)
              result.stats.duplicates++
              continue
            }
          }

          // 3. AI Lead Scoring
          if (enableLeadScoring) {
            try {
              const leadScore = await aiLeadScoringService.getLeadScore(processedBusiness)

              // Add lead score to business record
              processedBusiness.leadScore = {
                score: leadScore.score,
                confidence: leadScore.confidence,
                scoredAt: new Date(),
                factors: leadScore.factors,
                recommendations: leadScore.recommendations,
              }

              result.scores.set(processedBusiness.id, leadScore)
              result.stats.scored++
            } catch (error) {
              logger.warn(
                'EnhancedDataManager',
                `Failed to score business ${processedBusiness.id}`,
                error
              )
            }
          }

          // 4. Caching
          if (enableCaching) {
            try {
              await smartCacheManager.cacheBusinessData(
                processedBusiness.websiteUrl,
                processedBusiness
              )
            } catch (error) {
              logger.warn(
                'EnhancedDataManager',
                `Failed to cache business ${processedBusiness.id}`,
                error
              )
            }
          }

          result.processed.push(processedBusiness)
          result.stats.processed++
        } catch (error) {
          logger.error('EnhancedDataManager', `Failed to process business ${business.id}`, error)
          result.errors.push(
            `Failed to process ${business.businessName}: ${error instanceof Error ? error.message : 'Unknown error'}`
          )
          result.stats.errors++
        }
      }

      // Small delay between batches
      if (i + batchSize < businesses.length) {
        await new Promise(resolve => setTimeout(resolve, 100))
      }
    }

    logger.info(
      'EnhancedDataManager',
      `Processing complete: ${result.stats.processed}/${result.stats.total} processed`
    )
    return result
  }

  /**
   * Process a single business record
   */
  async processSingle(
    business: BusinessRecord,
    options: DataProcessingOptions = {}
  ): Promise<{ business: BusinessRecord; score?: LeadScore; error?: string }> {
    const result = await this.processBatch([business], options)

    if (result.processed.length > 0) {
      return {
        business: result.processed[0],
        score: result.scores.get(business.id),
      }
    } else if (result.errors.length > 0) {
      return {
        business,
        error: result.errors[0],
      }
    } else {
      return {
        business,
        error: 'Unknown processing error',
      }
    }
  }

  /**
   * Re-score existing business records
   */
  async rescoreBusinesses(businesses: BusinessRecord[]): Promise<Map<string, LeadScore>> {
    if (!this.isInitialized) {
      await this.initialize()
    }

    const scores = new Map<string, LeadScore>()

    for (const business of businesses) {
      try {
        const leadScore = await aiLeadScoringService.getLeadScore(business)
        scores.set(business.id, leadScore)
      } catch (error) {
        logger.error('EnhancedDataManager', `Failed to rescore business ${business.id}`, error)
      }
    }

    return scores
  }

  /**
   * Update lead scores in business records
   */
  updateBusinessesWithScores(
    businesses: BusinessRecord[],
    scores: Map<string, LeadScore>
  ): BusinessRecord[] {
    return businesses.map(business => {
      const score = scores.get(business.id)
      if (score) {
        return {
          ...business,
          leadScore: {
            score: score.score,
            confidence: score.confidence,
            scoredAt: new Date(),
            factors: score.factors,
            recommendations: score.recommendations,
          },
        }
      }
      return business
    })
  }

  /**
   * Filter businesses by lead score
   */
  filterByScore(
    businesses: BusinessRecord[],
    minScore: number = 0,
    maxScore: number = 100
  ): BusinessRecord[] {
    return businesses.filter(business => {
      const score = business.leadScore?.score
      return score !== undefined && score >= minScore && score <= maxScore
    })
  }

  /**
   * Sort businesses by lead score
   */
  sortByScore(businesses: BusinessRecord[], descending: boolean = true): BusinessRecord[] {
    return [...businesses].sort((a, b) => {
      const scoreA = a.leadScore?.score || 0
      const scoreB = b.leadScore?.score || 0
      return descending ? scoreB - scoreA : scoreA - scoreB
    })
  }

  /**
   * Get high-quality leads (score >= 70)
   */
  getHighQualityLeads(businesses: BusinessRecord[]): BusinessRecord[] {
    return this.filterByScore(businesses, 70, 100)
  }

  /**
   * Get businesses that need attention (low scores or missing data)
   */
  getBusinessesNeedingAttention(businesses: BusinessRecord[]): BusinessRecord[] {
    return businesses.filter(business => {
      const score = business.leadScore?.score
      const dataQuality = business.dataQualityScore

      return (
        (score !== undefined && score < 50) ||
        (dataQuality !== undefined && dataQuality < 60) ||
        !business.email.length ||
        !business.phone
      )
    })
  }

  /**
   * Check for duplicate business
   */
  private async checkForDuplicate(
    business: BusinessRecord,
    existingBusinesses: BusinessRecord[]
  ): Promise<boolean> {
    try {
      // Check against existing businesses in current batch
      for (const existing of existingBusinesses) {
        const similarity = await duplicateDetectionSystem.compareRecords(business, existing)
        if (similarity.isDuplicate) {
          return true
        }
      }

      // Could also check against database here
      return false
    } catch (error) {
      logger.error('EnhancedDataManager', 'Duplicate detection failed', error)
      return false
    }
  }

  /**
   * Get processing statistics
   */
  getProcessingStats(result: ProcessingResult): string {
    const { stats } = result
    const successRate = stats.total > 0 ? (stats.processed / stats.total) * 100 : 0
    const scoringRate = stats.processed > 0 ? (stats.scored / stats.processed) * 100 : 0

    return `Processing Stats:
- Total: ${stats.total}
- Processed: ${stats.processed} (${successRate.toFixed(1)}%)
- Scored: ${stats.scored} (${scoringRate.toFixed(1)}%)
- Duplicates: ${stats.duplicates}
- Errors: ${stats.errors}`
  }

  /**
   * Export enhanced business data with scores
   */
  exportEnhancedData(businesses: BusinessRecord[]): any[] {
    return businesses.map(business => ({
      ...business,
      leadScore: business.leadScore?.score || 0,
      leadConfidence: business.leadScore?.confidence || 0,
      dataQuality: business.dataQualityScore || 0,
      recommendations: business.leadScore?.recommendations?.join('; ') || '',
      scoredAt: business.leadScore?.scoredAt?.toISOString() || '',
      factors: business.leadScore?.factors
        ? {
            dataCompleteness: business.leadScore.factors.dataCompleteness,
            contactQuality: business.leadScore.factors.contactQuality,
            businessSize: business.leadScore.factors.businessSize,
            industryRelevance: business.leadScore.factors.industryRelevance,
            geographicDesirability: business.leadScore.factors.geographicDesirability,
            webPresence: business.leadScore.factors.webPresence,
          }
        : null,
    }))
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    if (this.isInitialized) {
      aiLeadScoringService.dispose()
      this.isInitialized = false
      logger.info('EnhancedDataManager', 'Data manager disposed')
    }
  }
}

// Export singleton instance
export const enhancedDataManager = new EnhancedDataManager()
