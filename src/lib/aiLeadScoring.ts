/**
 * AI-Powered Lead Scoring Service
 * Implements machine learning algorithms to score business leads based on multiple criteria
 */

import { sequential, layers, train, tensor2d, type LayersModel, type Tensor } from '@tensorflow/tfjs'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface LeadScore {
  score: number // 0-100
  confidence: number // 0-1
  factors: ScoreFactors
  recommendations: string[]
}

export interface ScoreFactors {
  dataCompleteness: number // 0-100
  contactQuality: number // 0-100
  businessSize: number // 0-100
  industryRelevance: number // 0-100
  geographicDesirability: number // 0-100
  webPresence: number // 0-100
}

export interface ScoringWeights {
  dataCompleteness: number
  contactQuality: number
  businessSize: number
  industryRelevance: number
  geographicDesirability: number
  webPresence: number
}

export interface ScoringConfig {
  weights: ScoringWeights
  industryPriorities: Record<string, number>
  geographicPriorities: Record<string, number>
  minimumScore: number
  confidenceThreshold: number
}

/**
 * Default scoring configuration
 */
const DEFAULT_CONFIG: ScoringConfig = {
  weights: {
    dataCompleteness: 0.25,
    contactQuality: 0.2,
    businessSize: 0.15,
    industryRelevance: 0.15,
    geographicDesirability: 0.15,
    webPresence: 0.1,
  },
  industryPriorities: {
    Technology: 1.0,
    Healthcare: 0.9,
    'Professional Services': 0.8,
    Manufacturing: 0.7,
    Retail: 0.6,
    Construction: 0.5,
  },
  geographicPriorities: {
    CA: 1.0, // California
    NY: 0.9, // New York
    TX: 0.8, // Texas
    FL: 0.7, // Florida
    WA: 0.9, // Washington
  },
  minimumScore: 20,
  confidenceThreshold: 0.7,
}

/**
 * AI Lead Scoring Service
 */
export class AILeadScoringService {
  private model: LayersModel | null = null
  private config: ScoringConfig
  private isInitialized = false

  constructor(config: Partial<ScoringConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Initialize the AI model
   */
  async initialize(): Promise<void> {
    try {
      logger.info('AILeadScoring', 'Initializing AI lead scoring model...')

      // Create a simple neural network for lead scoring
      this.model = sequential({
        layers: [
          layers.dense({ inputShape: [6], units: 16, activation: 'relu' }),
          layers.dropout({ rate: 0.2 }),
          layers.dense({ units: 8, activation: 'relu' }),
          layers.dense({ units: 1, activation: 'sigmoid' }),
        ],
      })

      // Compile the model
      this.model.compile({
        optimizer: train.adam(0.001),
        loss: 'meanSquaredError',
        metrics: ['accuracy'],
      })

      // Train with synthetic data for demonstration
      await this.trainModel()

      this.isInitialized = true
      logger.info('AILeadScoring', 'AI model initialized successfully')
    } catch (error) {
      logger.error('AILeadScoring', 'Failed to initialize AI model', error)
      throw error
    }
  }

  /**
   * Train the model with synthetic data
   */
  private async trainModel(): Promise<void> {
    // Generate synthetic training data
    const trainingData = this.generateSyntheticTrainingData(1000)

    const xs = tensor2d(trainingData.features)
    const ys = tensor2d(trainingData.labels, [trainingData.labels.length, 1])

    await this.model!.fit(xs, ys, {
      epochs: 50,
      batchSize: 32,
      validationSplit: 0.2,
      verbose: 0,
    })

    xs.dispose()
    ys.dispose()
  }

  /**
   * Generate synthetic training data for the model
   */
  private generateSyntheticTrainingData(samples: number): {
    features: number[][]
    labels: number[]
  } {
    const features: number[][] = []
    const labels: number[] = []

    for (let i = 0; i < samples; i++) {
      const dataCompleteness = Math.random()
      const contactQuality = Math.random()
      const businessSize = Math.random()
      const industryRelevance = Math.random()
      const geographicDesirability = Math.random()
      const webPresence = Math.random()

      // Synthetic scoring logic for training
      const score =
        dataCompleteness * 0.25 +
        contactQuality * 0.2 +
        businessSize * 0.15 +
        industryRelevance * 0.15 +
        geographicDesirability * 0.15 +
        webPresence * 0.1

      features.push([
        dataCompleteness,
        contactQuality,
        businessSize,
        industryRelevance,
        geographicDesirability,
        webPresence,
      ])
      labels.push(score)
    }

    return { features, labels }
  }

  /**
   * Calculate lead score for a business record
   */
  async getLeadScore(business: BusinessRecord): Promise<LeadScore> {
    if (!this.isInitialized) {
      await this.initialize()
    }

    try {
      const factors = this.calculateScoreFactors(business)
      const mlScore = await this.calculateMLScore(factors)
      const ruleBasedScore = this.calculateRuleBasedScore(factors)

      // Combine ML and rule-based scores
      const finalScore = Math.round((mlScore * 0.7 + ruleBasedScore * 0.3) * 100)
      const confidence = this.calculateConfidence(factors)
      const recommendations = this.generateRecommendations(factors, finalScore)

      return {
        score: Math.max(this.config.minimumScore, Math.min(100, finalScore)),
        confidence,
        factors,
        recommendations,
      }
    } catch (error) {
      logger.error('AILeadScoring', 'Failed to calculate lead score', error)

      // Fallback to rule-based scoring
      const factors = this.calculateScoreFactors(business)
      const fallbackScore = this.calculateRuleBasedScore(factors)

      return {
        score: Math.round(fallbackScore * 100),
        confidence: 0.5,
        factors,
        recommendations: ['Score calculated using fallback method due to AI model error'],
      }
    }
  }

  /**
   * Calculate individual scoring factors
   */
  private calculateScoreFactors(business: BusinessRecord): ScoreFactors {
    return {
      dataCompleteness: this.calculateDataCompleteness(business),
      contactQuality: this.calculateContactQuality(business),
      businessSize: this.calculateBusinessSize(business),
      industryRelevance: this.calculateIndustryRelevance(business),
      geographicDesirability: this.calculateGeographicDesirability(business),
      webPresence: this.calculateWebPresence(business),
    }
  }

  /**
   * Calculate data completeness score (0-100)
   */
  private calculateDataCompleteness(business: BusinessRecord): number {
    let score = 0
    let totalFields = 0

    // Required fields
    const requiredFields = [
      business.businessName,
      business.email?.length > 0,
      business.websiteUrl,
      business.address?.street,
      business.address?.city,
      business.address?.state,
      business.address?.zipCode,
      business.industry,
    ]

    requiredFields.forEach(field => {
      totalFields++
      if (field) score++
    })

    // Optional fields (bonus points)
    const optionalFields = [
      business.phone,
      business.contactPerson,
      business.coordinates?.lat,
      business.coordinates?.lng,
    ]

    optionalFields.forEach(field => {
      if (field) score += 0.5
    })

    return Math.min(100, (score / totalFields) * 100)
  }

  /**
   * Calculate contact quality score (0-100)
   */
  private calculateContactQuality(business: BusinessRecord): number {
    let score = 0

    // Email quality
    if (business.email && business.email.length > 0) {
      score += 40

      // Bonus for multiple emails
      if (business.email.length > 1) score += 10

      // Bonus for professional email domains
      const professionalDomains = business.email.some(
        email =>
          !email.includes('gmail.com') &&
          !email.includes('yahoo.com') &&
          !email.includes('hotmail.com')
      )
      if (professionalDomains) score += 15
    }

    // Phone number
    if (business.phone) score += 25

    // Contact person
    if (business.contactPerson) score += 20

    return Math.min(100, score)
  }

  /**
   * Calculate business size indicator (0-100)
   */
  private calculateBusinessSize(business: BusinessRecord): number {
    let score = 50 // Default medium size

    // Website quality indicator
    if (business.websiteUrl) {
      const domain = business.websiteUrl.toLowerCase()
      if (domain.includes('.com') || domain.includes('.org')) score += 20
      if (domain.length > 20) score += 10 // Longer domains might indicate established business
    }

    // Address completeness as size indicator
    if (business.address?.suite) score += 15 // Suite number suggests office space

    return Math.min(100, score)
  }

  /**
   * Calculate industry relevance score (0-100)
   */
  private calculateIndustryRelevance(business: BusinessRecord): number {
    const industryPriority = this.config.industryPriorities[business.industry] || 0.5
    return industryPriority * 100
  }

  /**
   * Calculate geographic desirability score (0-100)
   */
  private calculateGeographicDesirability(business: BusinessRecord): number {
    if (!business.address?.state) return 50

    const statePriority = this.config.geographicPriorities[business.address.state] || 0.5
    return statePriority * 100
  }

  /**
   * Calculate web presence score (0-100)
   */
  private calculateWebPresence(business: BusinessRecord): number {
    let score = 0

    if (business.websiteUrl) {
      score += 60

      // Bonus for HTTPS
      if (business.websiteUrl.startsWith('https://')) score += 20

      // Bonus for professional domain
      if (
        !business.websiteUrl.includes('wordpress.com') &&
        !business.websiteUrl.includes('wix.com') &&
        !business.websiteUrl.includes('squarespace.com')
      ) {
        score += 20
      }
    }

    return Math.min(100, score)
  }

  /**
   * Calculate ML-based score using the trained model
   */
  private async calculateMLScore(factors: ScoreFactors): Promise<number> {
    if (!this.model) return 0.5

    const input = tensor2d([
      [
        factors.dataCompleteness / 100,
        factors.contactQuality / 100,
        factors.businessSize / 100,
        factors.industryRelevance / 100,
        factors.geographicDesirability / 100,
        factors.webPresence / 100,
      ],
    ])

    const prediction = this.model.predict(input) as Tensor
    const score = await prediction.data()

    input.dispose()
    prediction.dispose()

    return score[0]
  }

  /**
   * Calculate rule-based score as fallback
   */
  private calculateRuleBasedScore(factors: ScoreFactors): number {
    const weights = this.config.weights

    return (
      (factors.dataCompleteness / 100) * weights.dataCompleteness +
      (factors.contactQuality / 100) * weights.contactQuality +
      (factors.businessSize / 100) * weights.businessSize +
      (factors.industryRelevance / 100) * weights.industryRelevance +
      (factors.geographicDesirability / 100) * weights.geographicDesirability +
      (factors.webPresence / 100) * weights.webPresence
    )
  }

  /**
   * Calculate confidence score
   */
  private calculateConfidence(factors: ScoreFactors): number {
    // Higher confidence when data is more complete
    const avgCompleteness = Object.values(factors).reduce((sum, val) => sum + val, 0) / 6
    return Math.min(1, avgCompleteness / 100)
  }

  /**
   * Generate recommendations based on scoring factors
   */
  private generateRecommendations(factors: ScoreFactors, score: number): string[] {
    const recommendations: string[] = []

    if (factors.dataCompleteness < 70) {
      recommendations.push('Improve data completeness by gathering missing contact information')
    }

    if (factors.contactQuality < 60) {
      recommendations.push('Verify and enhance contact information quality')
    }

    if (factors.webPresence < 50) {
      recommendations.push('Business may benefit from improved web presence')
    }

    if (score >= 80) {
      recommendations.push('High-quality lead - prioritize for immediate contact')
    } else if (score >= 60) {
      recommendations.push('Good lead - suitable for standard follow-up process')
    } else if (score >= 40) {
      recommendations.push('Moderate lead - may require additional qualification')
    } else {
      recommendations.push('Low-priority lead - consider for nurturing campaigns')
    }

    return recommendations
  }

  /**
   * Batch score multiple businesses
   */
  async scoreBusinesses(businesses: BusinessRecord[]): Promise<Map<string, LeadScore>> {
    const scores = new Map<string, LeadScore>()

    for (const business of businesses) {
      try {
        const score = await this.getLeadScore(business)
        scores.set(business.id, score)
      } catch (error) {
        logger.error('AILeadScoring', `Failed to score business ${business.id}`, error)
      }
    }

    return scores
  }

  /**
   * Update scoring configuration
   */
  updateConfig(newConfig: Partial<ScoringConfig>): void {
    this.config = { ...this.config, ...newConfig }
    logger.info('AILeadScoring', 'Scoring configuration updated')
  }

  /**
   * Get current configuration
   */
  getConfig(): ScoringConfig {
    return { ...this.config }
  }

  /**
   * Dispose of the model and free memory
   */
  dispose(): void {
    if (this.model) {
      this.model.dispose()
      this.model = null
    }
    this.isInitialized = false
    logger.info('AILeadScoring', 'AI model disposed')
  }
}

// Export singleton instance
export const aiLeadScoringService = new AILeadScoringService()
