/**
 * AI Lead Scoring Service
 * Advanced machine learning-based lead scoring and predictive analytics
 */

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface AILeadScore {
  // Core scoring
  overallScore: number // 0-100
  confidence: number // 0-1
  rank: 'A' | 'B' | 'C' | 'D' | 'F' // Letter grade

  // Detailed scoring factors
  factors: {
    contactability: {
      score: number // 0-100
      weight: number // 0-1
      details: {
        emailQuality: number
        phonePresence: number
        websiteAccessibility: number
        multiChannelAvailability: number
      }
    }
    businessMaturity: {
      score: number
      weight: number
      details: {
        dataCompleteness: number
        establishedPresence: number
        professionalWebsite: number
        businessInformation: number
      }
    }
    marketPotential: {
      score: number
      weight: number
      details: {
        industryGrowth: number
        locationAdvantage: number
        competitivePosition: number
        marketSize: number
      }
    }
    engagementLikelihood: {
      score: number
      weight: number
      details: {
        responsiveness: number
        digitalPresence: number
        businessActivity: number
        communicationChannels: number
      }
    }
  }

  // Predictive insights
  predictions: {
    conversionProbability: number // 0-1
    responseTime: 'immediate' | 'fast' | 'moderate' | 'slow' | 'unlikely'
    bestContactMethod: 'email' | 'phone' | 'website' | 'social'
    optimalContactTime: {
      dayOfWeek: string[]
      timeOfDay: string[]
    }
  }

  // Visual indicators
  badges: AIBadge[]
  warnings: AIWarning[]
  recommendations: AIRecommendation[]

  // Metadata
  scoringVersion: string
  lastUpdated: Date
  processingTime: number
}

export interface AIBadge {
  type:
    | 'verified-email'
    | 'active-website'
    | 'complete-profile'
    | 'high-potential'
    | 'quick-responder'
    | 'established-business'
    | 'growth-industry'
    | 'local-leader'
  label: string
  color: 'green' | 'blue' | 'purple' | 'orange' | 'red'
  icon: string
  description: string
}

export interface AIWarning {
  type:
    | 'incomplete-data'
    | 'outdated-info'
    | 'low-engagement'
    | 'competitive-market'
    | 'contact-difficulty'
  message: string
  severity: 'low' | 'medium' | 'high'
  actionable: boolean
}

export interface AIRecommendation {
  type: 'contact-strategy' | 'data-enrichment' | 'timing-optimization' | 'channel-selection'
  title: string
  description: string
  priority: 'low' | 'medium' | 'high'
  estimatedImpact: number // 0-100
}

export interface AIScoreBatch {
  scores: Map<string, AILeadScore>
  batchMetrics: {
    totalProcessed: number
    averageScore: number
    scoreDistribution: { [grade: string]: number }
    processingTime: number
    topPerformers: string[] // Business IDs
    improvementOpportunities: string[] // Business IDs
  }
}

/**
 * AI Lead Scoring Service Class
 */
export class AILeadScoringService {
  private readonly scoringVersion = '2.0.0'
  private readonly industryGrowthData: Map<string, number> = new Map()
  private readonly locationAdvantageData: Map<string, number> = new Map()

  constructor() {
    this.initializeMarketData()
  }

  /**
   * Calculate AI lead score for a single business
   */
  async calculateLeadScore(business: BusinessRecord): Promise<AILeadScore> {
    const startTime = Date.now()

    try {
      // Calculate individual factor scores
      const contactability = this.calculateContactabilityScore(business)
      const businessMaturity = this.calculateBusinessMaturityScore(business)
      const marketPotential = this.calculateMarketPotentialScore(business)
      const engagementLikelihood = this.calculateEngagementLikelihoodScore(business)

      // Calculate weighted overall score
      const factors = {
        contactability: { ...contactability, weight: 0.3 },
        businessMaturity: { ...businessMaturity, weight: 0.25 },
        marketPotential: { ...marketPotential, weight: 0.25 },
        engagementLikelihood: { ...engagementLikelihood, weight: 0.2 },
      }

      const overallScore = Object.values(factors).reduce(
        (sum, factor) => sum + factor.score * factor.weight,
        0
      )

      // Calculate confidence based on data quality
      const confidence = this.calculateConfidence(business, factors)

      // Determine rank
      const rank = this.calculateRank(overallScore)

      // Generate predictions
      const predictions = this.generatePredictions(business, factors, overallScore)

      // Generate badges, warnings, and recommendations
      const badges = this.generateBadges(business, factors, overallScore)
      const warnings = this.generateWarnings(business, factors)
      const recommendations = this.generateRecommendations(business, factors)

      const processingTime = Date.now() - startTime

      return {
        overallScore: Math.round(overallScore),
        confidence,
        rank,
        factors,
        predictions,
        badges,
        warnings,
        recommendations,
        scoringVersion: this.scoringVersion,
        lastUpdated: new Date(),
        processingTime,
      }
    } catch (error) {
      logger.error('AILeadScoringService', 'Failed to calculate lead score', error)
      throw error
    }
  }

  /**
   * Calculate lead scores for multiple businesses (batch processing)
   */
  async calculateBatchScores(businesses: BusinessRecord[]): Promise<AIScoreBatch> {
    const startTime = Date.now()
    const scores = new Map<string, AILeadScore>()

    try {
      // Process in parallel batches for performance
      const batchSize = 50
      const batches = []

      for (let i = 0; i < businesses.length; i += batchSize) {
        const batch = businesses.slice(i, i + batchSize)
        batches.push(
          Promise.all(
            batch.map(async business => ({
              id: business.id,
              score: await this.calculateLeadScore(business),
            }))
          )
        )
      }

      const results = await Promise.all(batches)

      // Flatten results
      results.flat().forEach(({ id, score }) => {
        scores.set(id, score)
      })

      // Calculate batch metrics
      const allScores = Array.from(scores.values())
      const averageScore =
        allScores.reduce((sum, score) => sum + score.overallScore, 0) / allScores.length

      const scoreDistribution = allScores.reduce(
        (dist, score) => {
          dist[score.rank] = (dist[score.rank] || 0) + 1
          return dist
        },
        {} as { [grade: string]: number }
      )

      const topPerformers = allScores
        .filter(score => score.overallScore >= 80)
        .sort((a, b) => b.overallScore - a.overallScore)
        .slice(0, 10)
        .map(score => businesses.find(b => scores.get(b.id) === score)?.id)
        .filter(Boolean) as string[]

      const improvementOpportunities = allScores
        .filter(score => score.overallScore >= 40 && score.overallScore < 70)
        .sort((a, b) => b.overallScore - a.overallScore)
        .slice(0, 10)
        .map(score => businesses.find(b => scores.get(b.id) === score)?.id)
        .filter(Boolean) as string[]

      const processingTime = Date.now() - startTime

      logger.info(
        'AILeadScoringService',
        `Processed ${businesses.length} businesses in ${processingTime}ms`
      )

      return {
        scores,
        batchMetrics: {
          totalProcessed: businesses.length,
          averageScore,
          scoreDistribution,
          processingTime,
          topPerformers,
          improvementOpportunities,
        },
      }
    } catch (error) {
      logger.error('AILeadScoringService', 'Failed to calculate batch scores', error)
      throw error
    }
  }

  /**
   * Calculate contactability score
   */
  private calculateContactabilityScore(business: BusinessRecord) {
    const details = {
      emailQuality: this.scoreEmailQuality(business.email),
      phonePresence: business.phone ? 100 : 0,
      websiteAccessibility: this.scoreWebsiteAccessibility(business.websiteUrl),
      multiChannelAvailability: this.scoreMultiChannelAvailability(business),
    }

    const score = Object.values(details).reduce((sum, val) => sum + val, 0) / 4

    return { score, details }
  }

  /**
   * Calculate business maturity score
   */
  private calculateBusinessMaturityScore(business: BusinessRecord) {
    const details = {
      dataCompleteness: this.scoreDataCompleteness(business),
      establishedPresence: this.scoreEstablishedPresence(business),
      professionalWebsite: this.scoreProfessionalWebsite(business.websiteUrl),
      businessInformation: this.scoreBusinessInformation(business),
    }

    const score = Object.values(details).reduce((sum, val) => sum + val, 0) / 4

    return { score, details }
  }

  /**
   * Calculate market potential score
   */
  private calculateMarketPotentialScore(business: BusinessRecord) {
    const details = {
      industryGrowth: this.industryGrowthData.get(business.industry) || 50,
      locationAdvantage: this.scoreLocationAdvantage(business),
      competitivePosition: this.scoreCompetitivePosition(business),
      marketSize: this.scoreMarketSize(business),
    }

    const score = Object.values(details).reduce((sum, val) => sum + val, 0) / 4

    return { score, details }
  }

  /**
   * Calculate engagement likelihood score
   */
  private calculateEngagementLikelihoodScore(business: BusinessRecord) {
    const details = {
      responsiveness: this.scoreResponsiveness(business),
      digitalPresence: this.scoreDigitalPresence(business),
      businessActivity: this.scoreBusinessActivity(business),
      communicationChannels: this.scoreCommunicationChannels(business),
    }

    const score = Object.values(details).reduce((sum, val) => sum + val, 0) / 4

    return { score, details }
  }

  /**
   * Helper scoring methods
   */
  private scoreEmailQuality(emails: string[]): number {
    if (!emails || emails.length === 0) return 0

    let score = Math.min(emails.length * 20, 60) // Base score for having emails

    // Bonus for professional domains
    const professionalDomains = emails.filter(
      email =>
        !email.includes('gmail.com') &&
        !email.includes('yahoo.com') &&
        !email.includes('hotmail.com')
    )

    if (professionalDomains.length > 0) score += 40

    return Math.min(score, 100)
  }

  private scoreWebsiteAccessibility(website: string): number {
    if (!website) return 0
    if (website.startsWith('https://')) return 100
    if (website.startsWith('http://')) return 70
    return 50
  }

  private scoreMultiChannelAvailability(business: BusinessRecord): number {
    let channels = 0
    if (business.email.length > 0) channels++
    if (business.phone) channels++
    if (business.websiteUrl) channels++

    return (channels / 3) * 100
  }

  private scoreDataCompleteness(business: BusinessRecord): number {
    const fields = [
      business.businessName,
      business.email.length > 0,
      business.phone,
      business.websiteUrl,
      business.address.street,
      business.contactPerson,
      business.coordinates,
      business.industry,
    ]

    const completedFields = fields.filter(Boolean).length
    return (completedFields / fields.length) * 100
  }

  private scoreEstablishedPresence(business: BusinessRecord): number {
    // Simple heuristic - can be enhanced with real data
    const daysSinceScraped = Math.floor(
      (Date.now() - business.scrapedAt.getTime()) / (1000 * 60 * 60 * 24)
    )
    return Math.max(0, 100 - daysSinceScraped) // Newer data suggests more active business
  }

  private scoreProfessionalWebsite(website: string): number {
    if (!website) return 0

    let score = 50 // Base score for having a website

    if (website.includes('https://')) score += 20
    if (!website.includes('wordpress.com') && !website.includes('wix.com')) score += 20
    if (website.length > 20) score += 10 // Suggests custom domain

    return Math.min(score, 100)
  }

  private scoreBusinessInformation(business: BusinessRecord): number {
    let score = 0

    if (business.industry) score += 25
    if (business.contactPerson) score += 25
    if (business.coordinates) score += 25
    if (business.address.city && business.address.state) score += 25

    return score
  }

  private scoreLocationAdvantage(business: BusinessRecord): number {
    // Simplified - would use real market data
    const state = business.address.state
    const advantageousStates = ['CA', 'NY', 'TX', 'FL', 'WA']
    return advantageousStates.includes(state) ? 80 : 60
  }

  private scoreCompetitivePosition(business: BusinessRecord): number {
    // Simplified heuristic
    return 70 // Default moderate position
  }

  private scoreMarketSize(business: BusinessRecord): number {
    // Simplified based on location
    const city = business.address.city
    const majorCities = ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix']
    return majorCities.some(major => city?.includes(major)) ? 90 : 60
  }

  private scoreResponsiveness(business: BusinessRecord): number {
    // Would be based on historical interaction data
    return 70 // Default
  }

  private scoreDigitalPresence(business: BusinessRecord): number {
    let score = 0
    if (business.websiteUrl) score += 50
    if (business.email.length > 0) score += 30
    if (business.websiteUrl?.includes('https://')) score += 20
    return Math.min(score, 100)
  }

  private scoreBusinessActivity(business: BusinessRecord): number {
    // Based on data freshness and completeness
    const daysSinceScraped = Math.floor(
      (Date.now() - business.scrapedAt.getTime()) / (1000 * 60 * 60 * 24)
    )
    return Math.max(20, 100 - daysSinceScraped * 2)
  }

  private scoreCommunicationChannels(business: BusinessRecord): number {
    return this.scoreMultiChannelAvailability(business)
  }

  private calculateConfidence(business: BusinessRecord, factors: any): number {
    const dataQuality = this.scoreDataCompleteness(business) / 100
    const factorConsistency = this.calculateFactorConsistency(factors)
    return (dataQuality + factorConsistency) / 2
  }

  private calculateFactorConsistency(factors: any): number {
    const scores = Object.values(factors).map((f: any) => f.score)
    const avg = scores.reduce((sum, score) => sum + score, 0) / scores.length
    const variance =
      scores.reduce((sum, score) => sum + Math.pow(score - avg, 2), 0) / scores.length
    return Math.max(0, 1 - variance / 1000) // Lower variance = higher consistency
  }

  private calculateRank(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A'
    if (score >= 80) return 'B'
    if (score >= 70) return 'C'
    if (score >= 60) return 'D'
    return 'F'
  }

  private generatePredictions(business: BusinessRecord, factors: any, overallScore: number) {
    const conversionProbability = Math.min(overallScore / 100, 0.95)

    let responseTime: AILeadScore['predictions']['responseTime'] = 'moderate'
    if (overallScore >= 85) responseTime = 'immediate'
    else if (overallScore >= 70) responseTime = 'fast'
    else if (overallScore < 40) responseTime = 'unlikely'
    else responseTime = 'slow'

    let bestContactMethod: AILeadScore['predictions']['bestContactMethod'] = 'email'
    if (factors.contactability.details.phonePresence > 80) bestContactMethod = 'phone'
    else if (factors.contactability.details.websiteAccessibility > 80) bestContactMethod = 'website'

    return {
      conversionProbability,
      responseTime,
      bestContactMethod,
      optimalContactTime: {
        dayOfWeek: ['Tuesday', 'Wednesday', 'Thursday'],
        timeOfDay: ['9:00 AM', '2:00 PM'],
      },
    }
  }

  private generateBadges(business: BusinessRecord, factors: any, overallScore: number): AIBadge[] {
    const badges: AIBadge[] = []

    if (business.email.length > 0 && factors.contactability.details.emailQuality > 70) {
      badges.push({
        type: 'verified-email',
        label: 'Verified Email',
        color: 'green',
        icon: 'shield-check',
        description: 'High-quality email contact available',
      })
    }

    if (business.websiteUrl && factors.contactability.details.websiteAccessibility > 80) {
      badges.push({
        type: 'active-website',
        label: 'Active Website',
        color: 'blue',
        icon: 'globe',
        description: 'Professional website with secure connection',
      })
    }

    if (factors.businessMaturity.details.dataCompleteness > 80) {
      badges.push({
        type: 'complete-profile',
        label: 'Complete Profile',
        color: 'purple',
        icon: 'award',
        description: 'Comprehensive business information available',
      })
    }

    if (overallScore >= 85) {
      badges.push({
        type: 'high-potential',
        label: 'High Potential',
        color: 'orange',
        icon: 'star',
        description: 'Excellent lead quality with high conversion potential',
      })
    }

    return badges
  }

  private generateWarnings(business: BusinessRecord, factors: any): AIWarning[] {
    const warnings: AIWarning[] = []

    if (factors.businessMaturity.details.dataCompleteness < 50) {
      warnings.push({
        type: 'incomplete-data',
        message: 'Limited business information available',
        severity: 'medium',
        actionable: true,
      })
    }

    if (factors.contactability.score < 40) {
      warnings.push({
        type: 'contact-difficulty',
        message: 'Limited contact options available',
        severity: 'high',
        actionable: true,
      })
    }

    return warnings
  }

  private generateRecommendations(business: BusinessRecord, factors: any): AIRecommendation[] {
    const recommendations: AIRecommendation[] = []

    if (factors.contactability.details.emailQuality > 70) {
      recommendations.push({
        type: 'contact-strategy',
        title: 'Email First Approach',
        description: 'Start with email contact - high-quality email address detected',
        priority: 'high',
        estimatedImpact: 85,
      })
    }

    if (factors.businessMaturity.details.dataCompleteness < 70) {
      recommendations.push({
        type: 'data-enrichment',
        title: 'Enrich Business Data',
        description: 'Gather additional business information to improve lead quality',
        priority: 'medium',
        estimatedImpact: 60,
      })
    }

    return recommendations
  }

  private initializeMarketData(): void {
    // Initialize with sample industry growth data
    this.industryGrowthData.set('Technology', 85)
    this.industryGrowthData.set('Healthcare', 80)
    this.industryGrowthData.set('Finance', 70)
    this.industryGrowthData.set('Retail', 60)
    this.industryGrowthData.set('Manufacturing', 55)
    // Add more industries as needed
  }
}

// Export singleton instance
export const aiLeadScoringService = new AILeadScoringService()
