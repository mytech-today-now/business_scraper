'use strict'

/**
 * AI and Machine Learning Types for Business Scraper
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

/**
 * Lead scoring result with confidence metrics
 */
export interface LeadScore {
  /** Overall lead quality score (0-100) */
  overallScore: number
  /** Confidence level in the score (0-1) */
  confidence: number
  /** Individual component scores */
  components: {
    websiteQuality: number
    businessMaturity: number
    conversionProbability: number
    industryRelevance: number
  }
  /** Detailed scoring breakdown */
  breakdown: {
    domainAuthority: number
    contentQuality: number
    technicalPerformance: number
    businessSignals: number
    contactAvailability: number
  }
  /** Timestamp when score was calculated */
  calculatedAt: Date
  /** Model version used for scoring */
  modelVersion: string
}

/**
 * Website quality analysis result
 */
export interface WebsiteQualityAnalysis {
  /** Overall website health score (0-100) */
  healthScore: number
  /** Lighthouse performance metrics */
  lighthouse: {
    performance: number
    accessibility: number
    bestPractices: number
    seo: number
    pwa: number
  }
  /** Content analysis results */
  content: {
    professionalismScore: number
    readabilityScore: number
    keywordRelevance: number
    callToActionPresence: boolean
    contactInfoAvailability: boolean
  }
  /** Technical analysis */
  technical: {
    loadTime: number
    mobileOptimized: boolean
    httpsEnabled: boolean
    socialMediaPresence: boolean
    structuredDataPresent: boolean
  }
  /** Analysis timestamp */
  analyzedAt: Date
}

/**
 * Business maturity indicators
 */
export interface BusinessMaturityIndicators {
  /** Overall maturity score (0-100) */
  maturityScore: number
  /** Growth indicators found */
  growthSignals: {
    careersPageExists: boolean
    jobPostingsFound: number
    fundingMentions: string[]
    pressReleases: string[]
    investorRelationsPage: boolean
    teamPageExists: boolean
    aboutPageQuality: number
  }
  /** Business size indicators */
  sizeIndicators: {
    estimatedEmployeeCount: number | null
    officeLocations: string[]
    serviceAreas: string[]
    clientTestimonials: number
    caseStudies: number
  }
  /** Digital presence maturity */
  digitalPresence: {
    socialMediaAccounts: string[]
    blogActivity: boolean
    lastBlogPost: Date | null
    emailMarketingSignup: boolean
    liveChatAvailable: boolean
  }
  /** Analysis timestamp */
  analyzedAt: Date
}

/**
 * Conversion probability prediction
 */
export interface ConversionPrediction {
  /** Probability of conversion (0-1) */
  probability: number
  /** Confidence interval */
  confidenceInterval: {
    lower: number
    upper: number
  }
  /** Factors influencing prediction */
  factors: {
    industryMatch: number
    businessSize: number
    websiteQuality: number
    contactAvailability: number
    geographicRelevance: number
  }
  /** Recommended outreach strategy */
  recommendedStrategy: 'email' | 'phone' | 'linkedin' | 'form'
  /** Best contact time prediction */
  bestContactTime: {
    dayOfWeek: string
    hourRange: string
    timezone: string
  }
  /** Prediction timestamp */
  predictedAt: Date
}

/**
 * Industry trend analysis
 */
export interface IndustryTrendAnalysis {
  /** Industry identifier */
  industry: string
  /** Trend direction */
  trendDirection: 'growing' | 'stable' | 'declining'
  /** Trend strength (0-1) */
  trendStrength: number
  /** Key insights */
  insights: {
    emergingKeywords: string[]
    decliningKeywords: string[]
    seasonalPatterns: SeasonalPattern[]
    competitorActivity: number
    marketSentiment: number
  }
  /** Analysis period */
  analysisPeriod: {
    startDate: Date
    endDate: Date
  }
  /** Analysis timestamp */
  analyzedAt: Date
}

/**
 * Seasonal business pattern
 */
export interface SeasonalPattern {
  /** Pattern name */
  name: string
  /** Peak months */
  peakMonths: number[]
  /** Low months */
  lowMonths: number[]
  /** Pattern strength (0-1) */
  strength: number
  /** Historical data points */
  historicalData: {
    month: number
    year: number
    activityLevel: number
  }[]
}

/**
 * Predictive analytics result
 */
export interface PredictiveAnalytics {
  /** Lead scoring predictions */
  leadScoring: LeadScore
  /** Website quality analysis */
  websiteQuality: WebsiteQualityAnalysis
  /** Business maturity assessment */
  businessMaturity: BusinessMaturityIndicators
  /** Conversion probability */
  conversionPrediction: ConversionPrediction
  /** Industry trends */
  industryTrends: IndustryTrendAnalysis[]
  /** Overall recommendation */
  recommendation: {
    priority: 'high' | 'medium' | 'low'
    reasoning: string
    nextSteps: string[]
    estimatedValue: number | null
  }
  /** Analytics timestamp */
  generatedAt: Date
}

/**
 * ML model configuration
 */
export interface MLModelConfig {
  /** Model name */
  name: string
  /** Model version */
  version: string
  /** Model type */
  type: 'classification' | 'regression' | 'clustering'
  /** Input features */
  features: string[]
  /** Model parameters */
  parameters: Record<string, any>
  /** Training data info */
  trainingInfo: {
    datasetSize: number
    lastTrainedAt: Date
    accuracy: number
    precision: number
    recall: number
  }
}

/**
 * AI service configuration
 */
export interface AIServiceConfig {
  /** Enable/disable AI features */
  enabled: boolean
  /** Model configurations */
  models: {
    leadScoring: MLModelConfig
    websiteQuality: MLModelConfig
    conversionPrediction: MLModelConfig
  }
  /** API configurations */
  apis: {
    huggingFace: {
      apiKey: string | null
      model: string
    }
    lighthouse: {
      enabled: boolean
      timeout: number
    }
  }
  /** Performance settings */
  performance: {
    batchSize: number
    maxConcurrentAnalysis: number
    cacheResults: boolean
    cacheTTL: number
  }
}

/**
 * AI processing job
 */
export interface AIProcessingJob {
  /** Job ID */
  id: string
  /** Job type */
  type: 'lead-scoring' | 'website-analysis' | 'trend-analysis' | 'batch-processing'
  /** Job status */
  status: 'pending' | 'running' | 'completed' | 'failed'
  /** Business record being processed */
  businessId: string
  /** Job progress (0-1) */
  progress: number
  /** Job result */
  result: PredictiveAnalytics | null
  /** Error message if failed */
  error: string | null
  /** Job timestamps */
  createdAt: Date
  startedAt: Date | null
  completedAt: Date | null
}

/**
 * AI insights summary
 */
export interface AIInsightsSummary {
  /** Total businesses analyzed */
  totalAnalyzed: number
  /** Average lead score */
  averageLeadScore: number
  /** High-priority leads count */
  highPriorityLeads: number
  /** Top performing industries */
  topIndustries: string[]
  /** Key trends identified */
  keyTrends: string[]
  /** Recommendations */
  recommendations: string[]
  /** Summary timestamp */
  generatedAt: Date
}
