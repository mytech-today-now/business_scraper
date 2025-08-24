/**
 * ROI (Return on Investment) Service
 * Tracks business value, calculates ROI metrics, and generates comprehensive reports
 */

import { ROIMetrics } from '@/types/multi-user'
import { database } from './postgresql-database'
import { logger } from '@/utils/logger'

export interface ROICalculationInput {
  workspaceId: string
  period: 'day' | 'week' | 'month' | 'quarter' | 'year'
  startDate: Date
  endDate: Date
  costPerHour?: number // Default hourly cost for time calculations
  estimatedLeadValue?: number // Estimated value per qualified lead
  conversionData?: {
    leadsContacted: number
    responseRate: number
    conversionRate: number
    avgDealValue: number
  }
}

export interface ROIReport {
  metrics: ROIMetrics
  breakdown: {
    costs: {
      timeInvestment: number
      toolCosts: number
      operationalCosts: number
      total: number
    }
    value: {
      leadsGenerated: number
      qualifiedLeads: number
      estimatedPipelineValue: number
      actualRevenue: number
      total: number
    }
    efficiency: {
      leadsPerHour: number
      costPerLead: number
      qualityScore: number
      timeToValue: number
    }
  }
  trends: {
    roiTrend: Array<{ date: string; roi: number }>
    costTrend: Array<{ date: string; cost: number }>
    valueTrend: Array<{ date: string; value: number }>
  }
  recommendations: string[]
}

export class ROIService {
  /**
   * Calculate comprehensive ROI metrics
   */
  static async calculateROI(input: ROICalculationInput): Promise<ROIMetrics> {
    try {
      // Get campaign and scraping data
      const campaignData = await this.getCampaignData(input)
      const scrapingData = await this.getScrapingData(input)
      const businessData = await this.getBusinessData(input)
      
      // Calculate input costs
      const totalTimeSpent = scrapingData.totalTimeHours
      const totalCosts = this.calculateTotalCosts(totalTimeSpent, input.costPerHour || 50)
      
      // Calculate output metrics
      const totalBusinessesFound = businessData.totalBusinesses
      const validatedBusinesses = businessData.validatedBusinesses
      const highQualityLeads = businessData.highQualityLeads
      const contactsEnriched = businessData.enrichedBusinesses
      
      // Calculate quality metrics
      const avgConfidenceScore = businessData.avgConfidenceScore
      const dataAccuracyRate = businessData.dataAccuracyRate
      const duplicateRate = businessData.duplicateRate
      
      // Calculate conversion metrics
      const conversionMetrics = this.calculateConversionMetrics(
        validatedBusinesses,
        input.conversionData
      )
      
      // Calculate ROI
      const costPerLead = totalBusinessesFound > 0 ? totalCosts / totalBusinessesFound : 0
      const costPerValidatedLead = validatedBusinesses > 0 ? totalCosts / validatedBusinesses : 0
      const estimatedValue = this.calculateEstimatedValue(
        highQualityLeads,
        input.estimatedLeadValue || 100,
        conversionMetrics
      )
      const roi = totalCosts > 0 ? ((estimatedValue - totalCosts) / totalCosts) * 100 : 0

      return {
        workspaceId: input.workspaceId,
        period: input.period,
        startDate: input.startDate,
        endDate: input.endDate,
        
        // Input metrics
        totalCampaigns: campaignData.totalCampaigns,
        totalScrapingSessions: scrapingData.totalSessions,
        totalTimeSpent,
        totalCosts,
        
        // Output metrics
        totalBusinessesFound,
        validatedBusinesses,
        highQualityLeads,
        contactsEnriched,
        
        // Quality metrics
        avgConfidenceScore,
        dataAccuracyRate,
        duplicateRate,
        
        // Conversion metrics
        leadsContacted: conversionMetrics.leadsContacted,
        responseRate: conversionMetrics.responseRate,
        conversionRate: conversionMetrics.conversionRate,
        
        // ROI calculations
        costPerLead,
        costPerValidatedLead,
        estimatedValue,
        roi
      }
    } catch (error) {
      logger.error('ROI Service', 'Error calculating ROI metrics', error)
      throw error
    }
  }

  /**
   * Generate comprehensive ROI report
   */
  static async generateROIReport(input: ROICalculationInput): Promise<ROIReport> {
    try {
      const metrics = await this.calculateROI(input)
      const breakdown = await this.calculateBreakdown(input, metrics)
      const trends = await this.calculateTrends(input)
      const recommendations = this.generateRecommendations(metrics, breakdown)

      return {
        metrics,
        breakdown,
        trends,
        recommendations
      }
    } catch (error) {
      logger.error('ROI Service', 'Error generating ROI report', error)
      throw error
    }
  }

  /**
   * Get campaign data for ROI calculation
   */
  private static async getCampaignData(input: ROICalculationInput): Promise<{
    totalCampaigns: number
    activeCampaigns: number
    completedCampaigns: number
  }> {
    const result = await database.query(`
      SELECT 
        COUNT(*) as total_campaigns,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_campaigns,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_campaigns
      FROM campaigns
      WHERE workspace_id = $1
      AND created_at >= $2 AND created_at <= $3
    `, [input.workspaceId, input.startDate, input.endDate])

    const row = result.rows[0]
    return {
      totalCampaigns: parseInt(row.total_campaigns) || 0,
      activeCampaigns: parseInt(row.active_campaigns) || 0,
      completedCampaigns: parseInt(row.completed_campaigns) || 0
    }
  }

  /**
   * Get scraping data for ROI calculation
   */
  private static async getScrapingData(input: ROICalculationInput): Promise<{
    totalSessions: number
    totalTimeHours: number
    successfulScrapes: number
    failedScrapes: number
  }> {
    const result = await database.query(`
      SELECT 
        COUNT(*) as total_sessions,
        SUM(EXTRACT(EPOCH FROM (completed_at - started_at)) / 3600) as total_time_hours,
        SUM(successful_scrapes) as successful_scrapes,
        SUM(failed_scrapes) as failed_scrapes
      FROM scraping_sessions
      WHERE workspace_id = $1
      AND started_at >= $2 AND started_at <= $3
      AND completed_at IS NOT NULL
    `, [input.workspaceId, input.startDate, input.endDate])

    const row = result.rows[0]
    return {
      totalSessions: parseInt(row.total_sessions) || 0,
      totalTimeHours: parseFloat(row.total_time_hours) || 0,
      successfulScrapes: parseInt(row.successful_scrapes) || 0,
      failedScrapes: parseInt(row.failed_scrapes) || 0
    }
  }

  /**
   * Get business data for ROI calculation
   */
  private static async getBusinessData(input: ROICalculationInput): Promise<{
    totalBusinesses: number
    validatedBusinesses: number
    highQualityLeads: number
    enrichedBusinesses: number
    avgConfidenceScore: number
    dataAccuracyRate: number
    duplicateRate: number
  }> {
    const result = await database.query(`
      SELECT 
        COUNT(*) as total_businesses,
        COUNT(CASE WHEN validation_status = 'validated' THEN 1 END) as validated_businesses,
        COUNT(CASE WHEN confidence_score > 0.8 THEN 1 END) as high_quality_leads,
        COUNT(CASE WHEN array_length(email, 1) > 0 THEN 1 END) as enriched_businesses,
        AVG(confidence_score) as avg_confidence_score
      FROM businesses b
      JOIN campaigns c ON b.campaign_id = c.id
      WHERE c.workspace_id = $1
      AND b.scraped_at >= $2 AND b.scraped_at <= $3
    `, [input.workspaceId, input.startDate, input.endDate])

    const row = result.rows[0]
    const totalBusinesses = parseInt(row.total_businesses) || 0
    const validatedBusinesses = parseInt(row.validated_businesses) || 0

    // Calculate data accuracy rate (simplified)
    const dataAccuracyRate = totalBusinesses > 0 ? (validatedBusinesses / totalBusinesses) * 100 : 0

    // Calculate duplicate rate (simplified - would need more complex logic)
    const duplicateRate = 5 // Placeholder - would need actual duplicate detection

    return {
      totalBusinesses,
      validatedBusinesses,
      highQualityLeads: parseInt(row.high_quality_leads) || 0,
      enrichedBusinesses: parseInt(row.enriched_businesses) || 0,
      avgConfidenceScore: parseFloat(row.avg_confidence_score) || 0,
      dataAccuracyRate,
      duplicateRate
    }
  }

  /**
   * Calculate total costs
   */
  private static calculateTotalCosts(timeHours: number, costPerHour: number): number {
    const laborCosts = timeHours * costPerHour
    const toolCosts = 100 // Placeholder for tool/infrastructure costs
    const operationalCosts = 50 // Placeholder for operational overhead
    
    return laborCosts + toolCosts + operationalCosts
  }

  /**
   * Calculate conversion metrics
   */
  private static calculateConversionMetrics(
    validatedBusinesses: number,
    conversionData?: ROICalculationInput['conversionData']
  ): {
    leadsContacted: number
    responseRate: number
    conversionRate: number
  } {
    if (!conversionData) {
      return {
        leadsContacted: 0,
        responseRate: 0,
        conversionRate: 0
      }
    }

    return {
      leadsContacted: conversionData.leadsContacted,
      responseRate: conversionData.responseRate,
      conversionRate: conversionData.conversionRate
    }
  }

  /**
   * Calculate estimated value
   */
  private static calculateEstimatedValue(
    highQualityLeads: number,
    estimatedLeadValue: number,
    conversionMetrics: { leadsContacted: number; responseRate: number; conversionRate: number }
  ): number {
    // Base value from high-quality leads
    const baseValue = highQualityLeads * estimatedLeadValue

    // Adjust for actual conversion data if available
    if (conversionMetrics.leadsContacted > 0) {
      const actualConversions = conversionMetrics.leadsContacted * 
                               (conversionMetrics.responseRate / 100) * 
                               (conversionMetrics.conversionRate / 100)
      const conversionValue = actualConversions * estimatedLeadValue * 5 // Assume 5x value for actual conversions
      return Math.max(baseValue, conversionValue)
    }

    return baseValue
  }

  /**
   * Calculate detailed breakdown
   */
  private static async calculateBreakdown(
    input: ROICalculationInput,
    metrics: ROIMetrics
  ): Promise<ROIReport['breakdown']> {
    const timeInvestment = metrics.totalTimeSpent * (input.costPerHour || 50)
    const toolCosts = 100 // Placeholder
    const operationalCosts = 50 // Placeholder

    const leadsPerHour = metrics.totalTimeSpent > 0 ? metrics.totalBusinessesFound / metrics.totalTimeSpent : 0
    const qualityScore = metrics.avgConfidenceScore * 100
    const timeToValue = 24 // Placeholder - hours from start to first qualified lead

    return {
      costs: {
        timeInvestment,
        toolCosts,
        operationalCosts,
        total: metrics.totalCosts
      },
      value: {
        leadsGenerated: metrics.totalBusinessesFound,
        qualifiedLeads: metrics.validatedBusinesses,
        estimatedPipelineValue: metrics.estimatedValue,
        actualRevenue: 0, // Would need to be tracked separately
        total: metrics.estimatedValue
      },
      efficiency: {
        leadsPerHour,
        costPerLead: metrics.costPerLead,
        qualityScore,
        timeToValue
      }
    }
  }

  /**
   * Calculate trend data
   */
  private static async calculateTrends(input: ROICalculationInput): Promise<ROIReport['trends']> {
    // Calculate daily ROI trends
    const roiTrendQuery = `
      WITH daily_metrics AS (
        SELECT 
          DATE(b.scraped_at) as date,
          COUNT(*) as businesses_found,
          COUNT(CASE WHEN b.validation_status = 'validated' THEN 1 END) as validated,
          AVG(b.confidence_score) as avg_confidence
        FROM businesses b
        JOIN campaigns c ON b.campaign_id = c.id
        WHERE c.workspace_id = $1
        AND b.scraped_at >= $2 AND b.scraped_at <= $3
        GROUP BY DATE(b.scraped_at)
      )
      SELECT 
        date,
        businesses_found,
        validated,
        avg_confidence
      FROM daily_metrics
      ORDER BY date
    `

    const trendResult = await database.query(roiTrendQuery, [
      input.workspaceId,
      input.startDate,
      input.endDate
    ])

    const roiTrend = trendResult.rows.map(row => ({
      date: row.date,
      roi: this.calculateDailyROI(row.businesses_found, row.validated, input.estimatedLeadValue || 100)
    }))

    const costTrend = trendResult.rows.map(row => ({
      date: row.date,
      cost: row.businesses_found * 2 // Simplified cost calculation
    }))

    const valueTrend = trendResult.rows.map(row => ({
      date: row.date,
      value: row.validated * (input.estimatedLeadValue || 100)
    }))

    return {
      roiTrend,
      costTrend,
      valueTrend
    }
  }

  /**
   * Calculate daily ROI
   */
  private static calculateDailyROI(businessesFound: number, validated: number, leadValue: number): number {
    const cost = businessesFound * 2 // Simplified
    const value = validated * leadValue
    return cost > 0 ? ((value - cost) / cost) * 100 : 0
  }

  /**
   * Generate recommendations
   */
  private static generateRecommendations(metrics: ROIMetrics, breakdown: ROIReport['breakdown']): string[] {
    const recommendations: string[] = []

    // ROI-based recommendations
    if (metrics.roi < 50) {
      recommendations.push('ROI is below target (50%). Consider optimizing search criteria or improving data quality.')
    }

    // Cost efficiency recommendations
    if (metrics.costPerLead > 10) {
      recommendations.push('Cost per lead is high. Consider automating more of the validation process.')
    }

    // Quality recommendations
    if (breakdown.efficiency.qualityScore < 70) {
      recommendations.push('Data quality score is low. Review and refine search parameters.')
    }

    // Volume recommendations
    if (breakdown.efficiency.leadsPerHour < 10) {
      recommendations.push('Lead generation rate is low. Consider expanding search criteria or improving scraping efficiency.')
    }

    // Conversion recommendations
    if (metrics.responseRate && metrics.responseRate < 20) {
      recommendations.push('Response rate is low. Consider improving lead qualification or outreach messaging.')
    }

    // Default recommendation if all metrics are good
    if (recommendations.length === 0) {
      recommendations.push('Performance metrics are strong. Consider scaling operations or exploring new markets.')
    }

    return recommendations
  }

  /**
   * Export ROI report to various formats
   */
  static async exportROIReport(
    report: ROIReport,
    format: 'json' | 'csv' | 'pdf'
  ): Promise<{ data: any; filename: string; mimeType: string }> {
    const timestamp = new Date().toISOString().split('T')[0]
    const filename = `roi_report_${report.metrics.workspaceId}_${timestamp}`

    switch (format) {
      case 'json':
        return {
          data: JSON.stringify(report, null, 2),
          filename: `${filename}.json`,
          mimeType: 'application/json'
        }

      case 'csv':
        const csvData = this.convertToCSV(report)
        return {
          data: csvData,
          filename: `${filename}.csv`,
          mimeType: 'text/csv'
        }

      case 'pdf':
        // Would need PDF generation library
        throw new Error('PDF export not implemented yet')

      default:
        throw new Error(`Unsupported export format: ${format}`)
    }
  }

  /**
   * Convert ROI report to CSV format
   */
  private static convertToCSV(report: ROIReport): string {
    const headers = [
      'Metric',
      'Value',
      'Period',
      'Start Date',
      'End Date'
    ]

    const rows = [
      ['Total Campaigns', report.metrics.totalCampaigns, report.metrics.period, report.metrics.startDate.toISOString(), report.metrics.endDate.toISOString()],
      ['Total Businesses Found', report.metrics.totalBusinessesFound, '', '', ''],
      ['Validated Businesses', report.metrics.validatedBusinesses, '', '', ''],
      ['High Quality Leads', report.metrics.highQualityLeads, '', '', ''],
      ['Total Costs', report.metrics.totalCosts, '', '', ''],
      ['Estimated Value', report.metrics.estimatedValue, '', '', ''],
      ['ROI (%)', report.metrics.roi, '', '', ''],
      ['Cost Per Lead', report.metrics.costPerLead, '', '', ''],
      ['Data Accuracy Rate (%)', report.metrics.dataAccuracyRate, '', '', '']
    ]

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n')

    return csvContent
  }
}
