/**
 * Compliance Reporting Service
 * Generates comprehensive compliance reports for various regulatory standards
 */

import { auditService, AuditLog, ComplianceReport } from './auditService'
import { gdprService } from './gdprService'
import { logger } from '@/utils/logger'

export interface ComplianceMetrics {
  totalEvents: number
  securityIncidents: number
  dataAccessEvents: number
  paymentEvents: number
  userRightsRequests: number
  dataBreaches: number
  complianceViolations: number
}

export interface ComplianceReportRequest {
  complianceType: 'GDPR' | 'PCI_DSS' | 'SOC2' | 'SOX' | 'HIPAA' | 'ISO27001'
  startDate: Date
  endDate: Date
  includeDetails: boolean
  format: 'json' | 'pdf' | 'csv' | 'xml'
  requestedBy: string
}

export interface DetailedComplianceReport extends ComplianceReport {
  metrics: ComplianceMetrics
  riskAssessment: RiskAssessment
  recommendations: string[]
  complianceScore: number
  previousPeriodComparison?: ComplianceComparison
}

export interface RiskAssessment {
  overallRisk: 'low' | 'medium' | 'high' | 'critical'
  riskFactors: RiskFactor[]
  mitigationStrategies: string[]
}

export interface RiskFactor {
  category: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  impact: string
  likelihood: string
}

export interface ComplianceComparison {
  previousPeriod: { startDate: Date; endDate: Date }
  metricsChange: Record<string, number>
  trendAnalysis: string[]
}

export class ComplianceReportingService {
  private reports: DetailedComplianceReport[] = []

  /**
   * Generate comprehensive compliance report
   */
  async generateComplianceReport(request: ComplianceReportRequest): Promise<DetailedComplianceReport> {
    try {
      logger.info('ComplianceReporting', `Generating ${request.complianceType} report`, {
        startDate: request.startDate,
        endDate: request.endDate,
        requestedBy: request.requestedBy
      })

      // Get base audit report
      const baseReport = await auditService.generateComplianceReport(
        request.startDate,
        request.endDate,
        request.complianceType
      )

      // Calculate detailed metrics
      const metrics = await this.calculateComplianceMetrics(
        request.startDate,
        request.endDate,
        request.complianceType
      )

      // Perform risk assessment
      const riskAssessment = await this.performRiskAssessment(
        baseReport.securityIncidents,
        metrics,
        request.complianceType
      )

      // Generate recommendations
      const recommendations = await this.generateRecommendations(
        riskAssessment,
        metrics,
        request.complianceType
      )

      // Calculate compliance score
      const complianceScore = this.calculateComplianceScore(metrics, riskAssessment)

      // Get previous period comparison if requested
      const previousPeriodComparison = request.includeDetails
        ? await this.getPreviousPeriodComparison(request)
        : undefined

      const detailedReport: DetailedComplianceReport = {
        ...baseReport,
        metrics,
        riskAssessment,
        recommendations,
        complianceScore,
        previousPeriodComparison
      }

      // Store report
      this.reports.push(detailedReport)

      // Log report generation
      await auditService.logAuditEvent('compliance_report_generated', 'system', {
        userId: request.requestedBy,
        resourceId: detailedReport.reportId,
        newValues: {
          complianceType: request.complianceType,
          period: `${request.startDate.toISOString()} - ${request.endDate.toISOString()}`,
          complianceScore: complianceScore,
          riskLevel: riskAssessment.overallRisk
        },
        severity: 'medium',
        category: 'system',
        complianceFlags: [request.complianceType]
      })

      logger.info('ComplianceReporting', `Compliance report generated successfully`, {
        reportId: detailedReport.reportId,
        complianceScore,
        riskLevel: riskAssessment.overallRisk
      })

      return detailedReport
    } catch (error) {
      logger.error('ComplianceReporting', 'Failed to generate compliance report', error)
      throw error
    }
  }

  /**
   * Generate GDPR-specific report
   */
  async generateGDPRReport(startDate: Date, endDate: Date, requestedBy: string): Promise<DetailedComplianceReport> {
    const request: ComplianceReportRequest = {
      complianceType: 'GDPR',
      startDate,
      endDate,
      includeDetails: true,
      format: 'json',
      requestedBy
    }

    const report = await this.generateComplianceReport(request)

    // Add GDPR-specific data
    const gdprRequests = await gdprService.getUserRequests('all') // Would need to implement this
    
    // Enhance report with GDPR-specific metrics
    report.metrics.userRightsRequests = gdprRequests.exportRequests.length + gdprRequests.deletionRequests.length

    return report
  }

  /**
   * Generate PCI DSS report
   */
  async generatePCIDSSReport(startDate: Date, endDate: Date, requestedBy: string): Promise<DetailedComplianceReport> {
    const request: ComplianceReportRequest = {
      complianceType: 'PCI_DSS',
      startDate,
      endDate,
      includeDetails: true,
      format: 'json',
      requestedBy
    }

    return await this.generateComplianceReport(request)
  }

  /**
   * Generate SOC 2 report
   */
  async generateSOC2Report(startDate: Date, endDate: Date, requestedBy: string): Promise<DetailedComplianceReport> {
    const request: ComplianceReportRequest = {
      complianceType: 'SOC2',
      startDate,
      endDate,
      includeDetails: true,
      format: 'json',
      requestedBy
    }

    return await this.generateComplianceReport(request)
  }

  /**
   * Get all compliance reports
   */
  async getComplianceReports(filters?: {
    complianceType?: string
    startDate?: Date
    endDate?: Date
    requestedBy?: string
  }): Promise<DetailedComplianceReport[]> {
    let filteredReports = [...this.reports]

    if (filters?.complianceType) {
      filteredReports = filteredReports.filter(r => r.complianceType === filters.complianceType)
    }

    if (filters?.startDate) {
      filteredReports = filteredReports.filter(r => r.period.startDate >= filters.startDate!)
    }

    if (filters?.endDate) {
      filteredReports = filteredReports.filter(r => r.period.endDate <= filters.endDate!)
    }

    return filteredReports.sort((a, b) => b.generatedAt.getTime() - a.generatedAt.getTime())
  }

  /**
   * Calculate detailed compliance metrics
   */
  private async calculateComplianceMetrics(
    startDate: Date,
    endDate: Date,
    complianceType: string
  ): Promise<ComplianceMetrics> {
    const auditLogs = await auditService.getAuditLogs({
      startDate,
      endDate,
      complianceFlags: [complianceType]
    })

    const logs = auditLogs.logs

    return {
      totalEvents: logs.length,
      securityIncidents: logs.filter(log => 
        log.category === 'security' && log.severity === 'critical'
      ).length,
      dataAccessEvents: logs.filter(log => log.category === 'data').length,
      paymentEvents: logs.filter(log => log.category === 'payment').length,
      userRightsRequests: logs.filter(log => 
        log.action.includes('data_export') || log.action.includes('data_deletion')
      ).length,
      dataBreaches: logs.filter(log => 
        log.action.includes('data_breach') || log.action.includes('unauthorized_access')
      ).length,
      complianceViolations: logs.filter(log => 
        log.severity === 'critical' && log.action.includes('violation')
      ).length
    }
  }

  /**
   * Perform risk assessment
   */
  private async performRiskAssessment(
    securityIncidents: AuditLog[],
    metrics: ComplianceMetrics,
    complianceType: string
  ): Promise<RiskAssessment> {
    const riskFactors: RiskFactor[] = []

    // Analyze security incidents
    if (metrics.securityIncidents > 0) {
      riskFactors.push({
        category: 'Security',
        description: `${metrics.securityIncidents} critical security incidents detected`,
        severity: metrics.securityIncidents > 5 ? 'critical' : 'high',
        impact: 'High - potential data compromise',
        likelihood: 'Medium'
      })
    }

    // Analyze data breaches
    if (metrics.dataBreaches > 0) {
      riskFactors.push({
        category: 'Data Protection',
        description: `${metrics.dataBreaches} potential data breaches detected`,
        severity: 'critical',
        impact: 'Critical - regulatory penalties possible',
        likelihood: 'High'
      })
    }

    // Analyze compliance violations
    if (metrics.complianceViolations > 0) {
      riskFactors.push({
        category: 'Compliance',
        description: `${metrics.complianceViolations} compliance violations detected`,
        severity: 'high',
        impact: 'High - regulatory action possible',
        likelihood: 'Medium'
      })
    }

    // Determine overall risk
    const criticalFactors = riskFactors.filter(f => f.severity === 'critical').length
    const highFactors = riskFactors.filter(f => f.severity === 'high').length

    let overallRisk: 'low' | 'medium' | 'high' | 'critical'
    if (criticalFactors > 0) {
      overallRisk = 'critical'
    } else if (highFactors > 2) {
      overallRisk = 'high'
    } else if (highFactors > 0 || riskFactors.length > 0) {
      overallRisk = 'medium'
    } else {
      overallRisk = 'low'
    }

    return {
      overallRisk,
      riskFactors,
      mitigationStrategies: this.generateMitigationStrategies(riskFactors, complianceType)
    }
  }

  /**
   * Generate compliance recommendations
   */
  private async generateRecommendations(
    riskAssessment: RiskAssessment,
    metrics: ComplianceMetrics,
    complianceType: string
  ): Promise<string[]> {
    const recommendations: string[] = []

    // General recommendations based on risk level
    if (riskAssessment.overallRisk === 'critical') {
      recommendations.push('Immediate security review and incident response required')
      recommendations.push('Consider engaging external security consultants')
    }

    // Specific recommendations based on compliance type
    switch (complianceType) {
      case 'GDPR':
        if (metrics.userRightsRequests > 10) {
          recommendations.push('Consider automating user rights request processing')
        }
        if (metrics.dataAccessEvents > 100) {
          recommendations.push('Implement stricter data access controls')
        }
        break

      case 'PCI_DSS':
        if (metrics.paymentEvents > 0 && metrics.securityIncidents > 0) {
          recommendations.push('Review payment processing security controls')
        }
        break

      case 'SOC2':
        if (metrics.securityIncidents > 0) {
          recommendations.push('Enhance security monitoring and alerting')
        }
        break
    }

    return recommendations
  }

  /**
   * Calculate compliance score (0-100)
   */
  private calculateComplianceScore(metrics: ComplianceMetrics, riskAssessment: RiskAssessment): number {
    let score = 100

    // Deduct points for incidents
    score -= metrics.securityIncidents * 10
    score -= metrics.dataBreaches * 20
    score -= metrics.complianceViolations * 15

    // Adjust based on overall risk
    switch (riskAssessment.overallRisk) {
      case 'critical':
        score -= 30
        break
      case 'high':
        score -= 20
        break
      case 'medium':
        score -= 10
        break
    }

    return Math.max(0, Math.min(100, score))
  }

  /**
   * Generate mitigation strategies
   */
  private generateMitigationStrategies(riskFactors: RiskFactor[], complianceType: string): string[] {
    const strategies: string[] = []

    riskFactors.forEach(factor => {
      switch (factor.category) {
        case 'Security':
          strategies.push('Implement additional security monitoring')
          strategies.push('Conduct security awareness training')
          break
        case 'Data Protection':
          strategies.push('Review data encryption practices')
          strategies.push('Implement data loss prevention controls')
          break
        case 'Compliance':
          strategies.push('Review compliance policies and procedures')
          strategies.push('Conduct compliance training for staff')
          break
      }
    })

    return [...new Set(strategies)] // Remove duplicates
  }

  /**
   * Get previous period comparison
   */
  private async getPreviousPeriodComparison(request: ComplianceReportRequest): Promise<ComplianceComparison | undefined> {
    const periodLength = request.endDate.getTime() - request.startDate.getTime()
    const previousStartDate = new Date(request.startDate.getTime() - periodLength)
    const previousEndDate = new Date(request.endDate.getTime() - periodLength)

    try {
      const previousMetrics = await this.calculateComplianceMetrics(
        previousStartDate,
        previousEndDate,
        request.complianceType
      )

      const currentMetrics = await this.calculateComplianceMetrics(
        request.startDate,
        request.endDate,
        request.complianceType
      )

      const metricsChange: Record<string, number> = {
        totalEvents: currentMetrics.totalEvents - previousMetrics.totalEvents,
        securityIncidents: currentMetrics.securityIncidents - previousMetrics.securityIncidents,
        dataAccessEvents: currentMetrics.dataAccessEvents - previousMetrics.dataAccessEvents,
        paymentEvents: currentMetrics.paymentEvents - previousMetrics.paymentEvents
      }

      const trendAnalysis: string[] = []
      if (metricsChange.securityIncidents > 0) {
        trendAnalysis.push('Security incidents have increased compared to previous period')
      }
      if (metricsChange.totalEvents > 0) {
        trendAnalysis.push('Overall activity has increased')
      }

      return {
        previousPeriod: { startDate: previousStartDate, endDate: previousEndDate },
        metricsChange,
        trendAnalysis
      }
    } catch (error) {
      logger.warn('ComplianceReporting', 'Failed to generate previous period comparison', error)
      return undefined
    }
  }
}

export const complianceReportingService = new ComplianceReportingService()
