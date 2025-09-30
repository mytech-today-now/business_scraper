/**
 * Compliance Reporting Service Tests
 * Comprehensive tests for compliance reporting features
 */

import {
  complianceReportingService,
  ComplianceReportingService,
  ComplianceReportRequest,
} from '@/model/complianceReportingService'
import { expectArrayElement } from '../utils/mockTypeHelpers'

// Mock dependencies
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/model/auditService', () => ({
  auditService: {
    generateComplianceReport: jest.fn().mockResolvedValue({
      complianceType: 'GDPR',
      period: { startDate: new Date('2024-01-01'), endDate: new Date('2024-01-31') },
      totalEvents: 100,
      eventsByCategory: { security: 10, data: 20, payment: 5 },
      eventsBySeverity: { low: 50, medium: 30, high: 15, critical: 5 },
      securityIncidents: [],
      dataAccessEvents: [],
      paymentEvents: [],
      generatedAt: new Date(),
      reportId: 'test_report_123',
    }),
    getAuditLogs: jest.fn().mockResolvedValue({
      logs: [
        {
          id: 'log_1',
          action: 'data_access',
          category: 'data',
          severity: 'medium',
          complianceFlags: ['GDPR'],
          timestamp: new Date(),
        },
        {
          id: 'log_2',
          action: 'security_incident',
          category: 'security',
          severity: 'critical',
          complianceFlags: ['SOC2'],
          timestamp: new Date(),
        },
      ],
      total: 2,
    }),
    logAuditEvent: jest.fn().mockResolvedValue(undefined),
  },
}))

jest.mock('@/model/gdprService', () => ({
  gdprService: {
    getUserRequests: jest.fn().mockResolvedValue({
      exportRequests: [{ id: 'export_1' }],
      deletionRequests: [{ id: 'delete_1' }],
    }),
  },
}))

describe('ComplianceReportingService', () => {
  let testReportingService: ComplianceReportingService

  beforeEach(() => {
    testReportingService = new ComplianceReportingService()
    jest.clearAllMocks()
  })

  describe('generateComplianceReport', () => {
    const baseRequest: ComplianceReportRequest = {
      complianceType: 'GDPR',
      startDate: new Date('2024-01-01'),
      endDate: new Date('2024-01-31'),
      includeDetails: true,
      format: 'json',
      requestedBy: 'admin_user',
    }

    it('should generate comprehensive compliance report', async () => {
      const report = await testReportingService.generateComplianceReport(baseRequest)

      expect(report.complianceType).toBe('GDPR')
      expect(report.period.startDate).toEqual(baseRequest.startDate)
      expect(report.period.endDate).toEqual(baseRequest.endDate)
      expect(report.metrics).toBeDefined()
      expect(report.riskAssessment).toBeDefined()
      expect(report.recommendations).toBeDefined()
      expect(report.complianceScore).toBeGreaterThanOrEqual(0)
      expect(report.complianceScore).toBeLessThanOrEqual(100)
    })

    it('should include previous period comparison when requested', async () => {
      const report = await testReportingService.generateComplianceReport({
        ...baseRequest,
        includeDetails: true,
      })

      expect(report.previousPeriodComparison).toBeDefined()
    })

    it('should exclude previous period comparison when not requested', async () => {
      const report = await testReportingService.generateComplianceReport({
        ...baseRequest,
        includeDetails: false,
      })

      expect(report.previousPeriodComparison).toBeUndefined()
    })

    it('should log audit event for report generation', async () => {
      const auditService = require('@/model/auditService')

      await testReportingService.generateComplianceReport(baseRequest)

      expect(auditService.auditService.logAuditEvent).toHaveBeenCalledWith(
        'compliance_report_generated',
        'system',
        expect.objectContaining({
          userId: 'admin_user',
          severity: 'medium',
          category: 'system',
          complianceFlags: ['GDPR'],
        })
      )
    })

    it('should handle different compliance types', async () => {
      const complianceTypes = ['GDPR', 'PCI_DSS', 'SOC2', 'SOX', 'HIPAA', 'ISO27001'] as const

      for (const complianceType of complianceTypes) {
        const report = await testReportingService.generateComplianceReport({
          ...baseRequest,
          complianceType,
        })

        expect(report.complianceType).toBe(complianceType)
      }
    })
  })

  describe('generateGDPRReport', () => {
    it('should generate GDPR-specific report with user rights requests', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')
      const requestedBy = 'admin_user'

      const report = await testReportingService.generateGDPRReport(startDate, endDate, requestedBy)

      expect(report.complianceType).toBe('GDPR')
      expect(report.metrics.userRightsRequests).toBe(2) // 1 export + 1 deletion
    })
  })

  describe('generatePCIDSSReport', () => {
    it('should generate PCI DSS report', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')
      const requestedBy = 'admin_user'

      const report = await testReportingService.generatePCIDSSReport(
        startDate,
        endDate,
        requestedBy
      )

      expect(report.complianceType).toBe('PCI_DSS')
    })
  })

  describe('generateSOC2Report', () => {
    it('should generate SOC 2 report', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')
      const requestedBy = 'admin_user'

      const report = await testReportingService.generateSOC2Report(startDate, endDate, requestedBy)

      expect(report.complianceType).toBe('SOC2')
    })
  })

  describe('getComplianceReports', () => {
    beforeEach(async () => {
      // Generate test reports
      await testReportingService.generateGDPRReport(
        new Date('2024-01-01'),
        new Date('2024-01-31'),
        'admin_user'
      )
      await testReportingService.generatePCIDSSReport(
        new Date('2024-02-01'),
        new Date('2024-02-28'),
        'admin_user'
      )
    })

    it('should return all reports when no filters applied', async () => {
      const reports = await testReportingService.getComplianceReports()
      expect(reports.length).toBeGreaterThanOrEqual(2)
    })

    it('should filter reports by compliance type', async () => {
      const reports = await testReportingService.getComplianceReports({
        complianceType: 'GDPR',
      })

      expect(reports.length).toBeGreaterThanOrEqual(1)
      expect(reports.every(r => r.complianceType === 'GDPR')).toBe(true)
    })

    it('should filter reports by date range', async () => {
      const reports = await testReportingService.getComplianceReports({
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
      })

      expect(reports.length).toBeGreaterThanOrEqual(1)
    })

    it('should sort reports by generation date (newest first)', async () => {
      const reports = await testReportingService.getComplianceReports()

      for (let i = 1; i < reports.length; i++) {
        const previousReport = expectArrayElement(reports, i - 1)
        const currentReport = expectArrayElement(reports, i)
        expect(previousReport.generatedAt.getTime()).toBeGreaterThanOrEqual(
          currentReport.generatedAt.getTime()
        )
      }
    })
  })

  describe('calculateComplianceMetrics', () => {
    it('should calculate metrics correctly', async () => {
      const testService = new ComplianceReportingService()

      const metrics = await (testService as any).calculateComplianceMetrics(
        new Date('2024-01-01'),
        new Date('2024-01-31'),
        'GDPR'
      )

      expect(metrics.totalEvents).toBe(2)
      expect(metrics.securityIncidents).toBe(1) // One critical security log
      expect(metrics.dataAccessEvents).toBe(1) // One data category log
      expect(metrics.paymentEvents).toBe(0)
      expect(metrics.userRightsRequests).toBe(0)
      expect(metrics.dataBreaches).toBe(0)
      expect(metrics.complianceViolations).toBe(0)
    })
  })

  describe('performRiskAssessment', () => {
    it('should assess low risk for no incidents', async () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 0,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const riskAssessment = await (testService as any).performRiskAssessment([], metrics, 'GDPR')

      expect(riskAssessment.overallRisk).toBe('low')
      expect(riskAssessment.riskFactors).toHaveLength(0)
    })

    it('should assess high risk for security incidents', async () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 3,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const riskAssessment = await (testService as any).performRiskAssessment([], metrics, 'GDPR')

      expect(riskAssessment.overallRisk).toBe('high')
      expect(riskAssessment.riskFactors.length).toBeGreaterThan(0)
      const firstRiskFactor = expectArrayElement(riskAssessment.riskFactors, 0)
      expect(firstRiskFactor.category).toBe('Security')
    })

    it('should assess critical risk for data breaches', async () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 1,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 1,
        complianceViolations: 0,
      }

      const riskAssessment = await (testService as any).performRiskAssessment([], metrics, 'GDPR')

      expect(riskAssessment.overallRisk).toBe('critical')
      expect(riskAssessment.riskFactors.some(f => f.category === 'Data Protection')).toBe(true)
    })
  })

  describe('generateRecommendations', () => {
    it('should generate recommendations based on risk assessment', async () => {
      const testService = new ComplianceReportingService()

      const riskAssessment = {
        overallRisk: 'critical' as const,
        riskFactors: [
          {
            category: 'Security',
            description: 'Multiple security incidents',
            severity: 'critical' as const,
            impact: 'High',
            likelihood: 'Medium',
          },
        ],
        mitigationStrategies: [],
      }

      const metrics = {
        totalEvents: 10,
        securityIncidents: 5,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const recommendations = await (testService as any).generateRecommendations(
        riskAssessment,
        metrics,
        'GDPR'
      )

      expect(recommendations.length).toBeGreaterThan(0)
      expect(recommendations).toContain('Immediate security review and incident response required')
    })

    it('should generate GDPR-specific recommendations', async () => {
      const testService = new ComplianceReportingService()

      const riskAssessment = {
        overallRisk: 'medium' as const,
        riskFactors: [],
        mitigationStrategies: [],
      }

      const metrics = {
        totalEvents: 10,
        securityIncidents: 0,
        dataAccessEvents: 150, // High data access
        paymentEvents: 2,
        userRightsRequests: 15, // High user rights requests
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const recommendations = await (testService as any).generateRecommendations(
        riskAssessment,
        metrics,
        'GDPR'
      )

      expect(recommendations).toContain('Consider automating user rights request processing')
      expect(recommendations).toContain('Implement stricter data access controls')
    })
  })

  describe('calculateComplianceScore', () => {
    it('should calculate perfect score for no incidents', () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 0,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const riskAssessment = {
        overallRisk: 'low' as const,
        riskFactors: [],
        mitigationStrategies: [],
      }

      const score = (testService as any).calculateComplianceScore(metrics, riskAssessment)
      expect(score).toBe(100)
    })

    it('should deduct points for security incidents', () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 2,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 0,
        complianceViolations: 0,
      }

      const riskAssessment = {
        overallRisk: 'medium' as const,
        riskFactors: [],
        mitigationStrategies: [],
      }

      const score = (testService as any).calculateComplianceScore(metrics, riskAssessment)
      expect(score).toBe(70) // 100 - (2*10) - 10 for medium risk
    })

    it('should ensure score never goes below 0', () => {
      const testService = new ComplianceReportingService()

      const metrics = {
        totalEvents: 10,
        securityIncidents: 20,
        dataAccessEvents: 5,
        paymentEvents: 2,
        userRightsRequests: 1,
        dataBreaches: 10,
        complianceViolations: 5,
      }

      const riskAssessment = {
        overallRisk: 'critical' as const,
        riskFactors: [],
        mitigationStrategies: [],
      }

      const score = (testService as any).calculateComplianceScore(metrics, riskAssessment)
      expect(score).toBe(0)
    })
  })

  describe('error handling', () => {
    it('should handle audit service errors gracefully', async () => {
      const auditService = require('@/model/auditService')
      auditService.auditService.generateComplianceReport.mockRejectedValueOnce(
        new Error('Audit error')
      )

      const request: ComplianceReportRequest = {
        complianceType: 'GDPR',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        includeDetails: true,
        format: 'json',
        requestedBy: 'admin_user',
      }

      await expect(testReportingService.generateComplianceReport(request)).rejects.toThrow(
        'Audit error'
      )
    })

    it('should handle previous period comparison errors gracefully', async () => {
      const auditService = require('@/model/auditService')
      auditService.auditService.getAuditLogs.mockRejectedValueOnce(new Error('Query error'))

      const request: ComplianceReportRequest = {
        complianceType: 'GDPR',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        includeDetails: true,
        format: 'json',
        requestedBy: 'admin_user',
      }

      const report = await testReportingService.generateComplianceReport(request)

      // Should still generate report without previous period comparison
      expect(report).toBeDefined()
      expect(report.previousPeriodComparison).toBeUndefined()
    })
  })
})
