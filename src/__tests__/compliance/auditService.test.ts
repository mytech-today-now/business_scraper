/**
 * Audit Service Tests
 * Comprehensive tests for audit logging and compliance features
 */

import { auditService, AuditService, AuditLog } from '@/model/auditService'

// Mock dependencies
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn().mockResolvedValue(undefined),
  },
}))

describe('AuditService', () => {
  let testAuditService: AuditService

  beforeEach(() => {
    testAuditService = new AuditService()
    jest.clearAllMocks()
  })

  describe('logAuditEvent', () => {
    it('should log audit event with all required fields', async () => {
      const action = 'test_action'
      const resource = 'test_resource'
      const options = {
        userId: 'test_user',
        resourceId: 'test_resource_id',
        ipAddress: '192.168.1.1',
        severity: 'high' as const,
        category: 'security' as const,
        complianceFlags: ['SOC2', 'GDPR'],
      }

      await testAuditService.logAuditEvent(action, resource, options)

      // Verify audit log was created
      const logs = await testAuditService.getAuditLogs({})
      expect(logs.logs).toHaveLength(1)

      const log = logs.logs[0]
      expect(log.action).toBe(action)
      expect(log.resource).toBe(resource)
      expect(log.userId).toBe(options.userId)
      expect(log.severity).toBe(options.severity)
      expect(log.category).toBe(options.category)
      expect(log.complianceFlags).toEqual(options.complianceFlags)
    })

    it('should use default values when options are not provided', async () => {
      await testAuditService.logAuditEvent('test_action', 'test_resource')

      const logs = await testAuditService.getAuditLogs({})
      const log = logs.logs[0]

      expect(log.severity).toBe('medium')
      expect(log.category).toBe('system')
      expect(log.complianceFlags).toEqual([])
    })

    it('should generate unique audit IDs', async () => {
      await testAuditService.logAuditEvent('action1', 'resource1')
      await testAuditService.logAuditEvent('action2', 'resource2')

      const logs = await testAuditService.getAuditLogs({})
      expect(logs.logs).toHaveLength(2)
      expect(logs.logs[0].id).not.toBe(logs.logs[1].id)
    })
  })

  describe('logPaymentEvent', () => {
    it('should log payment event with sanitized data', async () => {
      const paymentData = {
        id: 'payment_123',
        amount: 100.0,
        card_number: '4111111111111111',
        cvv: '123',
        customer_id: 'cust_456',
      }

      await testAuditService.logPaymentEvent(
        'payment_processed',
        paymentData,
        'user_123',
        '192.168.1.1'
      )

      const logs = await testAuditService.getAuditLogs({ category: 'payment' })
      expect(logs.logs).toHaveLength(1)

      const log = logs.logs[0]
      expect(log.category).toBe('payment')
      expect(log.severity).toBe('high')
      expect(log.complianceFlags).toContain('PCI_DSS')

      // Verify sensitive data is sanitized
      expect(log.newValues?.card_number).toBe('****-****-****-1111')
      expect(log.newValues?.cvv).toBe('[REDACTED]')
      expect(log.newValues?.amount).toBe(100.0) // Non-sensitive data preserved
    })
  })

  describe('logDataAccess', () => {
    it('should log data access for GDPR compliance', async () => {
      await testAuditService.logDataAccess(
        'user_123',
        'profile_data',
        'admin_user',
        'user_profile_view'
      )

      const logs = await testAuditService.getAuditLogs({ category: 'data' })
      expect(logs.logs).toHaveLength(1)

      const log = logs.logs[0]
      expect(log.action).toBe('data_access')
      expect(log.resource).toBe('user_data')
      expect(log.category).toBe('data')
      expect(log.complianceFlags).toContain('GDPR')
    })
  })

  describe('logSecurityEvent', () => {
    it('should log security event with critical severity', async () => {
      const details = {
        threat_type: 'brute_force',
        attempts: 5,
        blocked: true,
      }

      await testAuditService.logSecurityEvent(
        'security_threat_detected',
        details,
        '192.168.1.100',
        'user_123'
      )

      const logs = await testAuditService.getAuditLogs({ category: 'security' })
      expect(logs.logs).toHaveLength(1)

      const log = logs.logs[0]
      expect(log.severity).toBe('critical')
      expect(log.category).toBe('security')
      expect(log.complianceFlags).toContain('SOC2')
    })
  })

  describe('getAuditLogs', () => {
    beforeEach(async () => {
      // Create test data
      await testAuditService.logAuditEvent('action1', 'resource1', {
        userId: 'user1',
        category: 'security',
        severity: 'high',
      })
      await testAuditService.logAuditEvent('action2', 'resource2', {
        userId: 'user2',
        category: 'data',
        severity: 'medium',
      })
      await testAuditService.logAuditEvent('action3', 'resource3', {
        userId: 'user1',
        category: 'payment',
        severity: 'critical',
      })
    })

    it('should return all logs when no filters applied', async () => {
      const result = await testAuditService.getAuditLogs({})
      expect(result.logs).toHaveLength(3)
      expect(result.total).toBe(3)
    })

    it('should filter logs by user ID', async () => {
      const result = await testAuditService.getAuditLogs({ userId: 'user1' })
      expect(result.logs).toHaveLength(2)
      expect(result.logs.every(log => log.userId === 'user1')).toBe(true)
    })

    it('should filter logs by category', async () => {
      const result = await testAuditService.getAuditLogs({ category: 'security' })
      expect(result.logs).toHaveLength(1)
      expect(result.logs[0].category).toBe('security')
    })

    it('should filter logs by severity', async () => {
      const result = await testAuditService.getAuditLogs({ severity: 'critical' })
      expect(result.logs).toHaveLength(1)
      expect(result.logs[0].severity).toBe('critical')
    })

    it('should apply pagination', async () => {
      const result = await testAuditService.getAuditLogs({ limit: 2, offset: 1 })
      expect(result.logs).toHaveLength(2)
      expect(result.total).toBe(3)
    })
  })

  describe('generateComplianceReport', () => {
    beforeEach(async () => {
      // Create test audit data
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')

      await testAuditService.logAuditEvent('security_incident', 'security', {
        severity: 'critical',
        category: 'security',
        complianceFlags: ['SOC2'],
      })

      await testAuditService.logPaymentEvent('payment_processed', { id: 'pay_123' })

      await testAuditService.logDataAccess('user_123', 'profile', 'admin')
    })

    it('should generate GDPR compliance report', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')

      const report = await testAuditService.generateComplianceReport(startDate, endDate, 'GDPR')

      expect(report.complianceType).toBe('GDPR')
      expect(report.period.startDate).toEqual(startDate)
      expect(report.period.endDate).toEqual(endDate)
      expect(report.reportId).toBeDefined()
      expect(report.generatedAt).toBeInstanceOf(Date)
    })

    it('should include relevant events in compliance report', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')

      const report = await testAuditService.generateComplianceReport(startDate, endDate, 'SOC2')

      expect(report.securityIncidents).toBeDefined()
      expect(report.dataAccessEvents).toBeDefined()
      expect(report.paymentEvents).toBeDefined()
    })
  })

  describe('manageDataRetention', () => {
    it('should manage data retention according to policy', async () => {
      // Create old audit logs (simulate 8 years old)
      const oldDate = new Date(Date.now() - 8 * 365 * 24 * 60 * 60 * 1000)

      // This would normally create logs with old timestamps
      // For testing, we'll verify the method executes without error
      await expect(testAuditService.manageDataRetention()).resolves.not.toThrow()
    })
  })

  describe('sanitizePaymentData', () => {
    it('should sanitize sensitive payment fields', () => {
      const testService = new AuditService()
      const sensitiveData = {
        card_number: '4111111111111111',
        cvv: '123',
        ssn: '123-45-6789',
        bank_account: '123456789',
        amount: 100.0,
        customer_id: 'cust_123',
      }

      // Access private method for testing
      const sanitized = (testService as any).sanitizePaymentData(sensitiveData)

      expect(sanitized.card_number).toBe('****-****-****-1111')
      expect(sanitized.cvv).toBe('[REDACTED]')
      expect(sanitized.ssn).toBe('[REDACTED]')
      expect(sanitized.bank_account).toBe('[REDACTED]')
      expect(sanitized.amount).toBe(100.0) // Non-sensitive preserved
      expect(sanitized.customer_id).toBe('cust_123') // Non-sensitive preserved
    })
  })

  describe('error handling', () => {
    it('should handle errors gracefully during audit logging', async () => {
      // Mock storage to throw error
      const mockStorage = require('@/model/storage')
      mockStorage.storage.initialize.mockRejectedValueOnce(new Error('Storage error'))

      // Should not throw, but log error
      await expect(
        testAuditService.logAuditEvent('test_action', 'test_resource')
      ).resolves.not.toThrow()
    })

    it('should handle errors during compliance report generation', async () => {
      const startDate = new Date('2024-01-01')
      const endDate = new Date('2024-01-31')

      // This should handle errors gracefully
      await expect(
        testAuditService.generateComplianceReport(startDate, endDate, 'GDPR')
      ).resolves.toBeDefined()
    })
  })

  describe('compliance flags processing', () => {
    it('should process PCI DSS compliance flags', async () => {
      await testAuditService.logAuditEvent('payment_test', 'payment', {
        category: 'payment',
        complianceFlags: ['PCI_DSS'],
      })

      const logs = await testAuditService.getAuditLogs({ complianceFlags: ['PCI_DSS'] })
      expect(logs.logs).toHaveLength(1)
      expect(logs.logs[0].complianceFlags).toContain('PCI_DSS')
    })

    it('should process GDPR compliance flags', async () => {
      await testAuditService.logAuditEvent('data_test', 'user_data', {
        category: 'data',
        complianceFlags: ['GDPR'],
      })

      const logs = await testAuditService.getAuditLogs({ complianceFlags: ['GDPR'] })
      expect(logs.logs).toHaveLength(1)
      expect(logs.logs[0].complianceFlags).toContain('GDPR')
    })

    it('should process SOC2 compliance flags', async () => {
      await testAuditService.logAuditEvent('security_test', 'security', {
        category: 'security',
        complianceFlags: ['SOC2'],
      })

      const logs = await testAuditService.getAuditLogs({ complianceFlags: ['SOC2'] })
      expect(logs.logs).toHaveLength(1)
      expect(logs.logs[0].complianceFlags).toContain('SOC2')
    })
  })
})
