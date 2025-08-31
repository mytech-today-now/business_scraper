/**
 * Data Retention Service Tests
 * Comprehensive tests for data retention and archival features
 */

import {
  dataRetentionService,
  DataRetentionService,
  RetentionPolicy,
  RetentionJob,
} from '@/model/dataRetentionService'

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
    getAuditLogs: jest.fn().mockResolvedValue({
      logs: [
        { id: 'log_1', timestamp: new Date('2020-01-01') },
        { id: 'log_2', timestamp: new Date('2020-01-02') },
      ],
      total: 2,
    }),
    manageDataRetention: jest.fn().mockResolvedValue(undefined),
    logAuditEvent: jest.fn().mockResolvedValue(undefined),
  },
}))

jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn().mockResolvedValue(undefined),
  },
}))

describe('DataRetentionService', () => {
  let testRetentionService: DataRetentionService

  beforeEach(() => {
    testRetentionService = new DataRetentionService()
    jest.clearAllMocks()
  })

  describe('initialization', () => {
    it('should initialize with default retention policies', () => {
      const service = new DataRetentionService()
      expect(service).toBeDefined()
    })

    it('should have predefined retention policies', async () => {
      // Access private property for testing
      const policies = (testRetentionService as any).retentionPolicies

      expect(policies.length).toBeGreaterThan(0)
      expect(policies.some((p: RetentionPolicy) => p.dataType === 'audit_logs')).toBe(true)
      expect(policies.some((p: RetentionPolicy) => p.dataType === 'user_data')).toBe(true)
      expect(policies.some((p: RetentionPolicy) => p.dataType === 'business_data')).toBe(true)
      expect(policies.some((p: RetentionPolicy) => p.dataType === 'session_data')).toBe(true)
      expect(policies.some((p: RetentionPolicy) => p.dataType === 'export_files')).toBe(true)
    })
  })

  describe('executeRetentionPolicies', () => {
    it('should execute all retention policies', async () => {
      const jobs = await testRetentionService.executeRetentionPolicies()

      expect(jobs.length).toBeGreaterThan(0)
      expect(jobs.every(job => job.status === 'completed' || job.status === 'failed')).toBe(true)
    })

    it('should log audit event for retention execution', async () => {
      const auditService = require('@/model/auditService')

      await testRetentionService.executeRetentionPolicies()

      expect(auditService.auditService.logAuditEvent).toHaveBeenCalledWith(
        'data_retention_executed',
        'system',
        expect.objectContaining({
          severity: 'medium',
          category: 'data',
          complianceFlags: ['GDPR', 'SOX', 'PCI_DSS'],
        })
      )
    })

    it('should handle errors during policy execution', async () => {
      // Mock audit service to throw error
      const auditService = require('@/model/auditService')
      auditService.auditService.getAuditLogs.mockRejectedValueOnce(new Error('Audit error'))

      await expect(testRetentionService.executeRetentionPolicies()).rejects.toThrow()
    })
  })

  describe('executeRetentionPolicy', () => {
    const testPolicy: RetentionPolicy = {
      id: 'test_policy',
      name: 'Test Policy',
      dataType: 'audit_logs',
      retentionPeriod: 365 * 24 * 60 * 60 * 1000, // 1 year
      archivalRequired: true,
      complianceRequirements: ['TEST'],
      autoDelete: true,
      legalHoldExempt: false,
    }

    it('should execute retention policy successfully', async () => {
      const job = await testRetentionService.executeRetentionPolicy(testPolicy)

      expect(job.policyId).toBe(testPolicy.id)
      expect(job.status).toBe('completed')
      expect(job.executedAt).toBeInstanceOf(Date)
      expect(job.itemsProcessed).toBeGreaterThanOrEqual(0)
    })

    it('should handle different data types', async () => {
      const dataTypes: Array<RetentionPolicy['dataType']> = [
        'audit_logs',
        'user_data',
        'business_data',
        'session_data',
        'export_files',
      ]

      for (const dataType of dataTypes) {
        const policy = { ...testPolicy, dataType, id: `test_${dataType}` }
        const job = await testRetentionService.executeRetentionPolicy(policy)

        expect(job.status).toBe('completed')
      }
    })

    it('should handle policy execution errors', async () => {
      // Mock storage to throw error for business data
      const mockStorage = require('@/model/storage')
      mockStorage.storage.initialize.mockRejectedValueOnce(new Error('Storage error'))

      const policy = { ...testPolicy, dataType: 'business_data' as const }

      await expect(testRetentionService.executeRetentionPolicy(policy)).rejects.toThrow()
    })
  })

  describe('audit logs processing', () => {
    it('should process audit logs according to policy', async () => {
      const testService = new DataRetentionService()
      const policy: RetentionPolicy = {
        id: 'audit_test',
        name: 'Audit Test',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['SOX'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      const job: RetentionJob = {
        id: 'job_1',
        policyId: policy.id,
        scheduledAt: new Date(),
        status: 'running',
        itemsProcessed: 0,
        itemsArchived: 0,
        itemsDeleted: 0,
        errors: [],
      }

      const cutoffDate = new Date(Date.now() - policy.retentionPeriod)

      await (testService as any).processAuditLogs(policy, cutoffDate, job)

      expect(job.itemsProcessed).toBe(2) // Mock returns 2 logs
      expect(job.itemsArchived).toBe(2) // Should archive when required
      expect(job.itemsDeleted).toBe(2) // Should delete when autoDelete is true
    })

    it('should not delete when autoDelete is false', async () => {
      const testService = new DataRetentionService()
      const policy: RetentionPolicy = {
        id: 'audit_test',
        name: 'Audit Test',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['SOX'],
        autoDelete: false, // Don't auto-delete
        legalHoldExempt: false,
      }

      const job: RetentionJob = {
        id: 'job_1',
        policyId: policy.id,
        scheduledAt: new Date(),
        status: 'running',
        itemsProcessed: 0,
        itemsArchived: 0,
        itemsDeleted: 0,
        errors: [],
      }

      const cutoffDate = new Date(Date.now() - policy.retentionPeriod)

      await (testService as any).processAuditLogs(policy, cutoffDate, job)

      expect(job.itemsDeleted).toBe(0) // Should not delete
      expect(job.itemsArchived).toBe(2) // Should still archive
    })
  })

  describe('data archival', () => {
    it('should archive data correctly', async () => {
      const testService = new DataRetentionService()
      const testData = [
        { id: 'data_1', content: 'test content 1' },
        { id: 'data_2', content: 'test content 2' },
      ]

      const policy: RetentionPolicy = {
        id: 'test_policy',
        name: 'Test Policy',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['TEST'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      const archive = await (testService as any).archiveData('test_data', testData, policy)

      expect(archive.id).toBeDefined()
      expect(archive.dataType).toBe('test_data')
      expect(archive.itemCount).toBe(2)
      expect(archive.archiveDate).toBeInstanceOf(Date)
      expect(archive.compressedSize).toBeGreaterThan(0)
      expect(archive.checksum).toBeDefined()
      expect(archive.location).toContain('archives/test_data/')
    })

    it('should calculate retention period for archives', async () => {
      const testService = new DataRetentionService()
      const testData = [{ id: 'data_1' }]

      const policy: RetentionPolicy = {
        id: 'test_policy',
        name: 'Test Policy',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000, // 1 year
        archivalRequired: true,
        complianceRequirements: ['TEST'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      const archive = await (testService as any).archiveData('test_data', testData, policy)

      // Archive should be retained for double the retention period
      const expectedRetentionUntil = new Date(
        archive.archiveDate.getTime() + policy.retentionPeriod * 2
      )
      const timeDiff = Math.abs(archive.retentionUntil.getTime() - expectedRetentionUntil.getTime())
      expect(timeDiff).toBeLessThan(1000) // Within 1 second
    })
  })

  describe('getRetentionJobs', () => {
    beforeEach(async () => {
      // Execute some policies to create jobs
      await testRetentionService.executeRetentionPolicies()
    })

    it('should return all retention jobs', async () => {
      const jobs = await testRetentionService.getRetentionJobs()
      expect(jobs.length).toBeGreaterThan(0)
    })

    it('should filter jobs by policy ID', async () => {
      const allJobs = await testRetentionService.getRetentionJobs()
      const firstPolicyId = allJobs[0].policyId

      const filteredJobs = await testRetentionService.getRetentionJobs({
        policyId: firstPolicyId,
      })

      expect(filteredJobs.every(job => job.policyId === firstPolicyId)).toBe(true)
    })

    it('should filter jobs by status', async () => {
      const completedJobs = await testRetentionService.getRetentionJobs({
        status: 'completed',
      })

      expect(completedJobs.every(job => job.status === 'completed')).toBe(true)
    })

    it('should filter jobs by date range', async () => {
      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000) // 1 day ago
      const endDate = new Date()

      const jobs = await testRetentionService.getRetentionJobs({
        startDate,
        endDate,
      })

      expect(jobs.every(job => job.scheduledAt >= startDate && job.scheduledAt <= endDate)).toBe(
        true
      )
    })

    it('should sort jobs by scheduled date (newest first)', async () => {
      const jobs = await testRetentionService.getRetentionJobs()

      for (let i = 1; i < jobs.length; i++) {
        expect(jobs[i - 1].scheduledAt.getTime()).toBeGreaterThanOrEqual(
          jobs[i].scheduledAt.getTime()
        )
      }
    })
  })

  describe('getDataArchives', () => {
    beforeEach(async () => {
      // Execute policies to create archives
      await testRetentionService.executeRetentionPolicies()
    })

    it('should return data archives', async () => {
      const archives = await testRetentionService.getDataArchives()
      expect(archives).toBeDefined()
      expect(Array.isArray(archives)).toBe(true)
    })

    it('should filter archives by data type', async () => {
      const archives = await testRetentionService.getDataArchives({
        dataType: 'audit_logs',
      })

      expect(archives.every(archive => archive.dataType === 'audit_logs')).toBe(true)
    })

    it('should filter archives by date range', async () => {
      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000) // 1 day ago
      const endDate = new Date()

      const archives = await testRetentionService.getDataArchives({
        startDate,
        endDate,
      })

      expect(
        archives.every(
          archive => archive.archiveDate >= startDate && archive.archiveDate <= endDate
        )
      ).toBe(true)
    })
  })

  describe('helper methods', () => {
    it('should generate unique job IDs', () => {
      const testService = new DataRetentionService()

      const id1 = (testService as any).generateJobId()
      const id2 = (testService as any).generateJobId()

      expect(id1).not.toBe(id2)
      expect(id1).toMatch(/^retention_job_\d+_[a-z0-9]+$/)
    })

    it('should generate unique archive IDs', () => {
      const testService = new DataRetentionService()

      const id1 = (testService as any).generateArchiveId()
      const id2 = (testService as any).generateArchiveId()

      expect(id1).not.toBe(id2)
      expect(id1).toMatch(/^archive_\d+_[a-z0-9]+$/)
    })

    it('should calculate checksums consistently', () => {
      const testService = new DataRetentionService()
      const testData = 'test data for checksum'

      const checksum1 = (testService as any).calculateChecksum(testData)
      const checksum2 = (testService as any).calculateChecksum(testData)

      expect(checksum1).toBe(checksum2)
      expect(typeof checksum1).toBe('string')
    })

    it('should calculate different checksums for different data', () => {
      const testService = new DataRetentionService()

      const checksum1 = (testService as any).calculateChecksum('data1')
      const checksum2 = (testService as any).calculateChecksum('data2')

      expect(checksum1).not.toBe(checksum2)
    })
  })

  describe('error handling', () => {
    it('should handle storage errors gracefully', async () => {
      const mockStorage = require('@/model/storage')
      mockStorage.storage.initialize.mockRejectedValueOnce(new Error('Storage error'))

      const testService = new DataRetentionService()
      const policy: RetentionPolicy = {
        id: 'test_policy',
        name: 'Test Policy',
        dataType: 'business_data',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['TEST'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      await expect(testService.executeRetentionPolicy(policy)).rejects.toThrow('Storage error')
    })

    it('should handle audit service errors', async () => {
      const auditService = require('@/model/auditService')
      auditService.auditService.getAuditLogs.mockRejectedValueOnce(new Error('Audit error'))

      const testService = new DataRetentionService()
      const policy: RetentionPolicy = {
        id: 'test_policy',
        name: 'Test Policy',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['TEST'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      await expect(testService.executeRetentionPolicy(policy)).rejects.toThrow('Audit error')
    })

    it('should record errors in job status', async () => {
      const auditService = require('@/model/auditService')
      auditService.auditService.getAuditLogs.mockRejectedValueOnce(new Error('Test error'))

      const testService = new DataRetentionService()
      const policy: RetentionPolicy = {
        id: 'test_policy',
        name: 'Test Policy',
        dataType: 'audit_logs',
        retentionPeriod: 365 * 24 * 60 * 60 * 1000,
        archivalRequired: true,
        complianceRequirements: ['TEST'],
        autoDelete: true,
        legalHoldExempt: false,
      }

      try {
        await testService.executeRetentionPolicy(policy)
      } catch (error) {
        // Expected to throw
      }

      const jobs = await testService.getRetentionJobs({ policyId: policy.id })
      expect(jobs.length).toBe(1)
      expect(jobs[0].status).toBe('failed')
      expect(jobs[0].errors.length).toBeGreaterThan(0)
    })
  })
})
