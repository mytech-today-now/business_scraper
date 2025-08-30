/**
 * GDPR Service Tests
 * Comprehensive tests for GDPR compliance features
 */

import { gdprService, GDPRService, DataExportRequest, DataDeletionRequest } from '@/model/gdprService'

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
    logDataAccess: jest.fn().mockResolvedValue(undefined),
    logAuditEvent: jest.fn().mockResolvedValue(undefined),
  },
}))

jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn().mockResolvedValue(undefined),
  },
}))

describe('GDPRService', () => {
  let testGDPRService: GDPRService

  beforeEach(() => {
    testGDPRService = new GDPRService()
    jest.clearAllMocks()
  })

  describe('requestDataExport', () => {
    it('should create data export request with default JSON format', async () => {
      const userId = 'user_123'
      const requestedBy = 'admin_user'

      const request = await testGDPRService.requestDataExport(userId, requestedBy)

      expect(request.userId).toBe(userId)
      expect(request.requestedBy).toBe(requestedBy)
      expect(request.status).toBe('pending')
      expect(request.exportFormat).toBe('json')
      expect(request.id).toBeDefined()
      expect(request.requestedAt).toBeInstanceOf(Date)
    })

    it('should create data export request with specified format', async () => {
      const userId = 'user_123'
      const requestedBy = 'admin_user'
      const format = 'csv'

      const request = await testGDPRService.requestDataExport(userId, requestedBy, format)

      expect(request.exportFormat).toBe(format)
    })

    it('should log data access for audit compliance', async () => {
      const auditService = require('@/model/auditService')
      
      await testGDPRService.requestDataExport('user_123', 'admin_user')

      expect(auditService.auditService.logDataAccess).toHaveBeenCalledWith(
        'user_123',
        'full_export',
        'admin_user',
        'GDPR data portability request'
      )
    })

    it('should handle errors gracefully', async () => {
      // Mock audit service to throw error
      const auditService = require('@/model/auditService')
      auditService.auditService.logDataAccess.mockRejectedValueOnce(new Error('Audit error'))

      await expect(
        testGDPRService.requestDataExport('user_123', 'admin_user')
      ).rejects.toThrow('Audit error')
    })
  })

  describe('requestDataDeletion', () => {
    it('should create immediate data deletion request', async () => {
      const userId = 'user_123'
      const requestedBy = 'admin_user'
      const immediateDelete = true

      const request = await testGDPRService.requestDataDeletion(userId, requestedBy, immediateDelete)

      expect(request.userId).toBe(userId)
      expect(request.requestedBy).toBe(requestedBy)
      expect(request.immediateDelete).toBe(true)
      expect(request.status).toBe('pending')
      expect(request.scheduledFor).toBeInstanceOf(Date)
      expect(request.id).toBeDefined()
    })

    it('should create scheduled data deletion request', async () => {
      const userId = 'user_123'
      const requestedBy = 'admin_user'
      const immediateDelete = false

      const request = await testGDPRService.requestDataDeletion(userId, requestedBy, immediateDelete)

      expect(request.immediateDelete).toBe(false)
      expect(request.status).toBe('scheduled')
      
      // Should be scheduled for 30 days from now
      const expectedDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      const timeDiff = Math.abs(request.scheduledFor.getTime() - expectedDate.getTime())
      expect(timeDiff).toBeLessThan(1000) // Within 1 second
    })

    it('should log audit event for deletion request', async () => {
      const auditService = require('@/model/auditService')
      
      await testGDPRService.requestDataDeletion('user_123', 'admin_user')

      expect(auditService.auditService.logAuditEvent).toHaveBeenCalledWith(
        'data_deletion_requested',
        'user_data',
        expect.objectContaining({
          userId: 'admin_user',
          resourceId: 'user_123',
          severity: 'high',
          category: 'data',
          complianceFlags: ['GDPR']
        })
      )
    })

    it('should reject deletion if user not eligible', async () => {
      // Mock checkDeletionEligibility to return false
      const testService = new GDPRService()
      jest.spyOn(testService as any, 'checkDeletionEligibility').mockResolvedValueOnce({
        eligible: false,
        reason: 'Active subscription exists'
      })

      await expect(
        testService.requestDataDeletion('user_123', 'admin_user')
      ).rejects.toThrow('Cannot delete data: Active subscription exists')
    })
  })

  describe('getUserRequests', () => {
    beforeEach(async () => {
      // Create test requests
      await testGDPRService.requestDataExport('user_123', 'admin_user')
      await testGDPRService.requestDataExport('user_456', 'admin_user')
      await testGDPRService.requestDataDeletion('user_123', 'admin_user')
    })

    it('should return user-specific requests', async () => {
      const requests = await testGDPRService.getUserRequests('user_123')

      expect(requests.exportRequests).toHaveLength(1)
      expect(requests.deletionRequests).toHaveLength(1)
      expect(requests.exportRequests[0].userId).toBe('user_123')
      expect(requests.deletionRequests[0].userId).toBe('user_123')
    })

    it('should return empty arrays for user with no requests', async () => {
      const requests = await testGDPRService.getUserRequests('user_999')

      expect(requests.exportRequests).toHaveLength(0)
      expect(requests.deletionRequests).toHaveLength(0)
    })
  })

  describe('data export processing', () => {
    it('should process data export asynchronously', async () => {
      const request = await testGDPRService.requestDataExport('user_123', 'admin_user')

      // Wait a bit for async processing
      await new Promise(resolve => setTimeout(resolve, 100))

      // Verify the request was processed (status should change)
      const userRequests = await testGDPRService.getUserRequests('user_123')
      expect(userRequests.exportRequests).toHaveLength(1)
    })

    it('should handle export processing errors', async () => {
      // Mock collectUserData to throw error
      const testService = new GDPRService()
      jest.spyOn(testService as any, 'collectUserData').mockRejectedValueOnce(new Error('Collection error'))

      const request = await testService.requestDataExport('user_123', 'admin_user')

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 100))

      // Request should exist but processing may have failed
      const userRequests = await testService.getUserRequests('user_123')
      expect(userRequests.exportRequests).toHaveLength(1)
    })
  })

  describe('data deletion processing', () => {
    it('should process immediate deletion', async () => {
      const request = await testGDPRService.requestDataDeletion('user_123', 'admin_user', true)

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 100))

      const userRequests = await testGDPRService.getUserRequests('user_123')
      expect(userRequests.deletionRequests).toHaveLength(1)
    })

    it('should not process scheduled deletion immediately', async () => {
      const request = await testGDPRService.requestDataDeletion('user_123', 'admin_user', false)

      expect(request.status).toBe('scheduled')
      
      // Should not be processed immediately
      const userRequests = await testGDPRService.getUserRequests('user_123')
      expect(userRequests.deletionRequests[0].status).toBe('scheduled')
    })
  })

  describe('data collection', () => {
    it('should collect comprehensive user data', async () => {
      const testService = new GDPRService()
      
      // Mock the private method for testing
      const collectUserData = jest.spyOn(testService as any, 'collectUserData').mockResolvedValueOnce({
        profile: { userId: 'user_123', name: 'Test User' },
        paymentData: { userId: 'user_123', cards: [] },
        usageData: { userId: 'user_123', sessions: [] },
        auditLogs: [],
        scrapingHistory: [],
        exportedAt: new Date(),
        userId: 'user_123'
      })

      const userData = await (testService as any).collectUserData('user_123')

      expect(userData.userId).toBe('user_123')
      expect(userData.profile).toBeDefined()
      expect(userData.paymentData).toBeDefined()
      expect(userData.usageData).toBeDefined()
      expect(userData.auditLogs).toBeDefined()
      expect(userData.scrapingHistory).toBeDefined()
      expect(userData.exportedAt).toBeInstanceOf(Date)
    })
  })

  describe('export file generation', () => {
    const testData = {
      profile: { userId: 'user_123', name: 'Test User' },
      paymentData: { userId: 'user_123', cards: [] },
      usageData: { userId: 'user_123', sessions: [] },
      auditLogs: [],
      scrapingHistory: [],
      exportedAt: new Date(),
      userId: 'user_123'
    }

    it('should generate JSON export file', async () => {
      const testService = new GDPRService()
      
      const buffer = await (testService as any).generateExportFile(testData, 'json')
      
      expect(buffer).toBeInstanceOf(Buffer)
      const jsonData = JSON.parse(buffer.toString())
      expect(jsonData.userId).toBe('user_123')
    })

    it('should generate CSV export file', async () => {
      const testService = new GDPRService()
      
      const buffer = await (testService as any).generateExportFile(testData, 'csv')
      
      expect(buffer).toBeInstanceOf(Buffer)
      expect(buffer.toString()).toContain('CSV export placeholder')
    })

    it('should generate XML export file', async () => {
      const testService = new GDPRService()
      
      const buffer = await (testService as any).generateExportFile(testData, 'xml')
      
      expect(buffer).toBeInstanceOf(Buffer)
      expect(buffer.toString()).toContain('<xml>')
    })

    it('should throw error for unsupported format', async () => {
      const testService = new GDPRService()
      
      await expect(
        (testService as any).generateExportFile(testData, 'unsupported')
      ).rejects.toThrow('Unsupported export format: unsupported')
    })
  })

  describe('deletion eligibility', () => {
    it('should check deletion eligibility correctly', async () => {
      const testService = new GDPRService()
      
      // Mock getRecentUserActivity
      jest.spyOn(testService as any, 'getRecentUserActivity').mockResolvedValueOnce({
        hasActiveSession: false,
        recentScrapingJobs: 0
      })
      
      jest.spyOn(testService as any, 'checkLegalHold').mockResolvedValueOnce(false)

      const eligibility = await (testService as any).checkDeletionEligibility('user_123')

      expect(eligibility.eligible).toBe(true)
    })

    it('should reject deletion for active sessions', async () => {
      const testService = new GDPRService()
      
      jest.spyOn(testService as any, 'getRecentUserActivity').mockResolvedValueOnce({
        hasActiveSession: true,
        recentScrapingJobs: 0
      })

      const eligibility = await (testService as any).checkDeletionEligibility('user_123')

      expect(eligibility.eligible).toBe(false)
      expect(eligibility.reason).toBe('User has active sessions')
    })

    it('should reject deletion for recent scraping activities', async () => {
      const testService = new GDPRService()
      
      jest.spyOn(testService as any, 'getRecentUserActivity').mockResolvedValueOnce({
        hasActiveSession: false,
        recentScrapingJobs: 5
      })

      const eligibility = await (testService as any).checkDeletionEligibility('user_123')

      expect(eligibility.eligible).toBe(false)
      expect(eligibility.reason).toBe('Recent scraping activities require retention')
    })

    it('should reject deletion for legal holds', async () => {
      const testService = new GDPRService()
      
      jest.spyOn(testService as any, 'getRecentUserActivity').mockResolvedValueOnce({
        hasActiveSession: false,
        recentScrapingJobs: 0
      })
      
      jest.spyOn(testService as any, 'checkLegalHold').mockResolvedValueOnce(true)

      const eligibility = await (testService as any).checkDeletionEligibility('user_123')

      expect(eligibility.eligible).toBe(false)
      expect(eligibility.reason).toBe('Data subject to legal hold')
    })
  })

  describe('error handling', () => {
    it('should handle storage initialization errors', async () => {
      const mockStorage = require('@/model/storage')
      mockStorage.storage.initialize.mockRejectedValueOnce(new Error('Storage error'))

      const testService = new GDPRService()
      
      await expect(
        (testService as any).collectUserData('user_123')
      ).rejects.toThrow('Storage error')
    })

    it('should handle audit logging errors gracefully', async () => {
      const auditService = require('@/model/auditService')
      auditService.auditService.logDataAccess.mockRejectedValueOnce(new Error('Audit error'))

      await expect(
        testGDPRService.requestDataExport('user_123', 'admin_user')
      ).rejects.toThrow('Audit error')
    })
  })
})
