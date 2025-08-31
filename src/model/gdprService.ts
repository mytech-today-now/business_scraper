/**
 * GDPR Compliance Service
 * Handles user data rights including data portability and right to be forgotten
 */

import { auditService } from './auditService'
import { storage } from './storage'
import { logger } from '@/utils/logger'

export interface DataExportRequest {
  id: string
  userId: string
  requestedAt: Date
  completedAt?: Date
  status: 'pending' | 'processing' | 'completed' | 'failed'
  downloadUrl?: string
  expiresAt?: Date
  requestedBy: string
  exportFormat: 'json' | 'csv' | 'xml'
}

export interface DataDeletionRequest {
  id: string
  userId: string
  requestedAt: Date
  scheduledFor: Date
  completedAt?: Date
  status: 'pending' | 'scheduled' | 'completed' | 'failed'
  retentionReason?: string
  requestedBy: string
  immediateDelete: boolean
}

export interface UserDataCollection {
  profile: any
  paymentData: any
  usageData: any
  auditLogs: any[]
  scrapingHistory: any[]
  exportedAt: Date
  userId: string
}

export class GDPRService {
  private exportRequests: DataExportRequest[] = []
  private deletionRequests: DataDeletionRequest[] = []

  /**
   * Handle data export request (Right to Data Portability)
   */
  async requestDataExport(
    userId: string,
    requestedBy: string,
    exportFormat: 'json' | 'csv' | 'xml' = 'json'
  ): Promise<DataExportRequest> {
    try {
      const request: DataExportRequest = {
        id: this.generateRequestId(),
        userId,
        requestedAt: new Date(),
        status: 'pending',
        requestedBy,
        exportFormat,
      }

      await this.storeDataExportRequest(request)

      // Log the request for audit compliance
      await auditService.logDataAccess(
        userId,
        'full_export',
        requestedBy,
        'GDPR data portability request'
      )

      // Process export asynchronously
      this.processDataExport(request.id)

      logger.info('GDPR', `Data export requested for user: ${userId}`, {
        requestId: request.id,
        requestedBy,
        format: exportFormat,
      })

      return request
    } catch (error) {
      logger.error('GDPR', 'Failed to request data export', error)
      throw error
    }
  }

  /**
   * Handle data deletion request (Right to be Forgotten)
   */
  async requestDataDeletion(
    userId: string,
    requestedBy: string,
    immediateDelete: boolean = false
  ): Promise<DataDeletionRequest> {
    try {
      // Check if user has active subscriptions or legal holds
      const eligibilityCheck = await this.checkDeletionEligibility(userId)

      if (!eligibilityCheck.eligible) {
        throw new Error(`Cannot delete data: ${eligibilityCheck.reason}`)
      }

      const scheduledFor = immediateDelete
        ? new Date()
        : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days

      const request: DataDeletionRequest = {
        id: this.generateRequestId(),
        userId,
        requestedAt: new Date(),
        scheduledFor,
        status: immediateDelete ? 'pending' : 'scheduled',
        requestedBy,
        immediateDelete,
      }

      await this.storeDataDeletionRequest(request)

      // Log the request for audit compliance
      await auditService.logAuditEvent('data_deletion_requested', 'user_data', {
        userId: requestedBy,
        resourceId: userId,
        newValues: { scheduledFor, immediateDelete },
        severity: 'high',
        category: 'data',
        complianceFlags: ['GDPR'],
      })

      if (immediateDelete) {
        await this.processDataDeletion(request.id)
      }

      logger.info('GDPR', `Data deletion requested for user: ${userId}`, {
        requestId: request.id,
        scheduledFor,
        immediateDelete,
      })

      return request
    } catch (error) {
      logger.error('GDPR', 'Failed to request data deletion', error)
      throw error
    }
  }

  /**
   * Get user's data export/deletion requests
   */
  async getUserRequests(userId: string): Promise<{
    exportRequests: DataExportRequest[]
    deletionRequests: DataDeletionRequest[]
  }> {
    const exportRequests = this.exportRequests.filter(req => req.userId === userId)
    const deletionRequests = this.deletionRequests.filter(req => req.userId === userId)

    return { exportRequests, deletionRequests }
  }

  /**
   * Process data export asynchronously
   */
  private async processDataExport(requestId: string): Promise<void> {
    try {
      const request = await this.getDataExportRequest(requestId)
      if (!request) return

      // Update status to processing
      await this.updateDataExportRequest(requestId, { status: 'processing' })

      // Collect all user data
      const userData = await this.collectUserData(request.userId)

      // Generate export file in requested format
      const exportFile = await this.generateExportFile(userData, request.exportFormat)

      // Store file securely and generate download URL
      const downloadUrl = await this.storeExportFile(exportFile, request.userId)

      // Set expiration (7 days)
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

      // Update request with completion
      await this.updateDataExportRequest(requestId, {
        status: 'completed',
        completedAt: new Date(),
        downloadUrl,
        expiresAt,
      })

      // Send notification (would integrate with email service)
      await this.sendDataExportNotification(request.userId, downloadUrl, expiresAt)

      // Log completion
      await auditService.logAuditEvent('data_export_completed', 'user_data', {
        resourceId: request.userId,
        newValues: { requestId, downloadUrl },
        severity: 'medium',
        category: 'data',
        complianceFlags: ['GDPR'],
      })

      logger.info('GDPR', `Data export completed for request: ${requestId}`)
    } catch (error) {
      await this.updateDataExportRequest(requestId, { status: 'failed' })
      logger.error('GDPR', 'Failed to process data export', error)
    }
  }

  /**
   * Process data deletion asynchronously
   */
  private async processDataDeletion(requestId: string): Promise<void> {
    try {
      const request = await this.getDataDeletionRequest(requestId)
      if (!request) return

      // Final eligibility check
      const eligibilityCheck = await this.checkDeletionEligibility(request.userId)
      if (!eligibilityCheck.eligible) {
        await this.updateDataDeletionRequest(requestId, {
          status: 'failed',
          retentionReason: eligibilityCheck.reason,
        })
        return
      }

      // Delete user data across all systems
      await this.deleteUserData(request.userId)

      // Update request status
      await this.updateDataDeletionRequest(requestId, {
        status: 'completed',
        completedAt: new Date(),
      })

      // Log completion
      await auditService.logAuditEvent('data_deletion_completed', 'user_data', {
        resourceId: request.userId,
        newValues: { requestId },
        severity: 'critical',
        category: 'data',
        complianceFlags: ['GDPR'],
      })

      logger.info('GDPR', `Data deletion completed for request: ${requestId}`)
    } catch (error) {
      await this.updateDataDeletionRequest(requestId, { status: 'failed' })
      logger.error('GDPR', 'Failed to process data deletion', error)
    }
  }

  /**
   * Check if user data can be deleted
   */
  private async checkDeletionEligibility(
    userId: string
  ): Promise<{ eligible: boolean; reason?: string }> {
    try {
      // Check for active sessions or recent activity
      const recentActivity = await this.getRecentUserActivity(userId, 30) // 30 days
      if (recentActivity.hasActiveSession) {
        return { eligible: false, reason: 'User has active sessions' }
      }

      // Check for recent scraping activities (business requirement)
      if (recentActivity.recentScrapingJobs > 0) {
        return { eligible: false, reason: 'Recent scraping activities require retention' }
      }

      // Check for legal holds or compliance requirements
      const legalHold = await this.checkLegalHold(userId)
      if (legalHold) {
        return { eligible: false, reason: 'Data subject to legal hold' }
      }

      return { eligible: true }
    } catch (error) {
      logger.error('GDPR', 'Failed to check deletion eligibility', error)
      return { eligible: false, reason: 'Unable to verify eligibility' }
    }
  }

  /**
   * Collect all user data for export
   */
  private async collectUserData(userId: string): Promise<UserDataCollection> {
    try {
      await storage.initialize()

      const userData: UserDataCollection = {
        profile: await this.getUserProfile(userId),
        paymentData: await this.getUserPaymentData(userId),
        usageData: await this.getUserUsageData(userId),
        auditLogs: await this.getUserAuditLogs(userId),
        scrapingHistory: await this.getUserScrapingHistory(userId),
        exportedAt: new Date(),
        userId,
      }

      return userData
    } catch (error) {
      logger.error('GDPR', 'Failed to collect user data', error)
      throw error
    }
  }

  /**
   * Delete all user data across systems
   */
  private async deleteUserData(userId: string): Promise<void> {
    try {
      await Promise.all([
        this.deleteUserProfile(userId),
        this.deleteUserPaymentData(userId),
        this.deleteUserUsageData(userId),
        this.deleteUserScrapingHistory(userId),
        this.anonymizeAuditLogs(userId),
      ])

      logger.info('GDPR', `All user data deleted for user: ${userId}`)
    } catch (error) {
      logger.error('GDPR', 'Failed to delete user data', error)
      throw error
    }
  }

  /**
   * Generate export file in requested format
   */
  private async generateExportFile(
    data: UserDataCollection,
    format: 'json' | 'csv' | 'xml'
  ): Promise<Buffer> {
    try {
      switch (format) {
        case 'json':
          return Buffer.from(JSON.stringify(data, null, 2))
        case 'csv':
          return this.generateCSVExport(data)
        case 'xml':
          return this.generateXMLExport(data)
        default:
          throw new Error(`Unsupported export format: ${format}`)
      }
    } catch (error) {
      logger.error('GDPR', 'Failed to generate export file', error)
      throw error
    }
  }

  // Helper methods
  private generateRequestId(): string {
    return `gdpr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private async storeDataExportRequest(request: DataExportRequest): Promise<void> {
    this.exportRequests.push(request)
  }

  private async storeDataDeletionRequest(request: DataDeletionRequest): Promise<void> {
    this.deletionRequests.push(request)
  }

  private async getDataExportRequest(id: string): Promise<DataExportRequest | null> {
    return this.exportRequests.find(req => req.id === id) || null
  }

  private async getDataDeletionRequest(id: string): Promise<DataDeletionRequest | null> {
    return this.deletionRequests.find(req => req.id === id) || null
  }

  private async updateDataExportRequest(
    id: string,
    updates: Partial<DataExportRequest>
  ): Promise<void> {
    const index = this.exportRequests.findIndex(req => req.id === id)
    if (index !== -1) {
      this.exportRequests[index] = { ...this.exportRequests[index], ...updates }
    }
  }

  private async updateDataDeletionRequest(
    id: string,
    updates: Partial<DataDeletionRequest>
  ): Promise<void> {
    const index = this.deletionRequests.findIndex(req => req.id === id)
    if (index !== -1) {
      this.deletionRequests[index] = { ...this.deletionRequests[index], ...updates }
    }
  }

  // Placeholder implementations for data operations
  private async getRecentUserActivity(userId: string, days: number): Promise<any> {
    return { hasActiveSession: false, recentScrapingJobs: 0 }
  }

  private async checkLegalHold(userId: string): Promise<boolean> {
    return false
  }

  private async getUserProfile(userId: string): Promise<any> {
    return { userId, profileData: 'placeholder' }
  }

  private async getUserPaymentData(userId: string): Promise<any> {
    return { userId, paymentData: 'placeholder' }
  }

  private async getUserUsageData(userId: string): Promise<any> {
    return { userId, usageData: 'placeholder' }
  }

  private async getUserAuditLogs(userId: string): Promise<any[]> {
    return []
  }

  private async getUserScrapingHistory(userId: string): Promise<any[]> {
    return []
  }

  private async generateCSVExport(data: UserDataCollection): Promise<Buffer> {
    // Implementation would convert data to CSV format
    return Buffer.from('CSV export placeholder')
  }

  private async generateXMLExport(data: UserDataCollection): Promise<Buffer> {
    // Implementation would convert data to XML format
    return Buffer.from('<xml>XML export placeholder</xml>')
  }

  private async storeExportFile(file: Buffer, userId: string): Promise<string> {
    // Implementation would store file securely and return download URL
    return `https://secure-downloads.example.com/exports/${userId}/${Date.now()}`
  }

  private async sendDataExportNotification(
    userId: string,
    url: string,
    expires: Date
  ): Promise<void> {
    // Implementation would send email notification
    logger.info('GDPR', `Export notification sent to user: ${userId}`)
  }

  private async deleteUserProfile(userId: string): Promise<void> {
    // Implementation would delete user profile data
  }

  private async deleteUserPaymentData(userId: string): Promise<void> {
    // Implementation would delete payment data
  }

  private async deleteUserUsageData(userId: string): Promise<void> {
    // Implementation would delete usage data
  }

  private async deleteUserScrapingHistory(userId: string): Promise<void> {
    // Implementation would delete scraping history
  }

  private async anonymizeAuditLogs(userId: string): Promise<void> {
    // Implementation would anonymize audit logs
  }
}

export const gdprService = new GDPRService()
