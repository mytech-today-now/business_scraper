/**
 * Email Service Unit Tests
 * Comprehensive test suite for email notification functionality
 */

import { EmailService, emailService } from '@/model/emailService'
import { auditService } from '@/model/auditService'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'
import nodemailer from 'nodemailer'

// Mock dependencies
jest.mock('@/lib/config')
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')
jest.mock('nodemailer')

const mockConfig = {
  email: {
    smtpHost: 'smtp.test.com',
    smtpPort: 587,
    smtpSecure: false,
    smtpUser: 'test@example.com',
    smtpPassword: 'testpassword',
    fromAddress: 'noreply@businessscraper.com',
    supportEmail: 'support@businessscraper.com',
    templatePath: './src/templates/email'
  },
  app: {
    baseUrl: 'https://app.businessscraper.com'
  }
}

const mockTransporter = {
  sendMail: jest.fn()
}

describe('EmailService', () => {
  let emailServiceInstance: EmailService

  beforeEach(() => {
    jest.clearAllMocks()
    ;(getConfig as jest.Mock).mockReturnValue(mockConfig)
    ;(nodemailer.createTransporter as jest.Mock).mockReturnValue(mockTransporter)
    ;(auditService.logAuditEvent as jest.Mock).mockResolvedValue(undefined)
    
    emailServiceInstance = new EmailService()
  })

  describe('Constructor and Initialization', () => {
    it('should initialize SMTP transporter correctly', () => {
      expect(nodemailer.createTransporter).toHaveBeenCalledWith({
        host: 'smtp.test.com',
        port: 587,
        secure: false,
        auth: {
          user: 'test@example.com',
          pass: 'testpassword'
        }
      })
    })

    it('should log successful initialization', () => {
      expect(logger.info).toHaveBeenCalledWith(
        'EmailService',
        'SMTP transporter initialized successfully'
      )
    })
  })

  describe('sendPaymentConfirmation', () => {
    const paymentDetails = {
      amount: 2999,
      currency: 'USD',
      description: 'Professional Plan',
      transactionId: 'pi_test123',
      date: new Date('2025-01-01')
    }

    beforeEach(() => {
      mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
    })

    it('should send payment confirmation email successfully', async () => {
      await emailServiceInstance.sendPaymentConfirmation(
        'user@example.com',
        'John Doe',
        paymentDetails,
        'user123'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'user@example.com',
        subject: 'Payment Confirmation - pi_test123',
        html: expect.stringContaining('John Doe'),
        text: expect.stringContaining('John Doe')
      })

      expect(auditService.logAuditEvent).toHaveBeenCalledWith(
        'email_sent',
        'notification',
        expect.objectContaining({
          userId: 'user123',
          severity: 'low',
          category: 'system'
        })
      )
    })

    it('should format currency correctly', async () => {
      await emailServiceInstance.sendPaymentConfirmation(
        'user@example.com',
        'John Doe',
        paymentDetails,
        'user123'
      )

      const emailCall = mockTransporter.sendMail.mock.calls[0][0]
      expect(emailCall.html).toContain('$29.99')
      expect(emailCall.text).toContain('$29.99')
    })

    it('should handle email sending failure', async () => {
      const error = new Error('SMTP connection failed')
      mockTransporter.sendMail.mockRejectedValue(error)

      await expect(
        emailServiceInstance.sendPaymentConfirmation(
          'user@example.com',
          'John Doe',
          paymentDetails,
          'user123'
        )
      ).rejects.toThrow('SMTP connection failed')

      expect(logger.error).toHaveBeenCalledWith(
        'EmailService',
        'Failed to send payment confirmation',
        error
      )
    })
  })

  describe('sendSubscriptionWelcome', () => {
    const subscriptionDetails = {
      planName: 'Professional Plan',
      price: 2999,
      currency: 'USD',
      interval: 'month',
      features: ['Advanced scraping', 'Priority support', 'API access'],
      nextBillingDate: new Date('2025-02-01')
    }

    beforeEach(() => {
      mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
    })

    it('should send subscription welcome email successfully', async () => {
      await emailServiceInstance.sendSubscriptionWelcome(
        'user@example.com',
        'Jane Smith',
        subscriptionDetails,
        'user456'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'user@example.com',
        subject: 'Welcome to Professional Plan - Your subscription is active!',
        html: expect.stringContaining('Jane Smith'),
        text: expect.stringContaining('Jane Smith')
      })
    })

    it('should include all subscription features', async () => {
      await emailServiceInstance.sendSubscriptionWelcome(
        'user@example.com',
        'Jane Smith',
        subscriptionDetails,
        'user456'
      )

      const emailCall = mockTransporter.sendMail.mock.calls[0][0]
      expect(emailCall.html).toContain('Advanced scraping, Priority support, API access')
    })
  })

  describe('sendPaymentFailed', () => {
    const failureDetails = {
      amount: 2999,
      currency: 'USD',
      reason: 'Your card was declined',
      nextRetryDate: new Date('2025-01-05')
    }

    beforeEach(() => {
      mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
    })

    it('should send payment failed notification successfully', async () => {
      await emailServiceInstance.sendPaymentFailed(
        'user@example.com',
        'Bob Johnson',
        failureDetails,
        'user789'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'user@example.com',
        subject: 'Payment Failed - Action Required',
        html: expect.stringContaining('Bob Johnson'),
        text: expect.stringContaining('Bob Johnson')
      })
    })

    it('should include failure reason and retry date', async () => {
      await emailServiceInstance.sendPaymentFailed(
        'user@example.com',
        'Bob Johnson',
        failureDetails,
        'user789'
      )

      const emailCall = mockTransporter.sendMail.mock.calls[0][0]
      expect(emailCall.html).toContain('Your card was declined')
      expect(emailCall.html).toContain('1/5/2025')
    })
  })

  describe('sendSubscriptionCancellation', () => {
    const cancellationDetails = {
      planName: 'Professional Plan',
      endDate: new Date('2025-02-01'),
      reason: 'User requested cancellation'
    }

    beforeEach(() => {
      mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
    })

    it('should send subscription cancellation email successfully', async () => {
      await emailServiceInstance.sendSubscriptionCancellation(
        'user@example.com',
        'Alice Brown',
        cancellationDetails,
        'user101'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'user@example.com',
        subject: 'Subscription Cancelled - Professional Plan',
        html: expect.stringContaining('Alice Brown'),
        text: expect.stringContaining('Alice Brown')
      })
    })
  })

  describe('sendInvoiceNotification', () => {
    const invoiceDetails = {
      invoiceNumber: 'INV-2025-001',
      amount: 2999,
      currency: 'USD',
      dueDate: new Date('2025-01-15'),
      downloadUrl: 'https://app.businessscraper.com/invoices/INV-2025-001'
    }

    beforeEach(() => {
      mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
    })

    it('should send invoice notification successfully', async () => {
      await emailServiceInstance.sendInvoiceNotification(
        'user@example.com',
        'Charlie Wilson',
        invoiceDetails,
        'user202'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'user@example.com',
        subject: 'Invoice INV-2025-001 - $29.99 due 1/15/2025',
        html: expect.stringContaining('Charlie Wilson'),
        text: expect.stringContaining('Charlie Wilson')
      })
    })
  })

  describe('Variable Replacement', () => {
    it('should replace template variables correctly', async () => {
      const paymentDetails = {
        amount: 1000,
        currency: 'USD',
        description: 'Test Payment',
        transactionId: 'test_123',
        date: new Date('2025-01-01')
      }

      await emailServiceInstance.sendPaymentConfirmation(
        'test@example.com',
        'Test User',
        paymentDetails
      )

      const emailCall = mockTransporter.sendMail.mock.calls[0][0]
      expect(emailCall.html).toContain('Test User')
      expect(emailCall.html).toContain('$10.00')
      expect(emailCall.html).toContain('test_123')
      expect(emailCall.html).toContain('1/1/2025')
    })
  })

  describe('Error Handling', () => {
    it('should handle transporter initialization failure', () => {
      const error = new Error('SMTP configuration invalid')
      ;(nodemailer.createTransporter as jest.Mock).mockImplementation(() => {
        throw error
      })

      expect(() => new EmailService()).toThrow('SMTP configuration invalid')
    })

    it('should handle missing transporter', async () => {
      // Create instance with null transporter
      const service = new EmailService()
      ;(service as any).transporter = null

      await expect(
        service.sendPaymentConfirmation(
          'test@example.com',
          'Test User',
          {
            amount: 1000,
            currency: 'USD',
            description: 'Test',
            transactionId: 'test',
            date: new Date()
          }
        )
      ).rejects.toThrow('Email transporter not initialized')
    })
  })
})
