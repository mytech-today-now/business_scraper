/**
 * Tests for EmailService
 * Comprehensive test suite for email notification functionality
 */

import { EmailService } from '../emailService'
import nodemailer from 'nodemailer'

// Mock nodemailer
jest.mock('nodemailer')
const mockNodemailer = nodemailer as jest.Mocked<typeof nodemailer>

// Mock config
jest.mock('@/lib/config', () => ({
  getConfig: jest.fn(() => ({
    email: {
      smtpHost: 'smtp.test.com',
      smtpPort: 587,
      smtpSecure: false,
      smtpUser: 'test@test.com',
      smtpPassword: 'testpass',
      fromAddress: 'noreply@test.com',
      supportEmail: 'support@test.com',
    },
    app: {
      baseUrl: 'https://test.com',
    },
  })),
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
  },
}))

// Mock audit service
jest.mock('../auditService', () => ({
  auditService: {
    logAuditEvent: jest.fn(),
  },
}))

describe('EmailService', () => {
  let emailService: EmailService
  let mockTransporter: any

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()

    // Mock transporter
    mockTransporter = {
      sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
    }

    // Mock createTransport (correct method name)
    mockNodemailer.createTransport.mockReturnValue(mockTransporter)

    // Create new instance for each test
    emailService = new EmailService()

    // Set config manually for testing
    ;(emailService as any).config = {
      email: {
        smtpHost: 'smtp.test.com',
        smtpPort: 587,
        smtpSecure: false,
        smtpUser: 'test@test.com',
        smtpPassword: 'testpass',
        fromAddress: 'noreply@test.com',
        supportEmail: 'support@test.com',
      },
      app: {
        baseUrl: 'https://test.com',
      },
    }

    // Manually initialize transporter for testing
    ;(emailService as any).initializeTransporter()
  })

  describe('Initialization', () => {
    it('should initialize transporter with correct method name', () => {
      expect(mockNodemailer.createTransport).toHaveBeenCalledWith({
        host: 'smtp.test.com',
        port: 587,
        secure: false,
        auth: {
          user: 'test@test.com',
          pass: 'testpass',
        },
      })
    })

    it('should not call createTransporter (incorrect method)', () => {
      // Ensure the old incorrect method is not called
      expect((mockNodemailer as any).createTransporter).toBeUndefined()
    })
  })

  describe('Payment Confirmation Email', () => {
    it('should send payment confirmation email successfully', async () => {
      const paymentDetails = {
        amount: 2999,
        currency: 'USD',
        description: 'Premium Plan',
        transactionId: 'txn_123',
        date: new Date('2023-01-01'),
      }

      await emailService.sendPaymentConfirmation(
        'user@test.com',
        'John Doe',
        paymentDetails,
        'user123'
      )

      expect(mockTransporter.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'noreply@test.com',
          to: 'user@test.com',
          subject: expect.stringContaining('txn_123'),
          html: expect.stringContaining('John Doe'),
          text: expect.stringContaining('John Doe'),
        })
      )
    })
  })

  describe('Error Handling', () => {
    it('should handle transporter initialization errors gracefully', () => {
      mockNodemailer.createTransport.mockImplementation(() => {
        throw new Error('SMTP connection failed')
      })

      const testService = new EmailService()
      ;(testService as any).config = {
        email: {
          smtpHost: 'smtp.test.com',
          smtpPort: 587,
          smtpSecure: false,
          smtpUser: 'test@test.com',
          smtpPassword: 'testpass',
          fromAddress: 'noreply@test.com',
          supportEmail: 'support@test.com',
        },
        app: {
          baseUrl: 'https://test.com',
        },
      }

      expect(() => (testService as any).initializeTransporter()).toThrow('SMTP connection failed')
    })

    it('should handle email sending errors', async () => {
      mockTransporter.sendMail.mockRejectedValue(new Error('Send failed'))

      const paymentDetails = {
        amount: 2999,
        currency: 'USD',
        description: 'Premium Plan',
        transactionId: 'txn_123',
        date: new Date('2023-01-01'),
      }

      await expect(
        emailService.sendPaymentConfirmation('user@test.com', 'John Doe', paymentDetails, 'user123')
      ).rejects.toThrow('Send failed')
    })
  })

  describe('Template Processing', () => {
    it('should replace variables in email templates correctly', async () => {
      const paymentDetails = {
        amount: 2999,
        currency: 'USD',
        description: 'Premium Plan',
        transactionId: 'txn_123',
        date: new Date('2023-01-01'),
      }

      await emailService.sendPaymentConfirmation('user@test.com', 'John Doe', paymentDetails)

      const sentEmail = mockTransporter.sendMail.mock.calls[0][0]

      expect(sentEmail.html).toContain('John Doe')
      expect(sentEmail.html).toContain('$29.99')
      expect(sentEmail.html).toContain('txn_123')
      expect(sentEmail.text).toContain('John Doe')
      expect(sentEmail.text).toContain('$29.99')
      expect(sentEmail.text).toContain('txn_123')
    })
  })
})
