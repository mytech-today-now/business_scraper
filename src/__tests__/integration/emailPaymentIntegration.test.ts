/**
 * Email-Payment Integration Tests
 * Tests the integration between email service and payment service
 */

import { userPaymentService } from '@/model/userPaymentService'
import { emailService } from '@/model/emailService'
import { auditService } from '@/model/auditService'
import { getConfig } from '@/lib/config'
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

describe('Email-Payment Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(getConfig as jest.Mock).mockReturnValue(mockConfig)
    ;(nodemailer.createTransporter as jest.Mock).mockReturnValue(mockTransporter)
    ;(auditService.logAuditEvent as jest.Mock).mockResolvedValue(undefined)
    mockTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' })
  })

  describe('Payment Success Flow', () => {
    it('should send payment confirmation email when payment succeeds', async () => {
      // Mock user data
      const mockUser = {
        id: 'user123',
        email: 'customer@example.com',
        name: 'John Customer'
      }

      // Mock payment intent
      const mockPaymentIntent = {
        id: 'pi_test123',
        customer: 'cus_test123',
        amount: 2999,
        currency: 'usd',
        description: 'Professional Plan Subscription'
      }

      // Mock getUserById to return our test user
      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)

      // Execute payment success recording
      await userPaymentService.recordPaymentSuccess(mockPaymentIntent)

      // Verify email was sent
      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'customer@example.com',
        subject: 'Payment Confirmation - pi_test123',
        html: expect.stringContaining('John Customer'),
        text: expect.stringContaining('John Customer')
      })

      // Verify audit log was created
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

    it('should handle missing user gracefully', async () => {
      const mockPaymentIntent = {
        id: 'pi_test123',
        customer: 'cus_nonexistent',
        amount: 2999,
        currency: 'usd',
        description: 'Professional Plan Subscription'
      }

      // Mock getUserById to return null
      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(null)

      // Should not throw error
      await expect(
        userPaymentService.recordPaymentSuccess(mockPaymentIntent)
      ).resolves.not.toThrow()

      // Should not send email
      expect(mockTransporter.sendMail).not.toHaveBeenCalled()
    })
  })

  describe('Payment Failure Flow', () => {
    it('should send payment failed email when payment fails', async () => {
      const mockUser = {
        id: 'user456',
        email: 'customer@example.com',
        name: 'Jane Customer'
      }

      const mockPaymentIntent = {
        id: 'pi_test456',
        customer: 'cus_test456',
        amount: 2999,
        currency: 'usd',
        last_payment_error: {
          message: 'Your card was declined.'
        }
      }

      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)

      await userPaymentService.recordPaymentFailure(mockPaymentIntent)

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'customer@example.com',
        subject: 'Payment Failed - Action Required',
        html: expect.stringContaining('Jane Customer'),
        text: expect.stringContaining('Jane Customer')
      })
    })
  })

  describe('Subscription Creation Flow', () => {
    it('should send welcome email when subscription is created', async () => {
      const mockUser = {
        id: 'user789',
        email: 'subscriber@example.com',
        name: 'Bob Subscriber'
      }

      const mockProfile = {
        userId: 'user789',
        stripeCustomerId: 'cus_test789',
        email: 'subscriber@example.com'
      }

      const mockSubscription = {
        id: 'sub_test789',
        status: 'active',
        cancel_at_period_end: false,
        trial_end: null
      }

      const mockPlan = {
        name: 'Professional Plan',
        priceCents: 2999,
        currency: 'USD',
        interval: 'month',
        features: ['Advanced scraping', 'Priority support', 'API access']
      }

      // Mock methods
      jest.spyOn(userPaymentService, 'getUserPaymentProfile').mockResolvedValue(mockProfile)
      jest.spyOn(userPaymentService, 'updateUserPaymentProfile').mockResolvedValue(mockProfile)
      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)
      jest.spyOn(userPaymentService as any, 'getSubscriptionPlan').mockResolvedValue(mockPlan)

      // Mock stripeService.createSubscription
      const mockStripeService = require('@/model/stripeService')
      mockStripeService.stripeService = {
        createSubscription: jest.fn().mockResolvedValue(mockSubscription)
      }

      const result = await userPaymentService.createSubscription('user789', 'price_professional')

      expect(result.success).toBe(true)
      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'subscriber@example.com',
        subject: 'Welcome to Professional Plan - Your subscription is active!',
        html: expect.stringContaining('Bob Subscriber'),
        text: expect.stringContaining('Bob Subscriber')
      })
    })
  })

  describe('Invoice Notification Flow', () => {
    it('should send invoice notification email', async () => {
      const mockUser = {
        id: 'user101',
        email: 'billing@example.com',
        name: 'Alice Billing'
      }

      const invoiceDetails = {
        invoiceNumber: 'INV-2025-001',
        amount: 2999,
        currency: 'USD',
        dueDate: new Date('2025-01-15'),
        downloadUrl: 'https://app.businessscraper.com/invoices/INV-2025-001'
      }

      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)

      await userPaymentService.sendInvoiceNotification('user101', invoiceDetails)

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@businessscraper.com',
        to: 'billing@example.com',
        subject: 'Invoice INV-2025-001 - $29.99 due 1/15/2025',
        html: expect.stringContaining('Alice Billing'),
        text: expect.stringContaining('Alice Billing')
      })
    })
  })

  describe('Error Handling in Integration', () => {
    it('should handle email service failures gracefully', async () => {
      const mockUser = {
        id: 'user999',
        email: 'error@example.com',
        name: 'Error User'
      }

      const mockPaymentIntent = {
        id: 'pi_error',
        customer: 'cus_error',
        amount: 1000,
        currency: 'usd',
        description: 'Test Payment'
      }

      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)
      mockTransporter.sendMail.mockRejectedValue(new Error('SMTP server unavailable'))

      await expect(
        userPaymentService.recordPaymentSuccess(mockPaymentIntent)
      ).rejects.toThrow('SMTP server unavailable')
    })

    it('should handle audit service failures gracefully', async () => {
      const mockUser = {
        id: 'user888',
        email: 'audit@example.com',
        name: 'Audit User'
      }

      const mockPaymentIntent = {
        id: 'pi_audit',
        customer: 'cus_audit',
        amount: 1000,
        currency: 'usd',
        description: 'Test Payment'
      }

      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)
      ;(auditService.logAuditEvent as jest.Mock).mockRejectedValue(new Error('Audit service down'))

      // Email should still be sent even if audit fails
      await userPaymentService.recordPaymentSuccess(mockPaymentIntent)

      expect(mockTransporter.sendMail).toHaveBeenCalled()
    })
  })

  describe('Template Variable Integration', () => {
    it('should properly integrate payment data with email templates', async () => {
      const mockUser = {
        id: 'user555',
        email: 'template@example.com',
        name: 'Template User'
      }

      const mockPaymentIntent = {
        id: 'pi_template_test',
        customer: 'cus_template',
        amount: 4999,
        currency: 'usd',
        description: 'Enterprise Plan Subscription'
      }

      jest.spyOn(userPaymentService as any, 'getUserById').mockResolvedValue(mockUser)

      await userPaymentService.recordPaymentSuccess(mockPaymentIntent)

      const emailCall = mockTransporter.sendMail.mock.calls[0][0]
      
      // Verify all template variables are properly replaced
      expect(emailCall.html).toContain('Template User')
      expect(emailCall.html).toContain('$49.99')
      expect(emailCall.html).toContain('Enterprise Plan Subscription')
      expect(emailCall.html).toContain('pi_template_test')
      expect(emailCall.html).toContain('support@businessscraper.com')
      expect(emailCall.html).toContain('https://app.businessscraper.com/dashboard')
    })
  })
})
