/**
 * Email Notification Service
 * Comprehensive automated email notification system for payment events, 
 * subscription changes, and customer communication with professional templates
 */

import nodemailer from 'nodemailer'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'
import { auditService } from './auditService'

export interface EmailTemplate {
  id: string
  name: string
  subject: string
  htmlContent: string
  textContent: string
  variables: string[]
}

export interface EmailNotification {
  id: string
  to: string
  from: string
  subject: string
  htmlContent: string
  textContent: string
  templateId?: string
  variables?: Record<string, any>
  status: 'pending' | 'sent' | 'failed' | 'bounced'
  sentAt?: Date
  errorMessage?: string
  userId?: string
}

export class EmailService {
  private transporter: nodemailer.Transporter | null = null
  private config = getConfig()

  constructor() {
    this.initializeTransporter()
  }

  private initializeTransporter(): void {
    try {
      this.transporter = nodemailer.createTransporter({
        host: this.config.email.smtpHost,
        port: this.config.email.smtpPort,
        secure: this.config.email.smtpSecure,
        auth: {
          user: this.config.email.smtpUser,
          pass: this.config.email.smtpPassword
        }
      })

      logger.info('EmailService', 'SMTP transporter initialized successfully')
    } catch (error) {
      logger.error('EmailService', 'Failed to initialize SMTP transporter', error)
      throw error
    }
  }

  /**
   * Send payment confirmation email
   */
  async sendPaymentConfirmation(
    userEmail: string,
    userName: string,
    paymentDetails: {
      amount: number
      currency: string
      description: string
      transactionId: string
      date: Date
    },
    userId?: string
  ): Promise<void> {
    try {
      const template = await this.getEmailTemplate('payment_confirmation')

      const variables = {
        userName,
        amount: this.formatCurrency(paymentDetails.amount, paymentDetails.currency),
        description: paymentDetails.description,
        transactionId: paymentDetails.transactionId,
        date: paymentDetails.date.toLocaleDateString(),
        supportEmail: this.config.email.supportEmail,
        dashboardUrl: `${this.config.app.baseUrl}/dashboard`
      }

      await this.sendTemplatedEmail(
        userEmail,
        template,
        variables,
        userId
      )

      logger.info('EmailService', `Payment confirmation sent to: ${userEmail}`)
    } catch (error) {
      logger.error('EmailService', 'Failed to send payment confirmation', error)
      throw error
    }
  }

  /**
   * Send subscription welcome email
   */
  async sendSubscriptionWelcome(
    userEmail: string,
    userName: string,
    subscriptionDetails: {
      planName: string
      price: number
      currency: string
      interval: string
      features: string[]
      nextBillingDate: Date
    },
    userId?: string
  ): Promise<void> {
    try {
      const template = await this.getEmailTemplate('subscription_welcome')

      const variables = {
        userName,
        planName: subscriptionDetails.planName,
        price: this.formatCurrency(subscriptionDetails.price, subscriptionDetails.currency),
        interval: subscriptionDetails.interval,
        features: subscriptionDetails.features.join(', '),
        nextBillingDate: subscriptionDetails.nextBillingDate.toLocaleDateString(),
        dashboardUrl: `${this.config.app.baseUrl}/dashboard`,
        supportEmail: this.config.email.supportEmail
      }

      await this.sendTemplatedEmail(
        userEmail,
        template,
        variables,
        userId
      )

      logger.info('EmailService', `Subscription welcome sent to: ${userEmail}`)
    } catch (error) {
      logger.error('EmailService', 'Failed to send subscription welcome', error)
      throw error
    }
  }

  /**
   * Send payment failed notification
   */
  async sendPaymentFailed(
    userEmail: string,
    userName: string,
    failureDetails: {
      amount: number
      currency: string
      reason: string
      nextRetryDate?: Date
    },
    userId?: string
  ): Promise<void> {
    try {
      const template = await this.getEmailTemplate('payment_failed')

      const variables = {
        userName,
        amount: this.formatCurrency(failureDetails.amount, failureDetails.currency),
        reason: failureDetails.reason,
        nextRetryDate: failureDetails.nextRetryDate?.toLocaleDateString() || 'N/A',
        updatePaymentUrl: `${this.config.app.baseUrl}/billing/payment-methods`,
        supportEmail: this.config.email.supportEmail
      }

      await this.sendTemplatedEmail(
        userEmail,
        template,
        variables,
        userId
      )

      logger.info('EmailService', `Payment failed notification sent to: ${userEmail}`)
    } catch (error) {
      logger.error('EmailService', 'Failed to send payment failed notification', error)
      throw error
    }
  }

  /**
   * Send subscription cancellation confirmation
   */
  async sendSubscriptionCancellation(
    userEmail: string,
    userName: string,
    cancellationDetails: {
      planName: string
      endDate: Date
      reason?: string
    },
    userId?: string
  ): Promise<void> {
    try {
      const template = await this.getEmailTemplate('subscription_cancelled')

      const variables = {
        userName,
        planName: cancellationDetails.planName,
        endDate: cancellationDetails.endDate.toLocaleDateString(),
        reason: cancellationDetails.reason || 'Not specified',
        reactivateUrl: `${this.config.app.baseUrl}/pricing`,
        supportEmail: this.config.email.supportEmail
      }

      await this.sendTemplatedEmail(
        userEmail,
        template,
        variables,
        userId
      )

      logger.info('EmailService', `Subscription cancellation sent to: ${userEmail}`)
    } catch (error) {
      logger.error('EmailService', 'Failed to send subscription cancellation', error)
      throw error
    }
  }

  /**
   * Send invoice notification
   */
  async sendInvoiceNotification(
    userEmail: string,
    userName: string,
    invoiceDetails: {
      invoiceNumber: string
      amount: number
      currency: string
      dueDate: Date
      downloadUrl: string
    },
    userId?: string
  ): Promise<void> {
    try {
      const template = await this.getEmailTemplate('invoice_notification')

      const variables = {
        userName,
        invoiceNumber: invoiceDetails.invoiceNumber,
        amount: this.formatCurrency(invoiceDetails.amount, invoiceDetails.currency),
        dueDate: invoiceDetails.dueDate.toLocaleDateString(),
        downloadUrl: invoiceDetails.downloadUrl,
        paymentUrl: `${this.config.app.baseUrl}/billing/pay-invoice`,
        supportEmail: this.config.email.supportEmail
      }

      await this.sendTemplatedEmail(
        userEmail,
        template,
        variables,
        userId
      )

      logger.info('EmailService', `Invoice notification sent to: ${userEmail}`)
    } catch (error) {
      logger.error('EmailService', 'Failed to send invoice notification', error)
      throw error
    }
  }

  /**
   * Send templated email
   */
  private async sendTemplatedEmail(
    to: string,
    template: EmailTemplate,
    variables: Record<string, any>,
    userId?: string
  ): Promise<void> {
    if (!this.transporter) {
      throw new Error('Email transporter not initialized')
    }

    const notification: EmailNotification = {
      id: this.generateNotificationId(),
      to,
      from: this.config.email.fromAddress,
      subject: this.replaceVariables(template.subject, variables),
      htmlContent: this.replaceVariables(template.htmlContent, variables),
      textContent: this.replaceVariables(template.textContent, variables),
      templateId: template.id,
      variables,
      status: 'pending',
      userId
    }

    try {
      await this.storeNotification(notification)

      const result = await this.transporter.sendMail({
        from: this.config.email.fromAddress,
        to,
        subject: notification.subject,
        html: notification.htmlContent,
        text: notification.textContent
      })

      await this.updateNotificationStatus(notification.id, 'sent', new Date())

      // Log email sent for audit
      await auditService.logAuditEvent('email_sent', 'notification', {
        userId,
        resourceId: notification.id,
        newValues: { to, templateId: template.id },
        severity: 'low',
        category: 'system'
      })

    } catch (error) {
      await this.updateNotificationStatus(
        notification.id,
        'failed',
        undefined,
        error instanceof Error ? error.message : 'Unknown error'
      )
      throw error
    }
  }

  /**
   * Replace variables in template content
   */
  private replaceVariables(content: string, variables: Record<string, any>): string {
    let result = content

    Object.entries(variables).forEach(([key, value]) => {
      const regex = new RegExp(`{{\\s*${key}\\s*}}`, 'g')
      result = result.replace(regex, String(value))
    })

    return result
  }

  /**
   * Format currency
   */
  private formatCurrency(amount: number, currency: string): string {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase()
    }).format(amount / 100)
  }

  /**
   * Helper methods
   */
  private generateNotificationId(): string {
    return `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private async getEmailTemplate(templateId: string): Promise<EmailTemplate> {
    // Implementation would load template from database or file system
    return this.getDefaultTemplate(templateId)
  }

  private getDefaultTemplate(templateId: string): EmailTemplate {
    const templates: Record<string, EmailTemplate> = {
      payment_confirmation: {
        id: 'payment_confirmation',
        name: 'Payment Confirmation',
        subject: 'Payment Confirmation - {{transactionId}}',
        htmlContent: `
          <h2>Payment Confirmed</h2>
          <p>Hi {{userName}},</p>
          <p>Your payment of {{amount}} for {{description}} has been successfully processed.</p>
          <p><strong>Transaction ID:</strong> {{transactionId}}</p>
          <p><strong>Date:</strong> {{date}}</p>
          <p><a href="{{dashboardUrl}}">View Dashboard</a></p>
          <p>If you have any questions, please contact us at {{supportEmail}}.</p>
        `,
        textContent: `Payment Confirmed\n\nHi {{userName}},\n\nYour payment of {{amount}} for {{description}} has been successfully processed.\n\nTransaction ID: {{transactionId}}\nDate: {{date}}\n\nView Dashboard: {{dashboardUrl}}\n\nIf you have any questions, please contact us at {{supportEmail}}.`,
        variables: ['userName', 'amount', 'description', 'transactionId', 'date', 'supportEmail', 'dashboardUrl']
      },
      subscription_welcome: {
        id: 'subscription_welcome',
        name: 'Subscription Welcome',
        subject: 'Welcome to {{planName}} - Your subscription is active!',
        htmlContent: `
          <h2>Welcome to {{planName}}!</h2>
          <p>Hi {{userName}},</p>
          <p>Thank you for subscribing to {{planName}} at {{price}}/{{interval}}.</p>
          <p><strong>Features included:</strong> {{features}}</p>
          <p><strong>Next billing date:</strong> {{nextBillingDate}}</p>
          <p><a href="{{dashboardUrl}}">Access Your Dashboard</a></p>
          <p>If you have any questions, please contact us at {{supportEmail}}.</p>
        `,
        textContent: `Welcome to {{planName}}!\n\nHi {{userName}},\n\nThank you for subscribing to {{planName}} at {{price}}/{{interval}}.\n\nFeatures included: {{features}}\nNext billing date: {{nextBillingDate}}\n\nAccess Your Dashboard: {{dashboardUrl}}\n\nIf you have any questions, please contact us at {{supportEmail}}.`,
        variables: ['userName', 'planName', 'price', 'interval', 'features', 'nextBillingDate', 'dashboardUrl', 'supportEmail']
      },
      payment_failed: {
        id: 'payment_failed',
        name: 'Payment Failed',
        subject: 'Payment Failed - Action Required',
        htmlContent: `
          <h2>Payment Failed</h2>
          <p>Hi {{userName}},</p>
          <p>We were unable to process your payment of {{amount}}.</p>
          <p><strong>Reason:</strong> {{reason}}</p>
          <p><strong>Next retry:</strong> {{nextRetryDate}}</p>
          <p><a href="{{updatePaymentUrl}}">Update Payment Method</a></p>
          <p>If you have any questions, please contact us at {{supportEmail}}.</p>
        `,
        textContent: `Payment Failed\n\nHi {{userName}},\n\nWe were unable to process your payment of {{amount}}.\n\nReason: {{reason}}\nNext retry: {{nextRetryDate}}\n\nUpdate Payment Method: {{updatePaymentUrl}}\n\nIf you have any questions, please contact us at {{supportEmail}}.`,
        variables: ['userName', 'amount', 'reason', 'nextRetryDate', 'updatePaymentUrl', 'supportEmail']
      },
      subscription_cancelled: {
        id: 'subscription_cancelled',
        name: 'Subscription Cancelled',
        subject: 'Subscription Cancelled - {{planName}}',
        htmlContent: `
          <h2>Subscription Cancelled</h2>
          <p>Hi {{userName}},</p>
          <p>Your {{planName}} subscription has been cancelled.</p>
          <p><strong>End date:</strong> {{endDate}}</p>
          <p><strong>Reason:</strong> {{reason}}</p>
          <p><a href="{{reactivateUrl}}">Reactivate Subscription</a></p>
          <p>If you have any questions, please contact us at {{supportEmail}}.</p>
        `,
        textContent: `Subscription Cancelled\n\nHi {{userName}},\n\nYour {{planName}} subscription has been cancelled.\n\nEnd date: {{endDate}}\nReason: {{reason}}\n\nReactivate Subscription: {{reactivateUrl}}\n\nIf you have any questions, please contact us at {{supportEmail}}.`,
        variables: ['userName', 'planName', 'endDate', 'reason', 'reactivateUrl', 'supportEmail']
      },
      invoice_notification: {
        id: 'invoice_notification',
        name: 'Invoice Notification',
        subject: 'Invoice {{invoiceNumber}} - {{amount}} due {{dueDate}}',
        htmlContent: `
          <h2>Invoice {{invoiceNumber}}</h2>
          <p>Hi {{userName}},</p>
          <p>Your invoice for {{amount}} is due on {{dueDate}}.</p>
          <p><a href="{{downloadUrl}}">Download Invoice</a></p>
          <p><a href="{{paymentUrl}}">Pay Now</a></p>
          <p>If you have any questions, please contact us at {{supportEmail}}.</p>
        `,
        textContent: `Invoice {{invoiceNumber}}\n\nHi {{userName}},\n\nYour invoice for {{amount}} is due on {{dueDate}}.\n\nDownload Invoice: {{downloadUrl}}\nPay Now: {{paymentUrl}}\n\nIf you have any questions, please contact us at {{supportEmail}}.`,
        variables: ['userName', 'invoiceNumber', 'amount', 'dueDate', 'downloadUrl', 'paymentUrl', 'supportEmail']
      }
    }

    return templates[templateId] || templates.payment_confirmation
  }

  private async storeNotification(notification: EmailNotification): Promise<void> {
    // Implementation would store notification in database
    // For now, just log it
    logger.debug('EmailService', 'Storing email notification', {
      id: notification.id,
      to: notification.to,
      templateId: notification.templateId
    })
  }

  private async updateNotificationStatus(
    id: string,
    status: string,
    sentAt?: Date,
    errorMessage?: string
  ): Promise<void> {
    // Implementation would update notification status in database
    logger.debug('EmailService', 'Updating notification status', {
      id,
      status,
      sentAt,
      errorMessage
    })
  }
}

export const emailService = new EmailService()
