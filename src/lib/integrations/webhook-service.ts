/**
 * Webhook Service
 * Comprehensive webhook system for real-time data delivery
 */

import { 
  WebhookConfig, 
  WebhookEvent, 
  WebhookPayload, 
  WebhookDeliveryResult 
} from '@/types/integrations'
import { logger } from '@/utils/logger'
import crypto from 'crypto'

/**
 * Webhook Service implementation
 */
export class WebhookService {
  private webhooks: Map<string, WebhookConfig> = new Map()
  private deliveryQueue: Array<{
    webhookId: string
    payload: WebhookPayload
    attempt: number
    nextRetry: number
  }> = []
  private deliveryHistory: Map<string, WebhookDeliveryResult[]> = new Map()
  private isProcessing = false

  constructor() {
    this.startDeliveryProcessor()
  }

  /**
   * Create webhook
   */
  async createWebhook(
    webhookData: Omit<WebhookConfig, 'id' | 'status' | 'createdAt' | 'updatedAt' | 'successCount' | 'failureCount'>
  ): Promise<WebhookConfig> {
    const webhookId = this.generateWebhookId()

    const webhook: WebhookConfig = {
      id: webhookId,
      name: webhookData.name,
      description: webhookData.description,
      url: webhookData.url,
      events: webhookData.events,
      headers: webhookData.headers || {},
      secret: webhookData.secret || this.generateWebhookSecret(),
      retryPolicy: {
        maxRetries: 3,
        retryDelay: 1000,
        backoffMultiplier: 2,
        maxDelay: 30000,
        ...webhookData.retryPolicy
      },
      timeout: webhookData.timeout || 30000,
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      successCount: 0,
      failureCount: 0
    }

    this.webhooks.set(webhookId, webhook)
    this.deliveryHistory.set(webhookId, [])

    logger.info('WebhookService', `Created webhook: ${webhookId}`, {
      webhookId,
      name: webhook.name,
      url: webhook.url,
      events: webhook.events
    })

    return webhook
  }

  /**
   * Update webhook
   */
  async updateWebhook(
    webhookId: string, 
    updates: Partial<WebhookConfig>
  ): Promise<WebhookConfig> {
    const webhook = this.webhooks.get(webhookId)
    if (!webhook) {
      throw new Error('Webhook not found')
    }

    const updatedWebhook: WebhookConfig = {
      ...webhook,
      ...updates,
      id: webhookId, // Prevent ID changes
      updatedAt: new Date().toISOString()
    }

    this.webhooks.set(webhookId, updatedWebhook)

    logger.info('WebhookService', `Updated webhook: ${webhookId}`, {
      webhookId,
      updates: Object.keys(updates)
    })

    return updatedWebhook
  }

  /**
   * Delete webhook
   */
  async deleteWebhook(webhookId: string): Promise<void> {
    const webhook = this.webhooks.get(webhookId)
    if (!webhook) {
      throw new Error('Webhook not found')
    }

    this.webhooks.delete(webhookId)
    this.deliveryHistory.delete(webhookId)

    logger.info('WebhookService', `Deleted webhook: ${webhookId}`)
  }

  /**
   * Get webhook
   */
  async getWebhook(webhookId: string): Promise<WebhookConfig | null> {
    return this.webhooks.get(webhookId) || null
  }

  /**
   * List webhooks
   */
  async listWebhooks(filters?: {
    status?: 'active' | 'inactive' | 'failed'
    event?: WebhookEvent
  }): Promise<WebhookConfig[]> {
    let webhooks = Array.from(this.webhooks.values())

    if (filters?.status) {
      webhooks = webhooks.filter(w => w.status === filters.status)
    }

    if (filters?.event) {
      webhooks = webhooks.filter(w => w.events.includes(filters.event!))
    }

    return webhooks
  }

  /**
   * Trigger webhook
   */
  async triggerWebhook(
    webhookId: string, 
    event: WebhookEvent, 
    data: any
  ): Promise<WebhookDeliveryResult> {
    const webhook = this.webhooks.get(webhookId)
    if (!webhook) {
      throw new Error('Webhook not found')
    }

    if (webhook.status !== 'active') {
      throw new Error('Webhook is not active')
    }

    if (!webhook.events.includes(event)) {
      throw new Error(`Webhook does not subscribe to event: ${event}`)
    }

    const payload: WebhookPayload = {
      id: this.generatePayloadId(),
      event,
      timestamp: new Date().toISOString(),
      data,
      metadata: {
        source: 'business-scraper',
        version: 'v1',
        requestId: this.generateRequestId()
      }
    }

    logger.info('WebhookService', `Triggering webhook: ${webhookId}`, {
      webhookId,
      event,
      payloadId: payload.id
    })

    return this.deliverWebhook(webhook, payload)
  }

  /**
   * Trigger event for all subscribed webhooks
   */
  async triggerEvent(event: WebhookEvent, data: any): Promise<WebhookDeliveryResult[]> {
    const subscribedWebhooks = Array.from(this.webhooks.values()).filter(
      webhook => webhook.status === 'active' && webhook.events.includes(event)
    )

    if (subscribedWebhooks.length === 0) {
      logger.debug('WebhookService', `No webhooks subscribed to event: ${event}`)
      return []
    }

    const payload: WebhookPayload = {
      id: this.generatePayloadId(),
      event,
      timestamp: new Date().toISOString(),
      data,
      metadata: {
        source: 'business-scraper',
        version: 'v1',
        requestId: this.generateRequestId()
      }
    }

    logger.info('WebhookService', `Triggering event for ${subscribedWebhooks.length} webhooks`, {
      event,
      payloadId: payload.id,
      webhookCount: subscribedWebhooks.length
    })

    const results: WebhookDeliveryResult[] = []

    for (const webhook of subscribedWebhooks) {
      try {
        const result = await this.deliverWebhook(webhook, payload)
        results.push(result)
      } catch (error) {
        logger.error('WebhookService', `Failed to deliver webhook: ${webhook.id}`, error)
        
        const errorResult: WebhookDeliveryResult = {
          id: this.generateDeliveryId(),
          webhookId: webhook.id,
          event,
          url: webhook.url,
          status: 'failed',
          responseTime: 0,
          attempts: 1,
          lastAttempt: new Date().toISOString(),
          error: error instanceof Error ? error.message : 'Unknown error'
        }
        
        results.push(errorResult)
      }
    }

    return results
  }

  /**
   * Deliver webhook payload
   */
  private async deliverWebhook(
    webhook: WebhookConfig, 
    payload: WebhookPayload
  ): Promise<WebhookDeliveryResult> {
    const deliveryId = this.generateDeliveryId()
    const startTime = Date.now()

    try {
      // Prepare headers
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'Business-Scraper-Webhook/1.0',
        'X-Webhook-ID': webhook.id,
        'X-Event-Type': payload.event,
        'X-Delivery-ID': deliveryId,
        'X-Timestamp': payload.timestamp,
        ...webhook.headers
      }

      // Add signature if secret is provided
      if (webhook.secret) {
        const signature = this.generateSignature(payload, webhook.secret)
        headers['X-Webhook-Signature'] = signature
      }

      // Make HTTP request
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), webhook.timeout)

      const response = await fetch(webhook.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal
      })

      clearTimeout(timeoutId)

      const responseTime = Date.now() - startTime
      const responseText = await response.text()

      const result: WebhookDeliveryResult = {
        id: deliveryId,
        webhookId: webhook.id,
        event: payload.event,
        url: webhook.url,
        status: response.ok ? 'success' : 'failed',
        httpStatus: response.status,
        responseTime,
        attempts: 1,
        lastAttempt: new Date().toISOString(),
        response: responseText.substring(0, 1000) // Limit response size
      }

      if (!response.ok) {
        result.error = `HTTP ${response.status}: ${response.statusText}`
      }

      // Update webhook statistics
      if (response.ok) {
        webhook.successCount++
        webhook.lastTriggered = new Date().toISOString()
      } else {
        webhook.failureCount++
        
        // Queue for retry if configured
        if (webhook.retryPolicy.maxRetries > 0) {
          this.queueForRetry(webhook, payload, 1)
        }
      }

      // Store delivery result
      this.storeDeliveryResult(webhook.id, result)

      logger.info('WebhookService', `Webhook delivered: ${webhook.id}`, {
        webhookId: webhook.id,
        deliveryId,
        status: result.status,
        httpStatus: result.httpStatus,
        responseTime: result.responseTime
      })

      return result

    } catch (error) {
      const responseTime = Date.now() - startTime
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'

      const result: WebhookDeliveryResult = {
        id: deliveryId,
        webhookId: webhook.id,
        event: payload.event,
        url: webhook.url,
        status: 'failed',
        responseTime,
        attempts: 1,
        lastAttempt: new Date().toISOString(),
        error: errorMessage
      }

      // Update webhook statistics
      webhook.failureCount++

      // Queue for retry if configured
      if (webhook.retryPolicy.maxRetries > 0) {
        this.queueForRetry(webhook, payload, 1)
      }

      // Store delivery result
      this.storeDeliveryResult(webhook.id, result)

      logger.warn('WebhookService', `Webhook delivery failed: ${webhook.id}`, {
        webhookId: webhook.id,
        deliveryId,
        error: errorMessage,
        responseTime
      })

      return result
    }
  }

  /**
   * Queue webhook for retry
   */
  private queueForRetry(
    webhook: WebhookConfig, 
    payload: WebhookPayload, 
    attempt: number
  ): void {
    if (attempt >= webhook.retryPolicy.maxRetries) {
      return
    }

    const delay = Math.min(
      webhook.retryPolicy.retryDelay * Math.pow(webhook.retryPolicy.backoffMultiplier, attempt - 1),
      webhook.retryPolicy.maxDelay
    )

    const nextRetry = Date.now() + delay

    this.deliveryQueue.push({
      webhookId: webhook.id,
      payload,
      attempt: attempt + 1,
      nextRetry
    })

    logger.debug('WebhookService', `Queued webhook for retry: ${webhook.id}`, {
      webhookId: webhook.id,
      attempt: attempt + 1,
      delay,
      nextRetry: new Date(nextRetry).toISOString()
    })
  }

  /**
   * Start delivery processor for retries
   */
  private startDeliveryProcessor(): void {
    setInterval(async () => {
      if (this.isProcessing || this.deliveryQueue.length === 0) {
        return
      }

      this.isProcessing = true

      try {
        const now = Date.now()
        const readyForRetry = this.deliveryQueue.filter(item => item.nextRetry <= now)

        for (const item of readyForRetry) {
          const webhook = this.webhooks.get(item.webhookId)
          if (!webhook || webhook.status !== 'active') {
            continue
          }

          try {
            await this.deliverWebhook(webhook, item.payload)
          } catch (error) {
            logger.error('WebhookService', `Retry delivery failed: ${webhook.id}`, error)
          }

          // Remove from queue
          const index = this.deliveryQueue.indexOf(item)
          if (index !== -1) {
            this.deliveryQueue.splice(index, 1)
          }
        }
      } finally {
        this.isProcessing = false
      }
    }, 5000) // Check every 5 seconds
  }

  /**
   * Store delivery result
   */
  private storeDeliveryResult(webhookId: string, result: WebhookDeliveryResult): void {
    const history = this.deliveryHistory.get(webhookId) || []
    history.push(result)

    // Keep only last 100 delivery results
    if (history.length > 100) {
      history.splice(0, history.length - 100)
    }

    this.deliveryHistory.set(webhookId, history)
  }

  /**
   * Get delivery history
   */
  async getDeliveryHistory(
    webhookId: string, 
    limit: number = 50
  ): Promise<WebhookDeliveryResult[]> {
    const history = this.deliveryHistory.get(webhookId) || []
    return history.slice(-limit).reverse()
  }

  /**
   * Generate webhook signature
   */
  private generateSignature(payload: WebhookPayload, secret: string): string {
    const payloadString = JSON.stringify(payload)
    const signature = crypto
      .createHmac('sha256', secret)
      .update(payloadString)
      .digest('hex')
    
    return `sha256=${signature}`
  }

  /**
   * Verify webhook signature
   */
  verifySignature(payload: string, signature: string, secret: string): boolean {
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex')
    
    const providedSignature = signature.replace('sha256=', '')
    
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(providedSignature, 'hex')
    )
  }

  /**
   * Generate unique IDs
   */
  private generateWebhookId(): string {
    return `webhook_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`
  }

  private generatePayloadId(): string {
    return `payload_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`
  }

  private generateDeliveryId(): string {
    return `delivery_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`
  }

  private generateWebhookSecret(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  /**
   * Get webhook statistics
   */
  getWebhookStatistics(): {
    totalWebhooks: number
    activeWebhooks: number
    totalDeliveries: number
    successfulDeliveries: number
    failedDeliveries: number
    queuedRetries: number
  } {
    const webhooks = Array.from(this.webhooks.values())
    const totalWebhooks = webhooks.length
    const activeWebhooks = webhooks.filter(w => w.status === 'active').length
    const totalSuccessful = webhooks.reduce((sum, w) => sum + w.successCount, 0)
    const totalFailed = webhooks.reduce((sum, w) => sum + w.failureCount, 0)

    return {
      totalWebhooks,
      activeWebhooks,
      totalDeliveries: totalSuccessful + totalFailed,
      successfulDeliveries: totalSuccessful,
      failedDeliveries: totalFailed,
      queuedRetries: this.deliveryQueue.length
    }
  }
}

// Export singleton instance
export const webhookService = new WebhookService()
