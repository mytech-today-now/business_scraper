/**
 * CRM Webhook Handler API Endpoint
 * Handles incoming webhooks from CRM systems for real-time updates
 */

import { NextRequest, NextResponse } from 'next/server'
import { crmServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { CRMWebhookEvent } from '@/types/crm'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * POST /api/crm/webhook - Handle incoming CRM webhooks
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_WEBHOOK_API', `Webhook received from IP: ${ip}`)

    const url = new URL(request.url)
    const providerId = url.searchParams.get('providerId')

    if (!providerId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider ID is required',
        },
        { status: 400 }
      )
    }

    // Get the CRM service
    const service = crmServiceRegistry.getService(providerId)
    if (!service) {
      logger.warn('CRM_WEBHOOK_API', `Unknown provider ID: ${providerId}`)
      return NextResponse.json(
        {
          success: false,
          error: 'Unknown CRM provider',
        },
        { status: 404 }
      )
    }

    // Get request body and headers
    const body = await request.text()
    const headers = Object.fromEntries(request.headers.entries())

    // Extract webhook signature for validation
    const signature =
      headers['x-signature'] ||
      headers['x-hub-signature'] ||
      headers['x-webhook-signature'] ||
      headers['signature']

    // Parse webhook event based on provider type
    const webhookEvent = await parseWebhookEvent(providerId, body, headers, signature)

    if (!webhookEvent) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid webhook payload',
        },
        { status: 400 }
      )
    }

    logger.info('CRM_WEBHOOK_API', `Processing webhook event: ${webhookEvent.eventType}`, {
      providerId,
      objectType: webhookEvent.objectType,
      objectId: webhookEvent.objectId,
    })

    // Handle the webhook event
    await service.handleWebhookEvent(webhookEvent)

    // Log successful processing
    logger.info('CRM_WEBHOOK_API', `Webhook processed successfully`, {
      providerId,
      eventType: webhookEvent.eventType,
      objectId: webhookEvent.objectId,
    })

    return NextResponse.json({
      success: true,
      message: 'Webhook processed successfully',
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('CRM_WEBHOOK_API', 'Webhook processing failed', error)

    // Return 200 to prevent webhook retries for processing errors
    return NextResponse.json(
      {
        success: false,
        error: 'Webhook processing failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 200 }
    )
  }
}

/**
 * GET /api/crm/webhook - Get webhook configuration and status
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_WEBHOOK_API', `Get webhook status request from IP: ${ip}`)

    const url = new URL(request.url)
    const providerId = url.searchParams.get('providerId')

    if (providerId) {
      // Get webhook status for specific provider
      const service = crmServiceRegistry.getService(providerId)
      if (!service) {
        return NextResponse.json(
          {
            success: false,
            error: 'Provider not found',
          },
          { status: 404 }
        )
      }

      const provider = service.getProvider()
      const webhookUrl = provider.configuration.webhookUrl

      return NextResponse.json({
        success: true,
        data: {
          providerId,
          providerName: provider.name,
          webhookUrl,
          webhookSupport: provider.capabilities.webhookSupport,
          isActive: provider.isActive,
        },
      })
    } else {
      // Get webhook status for all providers
      const providers = crmServiceRegistry.getAllProviders()
      const webhookStatus = providers.map(provider => ({
        providerId: provider.id,
        providerName: provider.name,
        webhookUrl: provider.configuration.webhookUrl,
        webhookSupport: provider.capabilities.webhookSupport,
        isActive: provider.isActive,
      }))

      return NextResponse.json({
        success: true,
        data: {
          providers: webhookStatus,
          totalProviders: providers.length,
          webhookEnabledProviders: providers.filter(p => p.capabilities.webhookSupport).length,
        },
      })
    }
  } catch (error) {
    logger.error('CRM_WEBHOOK_API', 'Failed to get webhook status', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to retrieve webhook status',
      },
      { status: 500 }
    )
  }
}

/**
 * PUT /api/crm/webhook - Setup or update webhook subscriptions
 */
export async function PUT(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_WEBHOOK_API', `Setup webhook request from IP: ${ip}`)

    const body = await request.json()
    const { providerId, webhookUrl, eventTypes } = body

    if (!providerId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider ID is required',
        },
        { status: 400 }
      )
    }

    // Get the CRM service
    const service = crmServiceRegistry.getService(providerId)
    if (!service) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider not found',
        },
        { status: 404 }
      )
    }

    const provider = service.getProvider()

    // Check if provider supports webhooks
    if (!provider.capabilities.webhookSupport) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider does not support webhooks',
        },
        { status: 400 }
      )
    }

    // Update webhook URL in provider configuration if provided
    if (webhookUrl) {
      await crmServiceRegistry.updateProvider(providerId, {
        configuration: {
          ...provider.configuration,
          webhookUrl,
        },
      })
    }

    // Setup webhook subscriptions
    const subscriptions = await service.setupWebhooks()

    logger.info('CRM_WEBHOOK_API', `Webhook setup completed for ${provider.name}`, {
      providerId,
      subscriptionsCount: subscriptions.length,
    })

    return NextResponse.json({
      success: true,
      data: {
        providerId,
        providerName: provider.name,
        subscriptions,
        webhookUrl: provider.configuration.webhookUrl,
      },
      message: 'Webhook setup completed successfully',
    })
  } catch (error) {
    logger.error('CRM_WEBHOOK_API', 'Webhook setup failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Webhook setup failed',
      },
      { status: 500 }
    )
  }
}

/**
 * Parse webhook event based on provider type
 */
async function parseWebhookEvent(
  providerId: string,
  body: string,
  headers: Record<string, string>,
  signature?: string
): Promise<CRMWebhookEvent | null> {
  try {
    const provider = crmServiceRegistry.getProvider(providerId)
    if (!provider) {
      return null
    }

    let eventData: any
    try {
      eventData = JSON.parse(body)
    } catch {
      logger.error('CRM_WEBHOOK_API', 'Invalid JSON in webhook body')
      return null
    }

    // Parse based on provider type
    switch (provider.type) {
      case 'salesforce':
        return parseSalesforceWebhook(eventData, headers, signature)
      case 'hubspot':
        return parseHubSpotWebhook(eventData, headers, signature)
      case 'pipedrive':
        return parsePipedriveWebhook(eventData, headers, signature)
      case 'custom':
        return parseCustomWebhook(eventData, headers, signature)
      default:
        logger.warn('CRM_WEBHOOK_API', `Unsupported provider type: ${provider.type}`)
        return null
    }
  } catch (error) {
    logger.error('CRM_WEBHOOK_API', 'Failed to parse webhook event', error)
    return null
  }
}

function parseSalesforceWebhook(
  data: any,
  headers: Record<string, string>,
  signature?: string
): CRMWebhookEvent {
  return {
    id: `sf-webhook-${Date.now()}`,
    crmProviderId: 'salesforce',
    eventType: data.eventType || 'unknown',
    objectType: data.sobjectType || 'unknown',
    objectId: data.sobjectId || data.Id,
    timestamp: new Date(data.eventDate || Date.now()),
    data,
    signature,
  }
}

function parseHubSpotWebhook(
  data: any,
  headers: Record<string, string>,
  signature?: string
): CRMWebhookEvent {
  return {
    id: `hs-webhook-${Date.now()}`,
    crmProviderId: 'hubspot',
    eventType: data.subscriptionType || 'unknown',
    objectType: data.objectType || 'unknown',
    objectId: data.objectId?.toString(),
    timestamp: new Date(data.occurredAt || Date.now()),
    data,
    signature,
  }
}

function parsePipedriveWebhook(
  data: any,
  headers: Record<string, string>,
  signature?: string
): CRMWebhookEvent {
  return {
    id: `pd-webhook-${Date.now()}`,
    crmProviderId: 'pipedrive',
    eventType: data.event || 'unknown',
    objectType: data.object || 'unknown',
    objectId: data.current?.id?.toString(),
    timestamp: new Date(),
    data,
    signature,
  }
}

function parseCustomWebhook(
  data: any,
  headers: Record<string, string>,
  signature?: string
): CRMWebhookEvent {
  return {
    id: `custom-webhook-${Date.now()}`,
    crmProviderId: 'custom',
    eventType: data.event || data.type || 'unknown',
    objectType: data.object || data.entity || 'unknown',
    objectId: data.id?.toString(),
    timestamp: new Date(data.timestamp || Date.now()),
    data,
    signature,
  }
}

// No security middleware for webhooks as they come from external systems
// Validation is handled by each CRM service's signature verification
