/**
 * CRM Integration API Endpoint
 * Manages CRM provider configurations and sync operations
 */

import { NextRequest, NextResponse } from 'next/server'
import { crmServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { CRMProvider } from '@/types/crm'
import { logger } from '@/utils/logger'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { getClientIP } from '@/lib/security'

/**
 * GET /api/crm - Get all CRM providers and their status
 */
async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_API', `Get CRM providers request from IP: ${ip}`)

    // Get all providers and their status
    const providers = crmServiceRegistry.getAllProviders()
    const connectionTests = await crmServiceRegistry.testAllConnections()
    const statistics = crmServiceRegistry.getStatistics()

    const providersWithStatus = providers.map(provider => ({
      ...provider,
      isConnected: connectionTests[provider.id] || false,
      lastTested: new Date().toISOString(),
    }))

    return NextResponse.json({
      success: true,
      data: {
        providers: providersWithStatus,
        statistics,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('CRM_API', 'Failed to get CRM providers', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to retrieve CRM providers',
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/crm - Create or register a new CRM provider
 */
async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_API', `Create CRM provider request from IP: ${ip}`)

    const body = await request.json()

    // Validate required fields
    if (!body.name || !body.type || !body.configuration) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields: name, type, configuration',
        },
        { status: 400 }
      )
    }

    // Create provider object
    const provider: CRMProvider = {
      id: `crm-${body.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: body.name,
      type: body.type,
      version: body.version || '1.0.0',
      isActive: body.isActive !== false, // Default to true
      configuration: body.configuration,
      capabilities: body.capabilities || {
        bidirectionalSync: false,
        realTimeUpdates: false,
        bulkOperations: false,
        customFields: false,
        webhookSupport: false,
        deduplication: false,
        validation: false,
      },
    }

    // Register the provider
    await crmServiceRegistry.registerProvider(provider)

    // Test connection
    const isConnected = await crmServiceRegistry.testConnection(provider.id)

    logger.info('CRM_API', `CRM provider created successfully: ${provider.name}`, {
      providerId: provider.id,
      type: provider.type,
      isConnected,
    })

    return NextResponse.json(
      {
        success: true,
        data: {
          provider: {
            ...provider,
            isConnected,
          },
        },
        message: 'CRM provider created successfully',
      },
      { status: 201 }
    )
  } catch (error) {
    logger.error('CRM_API', 'Failed to create CRM provider', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create CRM provider',
      },
      { status: 500 }
    )
  }
}

/**
 * PUT /api/crm - Update an existing CRM provider
 */
async function PUT(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_API', `Update CRM provider request from IP: ${ip}`)

    const body = await request.json()

    if (!body.id) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider ID is required',
        },
        { status: 400 }
      )
    }

    // Update the provider
    await crmServiceRegistry.updateProvider(body.id, body)

    // Test connection after update
    const isConnected = await crmServiceRegistry.testConnection(body.id)
    const updatedProvider = crmServiceRegistry.getProvider(body.id)

    logger.info('CRM_API', `CRM provider updated successfully: ${body.id}`)

    return NextResponse.json({
      success: true,
      data: {
        provider: {
          ...updatedProvider,
          isConnected,
        },
      },
      message: 'CRM provider updated successfully',
    })
  } catch (error) {
    logger.error('CRM_API', 'Failed to update CRM provider', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update CRM provider',
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/crm - Remove a CRM provider
 */
async function DELETE(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_API', `Delete CRM provider request from IP: ${ip}`)

    const url = new URL(request.url)
    const providerId = url.searchParams.get('id')

    if (!providerId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider ID is required',
        },
        { status: 400 }
      )
    }

    // Get provider info before deletion
    const provider = crmServiceRegistry.getProvider(providerId)
    if (!provider) {
      return NextResponse.json(
        {
          success: false,
          error: 'Provider not found',
        },
        { status: 404 }
      )
    }

    // Unregister the provider
    await crmServiceRegistry.unregisterProvider(providerId)

    logger.info('CRM_API', `CRM provider deleted successfully: ${provider.name}`)

    return NextResponse.json({
      success: true,
      message: 'CRM provider deleted successfully',
    })
  } catch (error) {
    logger.error('CRM_API', 'Failed to delete CRM provider', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to delete CRM provider',
      },
      { status: 500 }
    )
  }
}

// Apply security middleware
const securedGET = withApiSecurity(GET, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

const securedPOST = withApiSecurity(POST, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

const securedPUT = withApiSecurity(PUT, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

const securedDELETE = withApiSecurity(DELETE, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

export { securedGET as GET, securedPOST as POST, securedPUT as PUT, securedDELETE as DELETE }
