/**
 * Ping Endpoint for Network Connectivity Testing
 * Business Scraper Application - Simple Health Check
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * Simple ping response interface
 */
interface PingResponse {
  status: 'ok'
  timestamp: string
  server: string
  responseTime: number
}

/**
 * GET /api/ping - Simple connectivity test endpoint
 * Used by useOfflineSupport hook and other monitoring tools
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  const ip = getClientIP(request)
  
  try {
    const response: PingResponse = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      server: 'business-scraper',
      responseTime: Date.now() - startTime,
    }

    logger.debug('Ping', `Ping request from IP: ${ip}`, {
      responseTime: response.responseTime,
      userAgent: request.headers.get('user-agent'),
    })

    return NextResponse.json(response, {
      status: 200,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
      },
    })
  } catch (error) {
    logger.error('Ping', 'Error processing ping request', {
      error: error instanceof Error ? error.message : 'Unknown error',
      ip,
    })

    return NextResponse.json(
      {
        status: 'error',
        timestamp: new Date().toISOString(),
        error: 'Internal server error',
      },
      { status: 500 }
    )
  }
}

/**
 * HEAD /api/ping - Lightweight connectivity test
 * Used for quick connectivity checks without response body
 */
export async function HEAD(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    logger.debug('Ping', `HEAD ping request from IP: ${ip}`)

    return new NextResponse(null, {
      status: 200,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
      },
    })
  } catch (error) {
    logger.error('Ping', 'Error processing HEAD ping request', {
      error: error instanceof Error ? error.message : 'Unknown error',
      ip,
    })

    return new NextResponse(null, { status: 500 })
  }
}

/**
 * OPTIONS /api/ping - CORS preflight support
 */
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  })
}

/**
 * Reject other HTTP methods
 */
export async function POST(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}

export async function PUT(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}

export async function DELETE(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}

export async function PATCH(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}
