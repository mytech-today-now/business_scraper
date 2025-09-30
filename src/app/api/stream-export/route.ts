/**
 * Streaming Export API
 * Memory-efficient export of large business datasets
 */

import { NextRequest, NextResponse } from 'next/server'
import { streamingExportService } from '@/lib/streamingExportService'
import { logger } from '@/utils/logger'
import { validationService } from '@/utils/validation'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { BusinessRecord } from '@/types/business'

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'

  try {
    // Rate limiting
    const rateLimitResult = advancedRateLimitService.checkRateLimit(
      `stream-export:${ip}`,
      { windowMs: 60000, maxRequests: 3 } // 3 exports per minute
    )

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded for streaming export',
          retryAfter: rateLimitResult.retryAfter,
        },
        { status: 429 }
      )
    }

    // Parse request body
    const body = await request.json()
    const { businesses, format = 'csv', filename } = body

    // Validate inputs
    if (!businesses || !Array.isArray(businesses)) {
      return NextResponse.json({ error: 'Invalid businesses data' }, { status: 400 })
    }

    if (!['csv', 'json'].includes(format)) {
      return NextResponse.json(
        { error: 'Invalid format. Supported formats: csv, json' },
        { status: 400 }
      )
    }

    // Sanitize filename
    const sanitizedFilename = filename
      ? validationService.sanitizeInput(filename)
      : `businesses_export_${Date.now()}.${format}`

    logger.info(
      'StreamExportAPI',
      `Starting streaming export: ${businesses.length} records as ${format}`
    )

    // Create streaming export
    const stream =
      format === 'csv'
        ? streamingExportService.createStreamingCSV(businesses as BusinessRecord[])
        : streamingExportService.createStreamingJSON(businesses as BusinessRecord[])

    // Set appropriate headers
    const headers = new Headers({
      'Content-Type': format === 'csv' ? 'text/csv' : 'application/json',
      'Content-Disposition': `attachment; filename="${sanitizedFilename}"`,
      'Cache-Control': 'no-cache',
      'Transfer-Encoding': 'chunked',
    })

    return new Response(stream, { headers })
  } catch (error) {
    logger.error('StreamExportAPI', 'Streaming export error', error)

    return NextResponse.json(
      {
        error: 'Internal server error',
        message: 'Failed to create streaming export',
      },
      { status: 500 }
    )
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const format = searchParams.get('format') || 'csv'
  const sampleSize = parseInt(searchParams.get('sampleSize') || '100')

  try {
    // Generate sample data for testing
    const sampleBusinesses: BusinessRecord[] = Array.from({ length: sampleSize }, (_, i) => ({
      id: `sample-${i + 1}`,
      businessName: `Sample Business ${i + 1}`,
      email: [`contact${i + 1}@samplebusiness.com`],
      phone: `(555) 000-${String(i + 1).padStart(4, '0')}`,
      websiteUrl: `https://samplebusiness${i + 1}.com`,
      address: {
        street: `${i + 1} Sample Street`,
        city: 'Sample City',
        state: 'SC',
        zipCode: `${String(i + 1).padStart(5, '0')}`,
      },
      contactPerson: `Contact Person ${i + 1}`,
      coordinates: {
        lat: 40.7128 + (Math.random() - 0.5) * 0.1,
        lng: -74.006 + (Math.random() - 0.5) * 0.1,
      },
      industry: 'Sample Industry',
      scrapedAt: new Date(),
    }))

    logger.info('StreamExportAPI', `Generating sample export: ${sampleSize} records as ${format}`)

    // Create streaming export for sample data
    const stream =
      format === 'csv'
        ? streamingExportService.createStreamingCSV(sampleBusinesses)
        : streamingExportService.createStreamingJSON(sampleBusinesses)

    const filename = `sample_businesses_${sampleSize}.${format}`

    const headers = new Headers({
      'Content-Type': format === 'csv' ? 'text/csv' : 'application/json',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-cache',
      'Transfer-Encoding': 'chunked',
    })

    return new Response(stream, { headers })
  } catch (error) {
    logger.error('StreamExportAPI', 'Sample export error', error)

    return NextResponse.json(
      {
        error: 'Internal server error',
        message: 'Failed to generate sample export',
      },
      { status: 500 }
    )
  }
}

export async function OPTIONS(request: NextRequest) {
  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}
