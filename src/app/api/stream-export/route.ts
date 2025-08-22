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
  const ip = request.headers.get('x-forwarded-for') || 
             request.headers.get('x-real-ip') || 
             'unknown'

  try {
    // Rate limiting
    const rateLimitResult = await advancedRateLimitService.checkRateLimit(
      ip,
      'stream-export',
      { windowMs: 60000, maxRequests: 3 } // 3 exports per minute
    )

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded for streaming export',
          retryAfter: rateLimitResult.retryAfter
        },
        { status: 429 }
      )
    }

    // Parse request body
    const body = await request.json()
    const { businesses, format = 'csv', filename } = body

    // Validate inputs
    if (!businesses || !Array.isArray(businesses)) {
      return NextResponse.json(
        { error: 'Invalid businesses data' },
        { status: 400 }
      )
    }

    if (!['csv', 'json'].includes(format)) {
      return NextResponse.json(
        { error: 'Invalid format. Supported formats: csv, json' },
        { status: 400 }
      )
    }

    // Sanitize filename
    const sanitizedFilename = filename ? 
      validationService.sanitizeInput(filename) : 
      `businesses_export_${Date.now()}.${format}`

    logger.info('StreamExportAPI', `Starting streaming export: ${businesses.length} records as ${format}`)

    // Create streaming export
    const stream = format === 'csv' 
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
        message: 'Failed to create streaming export'
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
      name: `Sample Business ${i + 1}`,
      phone: `(555) 000-${String(i + 1).padStart(4, '0')}`,
      email: `contact${i + 1}@samplebusiness.com`,
      website: `https://samplebusiness${i + 1}.com`,
      address: `${i + 1} Sample Street`,
      city: 'Sample City',
      state: 'SC',
      zipCode: `${String(i + 1).padStart(5, '0')}`,
      industry: 'Sample Industry',
      description: `This is a sample business description for business ${i + 1}`,
      latitude: 40.7128 + (Math.random() - 0.5) * 0.1,
      longitude: -74.0060 + (Math.random() - 0.5) * 0.1,
      rating: Math.round((Math.random() * 4 + 1) * 10) / 10,
      reviewCount: Math.floor(Math.random() * 100),
      isVerified: Math.random() > 0.5,
      lastUpdated: new Date(),
      source: 'sample-data',
      socialMedia: {
        facebook: `https://facebook.com/samplebusiness${i + 1}`,
        twitter: `https://twitter.com/samplebiz${i + 1}`,
        linkedin: `https://linkedin.com/company/sample-business-${i + 1}`
      },
      businessHours: {
        monday: '9:00 AM - 5:00 PM',
        tuesday: '9:00 AM - 5:00 PM',
        wednesday: '9:00 AM - 5:00 PM',
        thursday: '9:00 AM - 5:00 PM',
        friday: '9:00 AM - 5:00 PM',
        saturday: 'Closed',
        sunday: 'Closed'
      }
    }))

    logger.info('StreamExportAPI', `Generating sample export: ${sampleSize} records as ${format}`)

    // Create streaming export for sample data
    const stream = format === 'csv' 
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
        message: 'Failed to generate sample export'
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
