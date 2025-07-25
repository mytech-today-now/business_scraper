import { NextRequest, NextResponse } from 'next/server'
import { geocoder } from '@/model/geocoder'
import { sanitizeInput, validateInput, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

export async function POST(request: NextRequest) {
  const ip = getClientIP(request)

  try {
    const { address } = await request.json()

    // Validate address parameter
    if (!address || typeof address !== 'string') {
      logger.warn('Geocode API', `Missing or invalid address parameter from IP: ${ip}`)
      return NextResponse.json({ error: 'Address is required and must be a string' }, { status: 400 })
    }

    // Sanitize and validate address
    const sanitizedAddress = sanitizeInput(address)
    const addressValidation = validateInput(sanitizedAddress)

    if (!addressValidation.isValid) {
      logger.warn('Geocode API', `Invalid address format from IP: ${ip} - ${addressValidation.errors.join(', ')}`)
      return NextResponse.json({ error: 'Invalid address format' }, { status: 400 })
    }

    // Check address length
    if (sanitizedAddress.length < 3 || sanitizedAddress.length > 500) {
      return NextResponse.json({ error: 'Address must be between 3 and 500 characters' }, { status: 400 })
    }

    logger.info('Geocode API', `Geocoding request from IP: ${ip} for address: ${sanitizedAddress.substring(0, 50)}...`)

    const result = await geocoder.geocodeAddress(sanitizedAddress)
    return NextResponse.json({ result })

  } catch (error) {
    logger.error('Geocode API', `Error processing request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
