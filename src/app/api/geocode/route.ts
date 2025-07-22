import { NextRequest, NextResponse } from 'next/server'
import { geocoder } from '@/model/geocoder'

export async function POST(request: NextRequest) {
  try {
    const { address } = await request.json()
    
    if (!address) {
      return NextResponse.json({ error: 'Address is required' }, { status: 400 })
    }

    const result = await geocoder.geocodeAddress(address)
    return NextResponse.json({ result })
  } catch (error) {
    console.error('Geocoding API error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
