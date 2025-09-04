import { NextRequest, NextResponse } from 'next/server'

/**
 * Fallback image handler for missing images
 * Returns a 1x1 transparent PNG when images are not found
 */
export async function GET(request: NextRequest) {
  try {
    // 1x1 transparent PNG in base64
    const transparentPng = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jU77zgAAAABJRU5ErkJggg==',
      'base64'
    )

    return new NextResponse(transparentPng, {
      status: 200,
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=3600',
        'Content-Length': transparentPng.length.toString(),
      },
    })
  } catch (error) {
    console.error('Fallback image error:', error)
    
    return new NextResponse('Image not found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain',
      },
    })
  }
}

/**
 * Handle HEAD requests for fallback images
 */
export async function HEAD(request: NextRequest) {
  const response = await GET(request)
  
  return new NextResponse(null, {
    status: response.status,
    headers: response.headers,
  })
}
