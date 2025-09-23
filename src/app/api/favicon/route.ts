/**
 * Favicon API Route Handler
 * Provides fallback favicon handling with comprehensive error management
 * Ensures favicon requests never result in 500 errors
 */

import { NextRequest, NextResponse } from 'next/server'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { logger } from '@/utils/logger'

/**
 * GET /api/favicon - Fallback favicon handler
 * Serves favicon.ico with proper error handling and fallback mechanisms
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Try to serve the actual favicon.ico from public directory
    const faviconPath = join(process.cwd(), 'public', 'favicon.ico')
    
    try {
      const faviconBuffer = await readFile(faviconPath)
      
      return new NextResponse(faviconBuffer, {
        status: 200,
        headers: {
          'Content-Type': 'image/x-icon',
          'Cache-Control': 'public, max-age=86400, immutable', // Cache for 24 hours
          'Content-Length': faviconBuffer.length.toString(),
          'X-Favicon-Source': 'public-directory',
        },
      })
    } catch (fileError) {
      // If favicon.ico is not found, try favicon.png
      logger.warn('Favicon', 'favicon.ico not found, trying favicon.png fallback', {
        error: fileError instanceof Error ? fileError.message : 'Unknown error',
        path: faviconPath,
      })
      
      const faviconPngPath = join(process.cwd(), 'public', 'favicon.png')
      
      try {
        const faviconPngBuffer = await readFile(faviconPngPath)
        
        return new NextResponse(faviconPngBuffer, {
          status: 200,
          headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=86400, immutable',
            'Content-Length': faviconPngBuffer.length.toString(),
            'X-Favicon-Source': 'png-fallback',
          },
        })
      } catch (pngError) {
        // If both files are missing, generate a minimal favicon
        logger.warn('Favicon', 'Both favicon.ico and favicon.png not found, generating minimal fallback', {
          icoError: fileError instanceof Error ? fileError.message : 'Unknown error',
          pngError: pngError instanceof Error ? pngError.message : 'Unknown error',
        })
        
        // Generate a minimal 16x16 transparent ICO file
        const minimalIco = generateMinimalFavicon()
        
        return new NextResponse(minimalIco, {
          status: 200,
          headers: {
            'Content-Type': 'image/x-icon',
            'Cache-Control': 'public, max-age=3600', // Shorter cache for fallback
            'Content-Length': minimalIco.length.toString(),
            'X-Favicon-Source': 'generated-fallback',
          },
        })
      }
    }
  } catch (error) {
    // Final fallback - return a 204 No Content instead of 500 error
    logger.error('Favicon', 'Critical error in favicon handler', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    })
    
    return new NextResponse(null, {
      status: 204, // No Content - prevents browser errors
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Favicon-Source': 'error-fallback',
      },
    })
  }
}

/**
 * HEAD /api/favicon - Handle HEAD requests for favicon
 */
export async function HEAD(request: NextRequest): Promise<NextResponse> {
  try {
    const response = await GET(request)
    
    return new NextResponse(null, {
      status: response.status,
      headers: response.headers,
    })
  } catch (error) {
    logger.error('Favicon', 'Error in favicon HEAD request', {
      error: error instanceof Error ? error.message : 'Unknown error',
    })
    
    return new NextResponse(null, {
      status: 204,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Favicon-Source': 'head-error-fallback',
      },
    })
  }
}

/**
 * Generate a minimal 16x16 transparent favicon in ICO format
 * This is a last resort fallback when no favicon files are available
 */
function generateMinimalFavicon(): Buffer {
  // Minimal ICO file structure for 16x16 transparent icon
  // ICO header (6 bytes) + Directory entry (16 bytes) + PNG data
  const icoHeader = Buffer.from([
    0x00, 0x00, // Reserved (must be 0)
    0x01, 0x00, // Type (1 = ICO)
    0x01, 0x00, // Number of images
  ])
  
  // Directory entry for 16x16 image
  const directoryEntry = Buffer.from([
    0x10, // Width (16)
    0x10, // Height (16)
    0x00, // Color palette (0 = no palette)
    0x00, // Reserved
    0x01, 0x00, // Color planes
    0x20, 0x00, // Bits per pixel (32)
    0x68, 0x00, 0x00, 0x00, // Size of image data (104 bytes)
    0x16, 0x00, 0x00, 0x00, // Offset to image data (22 bytes)
  ])
  
  // Minimal PNG data for 16x16 transparent image
  const pngData = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, // 16x16 dimensions
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, // RGBA, no compression
    0x61, 0x00, 0x00, 0x00, 0x0B, 0x49, 0x44, 0x41, // IDAT chunk start
    0x54, 0x78, 0x9C, 0x63, 0x60, 0x00, 0x02, 0x00, // Compressed transparent data
    0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, // End of IDAT
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
    0xAE, 0x42, 0x60, 0x82, // PNG end
  ])
  
  return Buffer.concat([icoHeader, directoryEntry, pngData])
}

/**
 * OPTIONS /api/favicon - Handle CORS preflight requests
 */
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Cache-Control': 'public, max-age=86400',
    },
  })
}
