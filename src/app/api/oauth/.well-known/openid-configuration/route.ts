/**
 * OAuth 2.0 / OpenID Connect Discovery Endpoint
 * Provides server metadata for client configuration
 */

import { NextResponse } from 'next/server'
import { discoveryDocument } from '@/lib/oauth/config'

/**
 * GET /api/oauth/.well-known/openid-configuration - Discovery endpoint
 */
export async function GET(): Promise<NextResponse> {
  return NextResponse.json(discoveryDocument, {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
    },
  })
}
