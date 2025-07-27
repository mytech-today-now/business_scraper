import { NextRequest, NextResponse } from 'next/server'
import { scraperService } from '@/model/scraperService'
import { sanitizeInput, validateInput, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

export async function POST(request: NextRequest) {
  const ip = getClientIP(request)

  try {
    logger.info('Scrape API', `POST request received from IP: ${ip}`)

    const body = await request.json()
    const { action, ...params } = body

    logger.info('Scrape API', `Request body: ${JSON.stringify({ action, ...Object.keys(params) })}`)

    // Validate action parameter
    if (!action || typeof action !== 'string') {
      logger.warn('Scrape API', `Invalid action parameter from IP: ${ip}`)
      return NextResponse.json({ error: 'Action parameter is required' }, { status: 400 })
    }

    // Sanitize action
    const sanitizedAction = sanitizeInput(action)

    // Validate action against allowed values
    const allowedActions = ['initialize', 'search', 'scrape', 'cleanup']
    if (!allowedActions.includes(sanitizedAction)) {
      logger.warn('Scrape API', `Invalid action '${sanitizedAction}' from IP: ${ip}`)
      return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }

    logger.info('Scrape API', `Action '${sanitizedAction}' requested from IP: ${ip}`)

    switch (sanitizedAction) {
      case 'initialize':
        await scraperService.initialize()
        return NextResponse.json({ success: true })

      case 'search':
        const { query, zipCode, maxResults } = params

        // Validate and sanitize search parameters
        if (!query || typeof query !== 'string') {
          return NextResponse.json({ error: 'Query parameter is required' }, { status: 400 })
        }

        const sanitizedQuery = sanitizeInput(query)
        const queryValidation = validateInput(sanitizedQuery)

        if (!queryValidation.isValid) {
          logger.warn('Scrape API', `Invalid query from IP: ${ip} - ${queryValidation.errors.join(', ')}`)
          return NextResponse.json({ error: 'Invalid query format' }, { status: 400 })
        }

        // Validate zipCode if provided
        let sanitizedZipCode = ''
        if (zipCode) {
          sanitizedZipCode = sanitizeInput(String(zipCode))
          if (!/^\d{5}(-\d{4})?$/.test(sanitizedZipCode)) {
            return NextResponse.json({ error: 'Invalid zip code format' }, { status: 400 })
          }
        }

        // Parse maxResults (no upper limit - gather as many as possible)
        const numMaxResults = Math.max(parseInt(maxResults) || 1000, 1)

        const urls = await scraperService.searchForWebsites(sanitizedQuery, sanitizedZipCode, numMaxResults)
        return NextResponse.json({ urls: urls || [] })

      case 'scrape':
        const { url, depth, maxPages } = params

        logger.info('Scrape API', `Scrape request for URL: ${url}`)

        // Validate URL
        if (!url || typeof url !== 'string') {
          logger.warn('Scrape API', `Missing URL parameter from IP: ${ip}`)
          return NextResponse.json({ error: 'URL parameter is required' }, { status: 400 })
        }

        const sanitizedUrl = sanitizeInput(url)

        // Basic URL validation
        try {
          new URL(sanitizedUrl)
        } catch {
          logger.warn('Scrape API', `Invalid URL format: ${sanitizedUrl} from IP: ${ip}`)
          return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 })
        }

        // Validate depth and maxPages
        const numDepth = Math.min(Math.max(parseInt(depth) || 1, 1), 5)
        const numMaxPages = Math.min(Math.max(parseInt(maxPages) || 5, 1), 20)

        logger.info('Scrape API', `Starting scrape for ${sanitizedUrl} with depth ${numDepth}, maxPages ${numMaxPages}`)

        try {
          const businesses = await scraperService.scrapeWebsite(sanitizedUrl, numDepth, numMaxPages)
          logger.info('Scrape API', `Scrape completed for ${sanitizedUrl}, found ${businesses.length} businesses`)
          return NextResponse.json({ businesses })
        } catch (scrapeError) {
          logger.error('Scrape API', `Scraping failed for ${sanitizedUrl}`, scrapeError)
          return NextResponse.json({
            error: 'Scraping failed',
            message: scrapeError instanceof Error ? scrapeError.message : 'Unknown scraping error',
            businesses: [] // Return empty array as fallback
          }, { status: 500 })
        }

      case 'cleanup':
        await scraperService.cleanup()
        return NextResponse.json({ success: true })

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }
  } catch (error) {
    logger.error('Scrape API', `Error processing request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

// Add GET endpoint for testing
export async function GET() {
  return NextResponse.json({
    status: 'Scrape API is working',
    timestamp: new Date().toISOString(),
    availableActions: ['initialize', 'search', 'scrape', 'cleanup']
  })
}
