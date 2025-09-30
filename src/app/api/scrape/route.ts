import { NextRequest, NextResponse } from 'next/server'
import { scraperService } from '@/model/scraperService'
import { sanitizeInput, validateInput, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import { metrics } from '@/lib/metrics'
import {
  ScrapingComplianceMiddleware,
  ScrapingOperation,
  ScrapingComplianceUtils,
} from '@/lib/compliance/scraper-middleware'

/**
 * Interface for scrape request data
 */
interface ScrapeRequestData {
  body: {
    action: 'initialize' | 'search' | 'scrape' | 'cleanup'
    query?: string
    zipCode?: string
    maxResults?: number
    url?: string
    depth?: number
    maxPages?: number
    sessionId?: string
  }
}

// Temporarily simplified handler to debug validation issues
const scrapeHandler = async (request: NextRequest) => {
  const ip = getClientIP(request)
  const startTime = Date.now()

  try {
    // Initialize metrics
    await metrics.initialize()

    const body = await request.json()
    const { action, ...params } = body

    logger.info('Scrape API', `POST request received from IP: ${ip}`, { action })

    try {
      logger.info(
        'Scrape API',
        `Request body: ${JSON.stringify({ action, ...Object.keys(params) })}`
      )

      // Track start time for compliance logging
      const startTime = Date.now()

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

      // Extract session ID if provided
      const { sessionId } = params
      if (sessionId && typeof sessionId === 'string') {
        scraperService.setSessionId(sessionId)
      }

      // Create compliance context
      const complianceContext = ScrapingComplianceUtils.createContext(
        sanitizedAction as ScrapingOperation,
        request,
        {
          sessionId,
          query: params.query,
          url: params.url,
          zipCode: params.zipCode,
        }
      )

      // Validate consent for scraping operations
      if (['search', 'scrape'].includes(sanitizedAction)) {
        const consentValidation =
          await ScrapingComplianceMiddleware.validateConsent(complianceContext)
        if (!consentValidation.allowed) {
          logger.warn('Scrape API', `Consent validation failed for ${sanitizedAction}`, {
            missingConsents: consentValidation.missingConsents,
            sessionId,
          })
          return NextResponse.json(
            {
              error: 'Consent required',
              missingConsents: consentValidation.missingConsents,
              message: consentValidation.message,
            },
            { status: 403 }
          )
        }
      }

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
            logger.warn(
              'Scrape API',
              `Invalid query from IP: ${ip} - ${queryValidation.errors.join(', ')}`
            )
            return NextResponse.json({ error: 'Invalid query format' }, { status: 400 })
          }

          // Validate zipCode if provided
          let sanitizedZipCode = ''
          if (zipCode) {
            sanitizedZipCode = sanitizeInput(String(zipCode))
            // Use a safer regex pattern to prevent ReDoS attacks
            if (!/^[0-9]{5}(?:-[0-9]{4})?$/.test(sanitizedZipCode)) {
              return NextResponse.json({ error: 'Invalid zip code format' }, { status: 400 })
            }
          }

          // Parse maxResults (no upper limit - gather as many as possible)
          const numMaxResults = Math.max(parseInt(maxResults) || 1000, 1)

          try {
            const urls = await scraperService.searchForWebsites(
              sanitizedQuery,
              sanitizedZipCode,
              numMaxResults
            )

            // Log successful search operation
            await ScrapingComplianceMiddleware.logScrapingOperation(complianceContext, {
              success: true,
              recordsFound: urls?.length || 0,
              duration: Date.now() - startTime,
            })

            return NextResponse.json({ urls: urls || [] })
          } catch (searchError) {
            // Log failed search operation
            await ScrapingComplianceMiddleware.logScrapingOperation(complianceContext, {
              success: false,
              error: searchError instanceof Error ? searchError.message : 'Search failed',
              duration: Date.now() - startTime,
            })
            throw searchError
          }

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

          // Check scraping permissions
          const permissionCheck = await ScrapingComplianceMiddleware.checkScrapingPermissions(
            sanitizedUrl,
            complianceContext
          )
          if (!permissionCheck.allowed) {
            logger.warn(
              'Scrape API',
              `Scraping not allowed for ${sanitizedUrl}: ${permissionCheck.reason}`
            )
            return NextResponse.json(
              {
                error: 'Scraping not allowed',
                reason: permissionCheck.reason,
              },
              { status: 403 }
            )
          }

          logger.info(
            'Scrape API',
            `Starting scrape for ${sanitizedUrl} with depth ${numDepth}, maxPages ${numMaxPages}`
          )

          const scrapeStartTime = Date.now()
          try {
            const businesses = await scraperService.scrapeWebsite(
              sanitizedUrl,
              numDepth,
              numMaxPages
            )
            const scrapeDuration = (Date.now() - scrapeStartTime) / 1000

            // Record scraping metrics
            metrics.scrapingDuration.observe(
              { url: sanitizedUrl, strategy: 'website', status: 'success' },
              scrapeDuration
            )
            metrics.scrapingTotal.inc({ strategy: 'website', status: 'success' })
            metrics.businessesFound.inc(
              { strategy: 'website', industry: 'unknown' },
              businesses.length
            )

            // Log successful scrape operation
            await ScrapingComplianceMiddleware.logScrapingOperation(complianceContext, {
              success: true,
              recordsFound: businesses.length,
              duration: Date.now() - startTime,
            })

            logger.info(
              'Scrape API',
              `Scrape completed for ${sanitizedUrl}, found ${businesses.length} businesses`
            )
            return NextResponse.json({ businesses })
          } catch (scrapeError) {
            const scrapeDuration = (Date.now() - scrapeStartTime) / 1000

            // Record error metrics
            metrics.scrapingDuration.observe(
              { url: sanitizedUrl, strategy: 'website', status: 'error' },
              scrapeDuration
            )
            metrics.scrapingTotal.inc({ strategy: 'website', status: 'error' })
            metrics.scrapingErrors.inc({
              strategy: 'website',
              error_type: scrapeError instanceof Error ? scrapeError.name : 'unknown',
            })

            // Log failed scrape operation
            await ScrapingComplianceMiddleware.logScrapingOperation(complianceContext, {
              success: false,
              error: scrapeError instanceof Error ? scrapeError.message : 'Unknown scraping error',
              duration: Date.now() - startTime,
            })

            logger.error('Scrape API', `Scraping failed for ${sanitizedUrl}`, scrapeError)
            return NextResponse.json(
              {
                error: 'Scraping failed',
                message:
                  scrapeError instanceof Error ? scrapeError.message : 'Unknown scraping error',
                businesses: [], // Return empty array as fallback
              },
              { status: 500 }
            )
          }

        case 'cleanup':
          await scraperService.cleanup()
          return NextResponse.json({ success: true })

        default:
          return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
      }
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000

      // Record error metrics
      metrics.httpRequestDuration.observe(
        { method: 'POST', route: '/api/scrape', status_code: '500' },
        duration
      )
      metrics.httpRequestTotal.inc({ method: 'POST', route: '/api/scrape', status_code: '500' })
      metrics.httpRequestErrors.inc({
        method: 'POST',
        route: '/api/scrape',
        error_type: 'server_error',
      })

      logger.error('Scrape API', `Error processing request from IP: ${ip}`, error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
  } catch (parseError) {
    const duration = (Date.now() - startTime) / 1000

    // Record parsing error metrics
    metrics.httpRequestDuration.observe(
      { method: 'POST', route: '/api/scrape', status_code: '400' },
      duration
    )
    metrics.httpRequestTotal.inc({ method: 'POST', route: '/api/scrape', status_code: '400' })
    metrics.httpRequestErrors.inc({
      method: 'POST',
      route: '/api/scrape',
      error_type: 'client_error',
    })

    logger.error('Scrape API', `JSON parsing error from IP: ${ip}`, parseError)
    return NextResponse.json({ error: 'Invalid JSON in request body' }, { status: 400 })
  } finally {
    // Record successful request metrics
    const duration = (Date.now() - startTime) / 1000
    metrics.httpRequestDuration.observe(
      { method: 'POST', route: '/api/scrape', status_code: '200' },
      duration
    )
    metrics.httpRequestTotal.inc({ method: 'POST', route: '/api/scrape', status_code: '200' })
  }
}

export const POST = scrapeHandler

// Add GET endpoint for testing
export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    status: 'Scrape API is working',
    timestamp: new Date().toISOString(),
    availableActions: ['initialize', 'search', 'scrape', 'cleanup'],
  })
}
