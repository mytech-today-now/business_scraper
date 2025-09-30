/**
 * Server-Sent Events API for Real-time Search Results
 * Provides streaming search results with live updates
 */

import { NextRequest, NextResponse } from 'next/server'
import { streamingSearchService } from '@/lib/streamingSearchService'
import { logger } from '@/utils/logger'
import { validationService } from '@/utils/validation'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const query = searchParams.get('q')
    const location = searchParams.get('location') || ''
    const maxResults = parseInt(searchParams.get('maxResults') || '100')
    const batchSize = parseInt(searchParams.get('batchSize') || '10')

    // Get client IP for rate limiting
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    // Validate required parameters
    if (!query) {
      return NextResponse.json({ error: 'Query parameter "q" is required' }, { status: 400 })
    }

    // Sanitize inputs
    const sanitizedQuery = validationService.sanitizeInput(query)
    const sanitizedLocation = validationService.sanitizeInput(location)

    // Rate limiting - More permissive for streaming connections to allow retries
    const rateLimitResult = advancedRateLimitService.checkRateLimit(
      `stream-search:${ip}`,
      { windowMs: 60000, maxRequests: 30 } // 30 requests per minute for streaming
    )

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded for streaming search',
          retryAfter: rateLimitResult.retryAfter,
        },
        { status: 429 }
      )
    }

    logger.info(
      'StreamSearchAPI',
      `Starting streaming search for "${sanitizedQuery}" from IP: ${ip}`,
      {
        query: sanitizedQuery,
        location: sanitizedLocation,
        maxResults,
        batchSize,
        ip,
        userAgent: request.headers.get('user-agent'),
        timestamp: new Date().toISOString(),
      }
    )

    // Perform health check on streaming service with fallback
    let useStreamingMode = true
    try {
      const healthCheck = await streamingSearchService.healthCheck()
      if (!healthCheck.healthy) {
        logger.warn('StreamSearchAPI', 'Streaming service health check failed, will use fallback mode', healthCheck.details)
        useStreamingMode = false
      } else {
        logger.debug('StreamSearchAPI', 'Streaming service health check passed', healthCheck.details)
      }
    } catch (healthError) {
      logger.warn('StreamSearchAPI', 'Health check error, will use fallback mode', healthError)
      useStreamingMode = false
    }

    // If streaming is not available, redirect to batch search API
    if (!useStreamingMode) {
      logger.info('StreamSearchAPI', 'Redirecting to batch search API due to streaming unavailability')

      // Redirect to the regular search API with appropriate parameters
      const baseUrl = new URL(request.url).origin
      const searchUrl = new URL('/api/search', baseUrl)
      searchUrl.searchParams.set('q', sanitizedQuery)
      searchUrl.searchParams.set('location', sanitizedLocation)
      searchUrl.searchParams.set('maxResults', maxResults.toString())

      const redirectResponse = NextResponse.redirect(searchUrl.toString(), 302)
      logger.debug('StreamSearchAPI', `Redirecting to: ${searchUrl.toString()}`)
      return redirectResponse
    }

    // Create Server-Sent Events stream
    const stream = new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder()

        try {
          // Send initial connection event with diagnostics
          const sessionId = `stream-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
          const connectionEvent = `data: ${JSON.stringify({
            type: 'connected',
            message: 'Streaming search started',
            timestamp: Date.now(),
            sessionId,
            diagnostics: {
              query: sanitizedQuery,
              location: sanitizedLocation,
              maxResults,
              batchSize,
              serverTime: new Date().toISOString(),
            },
          })}\n\n`

          controller.enqueue(encoder.encode(connectionEvent))
          logger.info('StreamSearchAPI', `Streaming connection established for query: "${sanitizedQuery}"`, {
            sessionId,
            connectionEstablished: true,
          })
        } catch (error) {
          logger.error('StreamSearchAPI', 'Failed to send initial connection event', error)
          try {
            const errorEvent = `data: ${JSON.stringify({
              type: 'error',
              error: 'Failed to establish connection',
              timestamp: Date.now(),
              recoverable: false,
            })}\n\n`
            controller.enqueue(encoder.encode(errorEvent))
          } catch (secondaryError) {
            logger.error('StreamSearchAPI', 'Failed to send connection error event', secondaryError)
          }
          controller.close()
          return
        }

        // Start streaming search with enhanced error handling
        try {
          streamingSearchService
            .processStreamingSearch(
              sanitizedQuery,
              sanitizedLocation,

              // onResult callback
              business => {
                try {
                  if (!business) {
                    logger.warn('StreamSearchAPI', 'Received null/undefined business result')
                    return
                  }

                  const resultEvent = `data: ${JSON.stringify({
                    type: 'result',
                    data: business,
                    timestamp: Date.now(),
                  })}\n\n`

                  controller.enqueue(encoder.encode(resultEvent))
                  logger.debug('StreamSearchAPI', `Sent business result: ${business.businessName || 'Unknown'}`)
                } catch (error) {
                  logger.error('StreamSearchAPI', 'Failed to send result event', error)
                  // Don't close the stream for individual result errors
                }
              },

            // onProgress callback
            progress => {
              try {
                if (!progress) {
                  logger.warn('StreamSearchAPI', 'Received null/undefined progress update')
                  return
                }

                const progressEvent = `data: ${JSON.stringify({
                  type: 'progress',
                  data: progress,
                  timestamp: Date.now(),
                })}\n\n`

                controller.enqueue(encoder.encode(progressEvent))
                logger.debug('StreamSearchAPI', `Sent progress update: ${progress.processed || 0}/${progress.totalFound || 0}`)
              } catch (error) {
                logger.error('StreamSearchAPI', 'Failed to send progress event', error)
                // Don't close the stream for progress errors
              }
            },

            // onComplete callback
            totalResults => {
              try {
                const completeEvent = `data: ${JSON.stringify({
                  type: 'complete',
                  data: { totalResults: totalResults || 0 },
                  message: `Search completed with ${totalResults || 0} results`,
                  timestamp: Date.now(),
                })}\n\n`

                controller.enqueue(encoder.encode(completeEvent))
                logger.info('StreamSearchAPI', `Streaming search completed with ${totalResults || 0} results`)
                controller.close()
              } catch (error) {
                logger.error('StreamSearchAPI', 'Failed to send complete event', error)
                controller.close()
              }
            },

            // onError callback
            error => {
              try {
                const errorMessage = error || 'Unknown streaming error'
                const errorEvent = `data: ${JSON.stringify({
                  type: 'error',
                  error: errorMessage,
                  timestamp: Date.now(),
                  recoverable: true, // Indicate if client should retry
                })}\n\n`

                controller.enqueue(encoder.encode(errorEvent))
                logger.error('StreamSearchAPI', `Streaming search error: ${errorMessage}`)
                controller.close()
              } catch (err) {
                logger.error('StreamSearchAPI', 'Failed to send error event', err)
                controller.close()
              }
            },

            // Search options
            {
              maxResults,
              batchSize,
              delayBetweenBatches: 200,
              enableRealTimeUpdates: true,
            }
          )
        } catch (streamingError) {
          logger.error('StreamSearchAPI', 'Failed to start streaming search', streamingError)

          try {
            const errorEvent = `data: ${JSON.stringify({
              type: 'error',
              error: 'Failed to start streaming search',
              timestamp: Date.now(),
              recoverable: false,
            })}\n\n`

            controller.enqueue(encoder.encode(errorEvent))
          } catch (err) {
            logger.error('StreamSearchAPI', 'Failed to send streaming error event', err)
          } finally {
            controller.close()
          }
        }
      },

      cancel() {
        logger.info('StreamSearchAPI', 'Client disconnected from streaming search')
        // Stop the streaming search if client disconnects
        streamingSearchService.stopAllStreams()
      },
    })

    // Return Server-Sent Events response
    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Headers': 'Cache-Control',
      },
    })
  } catch (error) {
    logger.error('StreamSearchAPI', 'Streaming search API error', error)

    return NextResponse.json(
      {
        error: 'Internal server error',
        message: 'Failed to start streaming search',
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
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Cache-Control',
    },
  })
}
