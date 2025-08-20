/**
 * Server-Sent Events API for Real-time Search Results
 * Provides streaming search results with live updates
 */

import { NextRequest, NextResponse } from 'next/server'
import { streamingSearchService } from '@/lib/streamingSearchService'
import { logger } from '@/utils/logger'
import { validationService } from '@/lib/validation-middleware'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const query = searchParams.get('q')
  const location = searchParams.get('location') || ''
  const maxResults = parseInt(searchParams.get('maxResults') || '100')
  const batchSize = parseInt(searchParams.get('batchSize') || '10')
  
  // Get client IP for rate limiting
  const ip = request.headers.get('x-forwarded-for') || 
             request.headers.get('x-real-ip') || 
             'unknown'

  try {
    // Validate required parameters
    if (!query) {
      return NextResponse.json(
        { error: 'Query parameter "q" is required' },
        { status: 400 }
      )
    }

    // Sanitize inputs
    const sanitizedQuery = validationService.sanitizeInput(query)
    const sanitizedLocation = validationService.sanitizeInput(location)

    // Rate limiting
    const rateLimitResult = await advancedRateLimitService.checkRateLimit(
      ip,
      'stream-search',
      { windowMs: 60000, maxRequests: 5 } // 5 streaming searches per minute
    )

    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded for streaming search',
          retryAfter: rateLimitResult.retryAfter
        },
        { status: 429 }
      )
    }

    logger.info('StreamSearchAPI', `Starting streaming search for "${sanitizedQuery}" from IP: ${ip}`)

    // Create Server-Sent Events stream
    const stream = new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder()
        
        // Send initial connection event
        const connectionEvent = `data: ${JSON.stringify({
          type: 'connected',
          message: 'Streaming search started',
          timestamp: Date.now()
        })}\n\n`
        
        controller.enqueue(encoder.encode(connectionEvent))

        // Start streaming search
        streamingSearchService.processStreamingSearch(
          sanitizedQuery,
          sanitizedLocation,
          
          // onResult callback
          (business) => {
            try {
              const resultEvent = `data: ${JSON.stringify({
                type: 'result',
                data: business,
                timestamp: Date.now()
              })}\n\n`
              
              controller.enqueue(encoder.encode(resultEvent))
            } catch (error) {
              logger.error('StreamSearchAPI', 'Failed to send result event', error)
            }
          },
          
          // onProgress callback
          (progress) => {
            try {
              const progressEvent = `data: ${JSON.stringify({
                type: 'progress',
                data: progress,
                timestamp: Date.now()
              })}\n\n`
              
              controller.enqueue(encoder.encode(progressEvent))
            } catch (error) {
              logger.error('StreamSearchAPI', 'Failed to send progress event', error)
            }
          },
          
          // onComplete callback
          (totalResults) => {
            try {
              const completeEvent = `data: ${JSON.stringify({
                type: 'complete',
                data: { totalResults },
                message: `Search completed with ${totalResults} results`,
                timestamp: Date.now()
              })}\n\n`
              
              controller.enqueue(encoder.encode(completeEvent))
              controller.close()
            } catch (error) {
              logger.error('StreamSearchAPI', 'Failed to send complete event', error)
              controller.close()
            }
          },
          
          // onError callback
          (error) => {
            try {
              const errorEvent = `data: ${JSON.stringify({
                type: 'error',
                error: error,
                timestamp: Date.now()
              })}\n\n`
              
              controller.enqueue(encoder.encode(errorEvent))
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
            enableRealTimeUpdates: true
          }
        ).catch(error => {
          logger.error('StreamSearchAPI', 'Streaming search failed', error)
          
          try {
            const errorEvent = `data: ${JSON.stringify({
              type: 'error',
              error: 'Internal server error',
              timestamp: Date.now()
            })}\n\n`
            
            controller.enqueue(encoder.encode(errorEvent))
          } catch (err) {
            logger.error('StreamSearchAPI', 'Failed to send final error event', err)
          } finally {
            controller.close()
          }
        })
      },

      cancel() {
        logger.info('StreamSearchAPI', 'Client disconnected from streaming search')
        // Stop the streaming search if client disconnects
        streamingSearchService.stopAllStreams()
      }
    })

    // Return Server-Sent Events response
    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
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
        message: 'Failed to start streaming search'
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
