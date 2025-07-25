/**
 * Configuration API endpoints
 * Provides access to application configuration and health checks
 */

import { NextRequest, NextResponse } from 'next/server'
import { getConfig, getFeatureFlags } from '@/lib/config'
import { performConfigHealthCheck, validateConfiguration, generateConfigReport } from '@/lib/config-validator'
import { getAllFeatureFlags } from '@/lib/feature-flags'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * GET /api/config - Get configuration information
 */
export async function GET(request: NextRequest) {
  const ip = getClientIP(request)
  
  try {
    const url = new URL(request.url)
    const section = url.searchParams.get('section')
    const format = url.searchParams.get('format') || 'json'
    
    logger.info('Config API', `Configuration request from IP: ${ip}`, { section, format })
    
    if (section === 'health') {
      // Configuration health check
      const healthCheck = await performConfigHealthCheck()
      return NextResponse.json(healthCheck)
      
    } else if (section === 'validation') {
      // Configuration validation
      const validation = validateConfiguration()
      return NextResponse.json(validation)
      
    } else if (section === 'features') {
      // Feature flags
      const features = getAllFeatureFlags()
      return NextResponse.json(features)
      
    } else if (section === 'report') {
      // Configuration report
      if (format === 'markdown') {
        const report = generateConfigReport()
        return new NextResponse(report, {
          headers: {
            'Content-Type': 'text/markdown',
            'Content-Disposition': 'attachment; filename="config-report.md"'
          }
        })
      } else {
        const validation = validateConfiguration()
        const config = getConfig()
        const features = getFeatureFlags()
        
        return NextResponse.json({
          validation,
          environment: config.app.environment,
          version: config.app.version,
          features,
          timestamp: new Date().toISOString()
        })
      }
      
    } else {
      // Public configuration (non-sensitive)
      const config = getConfig()
      const features = getFeatureFlags()
      
      const publicConfig = {
        app: {
          name: config.app.name,
          version: config.app.version,
          environment: config.app.environment,
          debug: config.app.debug
        },
        features: {
          enableAuth: features.enableAuth,
          enableCaching: features.enableCaching,
          enableRateLimiting: features.enableRateLimiting,
          enableMetrics: features.enableMetrics,
          enableDebugMode: features.enableDebugMode,
          enableExperimentalFeatures: features.enableExperimentalFeatures
        },
        scraping: {
          timeout: config.scraping.timeout,
          maxRetries: config.scraping.maxRetries,
          maxSearchResults: config.scraping.maxSearchResults
        },
        cache: {
          type: config.cache.type
        },
        logging: {
          level: config.logging.level,
          format: config.logging.format
        }
      }
      
      return NextResponse.json(publicConfig)
    }
    
  } catch (error) {
    logger.error('Config API', `Error processing request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/config - Update configuration (admin only)
 */
export async function POST(request: NextRequest) {
  const ip = getClientIP(request)
  
  try {
    // This endpoint would require admin authentication in a real implementation
    // For now, we'll just return a not implemented response
    
    logger.warn('Config API', `Configuration update attempt from IP: ${ip}`)
    
    return NextResponse.json(
      { error: 'Configuration updates not implemented in this version' },
      { status: 501 }
    )
    
  } catch (error) {
    logger.error('Config API', `Error processing update request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
