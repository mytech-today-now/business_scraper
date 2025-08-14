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

import { withAuth } from '@/lib/auth-middleware'

/**
 * GET /api/config - Get configuration information
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
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
const configUpdateHandler = withAuth(
  async (request: NextRequest, authContext) => {
    const ip = getClientIP(request)

    try {
      const body = await request.json()
      const { action, ...params } = body

      logger.info('Config API', `Configuration update request: ${action} from IP: ${ip} (authenticated: ${authContext?.authenticated})`)

    switch (action) {
      case 'add-domain-to-blacklist':
        return await handleAddDomainToBlacklist(params, ip)

      default:
        logger.warn('Config API', `Unknown action: ${action} from IP: ${ip}`)
        return NextResponse.json(
          { error: 'Configuration updates not implemented in this version' },
          { status: 501 }
        )
    }

    } catch (error) {
      logger.error('Config API', `Error processing update request from IP: ${ip}`, error)
      return NextResponse.json(
        { error: 'Internal server error' },
        { status: 500 }
      )
    }
  },
  { required: true } // Require authentication for config updates
)

export const POST = configUpdateHandler

/**
 * Handle adding a domain to an industry blacklist
 */
async function handleAddDomainToBlacklist(params: any, ip: string) {
  const { domain, industry } = params

  if (!domain || !industry) {
    return NextResponse.json(
      { error: 'Domain and industry are required' },
      { status: 400 }
    )
  }

  try {
    // Import required modules
    const { storage } = await import('@/model/storage')
    const { DEFAULT_INDUSTRIES } = await import('@/lib/industry-config')

    // Initialize storage
    await storage.initialize()

    // Find the industry
    const allIndustries = await storage.getAllIndustries()
    let targetIndustry = allIndustries.find(ind => ind.id === industry || ind.name === industry)

    // If not found in storage, check default industries
    if (!targetIndustry) {
      targetIndustry = DEFAULT_INDUSTRIES.find(ind => ind.id === industry || ind.name === industry)
    }

    if (!targetIndustry) {
      return NextResponse.json(
        { error: 'Industry not found' },
        { status: 404 }
      )
    }

    // Extract clean domain (remove protocol, www, paths)
    const cleanDomain = extractDomain(domain)

    // Add domain to blacklist if not already present
    const currentBlacklist = targetIndustry.domainBlacklist || []
    if (!currentBlacklist.includes(cleanDomain)) {
      const updatedIndustry = {
        ...targetIndustry,
        domainBlacklist: [...currentBlacklist, cleanDomain]
      }

      // Save updated industry
      await storage.saveIndustry(updatedIndustry)

      logger.info('Config API', `Added domain ${cleanDomain} to ${targetIndustry.name} blacklist from IP: ${ip}`)

      return NextResponse.json({
        success: true,
        message: `Domain ${cleanDomain} added to ${targetIndustry.name} blacklist`,
        domain: cleanDomain,
        industry: targetIndustry.name
      })
    } else {
      return NextResponse.json({
        success: false,
        message: `Domain ${cleanDomain} already in ${targetIndustry.name} blacklist`,
        domain: cleanDomain,
        industry: targetIndustry.name
      })
    }

  } catch (error) {
    logger.error('Config API', `Failed to add domain to blacklist from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Failed to update blacklist' },
      { status: 500 }
    )
  }
}

/**
 * Extract clean domain from URL
 */
function extractDomain(url: string): string {
  try {
    // If it's already just a domain, return it
    if (!url.includes('://')) {
      url = 'https://' + url
    }

    const urlObj = new URL(url)
    let domain = urlObj.hostname.toLowerCase()

    // Remove www. prefix
    if (domain.startsWith('www.')) {
      domain = domain.substring(4)
    }

    return domain
  } catch (error) {
    // If URL parsing fails, try to extract domain manually
    let domain = url.toLowerCase()
    domain = domain.replace(/^https?:\/\//, '')
    domain = domain.replace(/^www\./, '')
    domain = domain.split('/')[0] || ''
    domain = domain.split('?')[0] || ''
    domain = domain.split('#')[0] || ''

    return domain
  }
}
