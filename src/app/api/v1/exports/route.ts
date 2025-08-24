/**
 * API v1 - Exports Endpoint
 * RESTful API for export operations with template support
 */

import { NextRequest } from 'next/server'
import { apiFramework } from '@/lib/integrations/api-framework'
import { enhancedExportService } from '@/lib/enhanced-export-service'
import { BusinessRecord } from '@/types/business'
import { ApiResponse, ApiRequestContext } from '@/types/integrations'
import { logger } from '@/utils/logger'

/**
 * GET /api/v1/exports - List available export templates
 */
export const GET = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const platform = searchParams.get('platform') as any
    const search = searchParams.get('search')

    try {
      let templates = platform 
        ? enhancedExportService.listTemplates(platform)
        : enhancedExportService.listTemplates()

      if (search) {
        templates = enhancedExportService.searchTemplates(search)
      }

      const statistics = enhancedExportService.getExportStatistics()

      return {
        success: true,
        data: {
          templates: templates.map(template => ({
            id: template.id,
            name: template.name,
            platform: template.platform,
            description: template.description,
            version: template.version,
            category: template.metadata.category,
            tags: template.metadata.tags,
            requiredFields: template.requiredFields,
            optionalFields: template.optionalFields
          })),
          statistics
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }
    } catch (error) {
      logger.error('ExportsAPI', 'Failed to list templates', error)
      throw error
    }
  },
  {
    permissions: ['read:exports']
  }
)

/**
 * POST /api/v1/exports - Create export using template
 */
export const POST = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { templateId, businesses, options = {} } = body

      // Validation
      if (!templateId) {
        throw new Error('Template ID is required')
      }

      if (!businesses || !Array.isArray(businesses)) {
        throw new Error('Businesses array is required')
      }

      if (businesses.length === 0) {
        throw new Error('At least one business record is required')
      }

      // Validate business records
      const validBusinesses: BusinessRecord[] = businesses.filter(business => 
        business && typeof business === 'object' && business.businessName
      )

      if (validBusinesses.length === 0) {
        throw new Error('No valid business records found')
      }

      logger.info('ExportsAPI', `Creating export with template: ${templateId}`, {
        requestId: context.requestId,
        templateId,
        businessCount: validBusinesses.length,
        clientId: context.clientId
      })

      // Execute export
      const result = await enhancedExportService.exportWithTemplate(
        templateId,
        validBusinesses,
        {
          validateData: options.validateData !== false,
          skipErrors: options.skipErrors === true,
          includeMetadata: options.includeMetadata !== false
        }
      )

      // Convert to downloadable format if requested
      let downloadData = null
      if (options.format && ['csv', 'json', 'xlsx'].includes(options.format)) {
        const downloadResult = await enhancedExportService.convertToDownloadableFormat(
          result,
          options.format
        )
        
        // Convert blob to base64 for JSON response
        const arrayBuffer = await downloadResult.blob.arrayBuffer()
        const base64 = Buffer.from(arrayBuffer).toString('base64')
        
        downloadData = {
          filename: downloadResult.filename,
          mimeType: downloadResult.mimeType,
          data: base64,
          size: downloadResult.blob.size
        }
      }

      return {
        success: true,
        data: {
          export: {
            id: `export_${Date.now()}`,
            templateId: result.templateId,
            status: result.success ? 'completed' : 'failed',
            recordsProcessed: result.recordsProcessed,
            recordsExported: result.recordsExported,
            recordsSkipped: result.recordsSkipped,
            errors: result.errors,
            warnings: result.warnings,
            metadata: result.metadata
          },
          exportData: options.includeData !== false ? result.exportData : undefined,
          download: downloadData
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('ExportsAPI', 'Export creation failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  },
  {
    permissions: ['write:exports'],
    rateLimit: {
      requestsPerMinute: 10,
      requestsPerHour: 100
    },
    validation: {
      body: {
        templateId: 'string',
        businesses: 'array'
      }
    }
  }
)

/**
 * POST /api/v1/exports/preview - Generate export preview
 */
export const preview = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { templateId, businesses, sampleSize = 5 } = body

      if (!templateId) {
        throw new Error('Template ID is required')
      }

      if (!businesses || !Array.isArray(businesses)) {
        throw new Error('Businesses array is required')
      }

      const validBusinesses: BusinessRecord[] = businesses.filter(business => 
        business && typeof business === 'object' && business.businessName
      )

      if (validBusinesses.length === 0) {
        throw new Error('No valid business records found')
      }

      logger.info('ExportsAPI', `Generating export preview: ${templateId}`, {
        requestId: context.requestId,
        templateId,
        businessCount: validBusinesses.length,
        sampleSize
      })

      const preview = await enhancedExportService.generateExportPreview(
        templateId,
        validBusinesses,
        Math.min(sampleSize, 10) // Limit sample size
      )

      return {
        success: true,
        data: {
          preview: {
            templateInfo: {
              id: preview.templateInfo.id,
              name: preview.templateInfo.name,
              platform: preview.templateInfo.platform,
              description: preview.templateInfo.description
            },
            sampleData: preview.sampleData,
            fieldMappings: preview.fieldMappings,
            validation: preview.validation,
            statistics: {
              totalBusinesses: validBusinesses.length,
              sampleSize: preview.sampleData.length,
              fieldCount: preview.fieldMappings.length
            }
          }
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('ExportsAPI', 'Preview generation failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  },
  {
    permissions: ['read:exports'],
    rateLimit: {
      requestsPerMinute: 20,
      requestsPerHour: 200
    }
  }
)

/**
 * POST /api/v1/exports/multi-platform - Export to multiple platforms
 */
export const multiPlatform = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { templateIds, businesses, options = {} } = body

      if (!templateIds || !Array.isArray(templateIds)) {
        throw new Error('Template IDs array is required')
      }

      if (!businesses || !Array.isArray(businesses)) {
        throw new Error('Businesses array is required')
      }

      const validBusinesses: BusinessRecord[] = businesses.filter(business => 
        business && typeof business === 'object' && business.businessName
      )

      if (validBusinesses.length === 0) {
        throw new Error('No valid business records found')
      }

      logger.info('ExportsAPI', `Multi-platform export started`, {
        requestId: context.requestId,
        templateIds,
        businessCount: validBusinesses.length,
        clientId: context.clientId
      })

      const result = await enhancedExportService.exportToMultiplePlatforms(
        templateIds,
        validBusinesses,
        {
          continueOnError: options.continueOnError !== false,
          includeMetadata: options.includeMetadata !== false
        }
      )

      return {
        success: true,
        data: {
          multiExport: {
            id: `multi_export_${Date.now()}`,
            results: result.results.map(r => ({
              templateId: r.templateId,
              success: r.result?.success || false,
              recordsExported: r.result?.recordsExported || 0,
              error: r.error
            })),
            summary: result.summary
          }
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('ExportsAPI', 'Multi-platform export failed', {
        requestId: context.requestId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  },
  {
    permissions: ['write:exports'],
    rateLimit: {
      requestsPerMinute: 5,
      requestsPerHour: 50
    }
  }
)

// Export named functions for specific endpoints
export { preview as POST_preview, multiPlatform as POST_multiPlatform }
