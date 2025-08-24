/**
 * API v1 - Templates Endpoint
 * RESTful API for export template management
 */

import { NextRequest } from 'next/server'
import { apiFramework } from '@/lib/integrations/api-framework'
import { enhancedExportService } from '@/lib/enhanced-export-service'
import { ApiResponse, ApiRequestContext } from '@/types/integrations'
import { logger } from '@/utils/logger'

/**
 * GET /api/v1/templates - List all export templates
 */
export const GET = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const platform = searchParams.get('platform') as any
    const category = searchParams.get('category')
    const search = searchParams.get('search')
    const includeDetails = searchParams.get('details') === 'true'

    try {
      let templates = platform 
        ? enhancedExportService.listTemplates(platform)
        : enhancedExportService.listTemplates()

      // Filter by category
      if (category) {
        templates = templates.filter(template => 
          template.metadata.category === category
        )
      }

      // Search functionality
      if (search) {
        templates = enhancedExportService.searchTemplates(search)
      }

      const templateData = templates.map(template => {
        const baseData = {
          id: template.id,
          name: template.name,
          platform: template.platform,
          description: template.description,
          version: template.version,
          category: template.metadata.category,
          tags: template.metadata.tags,
          createdAt: template.metadata.createdAt,
          updatedAt: template.metadata.updatedAt
        }

        if (includeDetails) {
          return {
            ...baseData,
            requiredFields: template.requiredFields,
            optionalFields: template.optionalFields,
            fieldMappings: template.fieldMappings.map(mapping => ({
              type: mapping.type,
              sourceFields: mapping.sourceFields,
              targetField: mapping.targetField,
              hasValidation: mapping.validation && mapping.validation.length > 0
            })),
            platformConfig: {
              fileFormat: template.platformConfig.fileFormat,
              delimiter: template.platformConfig.delimiter,
              encoding: template.platformConfig.encoding
            },
            qualityRules: template.qualityRules
          }
        }

        return baseData
      })

      const statistics = enhancedExportService.getExportStatistics()

      return {
        success: true,
        data: {
          templates: templateData,
          count: templateData.length,
          statistics,
          filters: {
            platforms: Object.keys(statistics.templatesByPlatform),
            categories: Object.keys(statistics.templatesByCategory)
          }
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('TemplatesAPI', 'Failed to list templates', error)
      throw error
    }
  },
  {
    permissions: ['read:templates']
  }
)

/**
 * GET /api/v1/templates/{id} - Get specific template details
 */
export const getTemplate = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const url = new URL(request.url)
      const pathParts = url.pathname.split('/')
      const templateId = pathParts[pathParts.length - 1]

      if (!templateId) {
        throw new Error('Template ID is required')
      }

      const template = enhancedExportService.getTemplate(templateId)
      
      if (!template) {
        throw new Error('Template not found')
      }

      // Validate template
      const validation = enhancedExportService.validateTemplate(template)

      return {
        success: true,
        data: {
          template: {
            id: template.id,
            name: template.name,
            platform: template.platform,
            description: template.description,
            version: template.version,
            requiredFields: template.requiredFields,
            optionalFields: template.optionalFields,
            fieldMappings: template.fieldMappings,
            platformConfig: template.platformConfig,
            metadata: template.metadata,
            qualityRules: template.qualityRules
          },
          validation
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('TemplatesAPI', 'Failed to get template', error)
      throw error
    }
  },
  {
    permissions: ['read:templates']
  }
)

/**
 * POST /api/v1/templates/validate - Validate template configuration
 */
export const validate = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { templateId, template } = body

      let templateToValidate = null

      if (templateId) {
        templateToValidate = enhancedExportService.getTemplate(templateId)
        if (!templateToValidate) {
          throw new Error('Template not found')
        }
      } else if (template) {
        templateToValidate = template
      } else {
        throw new Error('Either templateId or template object is required')
      }

      const validation = enhancedExportService.validateTemplate(templateToValidate)

      return {
        success: true,
        data: {
          validation: {
            isValid: validation.isValid,
            errors: validation.errors,
            warnings: validation.warnings,
            suggestions: validation.suggestions,
            compatibility: validation.compatibility
          },
          template: {
            id: templateToValidate.id,
            name: templateToValidate.name,
            platform: templateToValidate.platform
          }
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('TemplatesAPI', 'Template validation failed', error)
      throw error
    }
  },
  {
    permissions: ['read:templates']
  }
)

/**
 * GET /api/v1/templates/platforms - Get available platforms
 */
export const platforms = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const statistics = enhancedExportService.getExportStatistics()
      
      const platformDetails = Object.entries(statistics.templatesByPlatform).map(([platform, count]) => {
        const templates = enhancedExportService.listTemplates(platform as any)
        const categories = [...new Set(templates.map(t => t.metadata.category))]
        
        return {
          platform,
          templateCount: count,
          categories,
          description: this.getPlatformDescription(platform),
          features: this.getPlatformFeatures(platform)
        }
      })

      return {
        success: true,
        data: {
          platforms: platformDetails,
          totalPlatforms: platformDetails.length,
          totalTemplates: statistics.availableTemplates
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('TemplatesAPI', 'Failed to get platforms', error)
      throw error
    }
  },
  {
    permissions: ['read:templates']
  }
)

/**
 * Helper function to get platform description
 */
function getPlatformDescription(platform: string): string {
  const descriptions: Record<string, string> = {
    'salesforce': 'Leading CRM platform for sales and customer management',
    'hubspot': 'Inbound marketing and sales platform with CRM capabilities',
    'pipedrive': 'Sales-focused CRM designed for small to medium businesses',
    'mailchimp': 'Email marketing platform with automation and analytics',
    'constant-contact': 'Email marketing and digital marketing platform'
  }
  
  return descriptions[platform] || 'Export platform'
}

/**
 * Helper function to get platform features
 */
function getPlatformFeatures(platform: string): string[] {
  const features: Record<string, string[]> = {
    'salesforce': ['Lead Management', 'Account Management', 'Custom Fields', 'Workflow Automation'],
    'hubspot': ['Company Records', 'Contact Management', 'Marketing Automation', 'Analytics'],
    'pipedrive': ['Deal Pipeline', 'Organization Management', 'Activity Tracking', 'Reporting'],
    'mailchimp': ['Email Campaigns', 'List Segmentation', 'Automation', 'Analytics'],
    'constant-contact': ['Email Marketing', 'Contact Lists', 'Event Management', 'Social Media']
  }
  
  return features[platform] || ['Data Export']
}

// Export named functions for specific endpoints
export { getTemplate as GET_template, validate as POST_validate, platforms as GET_platforms }
