/**
 * Data Management API Endpoint
 * Comprehensive data validation, duplicate detection, and retention management
 */

import { NextRequest, NextResponse } from 'next/server'
import { dataValidationPipeline } from '@/lib/dataValidationPipeline'
import { duplicateDetectionSystem } from '@/lib/duplicateDetection'
import { dataRetentionSystem } from '@/lib/dataRetentionSystem'
import { exportService } from '@/utils/exportService'
import { database } from '@/lib/postgresql-database'
import { logger } from '@/utils/logger'

import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { getClientIP } from '@/lib/security'

/**
 * POST /api/data-management - Data management operations
 */
const dataManagementHandler = withApiSecurity(
  withValidation(
    async (request: NextRequest, validatedData: any) => {
      const ip = getClientIP(request)
      const { action, ...params } = validatedData.body || {}

      logger.info('DataManagementAPI', `Received ${action} request from IP: ${ip}`)

      try {
        switch (action) {
          case 'validate-business':
            const { business } = params
            if (!business) {
              return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
            }
            const validationResult = await dataValidationPipeline.validateBusiness(business)
            return NextResponse.json({ success: true, validation: validationResult })

          case 'validate-batch':
            const { businesses } = params
            if (!businesses || !Array.isArray(businesses)) {
              return NextResponse.json({ error: 'Businesses array is required' }, { status: 400 })
            }
            const batchResults = await dataValidationPipeline.validateBatch(businesses)
            return NextResponse.json({ success: true, results: batchResults })

          case 'quality-score':
            const { businessData } = params
            if (!businessData) {
              return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
            }
            const qualityScore = await dataValidationPipeline.calculateQualityScore(businessData)
            return NextResponse.json({ success: true, qualityScore })

          case 'enrich-data':
            const { businessToEnrich } = params
            if (!businessToEnrich) {
              return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
            }
            const enrichedData = await dataValidationPipeline.enrichBusinessData(businessToEnrich)
            return NextResponse.json({ success: true, enrichedData })

          case 'detect-duplicates':
            const { records } = params
            if (!records || !Array.isArray(records)) {
              return NextResponse.json({ error: 'Records array is required' }, { status: 400 })
            }
            const duplicates = await duplicateDetectionSystem.findDuplicates(records)
            return NextResponse.json({ success: true, duplicates })

          case 'compare-records':
            const { record1, record2 } = params
            if (!record1 || !record2) {
              return NextResponse.json({ error: 'Both records are required for comparison' }, { status: 400 })
            }
            const similarity = await duplicateDetectionSystem.calculateSimilarity(record1, record2)
            return NextResponse.json({ success: true, similarity })

          case 'execute-retention-policy':
            const { policyName } = params
            if (!policyName) {
              return NextResponse.json({ error: 'Policy name is required' }, { status: 400 })
            }
            const retentionResult = await dataRetentionSystem.executePolicy(policyName)
            return NextResponse.json({ success: true, result: retentionResult })

          case 'toggle-retention-policy':
            const { togglePolicyName, enabled } = params
            if (!togglePolicyName || typeof enabled !== 'boolean') {
              return NextResponse.json({ error: 'Policy name and enabled status are required' }, { status: 400 })
            }
            await dataRetentionSystem.togglePolicy(togglePolicyName, enabled)
            return NextResponse.json({
              success: true,
              message: `Policy ${togglePolicyName} ${enabled ? 'enabled' : 'disabled'}`
            })

          case 'export-data':
            const { exportBusinesses, format, filters, sorting, customFields } = params
            if (!exportBusinesses || !Array.isArray(exportBusinesses)) {
              return NextResponse.json({ error: 'Businesses array is required' }, { status: 400 })
            }
            if (!format) {
              return NextResponse.json({ error: 'Export format is required' }, { status: 400 })
            }
            const exportResult = await exportService.exportBusinesses(
              exportBusinesses,
              format,
              { filters, sorting, customFields }
            )
            return NextResponse.json({ success: true, export: exportResult })

          case 'cleanup-database':
            const { dryRun = false } = params
            const beforeStats = await getCleanupStats()
            if (!dryRun) {
              await performDatabaseCleanup()
            }
            const afterStats = dryRun ? beforeStats : await getCleanupStats()
            const cleanupStats = {
              before: beforeStats,
              after: afterStats,
              removed: Object.keys(beforeStats).reduce((acc, key) => {
                acc[key] = beforeStats[key] - afterStats[key]
                return acc
              }, {} as Record<string, number>)
            }
            return NextResponse.json({
              success: true,
              stats: cleanupStats,
              message: dryRun ? 'Dry run completed' : 'Cleanup completed'
            })

          case 'optimize-database':
            await optimizeDatabase()
            const optimizationResults = await dataRetentionSystem.executeAllPolicies()
            return NextResponse.json({
              success: true,
              message: 'Database optimization completed',
              results: optimizationResults
            })

          default:
            return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
        }
      } catch (error) {
        logger.error('DataManagementAPI', 'Request failed', error)
        return NextResponse.json({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error'
        }, { status: 500 })
      }
    },
    {
      body: [
        { field: 'action', required: true, type: 'string' as const, allowedValues: [
          'validate-business', 'validate-batch', 'quality-score', 'enrich-data',
          'detect-duplicates', 'compare-records', 'execute-retention-policy',
          'toggle-retention-policy', 'export-data', 'cleanup-database', 'optimize-database'
        ]},
        { field: 'business', type: 'object' as const },
        { field: 'businesses', type: 'array' as const },
        { field: 'businessData', type: 'object' as const },
        { field: 'businessToEnrich', type: 'object' as const },
        { field: 'records', type: 'array' as const },
        { field: 'record1', type: 'object' as const },
        { field: 'record2', type: 'object' as const },
        { field: 'policyName', type: 'string' as const, maxLength: 100 },
        { field: 'togglePolicyName', type: 'string' as const, maxLength: 100 },
        { field: 'enabled', type: 'boolean' as const },
        { field: 'exportBusinesses', type: 'array' as const },
        { field: 'format', type: 'string' as const, allowedValues: ['csv', 'xlsx', 'xls', 'ods', 'pdf', 'json', 'xml', 'vcf', 'sql'] },
        { field: 'filters', type: 'object' as const },
        { field: 'sorting', type: 'object' as const },
        { field: 'customFields', type: 'array' as const },
        { field: 'dryRun', type: 'boolean' as const }
      ]
    }
  ),
  {
    requireAuth: true,
    requireCSRF: true,
    rateLimit: 'general',
    validateInput: true,
    logRequests: true
  }
)

export const POST = dataManagementHandler

/**
 * Optimize database performance
 */
async function optimizeDatabase() {
  await database.executeQuery('ANALYZE businesses')
  await database.executeQuery('ANALYZE campaigns')
  await database.executeQuery('ANALYZE scraping_sessions')
  await database.executeQuery('VACUUM businesses')
  await database.executeQuery('VACUUM campaigns')
  await database.executeQuery('VACUUM scraping_sessions')
  await database.executeQuery('REINDEX TABLE businesses')
  await database.executeQuery('REINDEX TABLE campaigns')
  await database.executeQuery('REINDEX TABLE scraping_sessions')
  logger.info('DataManagementAPI', 'Database optimization completed')
}

/**
 * Get cleanup statistics
 */
async function getCleanupStats() {
  const queries = [
    {
      name: 'duplicateEmails',
      query: `SELECT COUNT(*) as count FROM (
        SELECT email FROM businesses
        WHERE email IS NOT NULL AND array_length(email, 1) > 0
        GROUP BY email HAVING COUNT(*) > 1
      ) duplicates`
    },
    {
      name: 'incompleteRecords',
      query: `SELECT COUNT(*) as count FROM businesses
        WHERE business_name IS NULL OR business_name = ''
           OR (email IS NULL OR array_length(email, 1) = 0) AND phone IS NULL`
    },
    {
      name: 'lowConfidenceRecords',
      query: `SELECT COUNT(*) as count FROM businesses WHERE confidence < 0.3`
    },
    {
      name: 'oldRecords',
      query: `SELECT COUNT(*) as count FROM businesses
        WHERE scraped_at < NOW() - INTERVAL '1 year'`
    }
  ]

  const stats: Record<string, number> = {}
  for (const { name, query } of queries) {
    try {
      const result = await database.executeQuery(query)
      stats[name] = parseInt(result.rows[0].count)
    } catch (error) {
      logger.error('DataManagementAPI', `Failed to get ${name} stats`, error)
      stats[name] = 0
    }
  }
  return stats
}

/**
 * Perform database cleanup
 */
async function performDatabaseCleanup() {
  await database.executeQuery(`
    DELETE FROM businesses b1 USING businesses b2
    WHERE b1.id < b2.id AND b1.email = b2.email AND array_length(b1.email, 1) > 0
  `)
  await database.executeQuery(`
    DELETE FROM businesses
    WHERE (business_name IS NULL OR business_name = ''
           OR (email IS NULL OR array_length(email, 1) = 0) AND phone IS NULL)
      AND scraped_at < NOW() - INTERVAL '30 days'
  `)
  logger.info('DataManagementAPI', 'Database cleanup completed')
}

/**
 * GET /api/data-management - Get data management statistics
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('DataManagementAPI', `Statistics request from IP: ${ip}`)

    const cleanupStats = await getCleanupStats()
    const retentionPolicies = await dataRetentionSystem.getAllPolicies()
    const validationStats = await dataValidationPipeline.getStatistics()
    const duplicateStats = await duplicateDetectionSystem.getStatistics()

    return NextResponse.json({
      success: true,
      statistics: {
        cleanup: cleanupStats,
        retention: retentionPolicies,
        validation: validationStats,
        duplicates: duplicateStats
      },
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('DataManagementAPI', 'GET request failed', error)
    return NextResponse.json({
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
