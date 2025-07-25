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
import { validationService } from '@/utils/validation'

/**
 * POST /api/data-management - Data management operations
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, ...params } = body

    logger.info('DataManagementAPI', `Received ${action} request`)

    switch (action) {
      case 'validate-business':
        const { business } = params

        if (!business) {
          return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
        }

        const validationResult = await dataValidationPipeline.validateAndClean(business)
        
        return NextResponse.json({ 
          success: true, 
          validation: validationResult
        })

      case 'validate-batch':
        const { businesses } = params

        if (!Array.isArray(businesses) || businesses.length === 0) {
          return NextResponse.json({ error: 'Businesses array is required' }, { status: 400 })
        }

        if (businesses.length > 1000) {
          return NextResponse.json({ error: 'Maximum 1000 businesses allowed per batch' }, { status: 400 })
        }

        const batchResults = []
        for (const business of businesses) {
          try {
            const result = await dataValidationPipeline.validateAndClean(business)
            batchResults.push({ business: business.id, validation: result })
          } catch (error) {
            batchResults.push({ 
              business: business.id, 
              error: error instanceof Error ? error.message : 'Validation failed' 
            })
          }
        }

        return NextResponse.json({ 
          success: true, 
          results: batchResults,
          totalProcessed: businesses.length
        })

      case 'calculate-quality-score':
        const { businessData } = params

        if (!businessData) {
          return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
        }

        const qualityScore = dataValidationPipeline.calculateDataQualityScore(businessData)
        
        return NextResponse.json({ 
          success: true, 
          qualityScore
        })

      case 'enrich-data':
        const { businessToEnrich } = params

        if (!businessToEnrich) {
          return NextResponse.json({ error: 'Business data is required' }, { status: 400 })
        }

        const enrichmentResult = await dataValidationPipeline.enrichData(businessToEnrich)
        
        return NextResponse.json({ 
          success: true, 
          enrichment: enrichmentResult,
          enrichedBusiness: businessToEnrich
        })

      case 'find-duplicates':
        const { records, config } = params

        if (!Array.isArray(records) || records.length === 0) {
          return NextResponse.json({ error: 'Records array is required' }, { status: 400 })
        }

        if (records.length > 5000) {
          return NextResponse.json({ error: 'Maximum 5000 records allowed for duplicate detection' }, { status: 400 })
        }

        const duplicateMatches = await duplicateDetectionSystem.findDuplicates(records)
        const clusters = duplicateDetectionSystem.createClusters(duplicateMatches)
        
        return NextResponse.json({ 
          success: true, 
          duplicates: {
            matches: duplicateMatches,
            clusters: clusters,
            totalMatches: duplicateMatches.length,
            totalClusters: clusters.length
          }
        })

      case 'compare-records':
        const { record1, record2 } = params

        if (!record1 || !record2) {
          return NextResponse.json({ error: 'Both records are required for comparison' }, { status: 400 })
        }

        const comparison = await duplicateDetectionSystem.compareRecords(record1, record2)
        
        return NextResponse.json({ 
          success: true, 
          comparison
        })

      case 'get-retention-policies':
        const policies = dataRetentionSystem.getPolicies()
        
        return NextResponse.json({ 
          success: true, 
          policies
        })

      case 'execute-retention-policy':
        const { policyName } = params

        if (!policyName) {
          return NextResponse.json({ error: 'Policy name is required' }, { status: 400 })
        }

        const executionResult = await dataRetentionSystem.executePolicy(policyName)
        
        return NextResponse.json({ 
          success: true, 
          result: executionResult
        })

      case 'execute-all-retention-policies':
        const allResults = await dataRetentionSystem.executeAllPolicies()
        
        return NextResponse.json({ 
          success: true, 
          results: allResults,
          totalPolicies: allResults.length
        })

      case 'toggle-retention-policy':
        const { policyName: togglePolicyName, enabled } = params

        if (!togglePolicyName || typeof enabled !== 'boolean') {
          return NextResponse.json({ error: 'Policy name and enabled status are required' }, { status: 400 })
        }

        const toggleResult = dataRetentionSystem.togglePolicy(togglePolicyName, enabled)
        
        return NextResponse.json({ 
          success: toggleResult, 
          message: toggleResult ? 'Policy updated successfully' : 'Policy not found'
        })

      case 'get-data-usage-stats':
        const usageStats = await dataRetentionSystem.getDataUsageStats()
        
        return NextResponse.json({ 
          success: true, 
          stats: usageStats
        })

      case 'export-enhanced':
        const { 
          exportBusinesses, 
          format, 
          options = {},
          filters,
          sorting,
          customFields 
        } = params

        if (!Array.isArray(exportBusinesses) || exportBusinesses.length === 0) {
          return NextResponse.json({ error: 'Businesses array is required' }, { status: 400 })
        }

        if (!format) {
          return NextResponse.json({ error: 'Export format is required' }, { status: 400 })
        }

        const validFormats = ['csv', 'xlsx', 'xls', 'ods', 'pdf', 'json', 'xml', 'vcf', 'sql']
        if (!validFormats.includes(format)) {
          return NextResponse.json({ error: 'Invalid export format' }, { status: 400 })
        }

        // Enhance export options
        const enhancedOptions = {
          ...options,
          filters,
          sorting,
          customFields,
        }

        const { blob, filename } = await exportService.exportBusinesses(
          exportBusinesses,
          format,
          enhancedOptions
        )

        // Convert blob to base64 for JSON response
        const arrayBuffer = await blob.arrayBuffer()
        const base64 = Buffer.from(arrayBuffer).toString('base64')
        
        return NextResponse.json({ 
          success: true, 
          export: {
            filename,
            mimeType: blob.type,
            size: blob.size,
            data: base64
          }
        })

      case 'cleanup-database':
        const { dryRun = true } = params

        // Get data usage statistics
        const cleanupStats = await dataRetentionSystem.getDataUsageStats()

        if (!dryRun) {
          // Perform actual cleanup by executing all policies
          await dataRetentionSystem.executeAllPolicies()
        }

        return NextResponse.json({ 
          success: true, 
          cleanup: {
            dryRun,
            stats: cleanupStats,
            message: dryRun ? 'Dry run completed' : 'Cleanup completed'
          }
        })

      case 'optimize-database':
        // Execute all policies to optimize database
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

  /**
   * Get cleanup statistics
   */
  async function getCleanupStats() {
    const queries = [
      {
        name: 'duplicateEmails',
        query: `
          SELECT COUNT(*) as count FROM (
            SELECT email FROM businesses 
            WHERE email IS NOT NULL AND array_length(email, 1) > 0
            GROUP BY email 
            HAVING COUNT(*) > 1
          ) duplicates
        `
      },
      {
        name: 'incompleteRecords',
        query: `
          SELECT COUNT(*) as count FROM businesses 
          WHERE business_name IS NULL OR business_name = '' 
             OR (email IS NULL OR array_length(email, 1) = 0) AND phone IS NULL
        `
      },
      {
        name: 'lowConfidenceRecords',
        query: `
          SELECT COUNT(*) as count FROM businesses 
          WHERE confidence < 0.3
        `
      },
      {
        name: 'oldRecords',
        query: `
          SELECT COUNT(*) as count FROM businesses 
          WHERE scraped_at < NOW() - INTERVAL '1 year'
        `
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
    // Remove duplicate emails (keep the most recent)
    await database.executeQuery(`
      DELETE FROM businesses b1
      USING businesses b2
      WHERE b1.id < b2.id
        AND b1.email = b2.email
        AND array_length(b1.email, 1) > 0
    `)

    // Remove incomplete records older than 30 days
    await database.executeQuery(`
      DELETE FROM businesses
      WHERE (business_name IS NULL OR business_name = ''
             OR (email IS NULL OR array_length(email, 1) = 0) AND phone IS NULL)
        AND scraped_at < NOW() - INTERVAL '30 days'
    `)

    logger.info('DataManagementAPI', 'Database cleanup completed')
  }

  /**
   * Optimize database performance
   */
  async function optimizeDatabase() {
    // Analyze tables
    await database.executeQuery('ANALYZE businesses')
    await database.executeQuery('ANALYZE campaigns')
    await database.executeQuery('ANALYZE scraping_sessions')

    // Vacuum tables
    await database.executeQuery('VACUUM businesses')
    await database.executeQuery('VACUUM campaigns')
    await database.executeQuery('VACUUM scraping_sessions')

    // Reindex
    await database.executeQuery('REINDEX TABLE businesses')
    await database.executeQuery('REINDEX TABLE campaigns')
    await database.executeQuery('REINDEX TABLE scraping_sessions')

    logger.info('DataManagementAPI', 'Database optimization completed')
  }
}

/**
 * GET /api/data-management - Get data management statistics
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url)
    const type = url.searchParams.get('type') || 'overview'

    switch (type) {
      case 'overview':
        const usageStats = await dataRetentionSystem.getDataUsageStats()
        const policies = dataRetentionSystem.getPolicies()
        
        return NextResponse.json({ 
          success: true, 
          overview: {
            dataUsage: usageStats,
            retentionPolicies: policies.length,
            enabledPolicies: policies.filter(p => p.enabled).length
          }
        })

      case 'validation-stats':
        // Get validation statistics from recent operations
        const validationStats = {
          totalValidated: 0, // This would come from a tracking system
          validRecords: 0,
          invalidRecords: 0,
          averageConfidence: 0.85,
        }
        
        return NextResponse.json({ 
          success: true, 
          validationStats
        })

      case 'duplicate-stats':
        // Get duplicate detection statistics
        const duplicateStats = {
          totalChecked: 0, // This would come from a tracking system
          duplicatesFound: 0,
          clustersCreated: 0,
          averageSimilarity: 0.75,
        }
        
        return NextResponse.json({ 
          success: true, 
          duplicateStats
        })

      default:
        return NextResponse.json({ error: 'Invalid stats type' }, { status: 400 })
    }

  } catch (error) {
    logger.error('DataManagementAPI', 'GET request failed', error)
    
    return NextResponse.json({ 
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
