/**
 * Virtualized Export Service
 * Handles efficient export of large datasets with server-side aggregation
 */

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { AdvancedFilterOptions, SortOptions } from '@/lib/enhancedFilteringService'
import { AILeadScore, aiLeadScoringService } from '@/lib/aiLeadScoringService'

export interface ExportOptions {
  format: 'csv' | 'xlsx' | 'json' | 'pdf'
  includeAIScores: boolean
  includeHeaders: boolean
  customFields?: string[]
  filters?: AdvancedFilterOptions
  sorting?: SortOptions
  maxRecords?: number
  batchSize?: number
}

export interface ExportProgress {
  totalRecords: number
  processedRecords: number
  currentBatch: number
  totalBatches: number
  percentage: number
  estimatedTimeRemaining: number // in seconds
  status: 'preparing' | 'processing' | 'finalizing' | 'completed' | 'error'
  errorMessage?: string
}

export interface ExportResult {
  success: boolean
  downloadUrl?: string
  fileName: string
  fileSize: number
  recordCount: number
  processingTime: number
  format: string
  includesAIScores: boolean
  error?: string
}

export interface StreamingExportConfig {
  chunkSize: number
  compressionLevel: number
  includeMetadata: boolean
  aiScoringBatchSize: number
}

/**
 * Virtualized Export Service Class
 */
export class VirtualizedExportService {
  private readonly defaultBatchSize = 1000
  private readonly defaultConfig: StreamingExportConfig = {
    chunkSize: 500,
    compressionLevel: 6,
    includeMetadata: true,
    aiScoringBatchSize: 100,
  }

  private activeExports = new Map<string, ExportProgress>()

  /**
   * Start a large dataset export with progress tracking
   */
  async startExport(
    exportId: string,
    options: ExportOptions,
    config: Partial<StreamingExportConfig> = {}
  ): Promise<{ exportId: string; estimatedDuration: number }> {
    const mergedConfig = { ...this.defaultConfig, ...config }
    const startTime = Date.now()

    try {
      logger.info(
        'VirtualizedExportService',
        `Starting export ${exportId} with format ${options.format}`
      )

      // Initialize progress tracking
      this.activeExports.set(exportId, {
        totalRecords: 0,
        processedRecords: 0,
        currentBatch: 0,
        totalBatches: 0,
        percentage: 0,
        estimatedTimeRemaining: 0,
        status: 'preparing',
      })

      // Start the export process asynchronously
      this.processExportAsync(exportId, options, mergedConfig)

      // Estimate duration based on record count and format
      const estimatedRecords = await this.estimateRecordCount(options.filters)
      const estimatedDuration = this.estimateExportDuration(
        estimatedRecords,
        options.format,
        options.includeAIScores
      )

      return { exportId, estimatedDuration }
    } catch (error) {
      logger.error('VirtualizedExportService', `Failed to start export ${exportId}`, error)
      this.updateExportProgress(exportId, {
        status: 'error',
        errorMessage: error instanceof Error ? error.message : 'Unknown error',
      })
      throw error
    }
  }

  /**
   * Get export progress
   */
  getExportProgress(exportId: string): ExportProgress | null {
    return this.activeExports.get(exportId) || null
  }

  /**
   * Cancel an active export
   */
  async cancelExport(exportId: string): Promise<boolean> {
    const progress = this.activeExports.get(exportId)
    if (!progress) return false

    this.updateExportProgress(exportId, {
      status: 'error',
      errorMessage: 'Export cancelled by user',
    })
    this.activeExports.delete(exportId)

    logger.info('VirtualizedExportService', `Export ${exportId} cancelled`)
    return true
  }

  /**
   * Process export asynchronously with streaming
   */
  private async processExportAsync(
    exportId: string,
    options: ExportOptions,
    config: StreamingExportConfig
  ): Promise<void> {
    const startTime = Date.now()

    try {
      // Step 1: Get total record count
      this.updateExportProgress(exportId, { status: 'preparing' })
      const totalRecords = await this.estimateRecordCount(options.filters)
      const totalBatches = Math.ceil(totalRecords / (options.batchSize || this.defaultBatchSize))

      this.updateExportProgress(exportId, {
        totalRecords,
        totalBatches,
        status: 'processing',
      })

      // Step 2: Initialize export file
      const fileName = this.generateFileName(options.format)
      const exportWriter = await this.createExportWriter(fileName, options.format, config)

      // Step 3: Process data in batches
      let processedRecords = 0
      let allBusinesses: BusinessRecord[] = []
      let aiScores: Map<string, AILeadScore> = new Map()

      for (let batch = 0; batch < totalBatches; batch++) {
        const batchStartTime = Date.now()

        // Fetch batch data
        const offset = batch * (options.batchSize || this.defaultBatchSize)
        const batchData = await this.fetchBatchData(
          options.filters,
          options.sorting,
          options.batchSize || this.defaultBatchSize,
          offset
        )

        allBusinesses.push(...batchData)

        // Calculate AI scores if requested
        if (options.includeAIScores) {
          const batchScores = await aiLeadScoringService.calculateBatchScores(batchData)
          batchScores.scores.forEach((score, businessId) => {
            aiScores.set(businessId, score)
          })
        }

        processedRecords += batchData.length

        // Update progress
        const batchTime = Date.now() - batchStartTime
        const avgBatchTime = batchTime
        const remainingBatches = totalBatches - batch - 1
        const estimatedTimeRemaining = (remainingBatches * avgBatchTime) / 1000

        this.updateExportProgress(exportId, {
          processedRecords,
          currentBatch: batch + 1,
          percentage: Math.round((processedRecords / totalRecords) * 100),
          estimatedTimeRemaining,
        })

        // Small delay to prevent overwhelming the system
        if (batch < totalBatches - 1) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
      }

      // Step 4: Finalize export
      this.updateExportProgress(exportId, { status: 'finalizing' })

      const exportResult = await this.finalizeExport(
        exportWriter,
        allBusinesses,
        aiScores,
        options,
        fileName
      )

      // Step 5: Complete export
      const processingTime = Date.now() - startTime
      this.updateExportProgress(exportId, {
        status: 'completed',
        percentage: 100,
        estimatedTimeRemaining: 0,
      })

      logger.info('VirtualizedExportService', `Export ${exportId} completed in ${processingTime}ms`)
    } catch (error) {
      logger.error('VirtualizedExportService', `Export ${exportId} failed`, error)
      this.updateExportProgress(exportId, {
        status: 'error',
        errorMessage: error instanceof Error ? error.message : 'Export processing failed',
      })
    }
  }

  /**
   * Estimate record count based on filters
   */
  private async estimateRecordCount(filters?: AdvancedFilterOptions): Promise<number> {
    try {
      // Make a count query to the database
      const response = await fetch(
        '/api/businesses/paginated?' +
          new URLSearchParams({
            limit: '1',
            ...(filters ? { filters: JSON.stringify(filters) } : {}),
          })
      )

      if (!response.ok) throw new Error('Failed to estimate record count')

      const result = await response.json()
      return result.pagination?.totalCount || 0
    } catch (error) {
      logger.warn(
        'VirtualizedExportService',
        'Failed to estimate record count, using default',
        error
      )
      return 10000 // Default estimate
    }
  }

  /**
   * Fetch batch data from API
   */
  private async fetchBatchData(
    filters?: AdvancedFilterOptions,
    sorting?: SortOptions,
    limit: number = this.defaultBatchSize,
    offset: number = 0
  ): Promise<BusinessRecord[]> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
    })

    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.set(key, typeof value === 'object' ? JSON.stringify(value) : String(value))
        }
      })
    }

    if (sorting) {
      params.set('sortBy', sorting.field)
      params.set('sortOrder', sorting.order)
    }

    const response = await fetch(`/api/businesses/paginated?${params.toString()}`)

    if (!response.ok) {
      throw new Error(`Failed to fetch batch data: ${response.statusText}`)
    }

    const result = await response.json()
    return result.data || []
  }

  /**
   * Create export writer based on format
   */
  private async createExportWriter(
    fileName: string,
    format: string,
    config: StreamingExportConfig
  ) {
    // This would create the appropriate writer (CSV, XLSX, etc.)
    // For now, returning a mock writer
    return {
      fileName,
      format,
      config,
      write: (data: any) => Promise.resolve(),
      finalize: () => Promise.resolve({ url: `/downloads/${fileName}`, size: 1024 }),
    }
  }

  /**
   * Finalize export and generate download
   */
  private async finalizeExport(
    writer: any,
    businesses: BusinessRecord[],
    aiScores: Map<string, AILeadScore>,
    options: ExportOptions,
    fileName: string
  ): Promise<ExportResult> {
    try {
      // Convert data to export format
      const exportData = this.prepareExportData(businesses, aiScores, options)

      // Write data to file
      await writer.write(exportData)
      const result = await writer.finalize()

      return {
        success: true,
        downloadUrl: result.url,
        fileName,
        fileSize: result.size,
        recordCount: businesses.length,
        processingTime: 0, // Will be set by caller
        format: options.format,
        includesAIScores: options.includeAIScores,
      }
    } catch (error) {
      logger.error('VirtualizedExportService', 'Failed to finalize export', error)
      throw error
    }
  }

  /**
   * Prepare data for export
   */
  private prepareExportData(
    businesses: BusinessRecord[],
    aiScores: Map<string, AILeadScore>,
    options: ExportOptions
  ): any[] {
    return businesses.map(business => {
      const baseData = {
        id: business.id,
        businessName: business.businessName,
        industry: business.industry,
        email: business.email.join('; '),
        phone: business.phone || '',
        website: business.websiteUrl,
        address:
          `${business.address.street || ''}, ${business.address.city || ''}, ${business.address.state || ''} ${business.address.zipCode || ''}`.trim(),
        contactPerson: business.contactPerson || '',
        scrapedAt: business.scrapedAt.toISOString(),
      }

      if (options.includeAIScores) {
        const aiScore = aiScores.get(business.id)
        if (aiScore) {
          return {
            ...baseData,
            aiScore: aiScore.overallScore,
            aiRank: aiScore.rank,
            aiConfidence: Math.round(aiScore.confidence * 100),
            contactabilityScore: aiScore.factors.contactability.score,
            businessMaturityScore: aiScore.factors.businessMaturity.score,
            marketPotentialScore: aiScore.factors.marketPotential.score,
            engagementLikelihoodScore: aiScore.factors.engagementLikelihood.score,
            conversionProbability: Math.round(aiScore.predictions.conversionProbability * 100),
            bestContactMethod: aiScore.predictions.bestContactMethod,
            badges: aiScore.badges.map(b => b.label).join('; '),
          }
        }
      }

      return baseData
    })
  }

  /**
   * Generate unique filename
   */
  private generateFileName(format: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    return `business-export-${timestamp}.${format}`
  }

  /**
   * Estimate export duration
   */
  private estimateExportDuration(recordCount: number, format: string, includeAI: boolean): number {
    // Base processing time per record (in milliseconds)
    let baseTimePerRecord = 1

    // Format multipliers
    const formatMultipliers = {
      csv: 1,
      xlsx: 2,
      json: 1.5,
      pdf: 5,
    }

    baseTimePerRecord *= formatMultipliers[format as keyof typeof formatMultipliers] || 1

    // AI scoring adds significant time
    if (includeAI) {
      baseTimePerRecord *= 3
    }

    return Math.ceil((recordCount * baseTimePerRecord) / 1000) // Convert to seconds
  }

  /**
   * Update export progress
   */
  private updateExportProgress(exportId: string, updates: Partial<ExportProgress>): void {
    const current = this.activeExports.get(exportId)
    if (current) {
      this.activeExports.set(exportId, { ...current, ...updates })
    }
  }
}

// Export singleton instance
export const virtualizedExportService = new VirtualizedExportService()
