/**
 * Enhanced Filtering Service
 * Provides advanced filtering, sorting, and search capabilities for business data
 */

import { database } from '@/lib/postgresql-database'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface AdvancedFilterOptions {
  // Text search
  fullTextSearch?: string
  businessNameSearch?: string
  industrySearch?: string
  locationSearch?: string
  
  // Contact filters
  hasEmail?: boolean
  hasPhone?: boolean
  hasWebsite?: boolean
  emailDomain?: string
  phoneAreaCode?: string
  
  // Quality filters
  confidenceScore?: {
    min?: number
    max?: number
  }
  dataCompleteness?: {
    min?: number // 0-1 representing percentage of filled fields
    max?: number
  }
  
  // Date filters
  scrapedDateRange?: {
    start?: string
    end?: string
  }
  
  // Location filters
  coordinates?: {
    lat: number
    lng: number
    radiusMiles: number
  }
  zipCodes?: string[]
  states?: string[]
  cities?: string[]
  
  // Business characteristics
  employeeCountRange?: {
    min?: number
    max?: number
  }
  revenueRange?: {
    min?: number
    max?: number
  }
  foundedYearRange?: {
    start?: number
    end?: number
  }
  
  // Advanced filters
  hasSocialMedia?: boolean
  hasBusinessHours?: boolean
  isEstablishedBusiness?: boolean // Has multiple data points indicating maturity
  
  // Exclusion filters
  excludeIndustries?: string[]
  excludeDomains?: string[]
  excludeBusinessNames?: string[]
}

export interface SortOptions {
  field: 'name' | 'industry' | 'confidence_score' | 'scraped_at' | 'data_completeness' | 'relevance_score'
  order: 'asc' | 'desc'
  secondarySort?: {
    field: string
    order: 'asc' | 'desc'
  }
}

export interface FilteredBusinessResult {
  businesses: BusinessRecord[]
  totalCount: number
  filteredCount: number
  aggregations: {
    industryDistribution: { [industry: string]: number }
    locationDistribution: { [location: string]: number }
    confidenceScoreDistribution: {
      high: number // 0.8+
      medium: number // 0.5-0.8
      low: number // <0.5
    }
    dataCompletenessStats: {
      average: number
      median: number
      distribution: { [range: string]: number }
    }
  }
  queryPerformance: {
    executionTimeMs: number
    indexesUsed: string[]
    queryPlan?: string
  }
}

/**
 * Enhanced Filtering Service Class
 */
export class EnhancedFilteringService {
  
  /**
   * Apply advanced filters to business data
   */
  async filterBusinesses(
    filters: AdvancedFilterOptions,
    sort: SortOptions,
    limit: number = 100,
    offset: number = 0
  ): Promise<FilteredBusinessResult> {
    const startTime = Date.now()
    
    try {
      // Build the main query
      const { query, params, countQuery, countParams } = this.buildFilterQuery(filters, sort, limit, offset)
      
      // Execute queries in parallel
      const [dataResult, countResult, aggregationsResult] = await Promise.all([
        database.query(query, params),
        database.query(countQuery, countParams),
        this.getAggregations(filters)
      ])
      
      const businesses = dataResult.rows.map(this.transformRowToBusiness)
      const totalCount = parseInt(countResult.rows[0].total_count)
      const filteredCount = parseInt(countResult.rows[0].filtered_count)
      
      const executionTime = Date.now() - startTime
      
      logger.info('EnhancedFilteringService', `Filtered ${filteredCount} businesses in ${executionTime}ms`)
      
      return {
        businesses,
        totalCount,
        filteredCount,
        aggregations: aggregationsResult,
        queryPerformance: {
          executionTimeMs: executionTime,
          indexesUsed: this.getIndexesUsed(filters),
          queryPlan: process.env.NODE_ENV === 'development' ? query : undefined
        }
      }
      
    } catch (error) {
      logger.error('EnhancedFilteringService', 'Failed to filter businesses', error)
      throw error
    }
  }
  
  /**
   * Build optimized SQL query with filters
   */
  private buildFilterQuery(
    filters: AdvancedFilterOptions,
    sort: SortOptions,
    limit: number,
    offset: number
  ): { query: string; params: any[]; countQuery: string; countParams: any[] } {
    const whereConditions: string[] = []
    const params: any[] = []
    let paramIndex = 1
    
    // Full-text search using PostgreSQL's built-in search
    if (filters.fullTextSearch) {
      whereConditions.push(`
        (to_tsvector('english', b.name || ' ' || COALESCE(b.industry, '') || ' ' || COALESCE(b.business_description, '')) 
         @@ plainto_tsquery('english', $${paramIndex}))
      `)
      params.push(filters.fullTextSearch)
      paramIndex++
    }
    
    // Specific field searches
    if (filters.businessNameSearch) {
      whereConditions.push(`b.name ILIKE $${paramIndex}`)
      params.push(`%${filters.businessNameSearch}%`)
      paramIndex++
    }
    
    if (filters.industrySearch) {
      whereConditions.push(`b.industry ILIKE $${paramIndex}`)
      params.push(`%${filters.industrySearch}%`)
      paramIndex++
    }
    
    if (filters.locationSearch) {
      whereConditions.push(`(
        b.address->>'city' ILIKE $${paramIndex} OR 
        b.address->>'state' ILIKE $${paramIndex} OR 
        b.address->>'street' ILIKE $${paramIndex}
      )`)
      params.push(`%${filters.locationSearch}%`)
      paramIndex++
    }
    
    // Contact filters
    if (filters.hasEmail !== undefined) {
      if (filters.hasEmail) {
        whereConditions.push(`b.email IS NOT NULL AND array_length(b.email, 1) > 0`)
      } else {
        whereConditions.push(`(b.email IS NULL OR array_length(b.email, 1) = 0)`)
      }
    }
    
    if (filters.hasPhone !== undefined) {
      if (filters.hasPhone) {
        whereConditions.push(`b.phone IS NOT NULL AND b.phone != ''`)
      } else {
        whereConditions.push(`(b.phone IS NULL OR b.phone = '')`)
      }
    }
    
    if (filters.hasWebsite !== undefined) {
      if (filters.hasWebsite) {
        whereConditions.push(`b.website IS NOT NULL AND b.website != ''`)
      } else {
        whereConditions.push(`(b.website IS NULL OR b.website = '')`)
      }
    }
    
    if (filters.emailDomain) {
      whereConditions.push(`EXISTS (
        SELECT 1 FROM unnest(b.email) AS email_addr 
        WHERE email_addr ILIKE $${paramIndex}
      )`)
      params.push(`%@${filters.emailDomain}%`)
      paramIndex++
    }
    
    // Quality filters
    if (filters.confidenceScore) {
      if (filters.confidenceScore.min !== undefined) {
        whereConditions.push(`b.confidence_score >= $${paramIndex}`)
        params.push(filters.confidenceScore.min)
        paramIndex++
      }
      if (filters.confidenceScore.max !== undefined) {
        whereConditions.push(`b.confidence_score <= $${paramIndex}`)
        params.push(filters.confidenceScore.max)
        paramIndex++
      }
    }
    
    // Data completeness filter
    if (filters.dataCompleteness) {
      const completenessExpression = `
        (CASE WHEN b.name IS NOT NULL AND b.name != '' THEN 1 ELSE 0 END +
         CASE WHEN b.email IS NOT NULL AND array_length(b.email, 1) > 0 THEN 1 ELSE 0 END +
         CASE WHEN b.phone IS NOT NULL AND b.phone != '' THEN 1 ELSE 0 END +
         CASE WHEN b.website IS NOT NULL AND b.website != '' THEN 1 ELSE 0 END +
         CASE WHEN b.address IS NOT NULL AND b.address != '{}' THEN 1 ELSE 0 END +
         CASE WHEN b.contact_person IS NOT NULL AND b.contact_person != '' THEN 1 ELSE 0 END +
         CASE WHEN b.coordinates IS NOT NULL THEN 1 ELSE 0 END +
         CASE WHEN b.industry IS NOT NULL AND b.industry != '' THEN 1 ELSE 0 END) / 8.0
      `
      
      if (filters.dataCompleteness.min !== undefined) {
        whereConditions.push(`(${completenessExpression}) >= $${paramIndex}`)
        params.push(filters.dataCompleteness.min)
        paramIndex++
      }
      if (filters.dataCompleteness.max !== undefined) {
        whereConditions.push(`(${completenessExpression}) <= $${paramIndex}`)
        params.push(filters.dataCompleteness.max)
        paramIndex++
      }
    }
    
    // Date filters
    if (filters.scrapedDateRange) {
      if (filters.scrapedDateRange.start) {
        whereConditions.push(`b.scraped_at >= $${paramIndex}`)
        params.push(filters.scrapedDateRange.start)
        paramIndex++
      }
      if (filters.scrapedDateRange.end) {
        whereConditions.push(`b.scraped_at <= $${paramIndex}`)
        params.push(filters.scrapedDateRange.end)
        paramIndex++
      }
    }
    
    // Location filters
    if (filters.coordinates) {
      whereConditions.push(`
        ST_DWithin(
          ST_Point((b.coordinates->>'lng')::float, (b.coordinates->>'lat')::float)::geography,
          ST_Point($${paramIndex}, $${paramIndex + 1})::geography,
          $${paramIndex + 2} * 1609.34
        )
      `)
      params.push(filters.coordinates.lng, filters.coordinates.lat, filters.coordinates.radiusMiles)
      paramIndex += 3
    }
    
    if (filters.zipCodes && filters.zipCodes.length > 0) {
      whereConditions.push(`b.address->>'zipCode' = ANY($${paramIndex})`)
      params.push(filters.zipCodes)
      paramIndex++
    }
    
    if (filters.states && filters.states.length > 0) {
      whereConditions.push(`b.address->>'state' = ANY($${paramIndex})`)
      params.push(filters.states)
      paramIndex++
    }
    
    if (filters.cities && filters.cities.length > 0) {
      whereConditions.push(`b.address->>'city' = ANY($${paramIndex})`)
      params.push(filters.cities)
      paramIndex++
    }
    
    // Business characteristics
    if (filters.employeeCountRange) {
      if (filters.employeeCountRange.min !== undefined) {
        whereConditions.push(`b.employee_count >= $${paramIndex}`)
        params.push(filters.employeeCountRange.min)
        paramIndex++
      }
      if (filters.employeeCountRange.max !== undefined) {
        whereConditions.push(`b.employee_count <= $${paramIndex}`)
        params.push(filters.employeeCountRange.max)
        paramIndex++
      }
    }
    
    // Exclusion filters
    if (filters.excludeIndustries && filters.excludeIndustries.length > 0) {
      whereConditions.push(`b.industry NOT IN (${filters.excludeIndustries.map((_, i) => `$${paramIndex + i}`).join(', ')})`)
      params.push(...filters.excludeIndustries)
      paramIndex += filters.excludeIndustries.length
    }
    
    // Build WHERE clause
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : ''
    
    // Build ORDER BY clause
    let orderClause = ''
    if (sort.field === 'relevance_score' && filters.fullTextSearch) {
      orderClause = `ORDER BY ts_rank(to_tsvector('english', b.name || ' ' || COALESCE(b.industry, '')), plainto_tsquery('english', '${filters.fullTextSearch}')) DESC`
    } else {
      const sortField = this.mapSortField(sort.field)
      orderClause = `ORDER BY ${sortField} ${sort.order.toUpperCase()}`
      
      if (sort.secondarySort) {
        const secondarySortField = this.mapSortField(sort.secondarySort.field)
        orderClause += `, ${secondarySortField} ${sort.secondarySort.order.toUpperCase()}`
      }
      
      // Always add ID as final sort for consistent pagination
      orderClause += `, b.id ${sort.order.toUpperCase()}`
    }
    
    // Main query
    const query = `
      SELECT b.*, c.name as campaign_name
      FROM businesses b
      LEFT JOIN campaigns c ON b.campaign_id = c.id
      ${whereClause}
      ${orderClause}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `
    params.push(limit, offset)
    
    // Count query
    const countQuery = `
      SELECT 
        COUNT(*) as filtered_count,
        (SELECT COUNT(*) FROM businesses) as total_count
      FROM businesses b
      ${whereClause}
    `
    const countParams = params.slice(0, -2) // Remove limit and offset
    
    return { query, params, countQuery, countParams }
  }
  
  /**
   * Map sort field names to database columns
   */
  private mapSortField(field: string): string {
    const fieldMap: { [key: string]: string } = {
      'name': 'b.name',
      'industry': 'b.industry',
      'confidence_score': 'b.confidence_score',
      'scraped_at': 'b.scraped_at',
      'data_completeness': `(
        (CASE WHEN b.name IS NOT NULL AND b.name != '' THEN 1 ELSE 0 END +
         CASE WHEN b.email IS NOT NULL AND array_length(b.email, 1) > 0 THEN 1 ELSE 0 END +
         CASE WHEN b.phone IS NOT NULL AND b.phone != '' THEN 1 ELSE 0 END +
         CASE WHEN b.website IS NOT NULL AND b.website != '' THEN 1 ELSE 0 END +
         CASE WHEN b.address IS NOT NULL AND b.address != '{}' THEN 1 ELSE 0 END +
         CASE WHEN b.contact_person IS NOT NULL AND b.contact_person != '' THEN 1 ELSE 0 END +
         CASE WHEN b.coordinates IS NOT NULL THEN 1 ELSE 0 END +
         CASE WHEN b.industry IS NOT NULL AND b.industry != '' THEN 1 ELSE 0 END) / 8.0
      )`
    }
    
    return fieldMap[field] || 'b.scraped_at'
  }
  
  /**
   * Get aggregations for filtered data
   */
  private async getAggregations(filters: AdvancedFilterOptions): Promise<FilteredBusinessResult['aggregations']> {
    // This would be implemented with additional queries to get distribution data
    // For now, returning mock data structure
    return {
      industryDistribution: {},
      locationDistribution: {},
      confidenceScoreDistribution: {
        high: 0,
        medium: 0,
        low: 0
      },
      dataCompletenessStats: {
        average: 0,
        median: 0,
        distribution: {}
      }
    }
  }
  
  /**
   * Get indexes used for the query (for performance monitoring)
   */
  private getIndexesUsed(filters: AdvancedFilterOptions): string[] {
    const indexes: string[] = []
    
    if (filters.fullTextSearch) indexes.push('idx_businesses_name_gin')
    if (filters.industrySearch) indexes.push('idx_businesses_industry')
    if (filters.confidenceScore) indexes.push('idx_businesses_confidence_score')
    if (filters.scrapedDateRange) indexes.push('idx_businesses_scraped_at')
    if (filters.hasEmail !== undefined) indexes.push('idx_businesses_email_gin')
    
    return indexes
  }
  
  /**
   * Transform database row to BusinessRecord
   */
  private transformRowToBusiness(row: any): BusinessRecord {
    return {
      id: row.id,
      businessName: row.name,
      email: row.email || [],
      phone: row.phone,
      websiteUrl: row.website || '',
      address: row.address || {},
      contactPerson: row.contact_person,
      coordinates: row.coordinates,
      industry: row.industry || '',
      scrapedAt: new Date(row.scraped_at)
    }
  }
}

// Export singleton instance
export const enhancedFilteringService = new EnhancedFilteringService()
