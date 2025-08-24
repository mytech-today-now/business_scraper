/**
 * Paginated Business Data API Endpoint
 * Supports virtual scrolling with cursor-based pagination, server-side filtering, and sorting
 */

import { NextRequest, NextResponse } from 'next/server'
import { database } from '@/lib/postgresql-database'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { getClientIP } from '@/lib/security'
import { enhancedFilteringService, AdvancedFilterOptions, SortOptions } from '@/lib/enhancedFilteringService'
import { z } from 'zod'

/**
 * Enhanced request validation schema with advanced filtering
 */
const PaginatedBusinessRequestSchema = z.object({
  cursor: z.string().optional(), // Cursor for pagination
  limit: z.number().min(1).max(1000).default(100), // Page size
  sortBy: z.enum(['name', 'industry', 'scraped_at', 'confidence_score', 'data_completeness', 'relevance_score']).default('scraped_at'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),

  // Enhanced filters
  filters: z.object({
    // Text search
    fullTextSearch: z.string().optional(),
    businessNameSearch: z.string().optional(),
    industrySearch: z.string().optional(),
    locationSearch: z.string().optional(),

    // Contact filters
    hasEmail: z.boolean().optional(),
    hasPhone: z.boolean().optional(),
    hasWebsite: z.boolean().optional(),
    emailDomain: z.string().optional(),
    phoneAreaCode: z.string().optional(),

    // Quality filters
    confidenceScore: z.object({
      min: z.number().min(0).max(1).optional(),
      max: z.number().min(0).max(1).optional()
    }).optional(),
    dataCompleteness: z.object({
      min: z.number().min(0).max(1).optional(),
      max: z.number().min(0).max(1).optional()
    }).optional(),

    // Date filters
    scrapedDateRange: z.object({
      start: z.string().optional(),
      end: z.string().optional()
    }).optional(),

    // Location filters
    coordinates: z.object({
      lat: z.number(),
      lng: z.number(),
      radiusMiles: z.number()
    }).optional(),
    zipCodes: z.array(z.string()).optional(),
    states: z.array(z.string()).optional(),
    cities: z.array(z.string()).optional(),

    // Business characteristics
    employeeCountRange: z.object({
      min: z.number().optional(),
      max: z.number().optional()
    }).optional(),
    revenueRange: z.object({
      min: z.number().optional(),
      max: z.number().optional()
    }).optional(),
    foundedYearRange: z.object({
      start: z.number().optional(),
      end: z.number().optional()
    }).optional(),

    // Advanced filters
    hasSocialMedia: z.boolean().optional(),
    hasBusinessHours: z.boolean().optional(),
    isEstablishedBusiness: z.boolean().optional(),

    // Exclusion filters
    excludeIndustries: z.array(z.string()).optional(),
    excludeDomains: z.array(z.string()).optional(),
    excludeBusinessNames: z.array(z.string()).optional()
  }).optional()
})

/**
 * Response interface
 */
interface PaginatedBusinessResponse {
  success: boolean
  data: BusinessRecord[]
  pagination: {
    nextCursor: string | null
    hasMore: boolean
    totalCount: number
    currentPage: number
    pageSize: number
  }
  metadata: {
    processingTime: number
    source: 'postgresql' | 'indexeddb'
    appliedFilters: Record<string, any>
    sortConfig: {
      field: string
      order: string
    }
  }
}

/**
 * GET /api/businesses/paginated - Get paginated business data with filtering and sorting
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  const startTime = Date.now()

  try {
    logger.info('PaginatedBusinessAPI', `Request from IP: ${ip}`)

    // Parse query parameters
    const url = new URL(request.url)
    const queryParams = {
      cursor: url.searchParams.get('cursor') || undefined,
      limit: parseInt(url.searchParams.get('limit') || '100'),
      sortBy: url.searchParams.get('sortBy') || 'scrapedAt',
      sortOrder: url.searchParams.get('sortOrder') || 'desc',
      filters: {
        search: url.searchParams.get('search') || undefined,
        industry: url.searchParams.get('industry') || undefined,
        hasEmail: url.searchParams.get('hasEmail') ? url.searchParams.get('hasEmail') === 'true' : undefined,
        hasPhone: url.searchParams.get('hasPhone') ? url.searchParams.get('hasPhone') === 'true' : undefined,
        qualityScore: {
          min: url.searchParams.get('qualityScoreMin') ? parseFloat(url.searchParams.get('qualityScoreMin')!) : undefined,
          max: url.searchParams.get('qualityScoreMax') ? parseFloat(url.searchParams.get('qualityScoreMax')!) : undefined
        },
        dateRange: {
          start: url.searchParams.get('dateStart') || undefined,
          end: url.searchParams.get('dateEnd') || undefined
        }
      }
    }

    // Validate request parameters
    const validatedParams = PaginatedBusinessRequestSchema.parse(queryParams)

    // Use enhanced filtering service for PostgreSQL
    let result: PaginatedBusinessResponse
    let source: 'postgresql' | 'indexeddb' = 'postgresql'

    try {
      // Convert to enhanced filter format
      const enhancedFilters: AdvancedFilterOptions = {
        fullTextSearch: validatedParams.filters?.fullTextSearch,
        businessNameSearch: validatedParams.filters?.businessNameSearch,
        industrySearch: validatedParams.filters?.industrySearch,
        locationSearch: validatedParams.filters?.locationSearch,
        hasEmail: validatedParams.filters?.hasEmail,
        hasPhone: validatedParams.filters?.hasPhone,
        hasWebsite: validatedParams.filters?.hasWebsite,
        emailDomain: validatedParams.filters?.emailDomain,
        phoneAreaCode: validatedParams.filters?.phoneAreaCode,
        confidenceScore: validatedParams.filters?.confidenceScore,
        dataCompleteness: validatedParams.filters?.dataCompleteness,
        scrapedDateRange: validatedParams.filters?.scrapedDateRange,
        coordinates: validatedParams.filters?.coordinates,
        zipCodes: validatedParams.filters?.zipCodes,
        states: validatedParams.filters?.states,
        cities: validatedParams.filters?.cities,
        employeeCountRange: validatedParams.filters?.employeeCountRange,
        revenueRange: validatedParams.filters?.revenueRange,
        foundedYearRange: validatedParams.filters?.foundedYearRange,
        hasSocialMedia: validatedParams.filters?.hasSocialMedia,
        hasBusinessHours: validatedParams.filters?.hasBusinessHours,
        isEstablishedBusiness: validatedParams.filters?.isEstablishedBusiness,
        excludeIndustries: validatedParams.filters?.excludeIndustries,
        excludeDomains: validatedParams.filters?.excludeDomains,
        excludeBusinessNames: validatedParams.filters?.excludeBusinessNames
      }

      const sortOptions: SortOptions = {
        field: validatedParams.sortBy as any,
        order: validatedParams.sortOrder
      }

      // Calculate offset from cursor (simplified for now)
      const offset = validatedParams.cursor ? parseInt(Buffer.from(validatedParams.cursor, 'base64').toString()) : 0

      const enhancedResult = await enhancedFilteringService.filterBusinesses(
        enhancedFilters,
        sortOptions,
        validatedParams.limit,
        offset
      )

      // Convert to expected response format
      result = {
        success: true,
        data: enhancedResult.businesses,
        pagination: {
          nextCursor: enhancedResult.businesses.length === validatedParams.limit
            ? Buffer.from((offset + validatedParams.limit).toString()).toString('base64')
            : null,
          hasMore: enhancedResult.businesses.length === validatedParams.limit,
          totalCount: enhancedResult.totalCount,
          currentPage: Math.floor(offset / validatedParams.limit) + 1,
          pageSize: validatedParams.limit
        },
        metadata: {
          processingTime: enhancedResult.queryPerformance.executionTimeMs,
          source: 'postgresql',
          appliedFilters: validatedParams.filters || {},
          sortConfig: {
            field: validatedParams.sortBy,
            order: validatedParams.sortOrder
          }
        }
      }

    } catch (postgresError) {
      logger.warn('PaginatedBusinessAPI', 'Enhanced filtering failed, falling back to IndexedDB', postgresError)
      source = 'indexeddb'
      result = await getPaginatedBusinessesFromIndexedDB(validatedParams)
      result.metadata.source = source
    }

    result.metadata.processingTime = Date.now() - startTime
    logger.info('PaginatedBusinessAPI', `Returned ${result.data.length} businesses from ${source}`)

    return NextResponse.json(result)

  } catch (error) {
    logger.error('PaginatedBusinessAPI', 'Request failed', error)
    
    return NextResponse.json({
      success: false,
      error: 'Failed to fetch paginated business data',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

/**
 * Get paginated businesses from PostgreSQL
 */
async function getPaginatedBusinessesFromPostgreSQL(params: z.infer<typeof PaginatedBusinessRequestSchema>): Promise<PaginatedBusinessResponse> {
  const { cursor, limit, sortBy, sortOrder, filters } = params

  // Build WHERE clause for filtering
  const whereConditions: string[] = []
  const queryParams: any[] = []
  let paramIndex = 1

  if (filters?.search) {
    whereConditions.push(`(
      business_name ILIKE $${paramIndex} OR 
      email::text ILIKE $${paramIndex} OR 
      website_url ILIKE $${paramIndex} OR 
      address::text ILIKE $${paramIndex}
    )`)
    queryParams.push(`%${filters.search}%`)
    paramIndex++
  }

  if (filters?.industry) {
    whereConditions.push(`industry = $${paramIndex}`)
    queryParams.push(filters.industry)
    paramIndex++
  }

  if (filters?.hasEmail !== undefined) {
    if (filters.hasEmail) {
      whereConditions.push(`email IS NOT NULL AND array_length(email, 1) > 0`)
    } else {
      whereConditions.push(`(email IS NULL OR array_length(email, 1) = 0)`)
    }
  }

  if (filters?.hasPhone !== undefined) {
    if (filters.hasPhone) {
      whereConditions.push(`phone IS NOT NULL AND phone != ''`)
    } else {
      whereConditions.push(`(phone IS NULL OR phone = '')`)
    }
  }

  if (filters?.dateRange?.start) {
    whereConditions.push(`scraped_at >= $${paramIndex}`)
    queryParams.push(filters.dateRange.start)
    paramIndex++
  }

  if (filters?.dateRange?.end) {
    whereConditions.push(`scraped_at <= $${paramIndex}`)
    queryParams.push(filters.dateRange.end)
    paramIndex++
  }

  // Handle cursor-based pagination
  if (cursor) {
    const decodedCursor = JSON.parse(Buffer.from(cursor, 'base64').toString())
    whereConditions.push(`(${sortBy}, id) ${sortOrder === 'asc' ? '>' : '<'} ($${paramIndex}, $${paramIndex + 1})`)
    queryParams.push(decodedCursor.sortValue, decodedCursor.id)
    paramIndex += 2
  }

  const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : ''

  // Build ORDER BY clause
  const orderClause = `ORDER BY ${sortBy} ${sortOrder.toUpperCase()}, id ${sortOrder.toUpperCase()}`

  // Get total count (for metadata)
  const countQuery = `
    SELECT COUNT(*) as total 
    FROM businesses 
    ${whereClause.replace(/\(\w+, id\)[<>]\(\$\d+, \$\d+\)/, '')}
  `
  const countParams = queryParams.slice(0, -2) // Remove cursor params for count

  // Get paginated data
  const dataQuery = `
    SELECT * FROM businesses 
    ${whereClause}
    ${orderClause}
    LIMIT $${paramIndex}
  `
  queryParams.push(limit + 1) // Get one extra to check if there are more

  const [countResult, dataResult] = await Promise.all([
    database.query(countQuery, countParams),
    database.query(dataQuery, queryParams)
  ])

  const totalCount = parseInt(countResult.rows[0].total)
  const businesses = dataResult.rows.slice(0, limit) // Remove the extra record
  const hasMore = dataResult.rows.length > limit

  // Generate next cursor
  let nextCursor: string | null = null
  if (hasMore && businesses.length > 0) {
    const lastBusiness = businesses[businesses.length - 1]
    const cursorData = {
      sortValue: lastBusiness[sortBy],
      id: lastBusiness.id
    }
    nextCursor = Buffer.from(JSON.stringify(cursorData)).toString('base64')
  }

  return {
    success: true,
    data: businesses.map(transformPostgreSQLToBusiness),
    pagination: {
      nextCursor,
      hasMore,
      totalCount,
      currentPage: cursor ? -1 : 1, // Page numbers don't apply to cursor pagination
      pageSize: limit
    },
    metadata: {
      processingTime: 0, // Will be set by caller
      source: 'postgresql',
      appliedFilters: filters || {},
      sortConfig: {
        field: sortBy,
        order: sortOrder
      }
    }
  }
}

/**
 * Get paginated businesses from IndexedDB (fallback)
 */
async function getPaginatedBusinessesFromIndexedDB(params: z.infer<typeof PaginatedBusinessRequestSchema>): Promise<PaginatedBusinessResponse> {
  const { cursor, limit, sortBy, sortOrder, filters } = params

  // Get all businesses from IndexedDB
  const allBusinesses = await storage.getAllBusinesses()

  // Apply filters
  let filteredBusinesses = allBusinesses

  if (filters?.search) {
    const searchLower = filters.search.toLowerCase()
    filteredBusinesses = filteredBusinesses.filter(business =>
      business.businessName.toLowerCase().includes(searchLower) ||
      business.email.some(email => email.toLowerCase().includes(searchLower)) ||
      business.websiteUrl.toLowerCase().includes(searchLower) ||
      `${business.address.street} ${business.address.city} ${business.address.state}`.toLowerCase().includes(searchLower)
    )
  }

  if (filters?.industry) {
    filteredBusinesses = filteredBusinesses.filter(business => business.industry === filters.industry)
  }

  if (filters?.hasEmail !== undefined) {
    filteredBusinesses = filteredBusinesses.filter(business => 
      filters.hasEmail ? business.email.length > 0 : business.email.length === 0
    )
  }

  if (filters?.hasPhone !== undefined) {
    filteredBusinesses = filteredBusinesses.filter(business => 
      filters.hasPhone ? !!business.phone : !business.phone
    )
  }

  if (filters?.dateRange?.start) {
    const startDate = new Date(filters.dateRange.start)
    filteredBusinesses = filteredBusinesses.filter(business => business.scrapedAt >= startDate)
  }

  if (filters?.dateRange?.end) {
    const endDate = new Date(filters.dateRange.end)
    filteredBusinesses = filteredBusinesses.filter(business => business.scrapedAt <= endDate)
  }

  // Apply sorting
  filteredBusinesses.sort((a, b) => {
    const aValue = a[sortBy as keyof BusinessRecord]
    const bValue = b[sortBy as keyof BusinessRecord]
    
    let comparison = 0
    if (aValue < bValue) comparison = -1
    else if (aValue > bValue) comparison = 1
    
    return sortOrder === 'desc' ? -comparison : comparison
  })

  // Handle cursor-based pagination
  let startIndex = 0
  if (cursor) {
    const decodedCursor = JSON.parse(Buffer.from(cursor, 'base64').toString())
    startIndex = filteredBusinesses.findIndex(business => business.id === decodedCursor.id) + 1
  }

  const paginatedBusinesses = filteredBusinesses.slice(startIndex, startIndex + limit)
  const hasMore = startIndex + limit < filteredBusinesses.length

  // Generate next cursor
  let nextCursor: string | null = null
  if (hasMore && paginatedBusinesses.length > 0) {
    const lastBusiness = paginatedBusinesses[paginatedBusinesses.length - 1]
    const cursorData = {
      sortValue: lastBusiness[sortBy as keyof BusinessRecord],
      id: lastBusiness.id
    }
    nextCursor = Buffer.from(JSON.stringify(cursorData)).toString('base64')
  }

  return {
    success: true,
    data: paginatedBusinesses,
    pagination: {
      nextCursor,
      hasMore,
      totalCount: filteredBusinesses.length,
      currentPage: Math.floor(startIndex / limit) + 1,
      pageSize: limit
    },
    metadata: {
      processingTime: 0, // Will be set by caller
      source: 'indexeddb',
      appliedFilters: filters || {},
      sortConfig: {
        field: sortBy,
        order: sortOrder
      }
    }
  }
}

/**
 * Transform PostgreSQL row to BusinessRecord
 */
function transformPostgreSQLToBusiness(row: any): BusinessRecord {
  return {
    id: row.id,
    businessName: row.business_name,
    email: row.email || [],
    phone: row.phone,
    websiteUrl: row.website_url,
    address: row.address || {},
    contactPerson: row.contact_person,
    coordinates: row.coordinates,
    industry: row.industry,
    scrapedAt: new Date(row.scraped_at)
  }
}
