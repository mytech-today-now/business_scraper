import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'
import { storage } from '@/model/storage'
import { BusinessRecord } from '@/types/business'
import { z } from 'zod'

/**
 * Query parameters schema for business pagination API
 */
const BusinessQuerySchema = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().min(1).max(1000).default(100),
  sortField: z.enum(['businessName', 'industry', 'scrapedAt', 'qualityScore']).default('scrapedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  search: z.string().optional(),
  industry: z.string().optional(),
  hasEmail: z
    .enum(['true', 'false'])
    .optional()
    .transform(val => (val === 'true' ? true : val === 'false' ? false : undefined)),
  hasPhone: z
    .enum(['true', 'false'])
    .optional()
    .transform(val => (val === 'true' ? true : val === 'false' ? false : undefined)),
  qualityScoreMin: z.coerce.number().min(0).max(100).optional(),
  qualityScoreMax: z.coerce.number().min(0).max(100).optional(),
  dateStart: z.string().optional(),
  dateEnd: z.string().optional(),
})

/**
 * Response interface for paginated business data
 */
interface PaginatedBusinessResponse {
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
 * Calculate quality score for a business record
 */
function calculateQualityScore(business: BusinessRecord): number {
  let score = 0

  // Business name (required) - 20 points
  if (business.businessName && business.businessName.trim().length > 0) {
    score += 20
  }

  // Email - 25 points
  if (business.email && business.email.includes('@')) {
    score += 25
  }

  // Phone - 20 points
  if (business.phone && business.phone.length >= 10) {
    score += 20
  }

  // Website - 15 points
  if (business.websiteUrl && business.websiteUrl.startsWith('http')) {
    score += 15
  }

  // Address - 10 points
  if (business.address && business.address.street && business.address.street.trim().length > 5) {
    score += 10
  }

  // Industry - 5 points
  if (business.industry && business.industry.trim().length > 0) {
    score += 5
  }

  // Contact Person - 5 points
  if (business.contactPerson && business.contactPerson.trim().length > 2) {
    score += 5
  }

  return Math.min(score, 100)
}

/**
 * Apply filters to business records
 */
function applyFilters(businesses: BusinessRecord[], filters: any): BusinessRecord[] {
  let filtered = businesses

  // Search filter
  if (filters.search) {
    const searchLower = filters.search.toLowerCase()
    filtered = filtered.filter(
      business =>
        business.businessName?.toLowerCase().includes(searchLower) ||
        business.email?.some(email => email.toLowerCase().includes(searchLower)) ||
        business.phone?.includes(filters.search) ||
        business.websiteUrl?.toLowerCase().includes(searchLower) ||
        business.address?.street?.toLowerCase().includes(searchLower) ||
        business.industry?.toLowerCase().includes(searchLower)
    )
  }

  // Industry filter
  if (filters.industry) {
    filtered = filtered.filter(business =>
      business.industry?.toLowerCase().includes(filters.industry.toLowerCase())
    )
  }

  // Email filter
  if (filters.hasEmail !== undefined) {
    filtered = filtered.filter(business => (filters.hasEmail ? !!business.email : !business.email))
  }

  // Phone filter
  if (filters.hasPhone !== undefined) {
    filtered = filtered.filter(business => (filters.hasPhone ? !!business.phone : !business.phone))
  }

  // Quality score filter
  if (filters.qualityScoreMin !== undefined || filters.qualityScoreMax !== undefined) {
    filtered = filtered.filter(business => {
      const score = calculateQualityScore(business)
      const min = filters.qualityScoreMin ?? 0
      const max = filters.qualityScoreMax ?? 100
      return score >= min && score <= max
    })
  }

  // Date range filter
  if (filters.dateStart || filters.dateEnd) {
    filtered = filtered.filter(business => {
      if (!business.scrapedAt) return false

      const businessDate = new Date(business.scrapedAt)
      const startDate = filters.dateStart ? new Date(filters.dateStart) : new Date(0)
      const endDate = filters.dateEnd ? new Date(filters.dateEnd) : new Date()

      return businessDate >= startDate && businessDate <= endDate
    })
  }

  return filtered
}

/**
 * Apply sorting to business records
 */
function applySorting(
  businesses: BusinessRecord[],
  sortField: string,
  sortOrder: string
): BusinessRecord[] {
  return businesses.sort((a, b) => {
    let aValue: any
    let bValue: any

    switch (sortField) {
      case 'businessName':
        aValue = a.businessName || ''
        bValue = b.businessName || ''
        break
      case 'industry':
        aValue = a.industry || ''
        bValue = b.industry || ''
        break
      case 'scrapedAt':
        aValue = a.scrapedAt ? new Date(a.scrapedAt).getTime() : 0
        bValue = b.scrapedAt ? new Date(b.scrapedAt).getTime() : 0
        break
      case 'qualityScore':
        aValue = calculateQualityScore(a)
        bValue = calculateQualityScore(b)
        break
      default:
        aValue = a.businessName || ''
        bValue = b.businessName || ''
    }

    if (sortOrder === 'asc') {
      return aValue < bValue ? -1 : aValue > bValue ? 1 : 0
    } else {
      return aValue > bValue ? -1 : aValue < bValue ? 1 : 0
    }
  })
}

/**
 * Generate cursor for pagination
 */
function generateCursor(business: BusinessRecord, sortField: string): string {
  const timestamp = business.scrapedAt ? new Date(business.scrapedAt).getTime() : Date.now()
  const value = business[sortField as keyof BusinessRecord] || ''
  return Buffer.from(`${timestamp}:${value}:${business.id}`).toString('base64')
}

/**
 * Parse cursor for pagination
 */
function parseCursor(cursor: string): { timestamp: number; value: string; id: string } | null {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf-8')
    const [timestamp, value, id] = decoded.split(':')

    if (!timestamp || !value || !id) {
      return null
    }

    return {
      timestamp: parseInt(timestamp),
      value,
      id,
    }
  } catch {
    return null
  }
}

/**
 * GET /api/businesses - Fetch paginated business data with filtering and sorting
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()

  try {
    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    const validatedParams = BusinessQuerySchema.parse(queryParams)

    logger.info('BusinessAPI', 'Fetching paginated businesses', {
      params: validatedParams,
      ip: request.ip,
    })

    // Get all businesses from storage
    const allBusinesses = await storage.getAllBusinesses()

    // Apply filters
    const filteredBusinesses = applyFilters(allBusinesses, validatedParams)

    // Apply sorting
    const sortedBusinesses = applySorting(
      filteredBusinesses,
      validatedParams.sortField,
      validatedParams.sortOrder
    )

    // Handle cursor-based pagination
    let startIndex = 0
    if (validatedParams.cursor) {
      const cursorData = parseCursor(validatedParams.cursor)
      if (cursorData) {
        // Find the index of the business after the cursor
        startIndex = sortedBusinesses.findIndex(business => {
          const businessTimestamp = business.scrapedAt ? new Date(business.scrapedAt).getTime() : 0
          const businessValue = business[validatedParams.sortField as keyof BusinessRecord] || ''

          if (validatedParams.sortOrder === 'desc') {
            return (
              businessTimestamp < cursorData.timestamp ||
              (businessTimestamp === cursorData.timestamp && businessValue < cursorData.value) ||
              (businessTimestamp === cursorData.timestamp &&
                businessValue === cursorData.value &&
                business.id === cursorData.id)
            )
          } else {
            return (
              businessTimestamp > cursorData.timestamp ||
              (businessTimestamp === cursorData.timestamp && businessValue > cursorData.value) ||
              (businessTimestamp === cursorData.timestamp &&
                businessValue === cursorData.value &&
                business.id === cursorData.id)
            )
          }
        })

        if (startIndex === -1) {
          startIndex = sortedBusinesses.length
        }
      }
    }

    // Get the page of results
    const endIndex = Math.min(startIndex + validatedParams.limit, sortedBusinesses.length)
    const pageBusinesses = sortedBusinesses.slice(startIndex, endIndex)

    // Generate next cursor
    let nextCursor: string | null = null
    if (endIndex < sortedBusinesses.length) {
      const lastBusiness = pageBusinesses[pageBusinesses.length - 1]
      if (lastBusiness) {
        nextCursor = generateCursor(lastBusiness, validatedParams.sortField)
      }
    }

    // Calculate current page number (approximate)
    const currentPage = Math.floor(startIndex / validatedParams.limit) + 1

    const processingTime = Date.now() - startTime

    const response: PaginatedBusinessResponse = {
      data: pageBusinesses,
      pagination: {
        nextCursor,
        hasMore: endIndex < sortedBusinesses.length,
        totalCount: filteredBusinesses.length,
        currentPage,
        pageSize: validatedParams.limit,
      },
      metadata: {
        processingTime,
        source: 'indexeddb',
        appliedFilters: {
          search: validatedParams.search,
          industry: validatedParams.industry,
          hasEmail: validatedParams.hasEmail,
          hasPhone: validatedParams.hasPhone,
          qualityScoreMin: validatedParams.qualityScoreMin,
          qualityScoreMax: validatedParams.qualityScoreMax,
          dateStart: validatedParams.dateStart,
          dateEnd: validatedParams.dateEnd,
        },
        sortConfig: {
          field: validatedParams.sortField,
          order: validatedParams.sortOrder,
        },
      },
    }

    logger.info('BusinessAPI', 'Successfully fetched paginated businesses', {
      totalCount: filteredBusinesses.length,
      pageSize: pageBusinesses.length,
      processingTime,
      hasMore: response.pagination.hasMore,
    })

    return NextResponse.json(response)
  } catch (error) {
    logger.error('BusinessAPI', 'Failed to fetch businesses', error)

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          error: 'Invalid query parameters',
          details: error.errors,
        },
        { status: 400 }
      )
    }

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * POST /api/businesses - Add new business records (bulk insert)
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()

    if (!Array.isArray(body.businesses)) {
      return NextResponse.json({ error: 'Expected array of businesses' }, { status: 400 })
    }

    const businesses: BusinessRecord[] = body.businesses

    // Save businesses to storage
    for (const business of businesses) {
      await storage.saveBusiness(business)
    }

    logger.info('BusinessAPI', `Saved ${businesses.length} businesses`)

    return NextResponse.json({
      success: true,
      count: businesses.length,
    })
  } catch (error) {
    logger.error('BusinessAPI', 'Failed to save businesses', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
