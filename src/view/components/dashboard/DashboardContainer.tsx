/**
 * Dashboard Container
 * Main container for the Advanced Results Dashboard with security boundaries
 */

'use client'

import React, { useState, useEffect } from 'react'
import { SecurityBoundary, SecurityUtils } from '../security/SecurityBoundary'
import { SearchAndFilters } from './SearchAndFilters'
import { ResultsViewManager } from './ResultsViewManager'
import { BulkActionsPanel } from './BulkActionsPanel'
import { DataVisualization } from './DataVisualization'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

export interface AdvancedFilter {
  field: string
  operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'gt' | 'lt' | 'between'
  value: any
  secondValue?: any
}

export interface SavedQuery {
  id: string
  name: string
  description: string
  filters: AdvancedFilter[]
  sorting: { field: string; direction: 'asc' | 'desc' }[]
  createdAt: Date
  isPublic: boolean
}

export interface ResultAnnotation {
  id: string
  businessId: string
  type: 'note' | 'flag' | 'rating' | 'tag'
  content: string
  rating?: number
  tags?: string[]
  createdAt: Date
  createdBy: string
}

export type ViewMode = 'table' | 'grid' | 'map' | 'streaming'

/**
 * Main Dashboard Container with security boundaries
 */
export function DashboardContainer(): JSX.Element {
  const [businesses, setBusinesses] = useState<BusinessRecord[]>([])
  const [filteredBusinesses, setFilteredBusinesses] = useState<BusinessRecord[]>([])
  const [selectedBusinesses, setSelectedBusinesses] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<ViewMode>('table')
  const [showVisualization, setShowVisualization] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  // Advanced filtering and search
  const [searchQuery, setSearchQuery] = useState('')
  const [advancedFilters, setAdvancedFilters] = useState<AdvancedFilter[]>([])
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([])

  // Sorting and pagination
  const [sortConfig, setSortConfig] = useState<{ field: string; direction: 'asc' | 'desc' }[]>([])
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10000)

  // Annotations
  const [annotations, setAnnotations] = useState<ResultAnnotation[]>([])

  // Load data on component mount
  useEffect(() => {
    loadBusinesses()
    loadSavedQueries()
    loadAnnotations()
  }, [])

  // Apply filters and search when data changes
  useEffect(() => {
    applyFiltersAndSearch()
  }, [businesses, searchQuery, advancedFilters, sortConfig])

  /**
   * Secure data loading with validation
   */
  const loadBusinesses = async () => {
    setIsLoading(true)
    try {
      // In a real implementation, this would fetch from your API
      // For now, we'll use mock data
      const mockBusinesses: BusinessRecord[] = [
        {
          id: '1',
          businessName: "Joe's Pizza",
          industry: 'Restaurant',
          email: ['info@joespizza.com'],
          phone: '(555) 123-4567',
          websiteUrl: 'https://joespizza.com',
          address: { street: '123 Main St', city: 'New York', state: 'NY', zipCode: '10001' },
          scrapedAt: new Date('2024-01-15'),
        },
      ]

      // Validate and sanitize loaded data
      const validatedBusinesses = mockBusinesses.map(business => {
        const validation = SecurityUtils.validateBusinessData(business)
        if (!validation.isValid) {
          logger.warn('DashboardContainer', 'Invalid business data loaded', validation.errors)
        }
        return SecurityUtils.sanitizeBusinessData(business)
      })

      setBusinesses(validatedBusinesses)
      logger.info('DashboardContainer', `Loaded ${validatedBusinesses.length} businesses`)
    } catch (error) {
      logger.error('DashboardContainer', 'Failed to load businesses', error)
      toast.error('Failed to load business data')
    } finally {
      setIsLoading(false)
    }
  }

  /**
   * Load saved queries with validation
   */
  const loadSavedQueries = async () => {
    try {
      // Mock saved queries - in real implementation, fetch from API
      const mockQueries: SavedQuery[] = [
        {
          id: '1',
          name: 'Restaurant Businesses',
          description: 'All restaurant businesses',
          filters: [{ field: 'industry', operator: 'equals', value: 'Restaurant' }],
          sorting: [{ field: 'businessName', direction: 'asc' }],
          createdAt: new Date('2024-01-10'),
          isPublic: true,
        },
      ]
      setSavedQueries(mockQueries)
    } catch (error) {
      logger.error('DashboardContainer', 'Failed to load saved queries', error)
    }
  }

  /**
   * Load annotations with validation
   */
  const loadAnnotations = async () => {
    try {
      // Mock annotations - in real implementation, fetch from API
      const mockAnnotations: ResultAnnotation[] = [
        {
          id: '1',
          businessId: '1',
          type: 'rating',
          content: 'High quality lead',
          rating: 5,
          createdAt: new Date('2024-01-16'),
          createdBy: 'user@example.com',
        },
      ]
      setAnnotations(mockAnnotations)
    } catch (error) {
      logger.error('DashboardContainer', 'Failed to load annotations', error)
    }
  }

  /**
   * Apply filters and search with security validation
   */
  const applyFiltersAndSearch = () => {
    try {
      let filtered = [...businesses]

      // Apply search query with sanitization
      if (searchQuery) {
        const sanitizedQuery = searchQuery.toLowerCase().trim()
        filtered = filtered.filter(
          business =>
            business.businessName.toLowerCase().includes(sanitizedQuery) ||
            business.industry.toLowerCase().includes(sanitizedQuery) ||
            business.email.some(email => email.toLowerCase().includes(sanitizedQuery)) ||
            (business.phone && business.phone.toLowerCase().includes(sanitizedQuery)) ||
            (business.websiteUrl && business.websiteUrl.toLowerCase().includes(sanitizedQuery))
        )
      }

      // Apply advanced filters
      advancedFilters.forEach(filter => {
        filtered = filtered.filter(business => {
          const fieldValue = getFieldValue(business, filter.field)
          return applyFilterOperator(fieldValue, filter.operator, filter.value, filter.secondValue)
        })
      })

      // Apply sorting
      if (sortConfig.length > 0) {
        filtered.sort((a, b) => {
          for (const sort of sortConfig) {
            const aValue = getFieldValue(a, sort.field)
            const bValue = getFieldValue(b, sort.field)

            let comparison = 0
            if (aValue < bValue) comparison = -1
            else if (aValue > bValue) comparison = 1

            if (comparison !== 0) {
              return sort.direction === 'desc' ? -comparison : comparison
            }
          }
          return 0
        })
      }

      setFilteredBusinesses(filtered)
      setCurrentPage(1)
    } catch (error) {
      logger.error('DashboardContainer', 'Failed to apply filters', error)
      toast.error('Failed to apply filters')
    }
  }

  /**
   * Get field value from business record
   */
  const getFieldValue = (business: BusinessRecord, field: string): any => {
    switch (field) {
      case 'businessName':
        return business.businessName
      case 'industry':
        return business.industry
      case 'email':
        return business.email.join(', ')
      case 'phone':
        return business.phone || ''
      case 'website':
        return business.websiteUrl || ''
      case 'city':
        return business.address?.city || ''
      case 'state':
        return business.address?.state || ''
      case 'scrapedAt':
        return business.scrapedAt
      default:
        return ''
    }
  }

  /**
   * Apply filter operator
   */
  const applyFilterOperator = (
    fieldValue: any,
    operator: string,
    value: any,
    secondValue?: any
  ): boolean => {
    switch (operator) {
      case 'equals':
        return fieldValue === value
      case 'contains':
        return String(fieldValue).toLowerCase().includes(String(value).toLowerCase())
      case 'startsWith':
        return String(fieldValue).toLowerCase().startsWith(String(value).toLowerCase())
      case 'endsWith':
        return String(fieldValue).toLowerCase().endsWith(String(value).toLowerCase())
      case 'gt':
        return Number(fieldValue) > Number(value)
      case 'lt':
        return Number(fieldValue) < Number(value)
      case 'between':
        return Number(fieldValue) >= Number(value) && Number(fieldValue) <= Number(secondValue)
      default:
        return true
    }
  }

  /**
   * Secure bulk action handler
   */
  const handleBulkAction = async (action: string) => {
    try {
      const selectedIds = Array.from(selectedBusinesses)
      logger.info('DashboardContainer', `Performing bulk action: ${action} on ${selectedIds.length} items`)

      // Validate selected businesses exist
      const validBusinesses = selectedIds.filter(id => businesses.find(b => b.id === id))
      if (validBusinesses.length !== selectedIds.length) {
        toast.error('Some selected businesses are no longer available')
        return
      }

      switch (action) {
        case 'export':
          // Export selected businesses
          break
        case 'tag':
          // Add tags to selected businesses
          break
        case 'delete':
          // Delete selected businesses
          break
        case 'annotate':
          // Add annotation to selected businesses
          break
      }

      await loadBusinesses()
      setSelectedBusinesses(new Set())
    } catch (error) {
      logger.error('DashboardContainer', `Bulk action ${action} failed`, error)
      toast.error(`Bulk action failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  return (
    <SecurityBoundary componentName="DashboardContainer">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Results Dashboard</h1>
            <p className="text-gray-600 mt-1">
              {filteredBusinesses.length} of {businesses.length} businesses
              {selectedBusinesses.size > 0 && ` • ${selectedBusinesses.size} selected`}
            </p>
          </div>
        </div>

        {/* Search and Filters */}
        <SearchAndFilters
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          advancedFilters={advancedFilters}
          onFiltersChange={setAdvancedFilters}
          savedQueries={savedQueries}
          onLoadQuery={(query) => {
            setAdvancedFilters(query.filters)
            setSortConfig(query.sorting)
          }}
        />

        {/* Bulk Actions */}
        {selectedBusinesses.size > 0 && (
          <BulkActionsPanel
            selectedCount={selectedBusinesses.size}
            onBulkAction={handleBulkAction}
            onClearSelection={() => setSelectedBusinesses(new Set())}
          />
        )}

        {/* Data Visualization */}
        {showVisualization && (
          <DataVisualization
            businesses={businesses}
            onClose={() => setShowVisualization(false)}
          />
        )}

        {/* Results View */}
        <ResultsViewManager
          businesses={filteredBusinesses}
          selectedBusinesses={selectedBusinesses}
          onToggleSelection={(businessId) => {
            const newSelection = new Set(selectedBusinesses)
            if (newSelection.has(businessId)) {
              newSelection.delete(businessId)
            } else {
              newSelection.add(businessId)
            }
            setSelectedBusinesses(newSelection)
          }}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          sortConfig={sortConfig}
          onSortChange={setSortConfig}
          annotations={annotations}
          isLoading={isLoading}
          currentPage={currentPage}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
        />
      </div>
    </SecurityBoundary>
  )
}
