'use client'

import React, { useState, useMemo, useCallback } from 'react'
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Edit,
  Trash2,
  ExternalLink,
  Search,
  Filter,
  SortAsc,
  SortDesc,
} from 'lucide-react'
import { BusinessRecord } from '@/types/business'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { formatBusinessName, formatAddress, formatPhoneNumber, formatUrl } from '@/utils/formatters'
import { clsx } from 'clsx'
import { usePerformance } from '@/controller/PerformanceContext'
import { DEFAULT_PAGINATION_CONFIG } from '@/types/performance'

/**
 * Paginated Results Table Props
 */
interface PaginatedResultsTableProps {
  /** Business records to display */
  businesses: BusinessRecord[]
  /** Edit business callback */
  onEdit: (id: string, updates: Partial<BusinessRecord>) => void
  /** Delete business callback */
  onDelete: (id: string) => void
  /** Export callback */
  onExport?: () => void
  /** Loading state */
  isLoading?: boolean
  /** Exporting state */
  isExporting?: boolean
  /** Additional CSS classes */
  className?: string
}

/**
 * Sort configuration
 */
interface SortConfig {
  key: keyof BusinessRecord | null
  direction: 'asc' | 'desc'
}

/**
 * Filter configuration
 */
interface FilterConfig {
  search: string
  industry: string
  hasEmail: boolean | null
  hasPhone: boolean | null
}

/**
 * Paginated Results Table Component
 * Optimized table with pagination for medium-sized datasets (2,500+ results)
 */
export function PaginatedResultsTable({
  businesses,
  onEdit,
  onDelete,
  onExport,
  isLoading = false,
  isExporting = false,
  className,
}: PaginatedResultsTableProps) {
  const { preferences, currentPage, setCurrentPage } = usePerformance()

  // State management
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: null, direction: 'asc' })
  const [filterConfig, setFilterConfig] = useState<FilterConfig>({
    search: '',
    industry: '',
    hasEmail: null,
    hasPhone: null,
  })
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set())
  const [pageSize, setPageSize] = useState(
    preferences.pageSize || DEFAULT_PAGINATION_CONFIG.pageSize
  )

  // Filtered and sorted data
  const filteredAndSortedBusinesses = useMemo(() => {
    let filtered = businesses

    // Apply filters
    if (filterConfig.search) {
      const searchLower = filterConfig.search.toLowerCase()
      filtered = filtered.filter(
        business =>
          business.businessName.toLowerCase().includes(searchLower) ||
          business.address.toLowerCase().includes(searchLower) ||
          business.email?.toLowerCase().includes(searchLower) ||
          business.phone?.includes(filterConfig.search)
      )
    }

    if (filterConfig.industry) {
      filtered = filtered.filter(business =>
        business.industry?.toLowerCase().includes(filterConfig.industry.toLowerCase())
      )
    }

    if (filterConfig.hasEmail !== null) {
      filtered = filtered.filter(business =>
        filterConfig.hasEmail ? !!business.email : !business.email
      )
    }

    if (filterConfig.hasPhone !== null) {
      filtered = filtered.filter(business =>
        filterConfig.hasPhone ? !!business.phone : !business.phone
      )
    }

    // Apply sorting
    if (sortConfig.key) {
      filtered.sort((a, b) => {
        const aValue = a[sortConfig.key!]
        const bValue = b[sortConfig.key!]

        if (aValue === null || aValue === undefined) return 1
        if (bValue === null || bValue === undefined) return -1

        if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1
        if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1
        return 0
      })
    }

    return filtered
  }, [businesses, filterConfig, sortConfig])

  // Pagination calculations
  const totalPages = Math.ceil(filteredAndSortedBusinesses.length / pageSize)
  const startIndex = (currentPage - 1) * pageSize
  const endIndex = startIndex + pageSize
  const currentPageData = filteredAndSortedBusinesses.slice(startIndex, endIndex)

  // Selection handlers
  const allSelected =
    currentPageData.length > 0 && currentPageData.every(b => selectedRows.has(b.id))
  const someSelected = currentPageData.some(b => selectedRows.has(b.id)) && !allSelected

  const handleSort = useCallback((key: keyof BusinessRecord) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }))
  }, [])

  const handleRowSelect = useCallback((id: string, selected: boolean) => {
    setSelectedRows(prev => {
      const newSet = new Set(prev)
      if (selected) {
        newSet.add(id)
      } else {
        newSet.delete(id)
      }
      return newSet
    })
  }, [])

  const handleSelectAll = useCallback(
    (selected: boolean) => {
      if (selected) {
        setSelectedRows(prev => {
          const newSet = new Set(prev)
          currentPageData.forEach(business => newSet.add(business.id))
          return newSet
        })
      } else {
        setSelectedRows(prev => {
          const newSet = new Set(prev)
          currentPageData.forEach(business => newSet.delete(business.id))
          return newSet
        })
      }
    },
    [currentPageData]
  )

  const handlePageChange = useCallback(
    (page: number) => {
      setCurrentPage(Math.max(1, Math.min(page, totalPages)))
    },
    [setCurrentPage, totalPages]
  )

  const handlePageSizeChange = useCallback(
    (newPageSize: number) => {
      setPageSize(newPageSize)
      setCurrentPage(1) // Reset to first page when changing page size
    },
    [setCurrentPage]
  )

  /**
   * Render sortable column header
   */
  const renderSortableHeader = (key: keyof BusinessRecord, label: string) => (
    <button
      type="button"
      className="flex items-center gap-1 hover:text-primary transition-colors font-medium text-sm"
      onClick={() => handleSort(key)}
    >
      {label}
      {sortConfig.key === key &&
        (sortConfig.direction === 'asc' ? (
          <SortAsc className="h-3 w-3" />
        ) : (
          <SortDesc className="h-3 w-3" />
        ))}
    </button>
  )

  /**
   * Render pagination controls
   */
  const renderPaginationControls = () => (
    <div className="flex items-center justify-between px-4 py-3 border-t bg-muted/20">
      <div className="flex items-center gap-4 text-sm text-muted-foreground">
        <span>
          Showing {startIndex + 1} to {Math.min(endIndex, filteredAndSortedBusinesses.length)} of{' '}
          {filteredAndSortedBusinesses.length} results
        </span>

        {DEFAULT_PAGINATION_CONFIG.showPageSizeSelector && (
          <div className="flex items-center gap-2">
            <span>Show:</span>
            <select
              value={pageSize}
              onChange={e => handlePageSizeChange(Number(e.target.value))}
              className="border rounded px-2 py-1 text-sm bg-background"
            >
              {DEFAULT_PAGINATION_CONFIG.pageSizeOptions.map(size => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
            <span>per page</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => handlePageChange(1)}
          disabled={currentPage === 1}
          className="h-8 w-8 p-0"
        >
          <ChevronsLeft className="h-4 w-4" />
        </Button>

        <Button
          variant="outline"
          size="sm"
          onClick={() => handlePageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="h-8 w-8 p-0"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>

        <div className="flex items-center gap-1">
          {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
            let pageNum
            if (totalPages <= 5) {
              pageNum = i + 1
            } else if (currentPage <= 3) {
              pageNum = i + 1
            } else if (currentPage >= totalPages - 2) {
              pageNum = totalPages - 4 + i
            } else {
              pageNum = currentPage - 2 + i
            }

            return (
              <Button
                key={pageNum}
                variant={currentPage === pageNum ? 'default' : 'outline'}
                size="sm"
                onClick={() => handlePageChange(pageNum)}
                className="h-8 w-8 p-0"
              >
                {pageNum}
              </Button>
            )
          })}
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => handlePageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="h-8 w-8 p-0"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>

        <Button
          variant="outline"
          size="sm"
          onClick={() => handlePageChange(totalPages)}
          disabled={currentPage === totalPages}
          className="h-8 w-8 p-0"
        >
          <ChevronsRight className="h-4 w-4" />
        </Button>

        {DEFAULT_PAGINATION_CONFIG.showQuickJump && (
          <div className="flex items-center gap-2 ml-4">
            <span className="text-sm">Go to:</span>
            <Input
              type="number"
              min={1}
              max={totalPages}
              value={currentPage}
              onChange={e => {
                const page = parseInt(e.target.value)
                if (!isNaN(page)) {
                  handlePageChange(page)
                }
              }}
              className="w-16 h-8 text-center"
            />
          </div>
        )}
      </div>
    </div>
  )

  if (businesses.length === 0) {
    return (
      <Card className={className}>
        <CardContent className="p-8 text-center">
          <p className="text-muted-foreground">No business records found.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <span>Business Results</span>
            <span className="text-sm font-normal text-muted-foreground">
              ({filteredAndSortedBusinesses.length.toLocaleString()} results - Paginated View)
            </span>
          </CardTitle>

          <div className="flex items-center gap-2">
            {selectedRows.size > 0 && (
              <span className="text-sm text-muted-foreground">{selectedRows.size} selected</span>
            )}
            {onExport && (
              <Button
                onClick={onExport}
                disabled={isExporting || businesses.length === 0}
                size="sm"
              >
                {isExporting ? 'Exporting...' : 'Export'}
              </Button>
            )}
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <Input
              placeholder="Search businesses..."
              value={filterConfig.search}
              onChange={e => setFilterConfig(prev => ({ ...prev, search: e.target.value }))}
              className="max-w-sm"
            />
          </div>
          <Button variant="outline" size="sm">
            <Filter className="h-4 w-4 mr-2" />
            Filters
          </Button>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {/* Table */}
        <div className="border rounded-lg overflow-hidden bg-white dark:bg-gray-900">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1200px]">
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className="w-12 p-3 text-left">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={el => {
                        if (el) el.indeterminate = someSelected
                      }}
                      onChange={e => handleSelectAll(e.target.checked)}
                      className="rounded"
                      title="Select all on this page"
                    />
                  </th>
                  <th className="text-left p-3 min-w-[200px]">
                    {renderSortableHeader('businessName', 'Business Name')}
                  </th>
                  <th className="text-left p-3 min-w-[120px]">
                    {renderSortableHeader('industry', 'Industry')}
                  </th>
                  <th className="text-left p-3 min-w-[180px]">Contact</th>
                  <th className="text-left p-3 min-w-[160px]">
                    {renderSortableHeader('address', 'Address')}
                  </th>
                  <th className="text-left p-3 w-24">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                        <span>Loading...</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  currentPageData.map(business => (
                    <tr
                      key={business.id}
                      className={clsx('border-b hover:bg-muted/50 transition-colors', {
                        'bg-primary/5': selectedRows.has(business.id),
                      })}
                    >
                      <td className="p-3">
                        <input
                          type="checkbox"
                          checked={selectedRows.has(business.id)}
                          onChange={e => handleRowSelect(business.id, e.target.checked)}
                          className="rounded"
                          title={`Select ${business.businessName}`}
                        />
                      </td>
                      <td className="p-3">
                        <div className="font-medium">
                          {formatBusinessName(business.businessName)}
                        </div>
                        {business.website && (
                          <div className="text-xs text-muted-foreground truncate">
                            {formatUrl(business.website)}
                          </div>
                        )}
                      </td>
                      <td className="p-3 text-sm">{business.industry || '-'}</td>
                      <td className="p-3">
                        <div className="space-y-1">
                          {business.email && <div className="text-sm">{business.email}</div>}
                          {business.phone && (
                            <div className="text-xs text-muted-foreground">
                              {formatPhoneNumber(business.phone)}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-sm">{formatAddress(business.address)}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onEdit(business.id, {})}
                            className="h-6 w-6 p-0"
                            title="Edit business"
                          >
                            <Edit className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onDelete(business.id)}
                            className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                            title="Delete business"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                          {business.website && (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => window.open(business.website, '_blank')}
                              className="h-6 w-6 p-0"
                              title="Visit website"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination Controls */}
        {renderPaginationControls()}
      </CardContent>
    </Card>
  )
}
