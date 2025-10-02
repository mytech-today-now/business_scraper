/**
 * Results View Manager
 * Secure results display manager with multiple view modes and validation
 */

'use client'

import React, { useState } from 'react'
import { List, Grid, Map, Activity, Settings, CheckSquare, Square } from 'lucide-react'
import { SecurityBoundary, SecurityUtils } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { VirtualizedResultsTable } from '../VirtualizedResultsTable'
import { StreamingResultsDisplay } from '../StreamingResultsDisplay'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

export type ViewMode = 'table' | 'grid' | 'map' | 'streaming'

export interface ResultsViewManagerProps {
  businesses: BusinessRecord[]
  selectedBusinesses: Set<string>
  onToggleSelection: (businessId: string) => void
  viewMode: ViewMode
  onViewModeChange: (mode: ViewMode) => void
  sortConfig: { field: string; direction: 'asc' | 'desc' }[]
  onSortChange: (config: { field: string; direction: 'asc' | 'desc' }[]) => void
  annotations: any[]
  isLoading: boolean
  currentPage: number
  pageSize: number
  onPageChange: (page: number) => void
  onPageSizeChange: (size: number) => void
}

/**
 * Results View Manager with security boundaries
 */
export function ResultsViewManager({
  businesses,
  selectedBusinesses,
  onToggleSelection,
  viewMode,
  onViewModeChange,
  sortConfig,
  onSortChange,
  annotations,
  isLoading,
  currentPage,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: ResultsViewManagerProps): JSX.Element {
  const [useVirtualScrolling, setUseVirtualScrolling] = useState(true)
  const [showColumnSettings, setShowColumnSettings] = useState(false)
  const [streamingStatus, setStreamingStatus] = useState<string>('idle')

  // Validate and sanitize business data
  const validatedBusinesses = businesses.map(business => {
    const validation = SecurityUtils.validateBusinessData(business)
    if (!validation.isValid) {
      logger.debug('ResultsViewManager', 'Sanitizing business data', {
        businessId: business.id,
        errors: validation.errors
      })
    }
    return SecurityUtils.sanitizeBusinessData(business)
  })

  // Pagination
  const totalPages = Math.ceil(validatedBusinesses.length / pageSize)
  const startIndex = (currentPage - 1) * pageSize
  const endIndex = startIndex + pageSize
  const paginatedBusinesses = validatedBusinesses.slice(startIndex, endIndex)

  /**
   * Secure view mode change handler
   */
  const handleSecureViewModeChange = (mode: ViewMode) => {
    try {
      const allowedModes: ViewMode[] = ['table', 'grid', 'map', 'streaming']
      if (!allowedModes.includes(mode)) {
        logger.warn('ResultsViewManager', 'Invalid view mode attempted', { mode })
        toast.error('Invalid view mode')
        return
      }

      logger.debug('ResultsViewManager', 'View mode changed', { from: viewMode, to: mode })
      onViewModeChange(mode)
    } catch (error) {
      logger.error('ResultsViewManager', 'View mode change failed', error)
      toast.error('Failed to change view mode')
    }
  }

  /**
   * Secure selection toggle handler
   */
  const handleSecureToggleSelection = (businessId: string) => {
    try {
      // Validate business ID
      if (!businessId || typeof businessId !== 'string') {
        logger.warn('ResultsViewManager', 'Invalid business ID for selection', { businessId })
        return
      }

      // Validate business exists
      const business = validatedBusinesses.find(b => b.id === businessId)
      if (!business) {
        logger.warn('ResultsViewManager', 'Business not found for selection', { businessId })
        toast.error('Business not found')
        return
      }

      onToggleSelection(businessId)
      logger.debug('ResultsViewManager', 'Selection toggled', { businessId })
    } catch (error) {
      logger.error('ResultsViewManager', 'Selection toggle failed', error)
      toast.error('Failed to toggle selection')
    }
  }

  /**
   * Select all visible businesses
   */
  const selectAllVisible = () => {
    try {
      const visibleIds = paginatedBusinesses.map(b => b.id)
      visibleIds.forEach(id => {
        if (!selectedBusinesses.has(id)) {
          onToggleSelection(id)
        }
      })
      logger.debug('ResultsViewManager', 'Selected all visible businesses', { count: visibleIds.length })
    } catch (error) {
      logger.error('ResultsViewManager', 'Select all failed', error)
      toast.error('Failed to select all businesses')
    }
  }

  /**
   * Clear all selections
   */
  const clearSelection = () => {
    try {
      Array.from(selectedBusinesses).forEach(id => onToggleSelection(id))
      logger.debug('ResultsViewManager', 'Cleared all selections')
    } catch (error) {
      logger.error('ResultsViewManager', 'Clear selection failed', error)
      toast.error('Failed to clear selection')
    }
  }

  return (
    <SecurityBoundary componentName="ResultsViewManager">
      <div className="space-y-4">
        {/* View Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            {/* View Mode Toggle */}
            <div className="flex items-center space-x-1 bg-gray-100 rounded-lg p-1">
              <Button
                variant={viewMode === 'table' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => handleSecureViewModeChange('table')}
                title="Table View"
                aria-label="Table view"
              >
                <List className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === 'grid' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => handleSecureViewModeChange('grid')}
                title="Grid View"
                aria-label="Grid view"
              >
                <Grid className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === 'map' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => handleSecureViewModeChange('map')}
                title="Map View"
                aria-label="Map view"
              >
                <Map className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === 'streaming' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => handleSecureViewModeChange('streaming')}
                title="Real-time Streaming View"
                aria-label="Streaming view"
                className={streamingStatus === 'streaming' ? 'animate-pulse' : ''}
              >
                <Activity className="h-4 w-4" />
              </Button>
            </div>

            {/* Virtual Scrolling Toggle (only for table view) */}
            {viewMode === 'table' && (
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600">Performance:</span>
                <Button
                  variant={useVirtualScrolling ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setUseVirtualScrolling(true)}
                >
                  Virtual
                </Button>
                <Button
                  variant={!useVirtualScrolling ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setUseVirtualScrolling(false)}
                >
                  Traditional
                </Button>
              </div>
            )}

            {/* Page Size Selector */}
            <select
              value={pageSize}
              onChange={e => onPageSizeChange(Number(e.target.value))}
              className="px-3 py-1 border border-gray-300 rounded text-sm"
              title="Results per page"
              aria-label="Results per page"
            >
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
              <option value={10000}>Show All</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              icon={Settings}
              onClick={() => setShowColumnSettings(!showColumnSettings)}
              aria-label="Column settings"
            >
              Columns
            </Button>

            {paginatedBusinesses.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={
                  selectedBusinesses.size === paginatedBusinesses.length
                    ? clearSelection
                    : selectAllVisible
                }
                icon={selectedBusinesses.size === paginatedBusinesses.length ? Square : CheckSquare}
                aria-label={
                  selectedBusinesses.size === paginatedBusinesses.length
                    ? 'Deselect all'
                    : 'Select all visible'
                }
              >
                {selectedBusinesses.size === paginatedBusinesses.length
                  ? 'Deselect All'
                  : 'Select All'}
              </Button>
            )}
          </div>
        </div>

        {/* Results Display */}
        <SecurityBoundary componentName="ResultsDisplay">
          {viewMode === 'table' ? (
            useVirtualScrolling ? (
              <VirtualizedResultsTable
                businesses={validatedBusinesses}
                onEdit={business => {
                  // Handle business edit with validation
                  const validation = SecurityUtils.validateBusinessData(business)
                  if (!validation.isValid) {
                    toast.error('Invalid business data')
                    return
                  }
                  // Edit logic would go here
                }}
                onDelete={businessId => {
                  // Handle business delete with validation
                  if (!businessId || !validatedBusinesses.find(b => b.id === businessId)) {
                    toast.error('Business not found')
                    return
                  }
                  // Delete logic would go here
                }}
                onExport={exportBusinesses => {
                  logger.info('ResultsViewManager', 'Export initiated', { count: exportBusinesses.length })
                }}
                isLoading={isLoading}
                height={600}
                initialFilters={{
                  search: '',
                  industry: '',
                  hasEmail: undefined,
                  hasPhone: undefined,
                }}
                initialSort={{
                  field: 'scrapedAt',
                  order: 'desc',
                }}
              />
            ) : (
              <ResultsTable
                businesses={paginatedBusinesses}
                selectedBusinesses={selectedBusinesses}
                onToggleSelection={handleSecureToggleSelection}
                sortConfig={sortConfig}
                onSort={onSortChange}
                annotations={annotations}
              />
            )
          ) : viewMode === 'grid' ? (
            <ResultsGrid
              businesses={paginatedBusinesses}
              selectedBusinesses={selectedBusinesses}
              onToggleSelection={handleSecureToggleSelection}
              annotations={annotations}
            />
          ) : viewMode === 'map' ? (
            <ResultsMap
              businesses={paginatedBusinesses}
              selectedBusinesses={selectedBusinesses}
              onToggleSelection={handleSecureToggleSelection}
            />
          ) : viewMode === 'streaming' ? (
            <StreamingResultsDisplay
              searchParams={{
                query: 'business',
                location: 'United States',
                industry: '',
                maxResults: 1000,
              }}
              onResultsUpdate={streamingResults => {
                // Handle streaming results update
                logger.debug('ResultsViewManager', 'Streaming results updated', { count: streamingResults.length })
              }}
              onStatusChange={setStreamingStatus}
              autoStart={false}
            />
          ) : null}
        </SecurityBoundary>

        {/* Pagination */}
        {totalPages > 1 && viewMode !== 'streaming' && (
          <SecurityBoundary componentName="Pagination">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-600">
                Showing {startIndex + 1} to {Math.min(endIndex, validatedBusinesses.length)} of{' '}
                {validatedBusinesses.length} results
              </p>

              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={currentPage === 1}
                  onClick={() => onPageChange(currentPage - 1)}
                  aria-label="Previous page"
                >
                  Previous
                </Button>

                <span className="text-sm">
                  Page {currentPage} of {totalPages}
                </span>

                <Button
                  variant="outline"
                  size="sm"
                  disabled={currentPage === totalPages}
                  onClick={() => onPageChange(currentPage + 1)}
                  aria-label="Next page"
                >
                  Next
                </Button>
              </div>
            </div>
          </SecurityBoundary>
        )}
      </div>
    </SecurityBoundary>
  )
}

// Placeholder components for different view modes
function ResultsTable({ businesses, selectedBusinesses, onToggleSelection, sortConfig, onSort, annotations }: any) {
  return (
    <div className="border rounded-lg overflow-hidden">
      <div className="bg-gray-50 p-4">
        <p className="text-sm text-gray-600">Traditional table view - {businesses.length} businesses</p>
      </div>
    </div>
  )
}

function ResultsGrid({ businesses, selectedBusinesses, onToggleSelection, annotations }: any) {
  return (
    <div className="border rounded-lg overflow-hidden">
      <div className="bg-gray-50 p-4">
        <p className="text-sm text-gray-600">Grid view - {businesses.length} businesses</p>
      </div>
    </div>
  )
}

function ResultsMap({ businesses, selectedBusinesses, onToggleSelection }: any) {
  return (
    <div className="border rounded-lg overflow-hidden">
      <div className="bg-gray-50 p-4 h-96 flex items-center justify-center">
        <p className="text-sm text-gray-600">Map view - {businesses.length} businesses</p>
      </div>
    </div>
  )
}
