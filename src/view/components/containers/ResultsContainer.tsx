/**
 * Results Container
 * Secure results display with data validation and sanitization
 */

'use client'

import React, { useState } from 'react'
import { PerformanceProvider } from '@/controller/PerformanceContext'
import { SecurityBoundary, SecurityUtils } from '../security/SecurityBoundary'
import { ResultsTable } from '../ResultsTable'
import { VirtualizedResultsTable } from '../VirtualizedResultsTable'
import { Button } from '../ui/Button'
import { BusinessRecord } from '@/types/business'
import { ExportFormat, ExportTemplate } from '@/utils/exportService'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

export interface ResultsContainerProps {
  businesses: BusinessRecord[]
  onEdit: (business: BusinessRecord) => void
  onDelete: (businessId: string) => void
  onExport: (format: string, selectedIds?: string[], template?: ExportTemplate) => Promise<void>
  isLoading: boolean
  isExporting: boolean
  useStreamingSearch: boolean
}

/**
 * Results Container with security boundaries and data validation
 */
export function ResultsContainer({
  businesses,
  onEdit,
  onDelete,
  onExport,
  isLoading,
  isExporting,
  useStreamingSearch,
}: ResultsContainerProps): JSX.Element {
  const [useVirtualScrolling, setUseVirtualScrolling] = useState(true)

  /**
   * Secure business edit handler with validation
   */
  const handleSecureEdit = (business: BusinessRecord) => {
    try {
      // Validate business data before editing
      const validation = SecurityUtils.validateBusinessData(business)
      if (!validation.isValid) {
        logger.warn('ResultsContainer', 'Invalid business data for edit', validation.errors)
        toast.error(`Cannot edit business: ${validation.errors.join(', ')}`)
        return
      }

      // Sanitize business data
      const sanitizedBusiness = SecurityUtils.sanitizeBusinessData(business)
      
      logger.info('ResultsContainer', 'Business edit initiated', { businessId: business.id })
      onEdit(sanitizedBusiness)
    } catch (error) {
      logger.error('ResultsContainer', 'Business edit failed', error)
      toast.error('Failed to edit business. Please try again.')
    }
  }

  /**
   * Secure business delete handler with validation
   */
  const handleSecureDelete = (businessId: string) => {
    try {
      // Validate business ID
      if (!businessId || typeof businessId !== 'string') {
        logger.warn('ResultsContainer', 'Invalid business ID for delete', { businessId })
        toast.error('Cannot delete business: Invalid ID')
        return
      }

      // Find business to validate it exists
      const business = businesses.find(b => b.id === businessId)
      if (!business) {
        logger.warn('ResultsContainer', 'Business not found for delete', { businessId })
        toast.error('Cannot delete business: Business not found')
        return
      }

      logger.info('ResultsContainer', 'Business delete initiated', { businessId })
      onDelete(businessId)
    } catch (error) {
      logger.error('ResultsContainer', 'Business delete failed', error)
      toast.error('Failed to delete business. Please try again.')
    }
  }

  /**
   * Secure export handler with data validation
   */
  const handleSecureExport = async (
    format: string,
    selectedIds?: string[],
    template?: ExportTemplate
  ) => {
    try {
      // Validate export parameters
      if (!format || typeof format !== 'string') {
        logger.warn('ResultsContainer', 'Invalid export format', { format })
        toast.error('Cannot export: Invalid format')
        return
      }

      // Validate selected businesses if provided
      if (selectedIds && Array.isArray(selectedIds)) {
        const invalidIds = selectedIds.filter(id => !businesses.find(b => b.id === id))
        if (invalidIds.length > 0) {
          logger.warn('ResultsContainer', 'Invalid business IDs for export', { invalidIds })
          toast.error(`Cannot export: Invalid business IDs found`)
          return
        }
      }

      // Validate all business data before export
      const businessesToExport = selectedIds 
        ? businesses.filter(b => selectedIds.includes(b.id))
        : businesses

      const invalidBusinesses = businessesToExport.filter(business => {
        const validation = SecurityUtils.validateBusinessData(business)
        return !validation.isValid
      })

      if (invalidBusinesses.length > 0) {
        logger.warn('ResultsContainer', 'Invalid business data found for export', {
          count: invalidBusinesses.length,
          total: businessesToExport.length
        })
        toast.warn(`${invalidBusinesses.length} businesses have invalid data and will be sanitized before export`)
      }

      logger.info('ResultsContainer', 'Export initiated', {
        format,
        selectedCount: selectedIds?.length || businesses.length,
        totalCount: businesses.length
      })

      await onExport(format, selectedIds, template)
    } catch (error) {
      logger.error('ResultsContainer', 'Export failed', error)
      toast.error('Export failed. Please try again.')
    }
  }

  // Validate and sanitize businesses data
  const validatedBusinesses = businesses.map(business => {
    const validation = SecurityUtils.validateBusinessData(business)
    if (!validation.isValid) {
      logger.debug('ResultsContainer', 'Sanitizing business data', {
        businessId: business.id,
        errors: validation.errors
      })
    }
    return SecurityUtils.sanitizeBusinessData(business)
  })

  return (
    <SecurityBoundary componentName="ResultsContainer">
      <div className="space-y-4">
        {/* Table Mode Toggle */}
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">
            Business Results ({validatedBusinesses.length.toLocaleString()})
          </h3>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Table Mode:</span>
            <Button
              variant={useVirtualScrolling ? 'default' : 'outline'}
              size="sm"
              onClick={() => setUseVirtualScrolling(true)}
            >
              Virtual (High Performance)
            </Button>
            <Button
              variant={!useVirtualScrolling ? 'default' : 'outline'}
              size="sm"
              onClick={() => setUseVirtualScrolling(false)}
            >
              Traditional
            </Button>
          </div>
        </div>

        {/* Results Table with Security Boundary */}
        <SecurityBoundary componentName="ResultsTable">
          <PerformanceProvider datasetSize={validatedBusinesses.length}>
            {useVirtualScrolling ? (
              <VirtualizedResultsTable
                businesses={validatedBusinesses}
                onEdit={handleSecureEdit}
                onDelete={handleSecureDelete}
                onExport={handleSecureExport}
                isLoading={isLoading}
                isExporting={isExporting}
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
                businesses={validatedBusinesses}
                onEdit={handleSecureEdit}
                onDelete={handleSecureDelete}
                onExport={handleSecureExport}
                isLoading={isLoading}
                isExporting={isExporting}
              />
            )}
          </PerformanceProvider>
        </SecurityBoundary>

        {/* Results Summary */}
        <div className="text-sm text-muted-foreground">
          {useStreamingSearch ? 'Real-time streaming results' : 'Batch scraping results'} • 
          {validatedBusinesses.length} businesses found • 
          Data validated and sanitized for security
        </div>
      </div>
    </SecurityBoundary>
  )
}
