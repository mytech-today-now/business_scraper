'use client'

import React, { useState, useMemo, useCallback, Suspense } from 'react'
import {
  Download,
  Edit,
  Trash2,
  ExternalLink,
  Search,
  Filter,
  SortAsc,
  SortDesc,
  Eye,
  EyeOff,
  FileText,
  Zap,
  Activity,
} from 'lucide-react'
import { BusinessRecord } from '@/types/business'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { LeadScoreBadge } from './LeadScoreBadge'
import { useResponsive } from '@/hooks/useResponsive'
import { useVirtualScroll } from '@/hooks/useVirtualScroll'
import {
  formatBusinessName,
  formatAddress,
  formatPhoneNumber,
  formatDate,
  formatUrl,
} from '@/utils/formatters'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'
import { ExportTemplateManager } from './ExportTemplateManager'
import { CRMExportTemplateManager } from './CRMExportTemplateManager'
import { ExportTemplate } from '@/utils/exportService'
import { CRMTemplate } from '@/utils/crm'
import { usePerformance } from '@/controller/PerformanceContext'
import { PerformanceAdvisoryBanner, PerformanceModePrompt } from './PerformanceAdvisoryBanner'

// Dynamic imports for performance optimization
const VirtualizedResultsTable = React.lazy(() =>
  import('./VirtualizedResultsTable').then(module => ({ default: module.VirtualizedResultsTable }))
)
const PaginatedResultsTable = React.lazy(() =>
  import('./PaginatedResultsTable').then(module => ({ default: module.PaginatedResultsTable }))
)

/**
 * Column definition interface
 */
interface Column {
  key:
    | keyof BusinessRecord
    | 'actions'
    | 'street'
    | 'city'
    | 'state'
    | 'zipCode'
    | 'source'
    | 'leadScore'
  label: string
  sortable: boolean
  visible: boolean
  width?: string
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
 * ResultsTable component props
 */
export interface ResultsTableProps {
  businesses: BusinessRecord[]
  onEdit?: (businessId: string, updates: Partial<BusinessRecord>) => void
  onDelete?: (businessId: string) => void
  onExport?: (
    format: string,
    selectedIds?: string[],
    template?: ExportTemplate | CRMTemplate
  ) => void
  isLoading?: boolean
  isExporting?: boolean
}

/**
 * Default columns configuration - Enhanced with better organization
 */
const DEFAULT_COLUMNS: Column[] = [
  { key: 'businessName', label: 'Business Name', sortable: true, visible: true, width: '200px' },
  { key: 'leadScore', label: 'Lead Score', sortable: false, visible: true, width: '120px' },
  { key: 'contactPerson', label: 'Contact Person', sortable: false, visible: true, width: '150px' },
  { key: 'email', label: 'Email', sortable: false, visible: true, width: '220px' },
  { key: 'phone', label: 'Phone', sortable: false, visible: true, width: '130px' },
  { key: 'websiteUrl', label: 'Website', sortable: false, visible: true, width: '180px' },
  { key: 'street', label: 'Street Address', sortable: false, visible: true, width: '200px' },
  { key: 'city', label: 'City', sortable: true, visible: true, width: '120px' },
  { key: 'state', label: 'State', sortable: true, visible: true, width: '80px' },
  { key: 'zipCode', label: 'ZIP Code', sortable: true, visible: true, width: '90px' },
  { key: 'industry', label: 'Industry', sortable: true, visible: true, width: '120px' },
  { key: 'source', label: 'Source', sortable: true, visible: true, width: '100px' },
  { key: 'scrapedAt', label: 'Scraped', sortable: true, visible: true, width: '120px' },
  { key: 'actions', label: 'Actions', sortable: false, visible: true, width: '100px' },
]

/**
 * ResultsTable component for displaying and managing scraped business data
 * Features: sorting, filtering, editing, exporting, column visibility
 */
export function ResultsTable({
  businesses,
  onEdit,
  onDelete,
  onExport,
  isLoading = false,
  isExporting = false,
}: ResultsTableProps): JSX.Element {
  // Performance context
  const { mode, showAdvisoryBanner, showPaginationPrompt } = usePerformance()

  // Responsive hooks
  const { isMobile, isTablet, isTouchDevice } = useResponsive()

  // State management
  const [columns, setColumns] = useState<Column[]>(DEFAULT_COLUMNS)
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: null, direction: 'asc' })
  const [filterConfig, setFilterConfig] = useState<FilterConfig>({
    search: '',
    industry: '',
    hasEmail: null,
    hasPhone: null,
  })
  const [showTemplateManager, setShowTemplateManager] = useState(false)
  const [showCRMTemplateManager, setShowCRMTemplateManager] = useState(false)
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set())
  const [editingCell, setEditingCell] = useState<{ businessId: string; field: string } | null>(null)
  const [showColumnSettings, setShowColumnSettings] = useState(false)

  /**
   * Get unique industries for filter dropdown
   */
  const uniqueIndustries = useMemo(() => {
    const industries = businesses.map(b => b.industry).filter(Boolean)
    return Array.from(new Set(industries)).sort()
  }, [businesses])

  /**
   * Filter and sort businesses
   */
  const filteredAndSortedBusinesses = useMemo(() => {
    let filtered = businesses

    // Apply filters
    if (filterConfig.search) {
      const searchLower = filterConfig.search.toLowerCase()
      filtered = filtered.filter(
        business =>
          business.businessName.toLowerCase().includes(searchLower) ||
          business.email.some(email => email.toLowerCase().includes(searchLower)) ||
          business.websiteUrl.toLowerCase().includes(searchLower) ||
          formatAddress(business.address).toLowerCase().includes(searchLower)
      )
    }

    if (filterConfig.industry) {
      filtered = filtered.filter(business => business.industry === filterConfig.industry)
    }

    if (filterConfig.hasEmail !== null) {
      filtered = filtered.filter(business =>
        filterConfig.hasEmail ? business.email.length > 0 : business.email.length === 0
      )
    }

    if (filterConfig.hasPhone !== null) {
      filtered = filtered.filter(business =>
        filterConfig.hasPhone ? !!business.phone : !business.phone
      )
    }

    // Apply sorting
    if (sortConfig.key) {
      const sortKey = sortConfig.key
      filtered.sort((a, b) => {
        const aValue = a[sortKey]
        const bValue = b[sortKey]

        let comparison = 0

        // Handle undefined values
        if (aValue == null && bValue == null) comparison = 0
        else if (aValue == null) comparison = -1
        else if (bValue == null) comparison = 1
        else if (aValue < bValue) comparison = -1
        else if (aValue > bValue) comparison = 1

        return sortConfig.direction === 'desc' ? -comparison : comparison
      })
    }

    return filtered
  }, [businesses, filterConfig, sortConfig])

  /**
   * Handle column sorting
   */
  const handleSort = useCallback((key: keyof BusinessRecord): void => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }))
  }, [])

  /**
   * Handle row selection
   */
  const handleRowSelect = useCallback((businessId: string, selected: boolean): void => {
    setSelectedRows(prev => {
      const newSet = new Set(prev)
      if (selected) {
        newSet.add(businessId)
      } else {
        newSet.delete(businessId)
      }
      return newSet
    })
  }, [])

  /**
   * Handle select all rows
   */
  const handleSelectAll = useCallback(
    (selected: boolean): void => {
      if (selected) {
        setSelectedRows(new Set(filteredAndSortedBusinesses.map(b => b.id)))
      } else {
        setSelectedRows(new Set())
      }
    },
    [filteredAndSortedBusinesses]
  )

  /**
   * Handle column visibility toggle
   */
  const handleColumnVisibility = useCallback((columnKey: string, visible: boolean): void => {
    setColumns(prev => prev.map(col => (col.key === columnKey ? { ...col, visible } : col)))
  }, [])

  /**
   * Handle cell editing
   */
  const handleCellEdit = useCallback(
    (businessId: string, field: string, value: any): void => {
      if (onEdit) {
        const business = businesses.find(b => b.id === businessId)
        if (business) {
          onEdit(businessId, { [field]: value })
        }
      }
      setEditingCell(null)
    },
    [businesses, onEdit]
  )

  /**
   * Render cell content
   */
  const renderCellContent = useCallback(
    (business: BusinessRecord, column: Column) => {
      const isEditing = editingCell?.businessId === business.id && editingCell?.field === column.key

      if (isEditing && column.key !== 'actions') {
        return (
          <Input
            defaultValue={String(business[column.key as keyof BusinessRecord] || '')}
            onBlur={e => handleCellEdit(business.id, column.key as string, e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                handleCellEdit(business.id, column.key as string, e.currentTarget.value)
              }
              if (e.key === 'Escape') {
                setEditingCell(null)
              }
            }}
            className="h-8 text-xs"
            autoFocus
          />
        )
      }

      switch (column.key) {
        case 'businessName':
          return (
            <div className="font-medium text-sm">{formatBusinessName(business.businessName)}</div>
          )

        case 'contactPerson':
          return business.contactPerson ? (
            <div className="text-sm">{business.contactPerson}</div>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          )

        case 'email':
          return (
            <div className="space-y-1">
              {business.email.slice(0, 2).map((email, index) => (
                <div key={index} className="text-xs">
                  <a href={`mailto:${email}`} className="text-primary hover:underline break-all">
                    {email}
                  </a>
                </div>
              ))}
              {business.email.length > 2 && (
                <div className="text-xs text-muted-foreground">
                  +{business.email.length - 2} more
                </div>
              )}
            </div>
          )

        case 'phone':
          return business.phone ? (
            <a
              href={`tel:${business.phone}`}
              className="text-primary hover:underline text-sm whitespace-nowrap"
            >
              {formatPhoneNumber(business.phone)}
            </a>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          )

        case 'websiteUrl':
          return (
            <div className="flex items-center gap-1">
              <a
                href={business.websiteUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline text-xs flex items-center gap-1 break-all"
              >
                {formatUrl(business.websiteUrl)}
                <ExternalLink className="h-3 w-3 flex-shrink-0" />
              </a>
              <button
                type="button"
                onClick={() => handleAddToBlacklist(business.websiteUrl, business.industry)}
                className="text-red-500 hover:text-red-700 hover:bg-red-50 rounded p-1 transition-colors"
                title={`Block ${extractDomain(business.websiteUrl)} from ${business.industry} searches`}
              >
                🚫
              </button>
            </div>
          )

        case 'street':
          return (
            <div className="text-sm">
              {business.address?.street ? (
                <>
                  {business.address.street}
                  {business.address.suite && (
                    <div className="text-xs text-muted-foreground">{business.address.suite}</div>
                  )}
                </>
              ) : (
                <span className="text-muted-foreground text-xs">—</span>
              )}
            </div>
          )

        case 'city':
          return (
            <div className="text-sm">
              {business.address?.city || <span className="text-muted-foreground text-xs">—</span>}
            </div>
          )

        case 'state':
          return (
            <div className="text-sm font-mono">
              {business.address?.state || <span className="text-muted-foreground text-xs">—</span>}
            </div>
          )

        case 'zipCode':
          return (
            <div className="text-sm font-mono">
              {business.address?.zipCode || (
                <span className="text-muted-foreground text-xs">—</span>
              )}
            </div>
          )

        case 'industry':
          return (
            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-secondary text-secondary-foreground whitespace-nowrap">
              {business.industry}
            </span>
          )

        case 'source':
          return (
            <div className="text-xs">
              {(business as any).source ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                  {(business as any).source}
                </span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </div>
          )

        case 'scrapedAt':
          return (
            <div className="text-xs text-muted-foreground whitespace-nowrap">
              {formatDate(business.scrapedAt)}
            </div>
          )

        case 'leadScore':
          return <LeadScoreBadge business={business} showDetails={true} size="sm" />

        case 'actions':
          return (
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={() => setEditingCell({ businessId: business.id, field: 'businessName' })}
              >
                <Edit className="h-3 w-3" />
              </Button>
              {onDelete && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 text-destructive hover:text-destructive"
                  onClick={() => onDelete(business.id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              )}
            </div>
          )

        default:
          return String(business[column.key as keyof BusinessRecord] || '')
      }
    },
    [editingCell, handleCellEdit, onDelete]
  )

  /**
   * Extract clean domain from URL
   */
  const extractDomain = useCallback((url: string): string => {
    try {
      // If it's already just a domain, return it
      if (!url.includes('://')) {
        url = 'https://' + url
      }

      const urlObj = new URL(url)
      let domain = urlObj.hostname.toLowerCase()

      // Remove www. prefix
      if (domain.startsWith('www.')) {
        domain = domain.substring(4)
      }

      return domain
    } catch (error) {
      // If URL parsing fails, try to extract domain manually
      let domain = url.toLowerCase()
      domain = domain.replace(/^https?:\/\//, '')
      domain = domain.replace(/^www\./, '')
      domain = domain.split('/')[0] || ''
      domain = domain.split('?')[0] || ''
      domain = domain.split('#')[0] || ''

      return domain
    }
  }, [])

  /**
   * Handle adding domain to blacklist
   */
  const handleAddToBlacklist = useCallback(
    async (url: string, industry: string): Promise<void> => {
      try {
        const domain = extractDomain(url)

        const response = await fetch('/api/config', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            action: 'add-domain-to-blacklist',
            domain,
            industry,
          }),
        })

        const result = await response.json()

        if (result.success) {
          toast.success(`Domain ${domain} added to ${industry} blacklist`)
        } else {
          toast.error(result.message || 'Failed to add domain to blacklist')
        }
      } catch (error) {
        console.error('Failed to add domain to blacklist:', error)
        toast.error('Failed to add domain to blacklist')
      }
    },
    [extractDomain]
  )

  const visibleColumns = columns.filter(col => col.visible)
  const allSelected =
    selectedRows.size === filteredAndSortedBusinesses.length &&
    filteredAndSortedBusinesses.length > 0
  const someSelected = selectedRows.size > 0

  // Dynamic rendering based on performance mode
  const renderTable = () => {
    switch (mode) {
      case 'virtualized':
        return (
          <Suspense fallback={<div className="p-8 text-center">Loading virtualized view...</div>}>
            <VirtualizedResultsTable
              businesses={filteredAndSortedBusinesses}
              onEdit={onEdit}
              onDelete={onDelete}
              onExport={onExport}
              isLoading={isLoading}
              isExporting={isExporting}
            />
          </Suspense>
        )

      case 'pagination':
        return (
          <Suspense fallback={<div className="p-8 text-center">Loading paginated view...</div>}>
            <PaginatedResultsTable
              businesses={filteredAndSortedBusinesses}
              onEdit={onEdit}
              onDelete={onDelete}
              onExport={onExport}
              isLoading={isLoading}
              isExporting={isExporting}
            />
          </Suspense>
        )

      default:
        // Normal table rendering for small datasets
        return renderNormalTable()
    }
  }

  const renderNormalTable = () => (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span>Business Results ({filteredAndSortedBusinesses.length})</span>
            {mode === 'advisory' && (
              <div className="flex items-center gap-1 text-yellow-600">
                <Activity className="h-4 w-4" />
                <span className="text-xs">Performance Mode</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-2">
            {/* Export Button */}
            {onExport && (
              <div className="relative group">
                <Button variant="outline" size="sm" icon={Download} disabled={isExporting}>
                  {isExporting ? 'Exporting...' : 'Export'}
                </Button>
                {!isExporting && (
                  <div className="absolute right-0 top-full mt-1 w-56 bg-popover border rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                    <div className="p-1">
                      {/* Primary formats */}
                      <div className="border-b border-border pb-1 mb-1">
                        <div className="px-3 py-1 text-xs font-medium text-muted-foreground">
                          Primary Formats
                        </div>
                        {['CSV', 'XLSX', 'PDF'].map(format => (
                          <button
                            key={format}
                            type="button"
                            className="w-full text-left px-3 py-2 text-sm hover:bg-accent rounded-sm"
                            onClick={() => onExport(format.toLowerCase())}
                          >
                            Export as {format}
                          </button>
                        ))}
                      </div>

                      {/* Additional formats */}
                      <div>
                        <div className="px-3 py-1 text-xs font-medium text-muted-foreground">
                          Additional Formats
                        </div>
                        {[
                          { format: 'JSON', description: 'Structured data' },
                          { format: 'XML', description: 'Markup format' },
                          { format: 'VCF', description: 'Contact cards' },
                          { format: 'SQL', description: 'Database inserts' },
                        ].map(({ format, description }) => (
                          <button
                            key={format}
                            type="button"
                            className="w-full text-left px-3 py-2 text-sm hover:bg-accent rounded-sm"
                            onClick={() => onExport(format.toLowerCase())}
                          >
                            <div className="flex flex-col">
                              <span>Export as {format}</span>
                              <span className="text-xs text-muted-foreground">{description}</span>
                            </div>
                          </button>
                        ))}
                      </div>

                      {/* Template Manager */}
                      <div className="border-t border-border pt-1 mt-1">
                        <button
                          type="button"
                          className="w-full text-left px-3 py-2 text-sm hover:bg-accent rounded-sm flex items-center gap-2"
                          onClick={() => setShowCRMTemplateManager(true)}
                        >
                          <FileText className="h-4 w-4" />
                          <div className="flex flex-col">
                            <span>🚀 CRM Templates</span>
                            <span className="text-xs text-muted-foreground">
                              Salesforce, HubSpot, Pipedrive
                            </span>
                          </div>
                        </button>
                        <button
                          type="button"
                          className="w-full text-left px-3 py-2 text-sm hover:bg-accent rounded-sm flex items-center gap-2"
                          onClick={() => setShowTemplateManager(true)}
                        >
                          <FileText className="h-4 w-4" />
                          <div className="flex flex-col">
                            <span>Custom Templates</span>
                            <span className="text-xs text-muted-foreground">
                              Manage export templates
                            </span>
                          </div>
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Column Settings */}
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                icon={showColumnSettings ? EyeOff : Eye}
                onClick={() => setShowColumnSettings(!showColumnSettings)}
              >
                Columns
              </Button>
              {showColumnSettings && (
                <div className="absolute right-0 top-full mt-1 w-56 bg-popover border rounded-md shadow-lg z-10">
                  <div className="p-3">
                    <h4 className="font-medium mb-2">Show/Hide Columns</h4>
                    <div className="space-y-2">
                      {columns.map(column => (
                        <label key={column.key} className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={column.visible}
                            onChange={e =>
                              handleColumnVisibility(column.key as string, e.target.checked)
                            }
                            className="rounded"
                          />
                          {column.label}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Business Summary Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-muted/30 rounded-lg">
          <div className="text-center">
            <div className="text-2xl font-bold text-primary">{businesses.length}</div>
            <div className="text-xs text-muted-foreground">Total Businesses</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {businesses.filter(b => b.email.length > 0).length}
            </div>
            <div className="text-xs text-muted-foreground">With Email</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">
              {businesses.filter(b => b.phone).length}
            </div>
            <div className="text-xs text-muted-foreground">With Phone</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">
              {new Set(businesses.map(b => b.industry)).size}
            </div>
            <div className="text-xs text-muted-foreground">Industries</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-64">
            <Input
              placeholder="Search businesses..."
              value={filterConfig.search}
              onChange={e => setFilterConfig(prev => ({ ...prev, search: e.target.value }))}
              className="h-9"
            />
          </div>

          <select
            value={filterConfig.industry}
            onChange={e => setFilterConfig(prev => ({ ...prev, industry: e.target.value }))}
            className="h-9 px-3 rounded-md border border-input bg-background text-sm"
          >
            <option value="">All Industries</option>
            {uniqueIndustries.map(industry => (
              <option key={industry} value={industry}>
                {industry}
              </option>
            ))}
          </select>

          <select
            value={filterConfig.hasEmail === null ? '' : String(filterConfig.hasEmail)}
            onChange={e =>
              setFilterConfig(prev => ({
                ...prev,
                hasEmail: e.target.value === '' ? null : e.target.value === 'true',
              }))
            }
            className="h-9 px-3 rounded-md border border-input bg-background text-sm"
          >
            <option value="">All Email Status</option>
            <option value="true">Has Email</option>
            <option value="false">No Email</option>
          </select>
        </div>

        {/* Selection Actions */}
        {someSelected && (
          <div className="flex items-center gap-2 p-3 bg-accent/50 rounded-lg">
            <span className="text-sm">
              {selectedRows.size} of {filteredAndSortedBusinesses.length} selected
            </span>
            <Button variant="outline" size="sm" onClick={() => setSelectedRows(new Set())}>
              Clear Selection
            </Button>

            {/* Export Selected */}
            {onExport && (
              <div className="relative group">
                <Button variant="outline" size="sm" icon={Download} disabled={isExporting}>
                  {isExporting ? 'Exporting...' : 'Export Selected'}
                </Button>
                {!isExporting && (
                  <div className="absolute left-0 top-full mt-1 w-48 bg-popover border rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                    <div className="p-1">
                      {['CSV', 'XLSX', 'PDF', 'JSON'].map(format => (
                        <button
                          key={format}
                          type="button"
                          className="w-full text-left px-3 py-2 text-sm hover:bg-accent rounded-sm"
                          onClick={() => onExport(format.toLowerCase(), Array.from(selectedRows))}
                        >
                          Export as {format}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {onDelete && (
              <Button
                variant="destructive"
                size="sm"
                icon={Trash2}
                onClick={() => {
                  selectedRows.forEach(id => onDelete(id))
                  setSelectedRows(new Set())
                }}
              >
                Delete Selected
              </Button>
            )}
          </div>
        )}

        {/* Enhanced Table with Better Organization */}
        <div className="border rounded-lg overflow-hidden bg-white dark:bg-gray-900">
          <div
            className={clsx(
              'overflow-x-auto',
              isMobile && 'scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-gray-100'
            )}
          >
            <table className={clsx('w-full', isMobile ? 'min-w-[800px]' : 'min-w-[1200px]')}>
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className={clsx('text-left', isMobile ? 'w-10 p-2' : 'w-12 p-3')}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={e => handleSelectAll(e.target.checked)}
                      className={clsx('rounded', isMobile && 'min-h-touch min-w-touch')}
                      title="Select all businesses"
                    />
                  </th>
                  {visibleColumns.map(column => (
                    <th
                      key={column.key}
                      className={clsx(
                        'text-left font-medium border-r border-muted/30 last:border-r-0',
                        isMobile ? 'p-2 text-xs' : 'p-3 text-sm'
                      )}
                      style={{ width: isMobile ? 'auto' : column.width }}
                    >
                      {column.sortable ? (
                        <button
                          type="button"
                          className={clsx(
                            'flex items-center gap-1 hover:text-primary transition-colors',
                            isMobile && 'min-h-touch'
                          )}
                          onClick={() => handleSort(column.key as keyof BusinessRecord)}
                        >
                          {column.label}
                          {sortConfig.key === column.key &&
                            (sortConfig.direction === 'asc' ? (
                              <SortAsc className="h-3 w-3" />
                            ) : (
                              <SortDesc className="h-3 w-3" />
                            ))}
                        </button>
                      ) : (
                        <span className="text-muted-foreground">{column.label}</span>
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-muted/30">
                {isLoading ? (
                  <tr>
                    <td colSpan={visibleColumns.length + 1} className="p-8 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                        <span className="text-muted-foreground">Loading business data...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredAndSortedBusinesses.length === 0 ? (
                  <tr>
                    <td
                      colSpan={visibleColumns.length + 1}
                      className="p-8 text-center text-muted-foreground"
                    >
                      <div className="flex flex-col items-center gap-2">
                        <Search className="h-8 w-8 text-muted-foreground/50" />
                        <span>
                          {businesses.length === 0
                            ? 'No businesses found'
                            : 'No businesses match your filters'}
                        </span>
                        {businesses.length > 0 && (
                          <span className="text-xs">Try adjusting your search filters</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredAndSortedBusinesses.map((business, index) => (
                    <tr
                      key={business.id}
                      className={clsx(
                        'hover:bg-accent/50 transition-colors group',
                        selectedRows.has(business.id) && 'bg-accent/30',
                        index % 2 === 0
                          ? 'bg-white dark:bg-gray-900'
                          : 'bg-gray-50/50 dark:bg-gray-800/50'
                      )}
                    >
                      <td className="p-3 border-r border-muted/20">
                        <input
                          type="checkbox"
                          checked={selectedRows.has(business.id)}
                          onChange={e => handleRowSelect(business.id, e.target.checked)}
                          className="rounded"
                          title={`Select ${business.businessName}`}
                        />
                      </td>
                      {visibleColumns.map(column => (
                        <td
                          key={column.key}
                          className="p-3 text-sm border-r border-muted/20 last:border-r-0 align-top"
                          style={{ width: column.width }}
                        >
                          {renderCellContent(business, column)}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination could be added here for large datasets */}
      </CardContent>
    </Card>
  )

  return (
    <>
      {/* Performance Advisory Banner */}
      <PerformanceAdvisoryBanner />

      {/* Performance Mode Prompt */}
      <PerformanceModePrompt />

      {/* Dynamic Table Rendering */}
      {renderTable()}

      {/* Export Template Manager */}
      {showTemplateManager && (
        <ExportTemplateManager
          onTemplateSelect={template => {
            setShowTemplateManager(false)
            if (onExport) {
              onExport('csv', undefined, template)
            }
          }}
          onClose={() => setShowTemplateManager(false)}
        />
      )}

      {/* CRM Export Template Manager */}
      {showCRMTemplateManager && (
        <CRMExportTemplateManager
          onTemplateSelect={template => {
            setShowCRMTemplateManager(false)
            if (onExport) {
              onExport('csv', undefined, template)
            }
          }}
          onClose={() => setShowCRMTemplateManager(false)}
          businessRecords={businesses}
        />
      )}
    </>
  )
}
