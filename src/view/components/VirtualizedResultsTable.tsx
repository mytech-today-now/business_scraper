'use client'

import React, { memo, useMemo, useCallback } from 'react'
import { FixedSizeList as List } from 'react-window'
import { BusinessRecord } from '@/types/business'
import { Button } from './ui/Button'
import {
  Edit,
  Trash2,
  ExternalLink,
  SortAsc,
  SortDesc,
} from 'lucide-react'
import {
  formatBusinessName,
  formatAddress,
  formatPhoneNumber,
  formatDate,
  formatUrl
} from '@/utils/formatters'
import { clsx } from 'clsx'

/**
 * Column definition interface
 */
interface Column {
  key: keyof BusinessRecord | 'actions' | 'street' | 'city' | 'state' | 'zipCode' | 'source'
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
 * Props for the virtualized table
 */
interface VirtualizedResultsTableProps {
  businesses: BusinessRecord[]
  columns: Column[]
  sortConfig: SortConfig
  selectedRows: Set<string>
  editingCell: { businessId: string; field: string } | null
  onSort: (key: keyof BusinessRecord) => void
  onRowSelect: (businessId: string, selected: boolean) => void
  onEdit?: (businessId: string, updates: Partial<BusinessRecord>) => void
  onDelete?: (businessId: string) => void
  onCellEdit: (businessId: string, field: string, value: string) => void
  height?: number
  itemSize?: number
}

/**
 * Props for individual row component
 */
interface RowProps {
  index: number
  style: React.CSSProperties
  data: {
    businesses: BusinessRecord[]
    columns: Column[]
    selectedRows: Set<string>
    editingCell: { businessId: string; field: string } | null
    onRowSelect: (businessId: string, selected: boolean) => void
    onDelete?: (businessId: string) => void
    onCellEdit: (businessId: string, field: string, value: string) => void
  }
}

/**
 * Individual row component for virtual scrolling
 */
const VirtualizedRow = memo(({ index, style, data }: RowProps) => {
  const { businesses, columns, selectedRows, editingCell, onRowSelect, onDelete, onCellEdit } = data
  const business = businesses[index]
  const visibleColumns = columns.filter(col => col.visible)

  // Safety check for undefined business
  if (!business) {
    return <div style={style} />
  }

  const renderCellContent = useCallback((business: BusinessRecord, column: Column) => {
    const isEditing = editingCell?.businessId === business.id && editingCell?.field === column.key

    if (isEditing && column.key !== 'actions') {
      return (
        <input
          type="text"
          defaultValue={String(business[column.key as keyof BusinessRecord] || '')}
          onBlur={(e) => onCellEdit(business.id, column.key as string, e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              onCellEdit(business.id, column.key as string, e.currentTarget.value)
            }
          }}
          className="w-full px-2 py-1 text-xs border rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
          autoFocus
        />
      )
    }

    switch (column.key) {
      case 'businessName':
        return (
          <div className="font-medium text-sm">
            {formatBusinessName(business.businessName)}
          </div>
        )
      
      case 'email':
        return (
          <div className="space-y-1">
            {business.email.slice(0, 2).map((email, idx) => (
              <div key={idx} className="text-xs">
                <a 
                  href={`mailto:${email}`}
                  className="text-blue-600 hover:text-blue-800 hover:underline"
                >
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
            className="text-blue-600 hover:text-blue-800 hover:underline text-sm"
          >
            {formatPhoneNumber(business.phone)}
          </a>
        ) : (
          <span className="text-muted-foreground text-xs">No phone</span>
        )
      
      case 'websiteUrl':
        return business.websiteUrl ? (
          <a 
            href={formatUrl(business.websiteUrl)}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:text-blue-800 hover:underline text-xs flex items-center gap-1"
          >
            <span className="truncate max-w-32">{business.websiteUrl}</span>
            <ExternalLink className="h-3 w-3 flex-shrink-0" />
          </a>
        ) : (
          <span className="text-muted-foreground text-xs">No website</span>
        )
      
      case 'street':
        return (
          <div className="text-xs">
            {business.address.street || 'No address'}
          </div>
        )
      
      case 'city':
        return (
          <div className="text-xs">
            {business.address.city || 'Unknown'}
          </div>
        )
      
      case 'state':
        return (
          <div className="text-xs">
            {business.address.state || 'Unknown'}
          </div>
        )
      
      case 'zipCode':
        return (
          <div className="text-xs">
            {business.address.zipCode || 'Unknown'}
          </div>
        )
      
      case 'industry':
        return (
          <div className="text-xs px-2 py-1 bg-blue-100 text-blue-800 rounded-full inline-block">
            {business.industry}
          </div>
        )
      
      case 'source':
        return (
          <div className="text-xs text-muted-foreground">
            {business.source || 'Unknown'}
          </div>
        )
      
      case 'scrapedAt':
        return (
          <div className="text-xs text-muted-foreground whitespace-nowrap">
            {formatDate(business.scrapedAt)}
          </div>
        )
      
      case 'actions':
        return (
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              onClick={() => onCellEdit(business.id, 'businessName', '')}
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
  }, [editingCell, onCellEdit, onDelete])

  return (
    <div
      style={style}
      className={clsx(
        'flex items-center border-b border-muted/30 hover:bg-accent/50 transition-colors group',
        selectedRows.has(business.id) && 'bg-accent/30',
        index % 2 === 0 ? 'bg-white dark:bg-gray-900' : 'bg-gray-50/50 dark:bg-gray-800/50'
      )}
    >
      {/* Checkbox column */}
      <div className="w-12 p-3 border-r border-muted/20 flex-shrink-0">
        <input
          type="checkbox"
          checked={selectedRows.has(business.id)}
          onChange={(e) => onRowSelect(business.id, e.target.checked)}
          className="rounded"
          title={`Select ${business.businessName}`}
        />
      </div>
      
      {/* Data columns */}
      {visibleColumns.map(column => (
        <div
          key={column.key}
          className="p-3 text-sm border-r border-muted/20 last:border-r-0 align-top flex-shrink-0"
          style={{ width: column.width || 'auto' }}
        >
          {renderCellContent(business, column)}
        </div>
      ))}
    </div>
  )
})

VirtualizedRow.displayName = 'VirtualizedRow'

/**
 * Virtualized table component using react-window for optimal performance with large datasets
 */
export function VirtualizedResultsTable({
  businesses,
  columns,
  sortConfig,
  selectedRows,
  editingCell,
  onSort,
  onRowSelect,
  onEdit,
  onDelete,
  onCellEdit,
  height = 600,
  itemSize = 60
}: VirtualizedResultsTableProps) {
  const visibleColumns = useMemo(() => columns.filter(col => col.visible), [columns])

  const rowData = useMemo(() => ({
    businesses,
    columns,
    selectedRows,
    editingCell,
    onRowSelect,
    onDelete,
    onCellEdit
  }), [businesses, columns, selectedRows, editingCell, onRowSelect, onDelete, onCellEdit])

  return (
    <div className="border rounded-lg overflow-hidden bg-white dark:bg-gray-900">
      {/* Table Header */}
      <div className="bg-muted/50 border-b">
        <div className="flex items-center">
          <div className="w-12 p-3 border-r border-muted/30">
            <input
              type="checkbox"
              checked={selectedRows.size === businesses.length && businesses.length > 0}
              onChange={(e) => {
                if (e.target.checked) {
                  businesses.forEach(b => onRowSelect(b.id, true))
                } else {
                  businesses.forEach(b => onRowSelect(b.id, false))
                }
              }}
              className="rounded"
              title="Select all businesses"
            />
          </div>
          {visibleColumns.map(column => (
            <div
              key={column.key}
              className="text-left p-3 font-medium text-sm border-r border-muted/30 last:border-r-0 flex-shrink-0"
              style={{ width: column.width || 'auto' }}
            >
              {column.sortable ? (
                <button
                  type="button"
                  className="flex items-center gap-1 hover:text-primary transition-colors"
                  onClick={() => onSort(column.key as keyof BusinessRecord)}
                >
                  {column.label}
                  {sortConfig.key === column.key && (
                    sortConfig.direction === 'asc' ?
                      <SortAsc className="h-3 w-3" /> :
                      <SortDesc className="h-3 w-3" />
                  )}
                </button>
              ) : (
                <span className="text-muted-foreground">{column.label}</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Virtualized Table Body */}
      <List
        height={height}
        width="100%"
        itemCount={businesses.length}
        itemSize={itemSize}
        itemData={rowData}
        overscanCount={5}
      >
        {VirtualizedRow}
      </List>
    </div>
  )
}
