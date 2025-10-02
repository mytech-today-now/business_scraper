/**
 * Search and Filters Component
 * Secure search and filtering interface with input validation
 */

'use client'

import React, { useState } from 'react'
import { Search, Filter, Bookmark, Trash2 } from 'lucide-react'
import { SecurityBoundary, useSecureInput } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { Card } from '../ui/Card'
import { sanitizeInput, validateInput } from '@/lib/security'
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

export interface SearchAndFiltersProps {
  searchQuery: string
  onSearchChange: (query: string) => void
  advancedFilters: AdvancedFilter[]
  onFiltersChange: (filters: AdvancedFilter[]) => void
  savedQueries: SavedQuery[]
  onLoadQuery: (query: SavedQuery) => void
}

/**
 * Search and Filters component with security validation
 */
export function SearchAndFilters({
  searchQuery,
  onSearchChange,
  advancedFilters,
  onFiltersChange,
  savedQueries,
  onLoadQuery,
}: SearchAndFiltersProps): JSX.Element {
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false)
  const [showSavedQueries, setShowSavedQueries] = useState(false)

  // Secure search input
  const {
    value: secureSearchValue,
    setValue: setSecureSearchValue,
    isValid: isSearchValid,
    errors: searchErrors,
  } = useSecureInput(searchQuery)

  /**
   * Secure search handler with validation
   */
  const handleSecureSearch = (value: string) => {
    try {
      // Validate input
      const validation = validateInput(value)
      if (!validation.isValid) {
        logger.warn('SearchAndFilters', 'Invalid search input', validation.errors)
        toast.error(`Invalid search: ${validation.errors.join(', ')}`)
        return
      }

      // Sanitize and update
      const sanitizedValue = sanitizeInput(value)
      setSecureSearchValue(sanitizedValue)
      onSearchChange(sanitizedValue)
      
      logger.debug('SearchAndFilters', 'Search query updated', { query: sanitizedValue })
    } catch (error) {
      logger.error('SearchAndFilters', 'Search update failed', error)
      toast.error('Search update failed')
    }
  }

  /**
   * Add advanced filter with validation
   */
  const addAdvancedFilter = () => {
    try {
      const newFilter: AdvancedFilter = {
        field: 'businessName',
        operator: 'contains',
        value: '',
      }
      
      const updatedFilters = [...advancedFilters, newFilter]
      onFiltersChange(updatedFilters)
      
      logger.debug('SearchAndFilters', 'Advanced filter added')
    } catch (error) {
      logger.error('SearchAndFilters', 'Failed to add filter', error)
      toast.error('Failed to add filter')
    }
  }

  /**
   * Remove advanced filter
   */
  const removeAdvancedFilter = (index: number) => {
    try {
      if (index < 0 || index >= advancedFilters.length) {
        logger.warn('SearchAndFilters', 'Invalid filter index for removal', { index })
        return
      }

      const updatedFilters = advancedFilters.filter((_, i) => i !== index)
      onFiltersChange(updatedFilters)
      
      logger.debug('SearchAndFilters', 'Advanced filter removed', { index })
    } catch (error) {
      logger.error('SearchAndFilters', 'Failed to remove filter', error)
      toast.error('Failed to remove filter')
    }
  }

  /**
   * Update advanced filter with validation
   */
  const updateAdvancedFilter = (index: number, updates: Partial<AdvancedFilter>) => {
    try {
      if (index < 0 || index >= advancedFilters.length) {
        logger.warn('SearchAndFilters', 'Invalid filter index for update', { index })
        return
      }

      // Validate filter value if it's a string
      if (updates.value && typeof updates.value === 'string') {
        const validation = validateInput(updates.value)
        if (!validation.isValid) {
          logger.warn('SearchAndFilters', 'Invalid filter value', validation.errors)
          toast.error(`Invalid filter value: ${validation.errors.join(', ')}`)
          return
        }
        updates.value = sanitizeInput(updates.value)
      }

      // Validate second value if present
      if (updates.secondValue && typeof updates.secondValue === 'string') {
        const validation = validateInput(updates.secondValue)
        if (!validation.isValid) {
          logger.warn('SearchAndFilters', 'Invalid filter second value', validation.errors)
          toast.error(`Invalid filter value: ${validation.errors.join(', ')}`)
          return
        }
        updates.secondValue = sanitizeInput(updates.secondValue)
      }

      const updatedFilters = advancedFilters.map((filter, i) =>
        i === index ? { ...filter, ...updates } : filter
      )
      onFiltersChange(updatedFilters)
      
      logger.debug('SearchAndFilters', 'Advanced filter updated', { index, updates })
    } catch (error) {
      logger.error('SearchAndFilters', 'Failed to update filter', error)
      toast.error('Failed to update filter')
    }
  }

  /**
   * Load saved query with validation
   */
  const handleLoadQuery = (query: SavedQuery) => {
    try {
      // Validate query structure
      if (!query.id || !query.filters || !Array.isArray(query.filters)) {
        logger.warn('SearchAndFilters', 'Invalid saved query structure', { queryId: query.id })
        toast.error('Invalid saved query')
        return
      }

      onLoadQuery(query)
      setShowSavedQueries(false)
      
      logger.info('SearchAndFilters', 'Saved query loaded', { queryId: query.id, name: query.name })
      toast.success(`Loaded query: ${query.name}`)
    } catch (error) {
      logger.error('SearchAndFilters', 'Failed to load saved query', error)
      toast.error('Failed to load saved query')
    }
  }

  return (
    <SecurityBoundary componentName="SearchAndFilters">
      <Card className="p-4">
        <div className="space-y-4">
          {/* Basic Search */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search businesses..."
                value={secureSearchValue}
                onChange={e => handleSecureSearch(e.target.value)}
                className="pl-10"
                aria-label="Search businesses"
              />
              {!isSearchValid && searchErrors.length > 0 && (
                <div className="absolute top-full left-0 mt-1 text-xs text-red-600">
                  {searchErrors.join(', ')}
                </div>
              )}
            </div>

            <Button
              variant="outline"
              icon={Filter}
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              aria-label="Toggle advanced filters"
            >
              Advanced Filters
            </Button>

            <Button
              variant="outline"
              icon={Bookmark}
              onClick={() => setShowSavedQueries(!showSavedQueries)}
              aria-label="Show saved queries"
            >
              Saved Queries
            </Button>
          </div>

          {/* Advanced Filters */}
          {showAdvancedFilters && (
            <SecurityBoundary componentName="AdvancedFilters">
              <div className="border-t pt-4">
                <div className="space-y-3">
                  {advancedFilters.map((filter, index) => (
                    <AdvancedFilterRow
                      key={index}
                      filter={filter}
                      onUpdate={updates => updateAdvancedFilter(index, updates)}
                      onRemove={() => removeAdvancedFilter(index)}
                    />
                  ))}

                  <Button variant="outline" size="sm" onClick={addAdvancedFilter}>
                    Add Filter
                  </Button>
                </div>
              </div>
            </SecurityBoundary>
          )}

          {/* Saved Queries */}
          {showSavedQueries && (
            <SecurityBoundary componentName="SavedQueries">
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3">Saved Queries</h4>
                <div className="space-y-2">
                  {savedQueries.map(query => (
                    <div
                      key={query.id}
                      className="flex items-center justify-between p-3 border rounded-lg hover:bg-gray-50"
                    >
                      <div>
                        <h5 className="font-medium">{query.name}</h5>
                        <p className="text-sm text-gray-600">{query.description}</p>
                        <p className="text-xs text-gray-500">
                          {query.filters.length} filters • Created {query.createdAt.toLocaleDateString()}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleLoadQuery(query)}
                      >
                        Load
                      </Button>
                    </div>
                  ))}
                  {savedQueries.length === 0 && (
                    <p className="text-sm text-gray-500 text-center py-4">
                      No saved queries available
                    </p>
                  )}
                </div>
              </div>
            </SecurityBoundary>
          )}
        </div>
      </Card>
    </SecurityBoundary>
  )
}

/**
 * Advanced Filter Row Component
 */
interface AdvancedFilterRowProps {
  filter: AdvancedFilter
  onUpdate: (updates: Partial<AdvancedFilter>) => void
  onRemove: () => void
}

function AdvancedFilterRow({ filter, onUpdate, onRemove }: AdvancedFilterRowProps) {
  const fields = [
    { value: 'businessName', label: 'Business Name' },
    { value: 'industry', label: 'Industry' },
    { value: 'email', label: 'Email' },
    { value: 'phone', label: 'Phone' },
    { value: 'city', label: 'City' },
    { value: 'state', label: 'State' },
  ]

  const operators = [
    { value: 'equals', label: 'Equals' },
    { value: 'contains', label: 'Contains' },
    { value: 'startsWith', label: 'Starts With' },
    { value: 'endsWith', label: 'Ends With' },
    { value: 'gt', label: 'Greater Than' },
    { value: 'lt', label: 'Less Than' },
    { value: 'between', label: 'Between' },
  ]

  return (
    <SecurityBoundary componentName="AdvancedFilterRow">
      <div className="flex items-center space-x-3">
        <select
          value={filter.field}
          onChange={e => onUpdate({ field: e.target.value })}
          className="px-3 py-2 border border-gray-300 rounded text-sm"
          aria-label="Filter field"
        >
          {fields.map(field => (
            <option key={field.value} value={field.value}>
              {field.label}
            </option>
          ))}
        </select>

        <select
          value={filter.operator}
          onChange={e => onUpdate({ operator: e.target.value as any })}
          className="px-3 py-2 border border-gray-300 rounded text-sm"
          aria-label="Filter operator"
        >
          {operators.map(op => (
            <option key={op.value} value={op.value}>
              {op.label}
            </option>
          ))}
        </select>

        <Input
          value={filter.value}
          onChange={e => onUpdate({ value: e.target.value })}
          placeholder="Value"
          className="w-32"
          aria-label="Filter value"
        />

        {filter.operator === 'between' && (
          <Input
            value={filter.secondValue || ''}
            onChange={e => onUpdate({ secondValue: e.target.value })}
            placeholder="To"
            className="w-32"
            aria-label="Filter second value"
          />
        )}

        <Button
          variant="ghost"
          size="sm"
          icon={Trash2}
          onClick={onRemove}
          aria-label="Remove filter"
        />
      </div>
    </SecurityBoundary>
  )
}
