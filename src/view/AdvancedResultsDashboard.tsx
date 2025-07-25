/**
 * Advanced Results Dashboard
 * Sophisticated results viewing and management system with data visualization
 */

'use client'

import React, { useState, useEffect, useMemo } from 'react'
import { 
  Search, 
  Filter, 
  Download, 
  Eye, 
  Edit, 
  Trash2, 
  Tag, 
  Star, 
  BarChart3, 
  PieChart, 
  Map, 
  Grid, 
  List, 
  SortAsc, 
  SortDesc,
  MoreHorizontal,
  CheckSquare,
  Square,
  RefreshCw,
  Settings,
  Bookmark,
  Share2
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface AdvancedFilter {
  field: string
  operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'gt' | 'lt' | 'between'
  value: any
  secondValue?: any // for 'between' operator
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

export interface DataVisualization {
  type: 'bar' | 'pie' | 'line' | 'scatter' | 'map'
  title: string
  data: any[]
  config: any
}

export function AdvancedResultsDashboard() {
  const [businesses, setBusinesses] = useState<BusinessRecord[]>([])
  const [filteredBusinesses, setFilteredBusinesses] = useState<BusinessRecord[]>([])
  const [selectedBusinesses, setSelectedBusinesses] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<'table' | 'grid' | 'map'>('table')
  const [showVisualization, setShowVisualization] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  
  // Advanced filtering and search
  const [searchQuery, setSearchQuery] = useState('')
  const [advancedFilters, setAdvancedFilters] = useState<AdvancedFilter[]>([])
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([])
  const [activeSavedQuery, setActiveSavedQuery] = useState<string | null>(null)
  
  // Sorting and pagination
  const [sortConfig, setSortConfig] = useState<{ field: string; direction: 'asc' | 'desc' }[]>([])
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  
  // Annotations and tags
  const [annotations, setAnnotations] = useState<ResultAnnotation[]>([])
  const [availableTags, setAvailableTags] = useState<string[]>([])
  
  // UI state
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false)
  const [showBulkActions, setShowBulkActions] = useState(false)
  const [showColumnSettings, setShowColumnSettings] = useState(false)

  // Load data
  useEffect(() => {
    loadBusinesses()
    loadSavedQueries()
    loadAnnotations()
  }, [])

  // Apply filters and search
  useEffect(() => {
    applyFiltersAndSearch()
  }, [businesses, searchQuery, advancedFilters, sortConfig])

  const loadBusinesses = async () => {
    setIsLoading(true)
    try {
      // This would fetch from your API
      const mockBusinesses: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Joe\'s Pizza',
          industry: 'Restaurant',
          email: ['info@joespizza.com'],
          phone: '(555) 123-4567',
          websiteUrl: 'https://joespizza.com',
          address: { street: '123 Main St', city: 'New York', state: 'NY', zipCode: '10001' },
          scrapedAt: new Date('2024-01-15'),
        },
        // Add more mock data...
      ]
      setBusinesses(mockBusinesses)
    } catch (error) {
      logger.error('AdvancedResultsDashboard', 'Failed to load businesses', error)
    } finally {
      setIsLoading(false)
    }
  }

  const loadSavedQueries = async () => {
    try {
      const mockQueries: SavedQuery[] = [
        {
          id: '1',
          name: 'Restaurant Businesses',
          description: 'All restaurant businesses',
          filters: [
            { field: 'industry', operator: 'equals', value: 'Restaurant' }
          ],
          sorting: [{ field: 'businessName', direction: 'asc' }],
          createdAt: new Date('2024-01-10'),
          isPublic: true,
        },
      ]
      setSavedQueries(mockQueries)
    } catch (error) {
      logger.error('AdvancedResultsDashboard', 'Failed to load saved queries', error)
    }
  }

  const loadAnnotations = async () => {
    try {
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
      logger.error('AdvancedResultsDashboard', 'Failed to load annotations', error)
    }
  }

  const applyFiltersAndSearch = () => {
    let filtered = [...businesses]

    // Apply search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(business =>
        business.businessName.toLowerCase().includes(query) ||
        business.industry.toLowerCase().includes(query) ||
        business.email.some(email => email.toLowerCase().includes(query)) ||
        (business.phone && business.phone.toLowerCase().includes(query)) ||
        (business.websiteUrl && business.websiteUrl.toLowerCase().includes(query))
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
    setCurrentPage(1) // Reset to first page when filters change
  }

  const getFieldValue = (business: BusinessRecord, field: string): any => {
    switch (field) {
      case 'businessName': return business.businessName
      case 'industry': return business.industry
      case 'email': return business.email.join(', ')
      case 'phone': return business.phone || ''
      case 'website': return business.websiteUrl || ''
      case 'city': return business.address?.city || ''
      case 'state': return business.address?.state || ''
      case 'scrapedAt': return business.scrapedAt
      default: return ''
    }
  }

  const applyFilterOperator = (fieldValue: any, operator: string, value: any, secondValue?: any): boolean => {
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

  const handleBulkAction = async (action: string) => {
    const selectedIds = Array.from(selectedBusinesses)
    logger.info('AdvancedResultsDashboard', `Performing bulk action: ${action} on ${selectedIds.length} items`)
    
    try {
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
      
      // Refresh data
      await loadBusinesses()
      setSelectedBusinesses(new Set())
    } catch (error) {
      logger.error('AdvancedResultsDashboard', `Bulk action ${action} failed`, error)
    }
  }

  const addAdvancedFilter = () => {
    setAdvancedFilters([
      ...advancedFilters,
      { field: 'businessName', operator: 'contains', value: '' }
    ])
  }

  const removeAdvancedFilter = (index: number) => {
    setAdvancedFilters(advancedFilters.filter((_, i) => i !== index))
  }

  const updateAdvancedFilter = (index: number, updates: Partial<AdvancedFilter>) => {
    setAdvancedFilters(advancedFilters.map((filter, i) => 
      i === index ? { ...filter, ...updates } : filter
    ))
  }

  const saveCurrentQuery = async (name: string, description: string) => {
    const newQuery: SavedQuery = {
      id: Date.now().toString(),
      name,
      description,
      filters: advancedFilters,
      sorting: sortConfig,
      createdAt: new Date(),
      isPublic: false,
    }
    
    setSavedQueries([...savedQueries, newQuery])
    logger.info('AdvancedResultsDashboard', `Saved query: ${name}`)
  }

  const loadSavedQuery = (query: SavedQuery) => {
    setAdvancedFilters(query.filters)
    setSortConfig(query.sorting)
    setActiveSavedQuery(query.id)
    logger.info('AdvancedResultsDashboard', `Loaded saved query: ${query.name}`)
  }

  const toggleBusinessSelection = (businessId: string) => {
    const newSelection = new Set(selectedBusinesses)
    if (newSelection.has(businessId)) {
      newSelection.delete(businessId)
    } else {
      newSelection.add(businessId)
    }
    setSelectedBusinesses(newSelection)
  }

  const selectAllVisible = () => {
    const visibleIds = paginatedBusinesses.map(b => b.id)
    setSelectedBusinesses(new Set(visibleIds))
  }

  const clearSelection = () => {
    setSelectedBusinesses(new Set())
  }

  // Pagination
  const totalPages = Math.ceil(filteredBusinesses.length / pageSize)
  const startIndex = (currentPage - 1) * pageSize
  const endIndex = startIndex + pageSize
  const paginatedBusinesses = filteredBusinesses.slice(startIndex, endIndex)

  // Data visualization
  const generateVisualization = (type: DataVisualization['type']): DataVisualization => {
    switch (type) {
      case 'pie':
        const industryData = businesses.reduce((acc, business) => {
          acc[business.industry] = (acc[business.industry] || 0) + 1
          return acc
        }, {} as Record<string, number>)
        
        return {
          type: 'pie',
          title: 'Businesses by Industry',
          data: Object.entries(industryData).map(([industry, count]) => ({
            name: industry,
            value: count
          })),
          config: {}
        }
      
      case 'bar':
        const stateData = businesses.reduce((acc, business) => {
          const state = business.address?.state || 'Unknown'
          acc[state] = (acc[state] || 0) + 1
          return acc
        }, {} as Record<string, number>)
        
        return {
          type: 'bar',
          title: 'Businesses by State',
          data: Object.entries(stateData).map(([state, count]) => ({
            name: state,
            value: count
          })),
          config: {}
        }
      
      default:
        return {
          type: 'bar',
          title: 'Default Visualization',
          data: [],
          config: {}
        }
    }
  }

  return (
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
        
        <div className="flex items-center space-x-3">
          <Button
            variant="outline"
            icon={RefreshCw}
            onClick={loadBusinesses}
            disabled={isLoading}
          >
            Refresh
          </Button>
          <Button
            variant="outline"
            icon={BarChart3}
            onClick={() => setShowVisualization(!showVisualization)}
          >
            Visualize
          </Button>
          <Button icon={Download}>
            Export
          </Button>
        </div>
      </div>

      {/* Search and Filters */}
      <Card className="p-4">
        <div className="space-y-4">
          {/* Basic Search */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search businesses..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            
            <Button
              variant="outline"
              icon={Filter}
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
            >
              Advanced Filters
            </Button>
            
            <Button
              variant="outline"
              icon={Bookmark}
              onClick={() => {/* Show saved queries */}}
            >
              Saved Queries
            </Button>
          </div>

          {/* Advanced Filters */}
          {showAdvancedFilters && (
            <div className="border-t pt-4">
              <div className="space-y-3">
                {advancedFilters.map((filter, index) => (
                  <AdvancedFilterRow
                    key={index}
                    filter={filter}
                    onUpdate={(updates) => updateAdvancedFilter(index, updates)}
                    onRemove={() => removeAdvancedFilter(index)}
                  />
                ))}
                
                <Button
                  variant="outline"
                  size="sm"
                  onClick={addAdvancedFilter}
                >
                  Add Filter
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Bulk Actions */}
      {selectedBusinesses.size > 0 && (
        <Card className="p-4 bg-blue-50 border-blue-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <span className="text-sm font-medium">
                {selectedBusinesses.size} businesses selected
              </span>
              <Button size="sm" variant="outline" onClick={clearSelection}>
                Clear Selection
              </Button>
            </div>
            
            <div className="flex items-center space-x-2">
              <Button size="sm" onClick={() => handleBulkAction('export')}>
                Export Selected
              </Button>
              <Button size="sm" onClick={() => handleBulkAction('tag')}>
                Add Tags
              </Button>
              <Button size="sm" onClick={() => handleBulkAction('annotate')}>
                Annotate
              </Button>
              <Button size="sm" variant="destructive" onClick={() => handleBulkAction('delete')}>
                Delete
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* View Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-1 bg-gray-100 rounded-lg p-1">
            <Button
              variant={viewMode === 'table' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('table')}
            >
              <List className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'grid' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('grid')}
            >
              <Grid className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'map' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('map')}
            >
              <Map className="h-4 w-4" />
            </Button>
          </div>
          
          <select
            value={pageSize}
            onChange={(e) => setPageSize(Number(e.target.value))}
            className="px-3 py-1 border border-gray-300 rounded text-sm"
          >
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={100}>100 per page</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            icon={Settings}
            onClick={() => setShowColumnSettings(!showColumnSettings)}
          >
            Columns
          </Button>
          
          {paginatedBusinesses.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={selectedBusinesses.size === paginatedBusinesses.length ? clearSelection : selectAllVisible}
            >
              {selectedBusinesses.size === paginatedBusinesses.length ? 'Deselect All' : 'Select All'}
            </Button>
          )}
        </div>
      </div>

      {/* Data Visualization */}
      {showVisualization && (
        <Card className="p-6">
          <CardHeader>
            <CardTitle>Data Visualization</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="h-64 bg-gray-100 rounded-lg flex items-center justify-center">
                <p className="text-gray-500">Industry Distribution Chart</p>
              </div>
              <div className="h-64 bg-gray-100 rounded-lg flex items-center justify-center">
                <p className="text-gray-500">Geographic Distribution Chart</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results Display */}
      {viewMode === 'table' ? (
        <ResultsTable
          businesses={paginatedBusinesses}
          selectedBusinesses={selectedBusinesses}
          onToggleSelection={toggleBusinessSelection}
          sortConfig={sortConfig}
          onSort={setSortConfig}
          annotations={annotations}
        />
      ) : viewMode === 'grid' ? (
        <ResultsGrid
          businesses={paginatedBusinesses}
          selectedBusinesses={selectedBusinesses}
          onToggleSelection={toggleBusinessSelection}
          annotations={annotations}
        />
      ) : (
        <ResultsMap
          businesses={paginatedBusinesses}
          selectedBusinesses={selectedBusinesses}
          onToggleSelection={toggleBusinessSelection}
        />
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-600">
            Showing {startIndex + 1} to {Math.min(endIndex, filteredBusinesses.length)} of {filteredBusinesses.length} results
          </p>
          
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === 1}
              onClick={() => setCurrentPage(currentPage - 1)}
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
              onClick={() => setCurrentPage(currentPage + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

// Placeholder components for different view modes
function ResultsTable({ businesses, selectedBusinesses, onToggleSelection, sortConfig, onSort, annotations }: any) {
  return (
    <Card>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="p-3 text-left">
                <input type="checkbox" className="rounded" />
              </th>
              <th className="p-3 text-left font-medium">Business Name</th>
              <th className="p-3 text-left font-medium">Industry</th>
              <th className="p-3 text-left font-medium">Contact</th>
              <th className="p-3 text-left font-medium">Location</th>
              <th className="p-3 text-left font-medium">Quality</th>
              <th className="p-3 text-left font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {businesses.map((business: BusinessRecord) => (
              <tr key={business.id} className="border-t hover:bg-gray-50">
                <td className="p-3">
                  <input
                    type="checkbox"
                    checked={selectedBusinesses.has(business.id)}
                    onChange={() => onToggleSelection(business.id)}
                    className="rounded"
                  />
                </td>
                <td className="p-3 font-medium">{business.businessName}</td>
                <td className="p-3">{business.industry}</td>
                <td className="p-3">
                  <div className="text-sm">
                    {business.email[0] && <div>{business.email[0]}</div>}
                    {business.phone && <div>{business.phone}</div>}
                  </div>
                </td>
                <td className="p-3">
                  {business.address?.city}, {business.address?.state}
                </td>
                <td className="p-3">
                  <span className="px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800">
                    Active
                  </span>
                </td>
                <td className="p-3">
                  <div className="flex items-center space-x-2">
                    <Button variant="ghost" size="sm" icon={Eye} />
                    <Button variant="ghost" size="sm" icon={Edit} />
                    <Button variant="ghost" size="sm" icon={MoreHorizontal} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ResultsGrid({ businesses, selectedBusinesses, onToggleSelection, annotations }: any) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {businesses.map((business: BusinessRecord) => (
        <Card key={business.id} className="p-4">
          <div className="flex items-start justify-between mb-3">
            <input
              type="checkbox"
              checked={selectedBusinesses.has(business.id)}
              onChange={() => onToggleSelection(business.id)}
              className="rounded"
            />
            <Button variant="ghost" size="sm" icon={MoreHorizontal} />
          </div>
          
          <h3 className="font-semibold mb-2">{business.businessName}</h3>
          <p className="text-sm text-gray-600 mb-2">{business.industry}</p>
          
          <div className="space-y-1 text-sm">
            {business.email[0] && <div>{business.email[0]}</div>}
            {business.phone && <div>{business.phone}</div>}
            <div>{business.address?.city}, {business.address?.state}</div>
          </div>
          
          <div className="mt-3 flex items-center justify-between">
            <span className="px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800">
              Active
            </span>
            
            <div className="flex items-center space-x-1">
              <Button variant="ghost" size="sm" icon={Eye} />
              <Button variant="ghost" size="sm" icon={Edit} />
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}

function ResultsMap({ businesses, selectedBusinesses, onToggleSelection }: any) {
  return (
    <Card className="p-6">
      <div className="h-96 bg-gray-100 rounded-lg flex items-center justify-center">
        <p className="text-gray-500">Interactive map view will be implemented here</p>
      </div>
    </Card>
  )
}

function AdvancedFilterRow({ filter, onUpdate, onRemove }: {
  filter: AdvancedFilter
  onUpdate: (updates: Partial<AdvancedFilter>) => void
  onRemove: () => void
}) {
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
    <div className="flex items-center space-x-3">
      <select
        value={filter.field}
        onChange={(e) => onUpdate({ field: e.target.value })}
        className="px-3 py-2 border border-gray-300 rounded text-sm"
      >
        {fields.map(field => (
          <option key={field.value} value={field.value}>{field.label}</option>
        ))}
      </select>

      <select
        value={filter.operator}
        onChange={(e) => onUpdate({ operator: e.target.value as any })}
        className="px-3 py-2 border border-gray-300 rounded text-sm"
      >
        {operators.map(op => (
          <option key={op.value} value={op.value}>{op.label}</option>
        ))}
      </select>

      <Input
        value={filter.value}
        onChange={(e) => onUpdate({ value: e.target.value })}
        placeholder="Value"
        className="w-32"
      />

      {filter.operator === 'between' && (
        <Input
          value={filter.secondValue || ''}
          onChange={(e) => onUpdate({ secondValue: e.target.value })}
          placeholder="To"
          className="w-32"
        />
      )}

      <Button
        variant="ghost"
        size="sm"
        icon={Trash2}
        onClick={onRemove}
      />
    </div>
  )
}
