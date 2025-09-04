'use client'

import React, { useState, useRef, useEffect, useMemo } from 'react'
import {
  Plus,
  Trash2,
  Check,
  X,
  Download,
  Upload,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { IndustryModal } from './IndustryModal'
import { IndustryItemEditor } from './IndustryItemEditor'
import { clsx } from 'clsx'
import { IndustryCategory, IndustrySubCategory, IndustryGroup } from '@/types/business'
import { DEFAULT_SUB_CATEGORIES } from '@/lib/industry-config'
import { useResponsive } from '@/hooks/useResponsive'
import toast from 'react-hot-toast'

/**
 * CategorySelector component props
 */
interface CategorySelectorProps {
  disabled?: boolean
}

/**
 * CategorySelector component for managing industry categories
 * Allows users to select, add, and remove industry categories
 */
export function CategorySelector({ disabled = false }: CategorySelectorProps): JSX.Element {
  const { isMobile, isTouchDevice } = useResponsive()
  const {
    state,
    toggleIndustry,
    selectAllIndustries,
    deselectAllIndustries,
    selectSubCategoryIndustries,
    deselectSubCategoryIndustries,
    removeIndustry,
    updateIndustry,
    addCustomIndustry,
    setAllIndustries,
    setAllSubCategories,
    refreshDefaultIndustries,
    startIndustryEdit,
    endIndustryEdit,
  } = useConfig()

  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingIndustry, setEditingIndustry] = useState<IndustryCategory | undefined>(undefined)
  const [expandedEditingId, setExpandedEditingId] = useState<string | null>(null)
  const [inlineEditingId, setInlineEditingId] = useState<string | null>(null)
  const [editingKeywords, setEditingKeywords] = useState<string>('')
  const [expandedSubCategories, setExpandedSubCategories] = useState<Set<string>>(
    new Set(['professional-services']) // Professional Services expanded by default
  )
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  /**
   * Handle opening modal for adding new industry
   */
  const handleAddIndustry = (): void => {
    setEditingIndustry(undefined)
    setIsModalOpen(true)
  }

  /**
   * Handle closing modal
   */
  const handleCloseModal = (): void => {
    setIsModalOpen(false)
    setEditingIndustry(undefined)
  }

  /**
   * Handle starting inline editing of keywords
   */
  const handleStartInlineEdit = (industry: IndustryCategory, e: React.MouseEvent): void => {
    e.stopPropagation()
    setInlineEditingId(industry.id)
    setEditingKeywords(industry.keywords.join('\n'))

    // Focus textarea after state update and auto-resize
    setTimeout(() => {
      if (textareaRef.current) {
        textareaRef.current.focus()
        // Auto-resize textarea to fit content
        textareaRef.current.style.height = 'auto'
        textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`
      }
    }, 0)
  }

  /**
   * Handle saving inline edited keywords
   */
  const handleSaveInlineEdit = async (industry: IndustryCategory): Promise<void> => {
    const newKeywords = editingKeywords
      .split('\n')
      .map(k => k.trim())
      .filter(Boolean)

    if (newKeywords.length === 0) {
      // Don't save if no keywords
      handleCancelInlineEdit()
      return
    }

    try {
      const updatedIndustry: IndustryCategory = {
        ...industry,
        keywords: newKeywords,
      }
      await updateIndustry(updatedIndustry, true)
      setInlineEditingId(null)
      setEditingKeywords('')
    } catch (error) {
      console.error('Failed to update industry keywords:', error)
    }
  }

  /**
   * Handle canceling inline edit
   */
  const handleCancelInlineEdit = (): void => {
    setInlineEditingId(null)
    setEditingKeywords('')
  }

  /**
   * Handle starting expanded edit mode
   */
  const handleStartExpandedEdit = (industryId: string): void => {
    // Close any other editing modes
    setInlineEditingId(null)
    setEditingKeywords('')
    setExpandedEditingId(industryId)
    // Track edit state
    startIndustryEdit(industryId)
  }

  /**
   * Handle canceling expanded edit mode
   */
  const handleCancelExpandedEdit = (): void => {
    if (expandedEditingId) {
      endIndustryEdit(expandedEditingId)
    }
    setExpandedEditingId(null)
  }

  /**
   * Handle updating industry from expanded editor
   */
  const handleUpdateFromExpandedEdit = async (industry: IndustryCategory): Promise<void> => {
    await updateIndustry(industry, true)
    endIndustryEdit(industry.id)
    setExpandedEditingId(null)
  }

  /**
   * Handle textarea content change with auto-resize
   */
  const handleTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>): void => {
    setEditingKeywords(e.target.value)

    // Auto-resize textarea
    const textarea = e.target
    textarea.style.height = 'auto'
    textarea.style.height = `${textarea.scrollHeight}px`
  }

  /**
   * Export all industries to JSON file (including pre-populated ones with their current settings)
   */
  const handleExportIndustries = (): void => {
    try {
      // Export ALL industries with their current settings
      const allIndustries = state.industries

      if (allIndustries.length === 0) {
        toast.error('No industries to export')
        return
      }

      // Create export data with standardized Business Scraper format including sub-categories
      const exportData = {
        name: 'Business Scraper',
        url: 'https://github.com/mytech-today-now/business_scraper',
        version: '2.0.0', // Updated version for sub-category support
        exportDate: new Date().toISOString(),
        subCategories: state.subCategories.map(subCategory => ({
          id: subCategory.id,
          name: subCategory.name,
          description: subCategory.description,
          isExpanded: subCategory.isExpanded,
        })),
        industries: allIndustries.map(industry => ({
          id: industry.id,
          name: industry.name,
          keywords: industry.keywords,
          isCustom: industry.isCustom,
          subCategoryId: industry.subCategoryId,
          domainBlacklist: industry.domainBlacklist || [],
        })),
      }

      // Create and download file
      const dataStr = JSON.stringify(exportData, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)

      const link = document.createElement('a')
      link.href = url
      link.download = `industries-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      toast.success(`Exported ${allIndustries.length} industries with their current settings`)
    } catch (error) {
      console.error('Export failed:', error)
      toast.error('Failed to export industries')
    }
  }

  /**
   * Import industries from JSON file (overwrites all current settings)
   */
  const handleImportIndustries = (): void => {
    fileInputRef.current?.click()
  }

  /**
   * Process imported file
   */
  const handleFileImport = async (event: React.ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0]
    if (!file) return

    try {
      const text = await file.text()
      const importData = JSON.parse(text)

      // Validate Business Scraper format
      if (!importData.name || importData.name !== 'Business Scraper') {
        throw new Error('Invalid file format: Expected Business Scraper export file')
      }

      if (!importData.url || !importData.version || !importData.exportDate) {
        throw new Error('Invalid file format: Missing required Business Scraper metadata')
      }

      // Support multiple formats: old (customIndustries), new (industries), and latest (with sub-categories)
      let industriesToImport: any[] = []
      let subCategoriesToImport: any[] = []

      if (importData.industries && Array.isArray(importData.industries)) {
        // New format - includes all industries with their settings
        industriesToImport = importData.industries

        // Check for sub-categories (version 2.0.0+)
        if (importData.subCategories && Array.isArray(importData.subCategories)) {
          subCategoriesToImport = importData.subCategories
        }
      } else if (importData.customIndustries && Array.isArray(importData.customIndustries)) {
        // Legacy format - only custom industries
        industriesToImport = importData.customIndustries.map((industry: any) => ({
          ...industry,
          isCustom: true,
          domainBlacklist: [],
        }))
      } else {
        throw new Error(
          'Invalid file format: Expected JSON with "industries" or "customIndustries" array'
        )
      }

      if (industriesToImport.length === 0) {
        toast('No industries found in the file')
        return
      }

      // Validate and process industries
      const validIndustries: IndustryCategory[] = []
      let skippedCount = 0

      for (const industryData of industriesToImport) {
        // Validate industry data
        if (!industryData.name || !industryData.keywords || !Array.isArray(industryData.keywords)) {
          console.warn('Skipping invalid industry data:', industryData)
          skippedCount++
          continue
        }

        // Create industry object with sub-category support
        const industry: IndustryCategory = {
          id:
            industryData.id || `imported-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          name: industryData.name,
          keywords: industryData.keywords.filter(Boolean), // Remove empty keywords
          isCustom: industryData.isCustom !== undefined ? industryData.isCustom : true,
          subCategoryId: industryData.subCategoryId || undefined,
          domainBlacklist:
            industryData.domainBlacklist && Array.isArray(industryData.domainBlacklist)
              ? industryData.domainBlacklist.filter(Boolean)
              : undefined,
        }

        validIndustries.push(industry)
      }

      if (validIndustries.length === 0) {
        toast.error(
          `No valid industries found in file${skippedCount > 0 ? ` (${skippedCount} skipped due to invalid data)` : ''}`
        )
        return
      }

      // Import sub-categories if available
      let importedSubCategories = 0
      if (subCategoriesToImport.length > 0) {
        const validSubCategories: IndustrySubCategory[] = []

        for (const subCategoryData of subCategoriesToImport) {
          if (subCategoryData.id && subCategoryData.name) {
            const subCategory: IndustrySubCategory = {
              id: subCategoryData.id,
              name: subCategoryData.name,
              description: subCategoryData.description || undefined,
              isExpanded: subCategoryData.isExpanded || false,
            }
            validSubCategories.push(subCategory)
          }
        }

        if (validSubCategories.length > 0) {
          await setAllSubCategories(validSubCategories)
          importedSubCategories = validSubCategories.length
        }
      }

      // Replace all industries with imported ones
      await setAllIndustries(validIndustries)

      // Show results
      const subCategoryMessage =
        importedSubCategories > 0 ? ` and ${importedSubCategories} sub-categories` : ''
      toast.success(
        `Imported ${validIndustries.length} industries${subCategoryMessage}${skippedCount > 0 ? ` (${skippedCount} skipped)` : ''}. All previous settings have been replaced.`
      )
    } catch (error) {
      console.error('Import failed:', error)
      toast.error('Failed to import industries. Please check the file format.')
    } finally {
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
  }

  /**
   * Auto-resize textarea based on content
   */
  useEffect(() => {
    if (textareaRef.current && inlineEditingId) {
      const textarea = textareaRef.current
      // Reset height to auto to get the correct scrollHeight
      textarea.style.height = 'auto'
      // Set height based on content, with minimum of 60px
      const newHeight = Math.max(60, textarea.scrollHeight)
      textarea.style.height = `${newHeight}px`
    }
  }, [editingKeywords, inlineEditingId])

  const allSelected = state.selectedIndustries.length === state.industries.length
  const noneSelected = state.selectedIndustries.length === 0

  /**
   * Group industries by sub-categories
   */
  const industryGroups = useMemo((): IndustryGroup[] => {
    // Create a map of sub-category ID to sub-category
    const subCategoryMap = new Map(DEFAULT_SUB_CATEGORIES.map(sc => [sc.id, sc]))

    // Group industries by sub-category
    const groupMap = new Map<string, IndustryCategory[]>()

    // Initialize groups for all sub-categories
    DEFAULT_SUB_CATEGORIES.forEach(subCategory => {
      groupMap.set(subCategory.id, [])
    })

    // Add industries to their respective groups
    state.industries.forEach(industry => {
      const subCategoryId = industry.subCategoryId || 'professional-services' // Default fallback
      if (!groupMap.has(subCategoryId)) {
        groupMap.set(subCategoryId, [])
      }
      groupMap.get(subCategoryId)!.push(industry)
    })

    // Convert to IndustryGroup array
    return Array.from(groupMap.entries())
      .map(([subCategoryId, industries]) => {
        const subCategory = subCategoryMap.get(subCategoryId)
        if (!subCategory) return null

        const selectedIndustries = industries.filter(industry =>
          state.selectedIndustries.includes(industry.id)
        )

        return {
          subCategory,
          industries,
          isSelected: industries.length > 0 && selectedIndustries.length === industries.length,
          isPartiallySelected:
            selectedIndustries.length > 0 && selectedIndustries.length < industries.length,
        }
      })
      .filter((group): group is IndustryGroup => group !== null)
      .filter(group => group.industries.length > 0) // Only show groups with industries
  }, [state.industries, state.selectedIndustries])

  /**
   * Toggle sub-category expansion
   */
  const toggleSubCategory = (subCategoryId: string): void => {
    setExpandedSubCategories(prev => {
      const newSet = new Set(prev)
      if (newSet.has(subCategoryId)) {
        newSet.delete(subCategoryId)
      } else {
        newSet.add(subCategoryId)
      }
      return newSet
    })
  }

  /**
   * Select/deselect all industries in a sub-category
   */
  const toggleSubCategorySelection = (group: IndustryGroup): void => {
    if (group.isSelected) {
      // Deselect all industries in this group
      deselectSubCategoryIndustries(group.subCategory.id)
    } else {
      // Select all industries in this group
      selectSubCategoryIndustries(group.subCategory.id)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Industry Categories</span>
          {disabled && (
            <p className="text-sm text-muted-foreground">
              🔒 Industry selection is locked during scraping
            </p>
          )}
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              icon={Plus}
              onClick={handleAddIndustry}
              disabled={disabled}
            >
              Add Custom
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={Download}
              onClick={handleExportIndustries}
              title="Export custom industries to JSON file"
              disabled={disabled}
            >
              Export
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={Upload}
              onClick={handleImportIndustries}
              title="Import custom industries from JSON file"
              disabled={disabled}
            >
              Import
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={RefreshCw}
              onClick={refreshDefaultIndustries}
              title="Refresh default industries with latest data"
            >
              Refresh Defaults
            </Button>
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Enhanced Selection Summary and Quick Actions */}
        <div className="flex items-center justify-between p-4 bg-muted/30 rounded-lg border">
          <div className="flex items-center space-x-4">
            <div className="text-sm font-medium text-foreground">
              {state.selectedIndustries.length} of {state.industries.length} categories selected
            </div>
            {state.selectedIndustries.length > 0 && (
              <div className="text-xs text-muted-foreground">
                ({Math.round((state.selectedIndustries.length / state.industries.length) * 100)}%
                selected)
              </div>
            )}
          </div>

          {/* Quick Selection Actions */}
          <div className="flex items-center space-x-3">
            <Button
              variant={allSelected ? 'default' : 'outline'}
              size="sm"
              onClick={allSelected ? deselectAllIndustries : selectAllIndustries}
              className={clsx(
                'transition-all duration-200',
                allSelected
                  ? 'bg-primary text-primary-foreground hover:bg-primary/90'
                  : 'hover:bg-primary/10 hover:border-primary/50'
              )}
            >
              {allSelected ? (
                <>
                  <X className="h-3 w-3 mr-1" />
                  Deselect All
                </>
              ) : (
                <>
                  <Check className="h-3 w-3 mr-1" />
                  Select All
                </>
              )}
            </Button>

            {/* Selection Progress Indicator */}
            <div className="flex items-center space-x-2">
              <div className="w-20 h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300 ease-out"
                  style={{
                    width: `${(state.selectedIndustries.length / state.industries.length) * 100}%`,
                  }}
                />
              </div>
              <span className="text-xs text-muted-foreground min-w-[2.5rem] text-right">
                {Math.round((state.selectedIndustries.length / state.industries.length) * 100)}%
              </span>
            </div>
          </div>
        </div>

        {/* Industry Groups by Sub-Category */}
        <div className="space-y-4">
          {industryGroups.map(group => {
            const isExpanded = expandedSubCategories.has(group.subCategory.id)

            return (
              <div key={group.subCategory.id} className="border rounded-lg overflow-hidden">
                {/* Sub-Category Header */}
                <div
                  className={clsx(
                    'flex items-center justify-between p-3 cursor-pointer transition-all',
                    'hover:bg-accent/50 border-b',
                    group.isSelected && 'bg-primary/5 border-primary/20',
                    group.isPartiallySelected &&
                      !group.isSelected &&
                      'bg-orange-50 border-orange-200'
                  )}
                  onClick={() => toggleSubCategory(group.subCategory.id)}
                >
                  <div className="flex items-center space-x-3">
                    {/* Expand/Collapse Icon */}
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}

                    {/* Sub-Category Info */}
                    <div>
                      <h3 className="font-medium text-sm">{group.subCategory.name}</h3>
                      {group.subCategory.description && (
                        <p className="text-xs text-muted-foreground">
                          {group.subCategory.description}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    {/* Selection Count */}
                    <span className="text-xs text-muted-foreground">
                      {group.industries.filter(i => state.selectedIndustries.includes(i.id)).length}{' '}
                      / {group.industries.length}
                    </span>

                    {/* Select/Deselect All Button */}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={e => {
                        e.stopPropagation()
                        toggleSubCategorySelection(group)
                      }}
                      className={clsx(
                        'h-6 px-2 text-xs',
                        group.isSelected && 'text-primary',
                        group.isPartiallySelected && !group.isSelected && 'text-orange-600'
                      )}
                      disabled={disabled}
                    >
                      {group.isSelected ? 'Deselect All' : 'Select All'}
                    </Button>

                    {/* Selection Indicator */}
                    <div
                      className={clsx(
                        'w-4 h-4 rounded border-2 transition-all',
                        group.isSelected
                          ? 'bg-primary border-primary'
                          : group.isPartiallySelected
                            ? 'bg-orange-200 border-orange-400'
                            : 'border-muted-foreground'
                      )}
                    >
                      {group.isSelected && <Check className="w-3 h-3 text-primary-foreground" />}
                      {group.isPartiallySelected && !group.isSelected && (
                        <div className="w-2 h-2 bg-orange-600 rounded-full mx-auto mt-0.5" />
                      )}
                    </div>
                  </div>
                </div>

                {/* Industries Grid (when expanded) */}
                {isExpanded && (
                  <div className="p-3 bg-accent/20">
                    <div
                      className={clsx(
                        'grid gap-2',
                        isMobile
                          ? 'grid-cols-1'
                          : 'grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
                      )}
                    >
                      {group.industries
                        .slice()
                        .sort((a, b) => a.name.localeCompare(b.name))
                        .map(industry => {
                          const isSelected = state.selectedIndustries.includes(industry.id)
                          const isInlineEditing = inlineEditingId === industry.id
                          const isExpandedEditing = expandedEditingId === industry.id

                          // Use expanded editor if in expanded editing mode
                          if (isExpandedEditing) {
                            return (
                              <div key={industry.id}>
                                <IndustryItemEditor
                                  industry={industry}
                                  isSelected={isSelected}
                                  onToggle={() => toggleIndustry(industry.id)}
                                  onUpdate={handleUpdateFromExpandedEdit}
                                  onCancel={handleCancelExpandedEdit}
                                />
                              </div>
                            )
                          }

                          return (
                            <div
                              key={industry.id}
                              className={clsx(
                                'relative border rounded-md transition-all group',
                                'hover:border-primary/50 hover:bg-accent/50',
                                isSelected && 'border-primary bg-primary/5',
                                !isSelected && 'border-border',
                                !isInlineEditing && !disabled && 'cursor-pointer',
                                isInlineEditing && 'border-primary bg-primary/10',
                                disabled && 'opacity-50 cursor-not-allowed',
                                // Mobile-first padding with touch-friendly targets
                                isMobile ? 'p-3 min-h-touch' : 'p-2'
                              )}
                              onClick={() =>
                                !isInlineEditing && !disabled && toggleIndustry(industry.id)
                              }
                            >
                              {/* Action buttons and Selection Indicator */}
                              {!isInlineEditing && (
                                <div
                                  className={clsx(
                                    'absolute flex items-center',
                                    isMobile ? 'top-3 right-3 space-x-2' : 'top-2 right-2 space-x-1'
                                  )}
                                >
                                  {/* Delete button for custom industries */}
                                  {industry.isCustom && !disabled && (
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className={clsx(
                                        'text-destructive hover:text-destructive hover:bg-destructive/10 transition-opacity',
                                        isMobile
                                          ? 'h-6 w-6 min-h-touch min-w-touch opacity-100'
                                          : 'h-4 w-4 opacity-0 group-hover:opacity-100'
                                      )}
                                      onClick={e => {
                                        e.stopPropagation()
                                        removeIndustry(industry.id)
                                      }}
                                      title="Delete custom industry"
                                    >
                                      <Trash2 className={isMobile ? 'h-4 w-4' : 'h-3 w-3'} />
                                    </Button>
                                  )}

                                  {/* Selection checkbox */}
                                  <div
                                    className={clsx(
                                      'rounded border-2 transition-all',
                                      isMobile ? 'w-5 h-5' : 'w-4 h-4',
                                      isSelected
                                        ? 'bg-primary border-primary'
                                        : 'border-muted-foreground'
                                    )}
                                  >
                                    {isSelected && (
                                      <Check
                                        className={clsx(
                                          'text-primary-foreground',
                                          isMobile ? 'w-4 h-4' : 'w-3 h-3'
                                        )}
                                      />
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* Industry Info */}
                              <div className={clsx('transition-all', !isInlineEditing && 'pr-5')}>
                                <h4 className="font-medium text-xs mb-1">{industry.name}</h4>

                                {/* Keywords Display/Edit */}
                                {isInlineEditing ? (
                                  <div className="space-y-3 mb-3">
                                    <textarea
                                      ref={textareaRef}
                                      value={editingKeywords}
                                      onChange={handleTextareaChange}
                                      className="w-full p-3 text-sm border border-primary rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent min-h-[80px] bg-background text-foreground placeholder:text-muted-foreground font-mono overflow-hidden"
                                      placeholder="Enter keywords, one per line..."
                                      autoFocus
                                    />
                                    <div className="flex items-center justify-end space-x-2">
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-8 px-3 text-green-600 hover:text-green-700 hover:bg-green-100 dark:hover:bg-green-900 border border-green-200 dark:border-green-800"
                                        onClick={() => handleSaveInlineEdit(industry)}
                                      >
                                        ✅ Save
                                      </Button>
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-8 px-3 text-red-600 hover:text-red-700 hover:bg-red-100 dark:hover:bg-red-900 border border-red-200 dark:border-red-800"
                                        onClick={handleCancelInlineEdit}
                                      >
                                        🚫 Cancel
                                      </Button>
                                    </div>
                                  </div>
                                ) : (
                                  <div className="mb-2">
                                    <p
                                      className={clsx(
                                        'text-xs text-muted-foreground transition-colors rounded-sm px-1 py-0.5 -mx-1 leading-tight',
                                        !disabled &&
                                          'cursor-pointer hover:text-primary hover:bg-accent'
                                      )}
                                      onClick={e => {
                                        if (!disabled) {
                                          e.stopPropagation()
                                          handleStartExpandedEdit(industry.id)
                                        }
                                      }}
                                      title={
                                        disabled
                                          ? 'Editing disabled during scraping'
                                          : 'Click to edit criteria and domain blacklist'
                                      }
                                    >
                                      {industry.keywords.join(', ')}
                                    </p>
                                    {industry.domainBlacklist &&
                                      industry.domainBlacklist.length > 0 && (
                                        <p className="text-xs text-muted-foreground/80 mt-0.5 px-1">
                                          🚫 {industry.domainBlacklist.length} blocked domain
                                          {industry.domainBlacklist.length !== 1 ? 's' : ''}
                                        </p>
                                      )}
                                    <p className="text-xs text-muted-foreground/60 mt-0.5 opacity-0 group-hover:opacity-100 transition-opacity px-1">
                                      Click criteria to edit keywords & blacklist
                                    </p>
                                  </div>
                                )}

                                {/* Bottom section with badges */}
                                {!isInlineEditing && industry.isCustom && (
                                  <div className="flex items-center justify-start">
                                    {/* Custom Industry Badge */}
                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs bg-secondary text-secondary-foreground">
                                      Custom
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Empty State */}
        {state.industries.length === 0 && (
          <div className="text-center py-8 text-muted-foreground">
            <p>No industry categories available.</p>
            <Button variant="outline" className="mt-2" icon={Plus} onClick={handleAddIndustry}>
              Add Your First Industry
            </Button>
          </div>
        )}

        {/* Hidden file input for import */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          onChange={handleFileImport}
          className="hidden"
          aria-label="Import custom industries JSON file"
        />

        {/* Industry Modal */}
        <IndustryModal isOpen={isModalOpen} onClose={handleCloseModal} industry={editingIndustry} />

        {/* Validation Message */}
        {noneSelected && (
          <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
            <p className="text-sm text-destructive">
              Please select at least one industry category to continue.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
