'use client'

import React, { useState, useRef, useEffect } from 'react'
import { Plus, Trash2, Check, X, Download, Upload } from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { IndustryModal } from './IndustryModal'
import { clsx } from 'clsx'
import { IndustryCategory } from '@/types/business'
import toast from 'react-hot-toast'

/**
 * CategorySelector component for managing industry categories
 * Allows users to select, add, and remove industry categories
 */
export function CategorySelector() {
  const {
    state,
    toggleIndustry,
    selectAllIndustries,
    deselectAllIndustries,
    removeIndustry,
    updateIndustry,
    addCustomIndustry,
  } = useConfig()

  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingIndustry, setEditingIndustry] = useState<IndustryCategory | undefined>(undefined)
  const [inlineEditingId, setInlineEditingId] = useState<string | null>(null)
  const [editingKeywords, setEditingKeywords] = useState<string>('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  /**
   * Handle opening modal for adding new industry
   */
  const handleAddIndustry = () => {
    setEditingIndustry(undefined)
    setIsModalOpen(true)
  }

  /**
   * Handle closing modal
   */
  const handleCloseModal = () => {
    setIsModalOpen(false)
    setEditingIndustry(undefined)
  }

  /**
   * Handle starting inline editing of keywords
   */
  const handleStartInlineEdit = (industry: IndustryCategory, e: React.MouseEvent) => {
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
  const handleSaveInlineEdit = async (industry: IndustryCategory) => {
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
        keywords: newKeywords
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
  const handleCancelInlineEdit = () => {
    setInlineEditingId(null)
    setEditingKeywords('')
  }

  /**
   * Handle textarea content change with auto-resize
   */
  const handleTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setEditingKeywords(e.target.value)

    // Auto-resize textarea
    const textarea = e.target
    textarea.style.height = 'auto'
    textarea.style.height = `${textarea.scrollHeight}px`
  }

  /**
   * Export custom industries to JSON file
   */
  const handleExportIndustries = () => {
    try {
      const customIndustries = state.industries.filter(industry => industry.isCustom)

      if (customIndustries.length === 0) {
        toast.error('No custom industries to export')
        return
      }

      // Create export data with standardized Business Scraper format
      const exportData = {
        name: "Business Scraper",
        url: "https://github.com/mytech-today-now/business_scraper",
        version: "1.0.0",
        exportDate: new Date().toISOString(),
        customIndustries: customIndustries.map(industry => ({
          name: industry.name,
          keywords: industry.keywords,
          // Don't include id or isCustom as these will be regenerated on import
        }))
      }

      // Create and download file
      const dataStr = JSON.stringify(exportData, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)

      const link = document.createElement('a')
      link.href = url
      link.download = `custom-industries-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      toast.success(`Exported ${customIndustries.length} custom industries`)
    } catch (error) {
      console.error('Export failed:', error)
      toast.error('Failed to export industries')
    }
  }

  /**
   * Import custom industries from JSON file
   */
  const handleImportIndustries = () => {
    fileInputRef.current?.click()
  }

  /**
   * Process imported file
   */
  const handleFileImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    try {
      const text = await file.text()
      const importData = JSON.parse(text)

      // Validate Business Scraper format
      if (!importData.name || importData.name !== "Business Scraper") {
        throw new Error('Invalid file format: Expected Business Scraper export file')
      }

      if (!importData.url || !importData.version || !importData.exportDate) {
        throw new Error('Invalid file format: Missing required Business Scraper metadata')
      }

      if (!importData.customIndustries || !Array.isArray(importData.customIndustries)) {
        throw new Error('Invalid file format: Expected JSON with "customIndustries" array')
      }

      if (importData.customIndustries.length === 0) {
        toast.info('No custom industries found in the file')
        return
      }

      let importedCount = 0
      let skippedCount = 0

      for (const industryData of importData.customIndustries) {
        // Validate industry data
        if (!industryData.name || !industryData.keywords || !Array.isArray(industryData.keywords)) {
          console.warn('Skipping invalid industry data:', industryData)
          skippedCount++
          continue
        }

        // Check if industry with same name already exists
        const existingIndustry = state.industries.find(
          existing => existing.name.toLowerCase() === industryData.name.toLowerCase()
        )

        if (existingIndustry) {
          console.warn(`Skipping duplicate industry: ${industryData.name}`)
          skippedCount++
          continue
        }

        // Import the industry
        try {
          await addCustomIndustry({
            name: industryData.name,
            keywords: industryData.keywords.filter(Boolean), // Remove empty keywords
          })
          importedCount++
        } catch (error) {
          console.error(`Failed to import industry ${industryData.name}:`, error)
          skippedCount++
        }
      }

      // Show results
      if (importedCount > 0) {
        toast.success(`Imported ${importedCount} custom industries${skippedCount > 0 ? ` (${skippedCount} skipped)` : ''}`)
      } else {
        toast.error(`No industries imported${skippedCount > 0 ? ` (${skippedCount} skipped due to duplicates or errors)` : ''}`)
      }

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

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Industry Categories</span>
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={allSelected ? deselectAllIndustries : selectAllIndustries}
            >
              {allSelected ? 'Deselect All' : 'Select All'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={Plus}
              onClick={handleAddIndustry}
            >
              Add Custom
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={Download}
              onClick={handleExportIndustries}
              title="Export custom industries to JSON file"
            >
              Export
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={Upload}
              onClick={handleImportIndustries}
              title="Import custom industries from JSON file"
            >
              Import
            </Button>
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Selection Summary */}
        <div className="text-sm text-muted-foreground">
          {state.selectedIndustries.length} of {state.industries.length} categories selected
        </div>



        {/* Industry Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {state.industries
            .slice()
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((industry) => {
            const isSelected = state.selectedIndustries.includes(industry.id)
            const isInlineEditing = inlineEditingId === industry.id

            return (
              <div
                key={industry.id}
                className={clsx(
                  'relative p-3 border rounded-lg transition-all group',
                  'hover:border-primary/50 hover:bg-accent/50',
                  isSelected && 'border-primary bg-primary/5',
                  !isSelected && 'border-border',
                  !isInlineEditing && 'cursor-pointer',
                  isInlineEditing && 'border-primary bg-primary/10'
                )}
                onClick={() => !isInlineEditing && toggleIndustry(industry.id)}
              >
                {/* Selection Indicator and Trash Icon */}
                {!isInlineEditing && (
                  <div className="absolute top-2 right-2 flex items-center space-x-1">
                    {/* Delete button for custom industries */}
                    {industry.isCustom && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-4 w-4 opacity-0 group-hover:opacity-100 transition-opacity text-destructive hover:text-destructive hover:bg-destructive/10"
                        onClick={(e) => {
                          e.stopPropagation()
                          removeIndustry(industry.id)
                        }}
                        title="Delete custom industry"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    )}

                    {/* Selection checkbox */}
                    <div
                      className={clsx(
                        'w-4 h-4 rounded border-2 transition-all',
                        isSelected
                          ? 'bg-primary border-primary'
                          : 'border-muted-foreground'
                      )}
                    >
                      {isSelected && (
                        <Check className="w-3 h-3 text-primary-foreground" />
                      )}
                    </div>
                  </div>
                )}

                {/* Industry Info */}
                <div className={clsx('transition-all', !isInlineEditing && 'pr-6')}>
                  <h4 className="font-medium text-sm mb-2">{industry.name}</h4>

                  {/* Keywords Display/Edit */}
                  {isInlineEditing ? (
                    <div className="space-y-3 mb-3">
                      <textarea
                        ref={textareaRef}
                        value={editingKeywords}
                        onChange={handleTextareaChange}
                        className="w-full p-3 text-sm border border-primary rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent min-h-[80px] bg-white dark:bg-gray-800 font-mono overflow-hidden"
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
                    <div className="mb-3">
                      <p
                        className="text-sm text-muted-foreground cursor-pointer hover:text-primary transition-colors hover:bg-accent rounded-md px-2 py-1 -mx-2 leading-relaxed"
                        onClick={(e) => handleStartInlineEdit(industry, e)}
                        title="Click to edit criteria"
                      >
                        {industry.keywords.join(', ')}
                      </p>
                      <p className="text-xs text-muted-foreground/60 mt-1 opacity-0 group-hover:opacity-100 transition-opacity px-2">
                        Click criteria to edit
                      </p>
                    </div>
                  )}

                  {/* Bottom section with badges */}
                  {!isInlineEditing && industry.isCustom && (
                    <div className="flex items-center justify-start">
                      {/* Custom Industry Badge */}
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-secondary text-secondary-foreground">
                        Custom
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {/* Empty State */}
        {state.industries.length === 0 && (
          <div className="text-center py-8 text-muted-foreground">
            <p>No industry categories available.</p>
            <Button
              variant="outline"
              className="mt-2"
              icon={Plus}
              onClick={handleAddIndustry}
            >
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
        <IndustryModal
          isOpen={isModalOpen}
          onClose={handleCloseModal}
          industry={editingIndustry}
        />

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
