'use client'

import React, { useState } from 'react'
import { Plus, Trash2, Check, X, Edit3 } from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { IndustryModal } from './IndustryModal'
import { clsx } from 'clsx'
import { IndustryCategory } from '@/types/business'

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
  } = useConfig()

  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingIndustry, setEditingIndustry] = useState<IndustryCategory | undefined>(undefined)

  /**
   * Handle opening modal for adding new industry
   */
  const handleAddIndustry = () => {
    setEditingIndustry(undefined)
    setIsModalOpen(true)
  }

  /**
   * Handle opening modal for editing existing industry
   */
  const handleEditIndustry = (industry: IndustryCategory) => {
    setEditingIndustry(industry)
    setIsModalOpen(true)
  }

  /**
   * Handle closing modal
   */
  const handleCloseModal = () => {
    setIsModalOpen(false)
    setEditingIndustry(undefined)
  }

  const allSelected = state.selectedIndustries.length === state.industries.length
  const noneSelected = state.selectedIndustries.length === 0

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Industry Categories</span>
          <div className="flex gap-2">
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
          {state.industries.map((industry) => {
            const isSelected = state.selectedIndustries.includes(industry.id)
            
            return (
              <div
                key={industry.id}
                className={clsx(
                  'relative p-3 border rounded-lg cursor-pointer transition-all group',
                  'hover:border-primary/50 hover:bg-accent/50',
                  isSelected && 'border-primary bg-primary/5',
                  !isSelected && 'border-border'
                )}
                onClick={() => toggleIndustry(industry.id)}
              >
                {/* Selection Indicator */}
                <div
                  className={clsx(
                    'absolute top-2 right-2 w-4 h-4 rounded border-2 transition-all',
                    isSelected
                      ? 'bg-primary border-primary'
                      : 'border-muted-foreground'
                  )}
                >
                  {isSelected && (
                    <Check className="w-3 h-3 text-primary-foreground" />
                  )}
                </div>

                {/* Industry Info */}
                <div className="pr-6">
                  <h4 className="font-medium text-sm mb-1">{industry.name}</h4>
                  <p className="text-xs text-muted-foreground mb-2">
                    {industry.keywords.slice(0, 3).join(', ')}
                    {industry.keywords.length > 3 && '...'}
                  </p>

                  {/* Bottom section with badges and actions */}
                  <div className="flex items-center justify-between">
                    {/* Custom Industry Badge */}
                    {industry.isCustom && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-secondary text-secondary-foreground">
                        Custom
                      </span>
                    )}

                    {/* Action buttons */}
                    <div className="flex items-center space-x-1 ml-auto">
                      {/* Edit Icon - Always visible on hover */}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity text-blue-600 hover:text-blue-700 hover:bg-blue-100 dark:hover:bg-blue-900"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleEditIndustry(industry)
                        }}
                        title="Edit industry keywords"
                      >
                        <Edit3 className="h-3 w-3" />
                      </Button>

                      {/* Delete button for custom industries */}
                      {industry.isCustom && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={(e) => {
                            e.stopPropagation()
                            removeIndustry(industry.id)
                          }}
                          title="Delete custom industry"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </div>
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
