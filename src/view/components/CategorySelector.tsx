'use client'

import React, { useState } from 'react'
import { Plus, Trash2, Check, X } from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { clsx } from 'clsx'

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
    addCustomIndustry,
    removeIndustry,
  } = useConfig()

  const [isAddingCustom, setIsAddingCustom] = useState(false)
  const [customIndustryForm, setCustomIndustryForm] = useState({
    name: '',
    keywords: '',
  })

  /**
   * Handle custom industry form submission
   */
  const handleAddCustomIndustry = async () => {
    if (!customIndustryForm.name.trim()) return

    const keywords = customIndustryForm.keywords
      .split(',')
      .map(k => k.trim())
      .filter(Boolean)

    if (keywords.length === 0) {
      keywords.push(customIndustryForm.name.toLowerCase())
    }

    await addCustomIndustry({
      name: customIndustryForm.name.trim(),
      keywords,
    })

    // Reset form
    setCustomIndustryForm({ name: '', keywords: '' })
    setIsAddingCustom(false)
  }

  /**
   * Handle canceling custom industry addition
   */
  const handleCancelCustomIndustry = () => {
    setCustomIndustryForm({ name: '', keywords: '' })
    setIsAddingCustom(false)
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
              onClick={() => setIsAddingCustom(true)}
              disabled={isAddingCustom}
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

        {/* Custom Industry Form */}
        {isAddingCustom && (
          <div className="space-y-3 p-4 border rounded-lg bg-muted/50">
            <h4 className="font-medium">Add Custom Industry</h4>
            <Input
              label="Industry Name"
              placeholder="e.g., Pet Services"
              value={customIndustryForm.name}
              onChange={(e) =>
                setCustomIndustryForm(prev => ({ ...prev, name: e.target.value }))
              }
            />
            <Input
              label="Keywords (comma-separated)"
              placeholder="e.g., pet, veterinary, grooming, boarding"
              helperText="Keywords help identify relevant businesses during scraping"
              value={customIndustryForm.keywords}
              onChange={(e) =>
                setCustomIndustryForm(prev => ({ ...prev, keywords: e.target.value }))
              }
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                icon={Check}
                onClick={handleAddCustomIndustry}
                disabled={!customIndustryForm.name.trim()}
              >
                Add Industry
              </Button>
              <Button
                variant="outline"
                size="sm"
                icon={X}
                onClick={handleCancelCustomIndustry}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Industry Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {state.industries.map((industry) => {
            const isSelected = state.selectedIndustries.includes(industry.id)
            
            return (
              <div
                key={industry.id}
                className={clsx(
                  'relative p-3 border rounded-lg cursor-pointer transition-all',
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
                  
                  {/* Custom Industry Badge */}
                  {industry.isCustom && (
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-secondary text-secondary-foreground">
                        Custom
                      </span>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 text-destructive hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation()
                          removeIndustry(industry.id)
                        }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
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
              onClick={() => setIsAddingCustom(true)}
            >
              Add Your First Industry
            </Button>
          </div>
        )}

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
