'use client'

import React, { useState, useRef, useEffect } from 'react'
import { Check, X, Edit2 } from 'lucide-react'
import { Button } from './ui/Button'
import { IndustryCategory } from '@/types/business'
import { clsx } from 'clsx'

interface IndustryItemEditorProps {
  industry: IndustryCategory
  isSelected: boolean
  onToggle: () => void
  onUpdate: (industry: IndustryCategory) => Promise<void>
  onCancel: () => void
}

export function IndustryItemEditor({ 
  industry, 
  isSelected, 
  onToggle, 
  onUpdate, 
  onCancel 
}: IndustryItemEditorProps) {
  const [keywordsText, setKeywordsText] = useState('')
  const [blacklistText, setBlacklistText] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const keywordsRef = useRef<HTMLTextAreaElement>(null)

  // Initialize text areas when component mounts
  useEffect(() => {
    setKeywordsText(industry.keywords.join('\n'))
    setBlacklistText((industry.domainBlacklist || []).join('\n'))
    
    // Focus on keywords textarea
    setTimeout(() => {
      keywordsRef.current?.focus()
    }, 100)
  }, [industry])

  const handleSave = async () => {
    const keywords = keywordsText
      .split('\n')
      .map(k => k.trim())
      .filter(Boolean)

    const domainBlacklist = blacklistText
      .split('\n')
      .map(d => d.trim())
      .filter(Boolean)

    if (keywords.length === 0) {
      return // Don't save if no keywords
    }

    try {
      setIsSaving(true)
      const updatedIndustry: IndustryCategory = {
        ...industry,
        keywords,
        domainBlacklist: domainBlacklist.length > 0 ? domainBlacklist : undefined
      }
      await onUpdate(updatedIndustry)
    } catch (error) {
      console.error('Failed to update industry:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleCancel = () => {
    setKeywordsText(industry.keywords.join('\n'))
    setBlacklistText((industry.domainBlacklist || []).join('\n'))
    onCancel()
  }

  return (
    <div className={clsx(
      'group relative border rounded-lg p-4 transition-all duration-200',
      'bg-card text-card-foreground shadow-sm',
      isSelected 
        ? 'border-primary bg-primary/5 shadow-md' 
        : 'border-border hover:border-primary/50 hover:shadow-md'
    )}>
      {/* Header with industry name and actions */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <input
            type="checkbox"
            checked={isSelected}
            onChange={onToggle}
            className="rounded border-gray-300 text-primary focus:ring-primary"
          />
          <h3 className="font-medium text-sm">{industry.name}</h3>
          {industry.isCustom && (
            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-secondary text-secondary-foreground">
              Custom
            </span>
          )}
        </div>
        
        <div className="flex items-center space-x-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleSave}
            disabled={isSaving}
            className="text-green-600 hover:text-green-700 hover:bg-green-50"
          >
            <Check className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCancel}
            className="text-gray-500 hover:text-gray-700 hover:bg-gray-50"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Keywords textarea */}
      <div className="space-y-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground">
          Search Keywords (one per line)
        </label>
        <textarea
          ref={keywordsRef}
          value={keywordsText}
          onChange={(e) => setKeywordsText(e.target.value)}
          className="w-full min-h-24 max-h-80 px-3 py-2 text-sm border border-input rounded-md resize-vertical overflow-auto focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground placeholder:text-muted-foreground"
          placeholder="Enter search keywords, one per line..."
        />
      </div>

      {/* Domain blacklist textarea */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-muted-foreground">
          Domain Blacklist (one per line, supports wildcards)
        </label>
        <textarea
          value={blacklistText}
          onChange={(e) => setBlacklistText(e.target.value)}
          className="w-full min-h-20 max-h-60 px-3 py-2 text-sm border border-input rounded-md resize-vertical overflow-auto focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent bg-background text-foreground placeholder:text-muted-foreground"
          placeholder="Enter domains to exclude, one per line:&#10;*.statefarm.*&#10;*insurance*"
        />
        <p className="text-xs text-muted-foreground">
          Supports wildcards: *.domain.com blocks subdomains, *keyword* blocks any domain containing keyword
        </p>
      </div>
    </div>
  )
}
