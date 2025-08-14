'use client'

import React, { useState, useEffect, useRef } from 'react'
import { X, Save, Plus, Edit3 } from 'lucide-react'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { IndustryCategory } from '@/types/business'
import { useConfig } from '@/controller/ConfigContext'
import toast from 'react-hot-toast'

interface IndustryModalProps {
  isOpen: boolean
  onClose: () => void
  industry?: IndustryCategory // If provided, we're editing; if not, we're adding
}

export function IndustryModal({ isOpen, onClose, industry }: IndustryModalProps): JSX.Element {
  const { addCustomIndustry, updateIndustry } = useConfig()
  const [name, setName] = useState('')
  const [keywordsText, setKeywordsText] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  
  const isEditing = !!industry
  const title = isEditing ? 'Edit Industry Category' : 'Add Industry Category'
  const saveButtonText = isEditing ? 'Update Industry' : 'Add Industry'

  // Initialize form when modal opens or industry changes
  useEffect(() => {
    if (isOpen) {
      if (industry) {
        setName(industry.name)
        setKeywordsText(industry.keywords.join('\n'))
      } else {
        setName('')
        setKeywordsText('')
      }
    }
  }, [isOpen, industry])

  // Auto-save functionality with debounce
  useEffect(() => {
    if (!isOpen || !isEditing || isSaving) return

    const timeoutId = setTimeout(() => {
      handleAutoSave()
    }, 1000) // Auto-save after 1 second of inactivity

    return () => clearTimeout(timeoutId)
  }, [name, keywordsText, isOpen, isEditing])

  const handleAutoSave = async (): Promise<void> => {
    if (!isEditing || !industry || !name.trim()) return

    const keywords = keywordsText
      .split('\n')
      .map(k => k.trim())
      .filter(Boolean)

    if (keywords.length === 0) return

    try {
      setIsSaving(true)
      const updatedIndustry: IndustryCategory = {
        ...industry,
        name: name.trim(),
        keywords,
      }

      // Auto-save without showing toast notifications
      await updateIndustry(updatedIndustry, false)
    } catch (error) {
      console.error('Auto-save failed:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleSave = async (): Promise<void> => {
    if (!name.trim()) {
      toast.error('Industry name is required')
      return
    }

    const keywords = keywordsText
      .split('\n')
      .map(k => k.trim())
      .filter(Boolean)

    if (keywords.length === 0) {
      toast.error('At least one keyword is required')
      return
    }

    try {
      setIsSaving(true)
      
      if (isEditing && industry) {
        const updatedIndustry: IndustryCategory = {
          ...industry,
          name: name.trim(),
          keywords,
        }
        // Manual save with toast notifications
        await updateIndustry(updatedIndustry, true)
      } else {
        await addCustomIndustry({
          name: name.trim(),
          keywords,
        })
      }
      
      onClose()
    } catch (error) {
      console.error('Save failed:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleClose = (): void => {
    setName('')
    setKeywordsText('')
    setIsSaving(false)
    onClose()
  }

  const handleKeywordsChange = (value: string): void => {
    setKeywordsText(value)
    
    // Auto-resize textarea
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-2">
            {isEditing ? (
              <Edit3 className="h-5 w-5 text-blue-600" />
            ) : (
              <Plus className="h-5 w-5 text-green-600" />
            )}
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              {title}
            </h2>
            {isEditing && isSaving && (
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-blue-600 dark:text-blue-400">
                  Saving
                </span>
              </div>
            )}
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <X className="h-5 w-5" />
          </Button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(90vh-140px)]">
          {/* Industry Name */}
          <div>
            <Input
              label="Industry Name"
              placeholder="e.g., Pet Services, Medical Clinics"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isSaving}
            />
          </div>

          {/* Keywords Textarea */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Search Keywords
              <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">
                (one per line)
              </span>
            </label>
            <textarea
              ref={textareaRef}
              className="w-full min-h-[200px] px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y font-mono text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400"
              value={keywordsText}
              onChange={(e) => handleKeywordsChange(e.target.value)}
              placeholder="Enter keywords, one per line:&#10;pet grooming&#10;veterinary&#10;animal hospital&#10;dog boarding&#10;cat clinic"
              disabled={isSaving}
            />
            <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              <p>• Each line represents a search keyword or phrase</p>
              <p>• Keywords help identify relevant businesses during scraping</p>
              <p>• Use specific terms for better results (e.g., &quot;dental clinic&quot; vs &quot;dental&quot;)</p>
              {isEditing && (
                <p className="text-blue-600 dark:text-blue-400 mt-1">
                  • Changes are automatically saved as you type (no interruptions)
                </p>
              )}
            </div>
          </div>

          {/* Keywords Count */}
          <div className="text-sm text-gray-600 dark:text-gray-400">
            Keywords: {keywordsText.split('\n').filter(k => k.trim()).length}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
          <Button
            variant="outline"
            onClick={handleClose}
            disabled={isSaving}
          >
            {isEditing ? 'Close' : 'Cancel'}
          </Button>
          <Button
            onClick={handleSave}
            disabled={isSaving || !name.trim() || keywordsText.split('\n').filter(k => k.trim()).length === 0}
            icon={Save}
          >
            {isSaving ? 'Saving...' : saveButtonText}
          </Button>
        </div>
      </div>
    </div>
  )
}
