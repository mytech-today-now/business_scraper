'use client'

import React, { useState, useEffect } from 'react'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Plus, Edit, Trash2, Save, X, Settings } from 'lucide-react'
import { ExportTemplate } from '@/utils/exportService'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

/**
 * Available fields for export templates
 */
const AVAILABLE_FIELDS = [
  { key: 'businessName', label: 'Business Name', type: 'string' },
  { key: 'email', label: 'Email Addresses', type: 'array' },
  { key: 'phone', label: 'Phone Number', type: 'string' },
  { key: 'websiteUrl', label: 'Website URL', type: 'string' },
  { key: 'address.street', label: 'Street Address', type: 'string' },
  { key: 'address.city', label: 'City', type: 'string' },
  { key: 'address.state', label: 'State', type: 'string' },
  { key: 'address.zipCode', label: 'ZIP Code', type: 'string' },
  { key: 'contactPerson', label: 'Contact Person', type: 'string' },
  { key: 'industry', label: 'Industry', type: 'string' },
  { key: 'coordinates.lat', label: 'Latitude', type: 'number' },
  { key: 'coordinates.lng', label: 'Longitude', type: 'number' },
  { key: 'scrapedAt', label: 'Scraped Date', type: 'date' },
]

/**
 * Default export templates
 */
const DEFAULT_TEMPLATES: ExportTemplate[] = [
  {
    name: 'Basic Contact Info',
    fields: ['businessName', 'email', 'phone', 'websiteUrl'],
    customHeaders: {
      businessName: 'Company Name',
      email: 'Email Address',
      phone: 'Phone Number',
      websiteUrl: 'Website',
    },
  },
  {
    name: 'Full Business Profile',
    fields: [
      'businessName',
      'email',
      'phone',
      'websiteUrl',
      'address.street',
      'address.city',
      'address.state',
      'address.zipCode',
      'industry',
    ],
    customHeaders: {
      businessName: 'Business Name',
      email: 'Email',
      phone: 'Phone',
      websiteUrl: 'Website',
      'address.street': 'Street',
      'address.city': 'City',
      'address.state': 'State',
      'address.zipCode': 'ZIP',
      industry: 'Industry',
    },
  },
  {
    name: 'Location Data',
    fields: [
      'businessName',
      'address.street',
      'address.city',
      'address.state',
      'address.zipCode',
      'coordinates.lat',
      'coordinates.lng',
    ],
    customHeaders: {
      businessName: 'Business Name',
      'address.street': 'Address',
      'address.city': 'City',
      'address.state': 'State',
      'address.zipCode': 'ZIP Code',
      'coordinates.lat': 'Latitude',
      'coordinates.lng': 'Longitude',
    },
  },
]

export interface ExportTemplateManagerProps {
  onTemplateSelect: (template: ExportTemplate) => void
  onClose: () => void
}

export function ExportTemplateManager({
  onTemplateSelect,
  onClose,
}: ExportTemplateManagerProps): JSX.Element {
  const [templates, setTemplates] = useState<ExportTemplate[]>(DEFAULT_TEMPLATES)
  const [editingTemplate, setEditingTemplate] = useState<ExportTemplate | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [newTemplateName, setNewTemplateName] = useState('')
  const [selectedFields, setSelectedFields] = useState<string[]>([])
  const [customHeaders, setCustomHeaders] = useState<Record<string, string>>({})

  /**
   * Load templates from localStorage on mount
   */
  useEffect(() => {
    // Only access localStorage on client side
    if (typeof window === 'undefined') return

    try {
      const savedTemplates = localStorage.getItem('exportTemplates')
      if (savedTemplates) {
        const parsed = JSON.parse(savedTemplates)
        setTemplates([...DEFAULT_TEMPLATES, ...parsed])
      }
    } catch (error) {
      logger.error('ExportTemplateManager', 'Failed to load templates', error)
    }
  }, [])

  /**
   * Save templates to localStorage
   */
  const saveTemplates = (newTemplates: ExportTemplate[]) => {
    // Only access localStorage on client side
    if (typeof window === 'undefined') return

    try {
      // Only save custom templates (not default ones)
      const customTemplates = newTemplates.filter(
        template =>
          !DEFAULT_TEMPLATES.some(defaultTemplate => defaultTemplate.name === template.name)
      )
      localStorage.setItem('exportTemplates', JSON.stringify(customTemplates))
      setTemplates(newTemplates)
    } catch (error) {
      logger.error('ExportTemplateManager', 'Failed to save templates', error)
      toast.error('Failed to save template')
    }
  }

  /**
   * Start creating a new template
   */
  const startCreating = () => {
    setIsCreating(true)
    setEditingTemplate(null)
    setNewTemplateName('')
    setSelectedFields([])
    setCustomHeaders({})
  }

  /**
   * Start editing an existing template
   */
  const startEditing = (template: ExportTemplate) => {
    setEditingTemplate(template)
    setIsCreating(false)
    setNewTemplateName(template.name)
    setSelectedFields(template.fields)
    setCustomHeaders(template.customHeaders || {})
  }

  /**
   * Save the current template
   */
  const saveTemplate = () => {
    if (!newTemplateName.trim()) {
      toast.error('Template name is required')
      return
    }

    if (selectedFields.length === 0) {
      toast.error('At least one field must be selected')
      return
    }

    const newTemplate: ExportTemplate = {
      name: newTemplateName.trim(),
      fields: selectedFields,
      customHeaders: customHeaders,
    }

    let updatedTemplates: ExportTemplate[]

    if (editingTemplate) {
      // Update existing template
      updatedTemplates = templates.map(template =>
        template.name === editingTemplate.name ? newTemplate : template
      )
    } else {
      // Add new template
      if (templates.some(template => template.name === newTemplate.name)) {
        toast.error('Template name already exists')
        return
      }
      updatedTemplates = [...templates, newTemplate]
    }

    saveTemplates(updatedTemplates)
    cancelEditing()
    toast.success(`Template "${newTemplate.name}" saved successfully`)
  }

  /**
   * Delete a template
   */
  const deleteTemplate = (templateName: string) => {
    // Prevent deletion of default templates
    if (DEFAULT_TEMPLATES.some(template => template.name === templateName)) {
      toast.error('Cannot delete default templates')
      return
    }

    const updatedTemplates = templates.filter(template => template.name !== templateName)
    saveTemplates(updatedTemplates)
    toast.success('Template deleted successfully')
  }

  /**
   * Cancel editing
   */
  const cancelEditing = () => {
    setIsCreating(false)
    setEditingTemplate(null)
    setNewTemplateName('')
    setSelectedFields([])
    setCustomHeaders({})
  }

  /**
   * Toggle field selection
   */
  const toggleField = (fieldKey: string) => {
    setSelectedFields(prev =>
      prev.includes(fieldKey) ? prev.filter(key => key !== fieldKey) : [...prev, fieldKey]
    )
  }

  /**
   * Update custom header for a field
   */
  const updateCustomHeader = (fieldKey: string, header: string) => {
    setCustomHeaders(prev => ({
      ...prev,
      [fieldKey]: header,
    }))
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <Card className="w-full max-w-4xl max-h-[90vh] overflow-hidden">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Export Template Manager
          </CardTitle>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>

        <CardContent className="overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="space-y-6">
            {/* Template List */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium">Available Templates</h3>
                <Button onClick={startCreating} icon={Plus} size="sm">
                  Create Template
                </Button>
              </div>

              <div className="grid gap-3">
                {templates.map(template => (
                  <div
                    key={template.name}
                    className="flex items-center justify-between p-3 border rounded-lg"
                  >
                    <div>
                      <h4 className="font-medium">{template.name}</h4>
                      <p className="text-sm text-muted-foreground">
                        {template.fields.length} fields: {template.fields.slice(0, 3).join(', ')}
                        {template.fields.length > 3 && '...'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onTemplateSelect(template)}
                      >
                        Use Template
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => startEditing(template)}>
                        <Edit className="h-4 w-4" />
                      </Button>
                      {!DEFAULT_TEMPLATES.some(
                        defaultTemplate => defaultTemplate.name === template.name
                      ) && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => deleteTemplate(template.name)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Template Editor */}
            {(isCreating || editingTemplate) && (
              <div className="border-t pt-6">
                <h3 className="text-lg font-medium mb-4">
                  {editingTemplate ? 'Edit Template' : 'Create New Template'}
                </h3>

                <div className="space-y-4">
                  {/* Template Name */}
                  <div>
                    <label className="block text-sm font-medium mb-2">Template Name</label>
                    <Input
                      value={newTemplateName}
                      onChange={e => setNewTemplateName(e.target.value)}
                      placeholder="Enter template name"
                    />
                  </div>

                  {/* Field Selection */}
                  <div>
                    <label className="block text-sm font-medium mb-2">Select Fields</label>
                    <div className="grid grid-cols-2 gap-2 max-h-60 overflow-y-auto border rounded-lg p-3">
                      {AVAILABLE_FIELDS.map(field => (
                        <label key={field.key} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={selectedFields.includes(field.key)}
                            onChange={() => toggleField(field.key)}
                            className="rounded"
                          />
                          <span className="text-sm">{field.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Custom Headers */}
                  {selectedFields.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Custom Headers (Optional)
                      </label>
                      <div className="space-y-2 max-h-40 overflow-y-auto">
                        {selectedFields.map(fieldKey => {
                          const field = AVAILABLE_FIELDS.find(f => f.key === fieldKey)
                          return (
                            <div key={fieldKey} className="flex items-center gap-2">
                              <span className="text-sm w-32 truncate">{field?.label}:</span>
                              <Input
                                value={customHeaders[fieldKey] || ''}
                                onChange={e => updateCustomHeader(fieldKey, e.target.value)}
                                placeholder={field?.label}
                                size="sm"
                              />
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-4">
                    <Button onClick={saveTemplate} icon={Save}>
                      Save Template
                    </Button>
                    <Button variant="outline" onClick={cancelEditing}>
                      Cancel
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
