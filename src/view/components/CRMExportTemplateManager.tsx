'use client'

/**
 * CRM Export Template Manager
 * Enhanced template manager with CRM-specific functionality
 */

import React, { useState, useEffect } from 'react'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import {
  Plus,
  Edit,
  Trash2,
  Save,
  X,
  Settings,
  Zap,
  Eye,
  CheckCircle,
  AlertCircle,
  Download,
} from 'lucide-react'
import { ExportTemplate } from '@/utils/exportService'
import { BusinessRecord } from '@/types/business'
import { CRMTemplate, CRMPlatform, crmTemplateManager, crmExportService } from '@/utils/crm'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

interface CRMExportTemplateManagerProps {
  onTemplateSelect: (template: ExportTemplate | CRMTemplate) => void
  onClose: () => void
  businessRecords?: BusinessRecord[]
}

/**
 * CRM platform display information
 */
const CRM_PLATFORMS = [
  {
    platform: 'salesforce' as CRMPlatform,
    name: 'Salesforce',
    description: "World's #1 CRM platform",
    color: 'bg-blue-500',
    icon: '⚡',
  },
  {
    platform: 'hubspot' as CRMPlatform,
    name: 'HubSpot',
    description: 'Inbound marketing & sales platform',
    color: 'bg-orange-500',
    icon: '🧲',
  },
  {
    platform: 'pipedrive' as CRMPlatform,
    name: 'Pipedrive',
    description: 'Sales-focused CRM',
    color: 'bg-green-500',
    icon: '📊',
  },
]

export function CRMExportTemplateManager({
  onTemplateSelect,
  onClose,
  businessRecords = [],
}: CRMExportTemplateManagerProps): JSX.Element {
  const [activeTab, setActiveTab] = useState<'browse' | 'create' | 'preview'>('browse')
  const [selectedPlatform, setSelectedPlatform] = useState<CRMPlatform | null>(null)
  const [crmTemplates, setCrmTemplates] = useState<CRMTemplate[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState<CRMTemplate | null>(null)
  const [previewData, setPreviewData] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(false)

  /**
   * Load CRM templates on component mount
   */
  useEffect(() => {
    loadCRMTemplates()
  }, [])

  /**
   * Load all CRM templates
   */
  const loadCRMTemplates = () => {
    try {
      const templates = crmTemplateManager.getAllTemplates()
      setCrmTemplates(templates)
      logger.info('CRMExportTemplateManager', `Loaded ${templates.length} CRM templates`)
    } catch (error) {
      logger.error('CRMExportTemplateManager', 'Failed to load CRM templates', error)
      toast.error('Failed to load CRM templates')
    }
  }

  /**
   * Get templates for selected platform
   */
  const getTemplatesForPlatform = (platform: CRMPlatform): CRMTemplate[] => {
    return crmTemplates.filter(template => template.platform === platform)
  }

  /**
   * Handle template selection
   */
  const handleTemplateSelect = (template: CRMTemplate) => {
    setSelectedTemplate(template)
    onTemplateSelect(template)
    toast.success(`Selected ${template.name} template`)
  }

  /**
   * Generate preview for template
   */
  const generatePreview = async (template: CRMTemplate) => {
    if (businessRecords.length === 0) {
      toast.error('No business records available for preview')
      return
    }

    setIsLoading(true)
    try {
      const preview = await crmExportService.getExportPreview(
        businessRecords,
        template,
        { template },
        3 // Preview first 3 records
      )
      setPreviewData(preview)
      setActiveTab('preview')
      toast.success('Preview generated successfully')
    } catch (error) {
      logger.error('CRMExportTemplateManager', 'Failed to generate preview', error)
      toast.error('Failed to generate preview')
    } finally {
      setIsLoading(false)
    }
  }

  /**
   * Validate records against template
   */
  const validateTemplate = async (template: CRMTemplate) => {
    if (businessRecords.length === 0) {
      toast.error('No business records available for validation')
      return
    }

    setIsLoading(true)
    try {
      const validation = await crmExportService.validateRecords(businessRecords, template)

      const message = `Validation Results: ${validation.validCount}/${businessRecords.length} valid records`

      if (validation.invalidCount > 0) {
        toast.error(`${message}. ${validation.invalidCount} records have errors.`)
      } else {
        toast.success(message)
      }
    } catch (error) {
      logger.error('CRMExportTemplateManager', 'Failed to validate template', error)
      toast.error('Failed to validate template')
    } finally {
      setIsLoading(false)
    }
  }

  /**
   * Render platform selection
   */
  const renderPlatformSelection = () => (
    <div className="space-y-4">
      <div className="text-center">
        <h3 className="text-lg font-semibold mb-2">Choose Your CRM Platform</h3>
        <p className="text-gray-600 text-sm">
          Select your CRM platform to see optimized export templates
        </p>
      </div>

      <div className="grid gap-4">
        {CRM_PLATFORMS.map(platform => {
          const templates = getTemplatesForPlatform(platform.platform)
          return (
            <Card
              key={platform.platform}
              className="cursor-pointer hover:shadow-md transition-shadow"
              onClick={() => setSelectedPlatform(platform.platform)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-10 h-10 rounded-lg ${platform.color} flex items-center justify-center text-white text-lg`}
                    >
                      {platform.icon}
                    </div>
                    <div>
                      <h4 className="font-semibold">{platform.name}</h4>
                      <p className="text-sm text-gray-600">{platform.description}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium">{templates.length} templates</div>
                    <div className="text-xs text-gray-500">available</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )

  /**
   * Render template list for selected platform
   */
  const renderTemplateList = () => {
    if (!selectedPlatform) return null

    const templates = getTemplatesForPlatform(selectedPlatform)
    const platformInfo = CRM_PLATFORMS.find(p => p.platform === selectedPlatform)

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" onClick={() => setSelectedPlatform(null)}>
              ← Back
            </Button>
            <h3 className="text-lg font-semibold">{platformInfo?.name} Templates</h3>
          </div>
        </div>

        <div className="grid gap-3">
          {templates.map(template => (
            <Card key={template.id} className="hover:shadow-md transition-shadow">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h4 className="font-semibold">{template.name}</h4>
                      <span
                        className={`px-2 py-1 text-xs rounded-full ${platformInfo?.color} text-white`}
                      >
                        {template.platform}
                      </span>
                      <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-700">
                        {template.exportFormat.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{template.description}</p>
                    <div className="text-xs text-gray-500">
                      {template.fieldMappings.length} fields mapped
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => generatePreview(template)}
                      disabled={isLoading || businessRecords.length === 0}
                    >
                      <Eye className="h-4 w-4 mr-1" />
                      Preview
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => validateTemplate(template)}
                      disabled={isLoading || businessRecords.length === 0}
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Validate
                    </Button>

                    <Button size="sm" onClick={() => handleTemplateSelect(template)}>
                      <Zap className="h-4 w-4 mr-1" />
                      Use Template
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {templates.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            <p>No templates available for {platformInfo?.name}</p>
          </div>
        )}
      </div>
    )
  }

  /**
   * Render preview data
   */
  const renderPreview = () => {
    if (!previewData || !selectedTemplate) return null

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" onClick={() => setActiveTab('browse')}>
              ← Back to Templates
            </Button>
            <h3 className="text-lg font-semibold">Preview: {selectedTemplate.name}</h3>
          </div>
        </div>

        {/* Preview Statistics */}
        <Card>
          <CardContent className="p-4">
            <div className="grid grid-cols-4 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold text-blue-600">{previewData.totalRecords}</div>
                <div className="text-sm text-gray-600">Total Records</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-green-600">
                  {previewData.preview.length}
                </div>
                <div className="text-sm text-gray-600">Preview Records</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-red-600">{previewData.errors.length}</div>
                <div className="text-sm text-gray-600">Errors</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-yellow-600">
                  {previewData.warnings.length}
                </div>
                <div className="text-sm text-gray-600">Warnings</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Preview Data Table */}
        {previewData.preview.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Preview Data</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      {Object.keys(previewData.preview[0]).map(key => (
                        <th key={key} className="text-left p-2 font-medium">
                          {selectedTemplate.customHeaders?.[key] || key}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {previewData.preview.map((record: any, index: number) => (
                      <tr key={index} className="border-b">
                        {Object.values(record).map((value: any, cellIndex: number) => (
                          <td key={cellIndex} className="p-2">
                            {String(value || '')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Errors and Warnings */}
        {(previewData.errors.length > 0 || previewData.warnings.length > 0) && (
          <Card>
            <CardHeader>
              <CardTitle>Issues Found</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {previewData.errors.length > 0 && (
                <div>
                  <h4 className="font-medium text-red-600 mb-2">
                    Errors ({previewData.errors.length})
                  </h4>
                  <div className="space-y-1">
                    {previewData.errors.slice(0, 5).map((error: any, index: number) => (
                      <div key={index} className="text-sm text-red-600 bg-red-50 p-2 rounded">
                        <strong>{error.field}:</strong> {error.message}
                      </div>
                    ))}
                    {previewData.errors.length > 5 && (
                      <div className="text-sm text-gray-500">
                        ... and {previewData.errors.length - 5} more errors
                      </div>
                    )}
                  </div>
                </div>
              )}

              {previewData.warnings.length > 0 && (
                <div>
                  <h4 className="font-medium text-yellow-600 mb-2">
                    Warnings ({previewData.warnings.length})
                  </h4>
                  <div className="space-y-1">
                    {previewData.warnings.slice(0, 5).map((warning: string, index: number) => (
                      <div key={index} className="text-sm text-yellow-600 bg-yellow-50 p-2 rounded">
                        {warning}
                      </div>
                    ))}
                    {previewData.warnings.length > 5 && (
                      <div className="text-sm text-gray-500">
                        ... and {previewData.warnings.length - 5} more warnings
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    )
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-6xl h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <div>
            <h2 className="text-xl font-semibold">CRM Export Templates</h2>
            <p className="text-gray-600 text-sm">
              Choose optimized templates for your CRM platform
            </p>
          </div>
          <Button variant="outline" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden">
          <div className="h-full overflow-y-auto p-6">
            {activeTab === 'browse' && !selectedPlatform && renderPlatformSelection()}
            {activeTab === 'browse' && selectedPlatform && renderTemplateList()}
            {activeTab === 'preview' && renderPreview()}
          </div>
        </div>

        {/* Footer */}
        <div className="border-t p-4 bg-gray-50">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              {businessRecords.length > 0
                ? `${businessRecords.length} business records available for export`
                : 'No business records available - preview and validation disabled'}
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
