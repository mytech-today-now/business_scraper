/**
 * Export Features - Comprehensive User Interaction Tests
 * 
 * Tests all export-related user interactions including:
 * - Export format selection
 * - Export template management
 * - CRM integration exports
 * - Download functionality
 * - Export progress and status
 */

import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ExportTemplateManager } from '@/view/components/ExportTemplateManager'
import { CRMExportTemplateManager } from '@/view/components/CRMExportTemplateManager'
import { ExportService, ExportFormat } from '@/utils/exportService'

// Mock dependencies
jest.mock('@/utils/exportService')
jest.mock('@/utils/logger')
jest.mock('@/lib/crmIntegration')

const mockExportService = ExportService as jest.MockedClass<typeof ExportService>

describe('Export Features - Comprehensive User Interaction Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Mock ExportService methods
    mockExportService.prototype.exportToCSV = jest.fn().mockResolvedValue('export-id-1')
    mockExportService.prototype.exportToXLSX = jest.fn().mockResolvedValue('export-id-2')
    mockExportService.prototype.exportToPDF = jest.fn().mockResolvedValue('export-id-3')
    mockExportService.prototype.exportToCRM = jest.fn().mockResolvedValue('export-id-4')
    mockExportService.prototype.getExportStatus = jest.fn().mockResolvedValue({
      id: 'export-id-1',
      status: 'completed',
      progress: 100,
      downloadUrl: '/downloads/export-id-1.csv'
    })
  })

  describe('Export Format Selection', () => {
    it('should render export format options', () => {
      render(<ExportTemplateManager />)
      
      expect(screen.getByText(/export format/i)).toBeInTheDocument()
      expect(screen.getByText(/csv/i)).toBeInTheDocument()
      expect(screen.getByText(/xlsx/i)).toBeInTheDocument()
      expect(screen.getByText(/pdf/i)).toBeInTheDocument()
    })

    it('should handle CSV export selection', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      expect(csvOption).toBeChecked()
    })

    it('should handle XLSX export selection', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const xlsxOption = screen.getByLabelText(/xlsx/i)
      await user.click(xlsxOption)

      expect(xlsxOption).toBeChecked()
    })

    it('should handle PDF export selection', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const pdfOption = screen.getByLabelText(/pdf/i)
      await user.click(pdfOption)

      expect(pdfOption).toBeChecked()
    })
  })

  describe('Export Template Management', () => {
    it('should display available templates', () => {
      render(<ExportTemplateManager />)
      
      expect(screen.getByText(/export templates/i)).toBeInTheDocument()
      expect(screen.getByText(/basic template/i)).toBeInTheDocument()
      expect(screen.getByText(/detailed template/i)).toBeInTheDocument()
    })

    it('should handle template selection', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const templateSelect = screen.getByLabelText(/select template/i)
      await user.selectOptions(templateSelect, 'detailed')

      expect(templateSelect).toHaveValue('detailed')
    })

    it('should create new template', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const createButton = screen.getByRole('button', { name: /create template/i })
      await user.click(createButton)

      expect(screen.getByText(/new template/i)).toBeInTheDocument()
      
      const templateNameInput = screen.getByLabelText(/template name/i)
      await user.type(templateNameInput, 'Custom Template')

      const saveButton = screen.getByRole('button', { name: /save/i })
      await user.click(saveButton)

      expect(screen.getByText('Custom Template')).toBeInTheDocument()
    })

    it('should edit existing template', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const editButton = screen.getByRole('button', { name: /edit basic template/i })
      await user.click(editButton)

      const templateNameInput = screen.getByDisplayValue(/basic template/i)
      await user.clear(templateNameInput)
      await user.type(templateNameInput, 'Modified Basic Template')

      const saveButton = screen.getByRole('button', { name: /save/i })
      await user.click(saveButton)

      expect(screen.getByText('Modified Basic Template')).toBeInTheDocument()
    })

    it('should delete template', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const deleteButton = screen.getByRole('button', { name: /delete basic template/i })
      await user.click(deleteButton)

      // Confirm deletion
      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      await user.click(confirmButton)

      expect(screen.queryByText(/basic template/i)).not.toBeInTheDocument()
    })
  })

  describe('CRM Integration Exports', () => {
    it('should display CRM export options', () => {
      render(<CRMExportTemplateManager />)
      
      expect(screen.getByText(/crm integration/i)).toBeInTheDocument()
      expect(screen.getByText(/salesforce/i)).toBeInTheDocument()
      expect(screen.getByText(/hubspot/i)).toBeInTheDocument()
    })

    it('should handle Salesforce export', async () => {
      const user = userEvent.setup()

      render(<CRMExportTemplateManager />)

      const salesforceOption = screen.getByLabelText(/salesforce/i)
      await user.click(salesforceOption)

      const exportButton = screen.getByRole('button', { name: /export to salesforce/i })
      await user.click(exportButton)

      expect(mockExportService.prototype.exportToCRM).toHaveBeenCalledWith(
        expect.objectContaining({
          crmType: 'salesforce'
        })
      )
    })

    it('should handle HubSpot export', async () => {
      const user = userEvent.setup()

      render(<CRMExportTemplateManager />)

      const hubspotOption = screen.getByLabelText(/hubspot/i)
      await user.click(hubspotOption)

      const exportButton = screen.getByRole('button', { name: /export to hubspot/i })
      await user.click(exportButton)

      expect(mockExportService.prototype.exportToCRM).toHaveBeenCalledWith(
        expect.objectContaining({
          crmType: 'hubspot'
        })
      )
    })

    it('should configure CRM mapping', async () => {
      const user = userEvent.setup()

      render(<CRMExportTemplateManager />)

      const configureButton = screen.getByRole('button', { name: /configure mapping/i })
      await user.click(configureButton)

      expect(screen.getByText(/field mapping/i)).toBeInTheDocument()
      
      const nameMapping = screen.getByLabelText(/business name maps to/i)
      await user.selectOptions(nameMapping, 'Account Name')

      expect(nameMapping).toHaveValue('Account Name')
    })
  })

  describe('Download Functionality', () => {
    it('should initiate download', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      expect(mockExportService.prototype.exportToCSV).toHaveBeenCalled()
    })

    it('should show download progress', async () => {
      mockExportService.prototype.getExportStatus = jest.fn().mockResolvedValue({
        id: 'export-id-1',
        status: 'processing',
        progress: 50,
        downloadUrl: null
      })

      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      await waitFor(() => {
        expect(screen.getByText(/processing/i)).toBeInTheDocument()
        expect(screen.getByRole('progressbar')).toBeInTheDocument()
      })
    })

    it('should handle download completion', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      await waitFor(() => {
        expect(screen.getByText(/download ready/i)).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /download/i })).toBeInTheDocument()
      })
    })

    it('should handle download errors', async () => {
      mockExportService.prototype.exportToCSV = jest.fn().mockRejectedValue(
        new Error('Export failed')
      )

      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      await waitFor(() => {
        expect(screen.getByText(/export failed/i)).toBeInTheDocument()
      })
    })
  })

  describe('Export Options and Filters', () => {
    it('should handle data selection for export', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const selectAllCheckbox = screen.getByLabelText(/select all/i)
      await user.click(selectAllCheckbox)

      expect(selectAllCheckbox).toBeChecked()
    })

    it('should handle individual record selection', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const recordCheckbox = screen.getByLabelText(/select record 1/i)
      await user.click(recordCheckbox)

      expect(recordCheckbox).toBeChecked()
    })

    it('should handle date range filter', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const startDateInput = screen.getByLabelText(/start date/i)
      const endDateInput = screen.getByLabelText(/end date/i)

      await user.type(startDateInput, '2023-01-01')
      await user.type(endDateInput, '2023-12-31')

      expect(startDateInput).toHaveValue('2023-01-01')
      expect(endDateInput).toHaveValue('2023-12-31')
    })

    it('should handle field selection for export', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const fieldSelector = screen.getByText(/select fields/i)
      await user.click(fieldSelector)

      const nameField = screen.getByLabelText(/business name/i)
      const addressField = screen.getByLabelText(/address/i)

      await user.click(nameField)
      await user.click(addressField)

      expect(nameField).toBeChecked()
      expect(addressField).toBeChecked()
    })
  })

  describe('Export Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<ExportTemplateManager />)

      const exportButton = screen.getByRole('button', { name: /export/i })
      expect(exportButton).toHaveAttribute('aria-label')
    })

    it('should announce export status to screen readers', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      await waitFor(() => {
        const statusRegion = screen.getByRole('status')
        expect(statusRegion).toHaveTextContent(/export completed/i)
      })
    })

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      const xlsxOption = screen.getByLabelText(/xlsx/i)
      const exportButton = screen.getByRole('button', { name: /export/i })

      await user.click(csvOption)
      expect(csvOption).toHaveFocus()

      await user.tab()
      expect(xlsxOption).toHaveFocus()

      await user.tab()
      expect(exportButton).toHaveFocus()
    })
  })

  describe('Export Performance', () => {
    it('should handle large dataset exports', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      // Select large dataset
      const largeDatasetOption = screen.getByLabelText(/export all records/i)
      await user.click(largeDatasetOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      // Should show progress for large exports
      await waitFor(() => {
        expect(screen.getByRole('progressbar')).toBeInTheDocument()
      })
    })

    it('should allow export cancellation', async () => {
      const user = userEvent.setup()

      render(<ExportTemplateManager />)

      const csvOption = screen.getByLabelText(/csv/i)
      await user.click(csvOption)

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      // Cancel export
      const cancelButton = screen.getByRole('button', { name: /cancel/i })
      await user.click(cancelButton)

      expect(screen.getByText(/export cancelled/i)).toBeInTheDocument()
    })
  })
})
