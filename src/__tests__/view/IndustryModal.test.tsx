/**
 * Tests for IndustryModal component
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { IndustryModal } from '@/view/components/IndustryModal'
import { useConfig } from '@/controller/ConfigContext'
import { IndustryCategory } from '@/types/business'

// Mock the useConfig hook
jest.mock('@/controller/ConfigContext', () => ({
  useConfig: jest.fn(),
}))

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}))

const mockUseConfig = useConfig as jest.MockedFunction<typeof useConfig>

describe('IndustryModal', () => {
  const mockAddCustomIndustry = jest.fn()
  const mockUpdateIndustry = jest.fn()
  const mockOnClose = jest.fn()

  const sampleIndustry: IndustryCategory = {
    id: 'test-industry',
    name: 'Test Industry',
    keywords: ['test', 'sample', 'example'],
    isCustom: true,
  }

  beforeEach(() => {
    mockUseConfig.mockReturnValue({
      addCustomIndustry: mockAddCustomIndustry,
      updateIndustry: mockUpdateIndustry,
    } as any)

    jest.clearAllMocks()
  })

  describe('Add Mode', () => {
    it('should render add modal correctly', () => {
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      expect(screen.getByText('Add Industry Category')).toBeInTheDocument()
      expect(screen.getByText('Add Industry')).toBeInTheDocument()
      expect(screen.getByPlaceholderText(/Enter keywords, one per line/)).toBeInTheDocument()
    })

    it('should handle adding new industry', async () => {
      const user = userEvent.setup()
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      // Fill in the form
      await user.type(screen.getByLabelText('Industry Name'), 'Pet Services')
      await user.type(
        screen.getByLabelText(/Search Keywords/),
        'pet grooming\nveterinary\nanimal hospital'
      )

      // Submit the form
      await user.click(screen.getByText('Add Industry'))

      await waitFor(() => {
        expect(mockAddCustomIndustry).toHaveBeenCalledWith({
          name: 'Pet Services',
          keywords: ['pet grooming', 'veterinary', 'animal hospital'],
        })
      })

      expect(mockOnClose).toHaveBeenCalled()
    })

    it('should validate required fields', async () => {
      const user = userEvent.setup()
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      // Try to submit without filling fields
      const addButton = screen.getByText('Add Industry')
      expect(addButton).toBeDisabled()

      // Add name but no keywords
      await user.type(screen.getByLabelText('Industry Name'), 'Test')
      expect(addButton).toBeDisabled()

      // Add keywords
      await user.type(screen.getByLabelText(/Search Keywords/), 'test keyword')
      expect(addButton).not.toBeDisabled()
    })
  })

  describe('Edit Mode', () => {
    it('should render edit modal correctly', () => {
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
          industry={sampleIndustry}
        />
      )

      expect(screen.getByText('Edit Industry Category')).toBeInTheDocument()
      expect(screen.getByText('Update Industry')).toBeInTheDocument()
      expect(screen.getByDisplayValue('Test Industry')).toBeInTheDocument()
      expect(screen.getByDisplayValue('test\nsample\nexample')).toBeInTheDocument()
    })

    it('should handle updating existing industry', async () => {
      const user = userEvent.setup()
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
          industry={sampleIndustry}
        />
      )

      // Modify the keywords
      const keywordsTextarea = screen.getByLabelText(/Search Keywords/)
      await user.clear(keywordsTextarea)
      await user.type(keywordsTextarea, 'updated\nkeywords\nlist')

      // Submit the form
      await user.click(screen.getByText('Update Industry'))

      await waitFor(() => {
        expect(mockUpdateIndustry).toHaveBeenCalledWith({
          ...sampleIndustry,
          keywords: ['updated', 'keywords', 'list'],
        })
      })

      expect(mockOnClose).toHaveBeenCalled()
    })

    it('should show auto-saving indicator', () => {
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
          industry={sampleIndustry}
        />
      )

      expect(screen.getByText(/Changes are automatically saved as you type/)).toBeInTheDocument()
    })
  })

  describe('Auto-save functionality', () => {
    beforeEach(() => {
      jest.useFakeTimers()
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    it('should auto-save changes after delay in edit mode', async () => {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime })
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
          industry={sampleIndustry}
        />
      )

      // Modify the name
      const nameInput = screen.getByDisplayValue('Test Industry')
      await user.clear(nameInput)
      await user.type(nameInput, 'Updated Industry')

      // Fast-forward time to trigger auto-save
      jest.advanceTimersByTime(1100)

      await waitFor(() => {
        expect(mockUpdateIndustry).toHaveBeenCalledWith({
          ...sampleIndustry,
          name: 'Updated Industry',
          keywords: ['test', 'sample', 'example'],
        })
      })
    })
  })

  describe('Textarea functionality', () => {
    it('should display keywords count', () => {
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
          industry={sampleIndustry}
        />
      )

      expect(screen.getByText('Keywords: 3')).toBeInTheDocument()
    })

    it('should update keywords count when typing', async () => {
      const user = userEvent.setup()
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      const keywordsTextarea = screen.getByLabelText(/Search Keywords/)
      await user.type(keywordsTextarea, 'keyword1\nkeyword2')

      expect(screen.getByText('Keywords: 2')).toBeInTheDocument()
    })

    it('should filter out empty lines from keywords count', async () => {
      const user = userEvent.setup()
      
      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      const keywordsTextarea = screen.getByLabelText(/Search Keywords/)
      await user.type(keywordsTextarea, 'keyword1\n\nkeyword2\n\n\nkeyword3')

      expect(screen.getByText('Keywords: 3')).toBeInTheDocument()
    })
  })

  describe('Modal behavior', () => {
    it('should close modal when clicking cancel button', async () => {
      const user = userEvent.setup()

      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      await user.click(screen.getByText('Cancel'))
      expect(mockOnClose).toHaveBeenCalled()
    })

    it('should close modal when clicking X button', async () => {
      const user = userEvent.setup()

      render(
        <IndustryModal
          isOpen={true}
          onClose={mockOnClose}
        />
      )

      // Find the X button in the header
      const closeButton = screen.getByRole('button', { name: '' })
      await user.click(closeButton)
      expect(mockOnClose).toHaveBeenCalled()
    })

    it('should not render when isOpen is false', () => {
      render(
        <IndustryModal
          isOpen={false}
          onClose={mockOnClose}
        />
      )

      expect(screen.queryByText('Add Industry Category')).not.toBeInTheDocument()
    })
  })
})
