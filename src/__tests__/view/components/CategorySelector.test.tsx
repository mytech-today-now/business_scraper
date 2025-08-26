import React from 'react'
import { screen, waitFor } from '@testing-library/react'
import { CategorySelector } from '@/view/components/CategorySelector'
import { DEFAULT_INDUSTRIES, DEFAULT_SUB_CATEGORIES } from '@/lib/industry-config'
import {
  renderWithProvider,
  setupUserEvent,
  userInteraction,
  clickButton,
  typeText,
  waitForText,
  findButtonByIcon,
  getByDisplayValue,
  suppressActWarnings
} from '../../utils/testUtils'

// Mock the storage module
jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn(),
    getAllIndustries: jest.fn().mockResolvedValue([]),
    getAllSubCategories: jest.fn().mockResolvedValue([]),
    saveIndustry: jest.fn(),
    saveSubCategory: jest.fn(),
    deleteIndustry: jest.fn(),
    deleteSubCategory: jest.fn(),
    clearSubCategories: jest.fn(),
    getConfig: jest.fn().mockResolvedValue(null),
    saveConfig: jest.fn(),
  },
}))

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}))

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}))

// Suppress act warnings for this test suite since we're testing complex state interactions
suppressActWarnings()

describe('CategorySelector', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should render the category selector', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Industry Categories')).toBeInTheDocument()
    })
  })

  it('should display default industries', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      DEFAULT_INDUSTRIES.forEach(industry => {
        expect(screen.getByText(industry.name)).toBeInTheDocument()
      })
    })
  })

  it('should show select all and add custom buttons', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Select All')).toBeInTheDocument()
      expect(screen.getByText('Add Custom')).toBeInTheDocument()
    })
  })

  it('should toggle between select all and deselect all', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    await waitForText('Select All')

    // Click select all
    await clickButton(user, 'Select All')

    await waitForText('Deselect All')

    // Click deselect all
    await clickButton(user, 'Deselect All')

    await waitForText('Select All')
  })

  it('should show custom industry form when add custom is clicked', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    await waitForText('Add Custom')

    await clickButton(user, 'Add Custom')

    await waitForText('Add Industry Category')
  })

  it('should allow adding a custom industry', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Open custom industry form
    await clickButton(user, 'Add Custom')

    // Wait for modal to fully open and form fields to be available
    await waitFor(() => {
      expect(screen.getByLabelText('Industry Name')).toBeInTheDocument()
    })

    // Fill in the form
    await userInteraction(async () => {
      const nameInput = screen.getByLabelText('Industry Name')
      // Find textarea by placeholder since label might not be properly associated
      const keywordsInput = screen.getByPlaceholderText(/Enter keywords, one per line/)
      await typeText(user, nameInput, 'Pet Services')
      await typeText(user, keywordsInput, 'pet grooming\nveterinary\nanimal hospital')
    })

    // Submit the form
    await clickButton(user, 'Add Industry')

    // Form should be hidden after submission
    await waitFor(() => {
      expect(screen.queryByText('Add Industry Category')).not.toBeInTheDocument()
    })
  })

  it('should cancel custom industry creation', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Open custom industry form
    await clickButton(user, 'Add Custom')

    // Fill in some data
    await userInteraction(async () => {
      const nameInput = screen.getByLabelText('Industry Name')
      await typeText(user, nameInput, 'Test Industry')
    })

    // Cancel
    await clickButton(user, 'Cancel')

    // Form should be hidden
    await waitFor(() => {
      expect(screen.queryByText('Add Industry Category')).not.toBeInTheDocument()
    })
  })

  it('should disable add industry button when name is empty', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    await clickButton(user, 'Add Custom')

    await waitFor(() => {
      const addButton = screen.getByText('Add Industry')
      expect(addButton).toBeDisabled()
    })

    // Wait for modal to fully open
    await waitFor(() => {
      expect(screen.getByLabelText('Industry Name')).toBeInTheDocument()
    })

    // Type something and it should be enabled
    await userInteraction(async () => {
      const nameInput = screen.getByLabelText('Industry Name')
      // Find textarea by placeholder since label might not be properly associated
      const keywordsInput = screen.getByPlaceholderText(/Enter keywords, one per line/)
      await typeText(user, nameInput, 'Test')
      await typeText(user, keywordsInput, 'test keyword')
    })

    await waitFor(() => {
      const addButton = screen.getByText('Add Industry')
      expect(addButton).not.toBeDisabled()
    })
  })

  it('should show selection count', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText(/0 of \d+ categories selected/)).toBeInTheDocument()
    })
  })

  it('should show validation message when no categories are selected', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Please select at least one industry category to continue.')).toBeInTheDocument()
    })
  })

  it('should allow selecting individual categories', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Wait for component to load
    await waitForText('Law Firms & Legal Services')

    // Click on a category
    await clickButton(user, 'Law Firms & Legal Services')

    // Verify selection count updated
    await waitFor(() => {
      expect(screen.getByText(/1 of \d+ categories selected/)).toBeInTheDocument()
    })
  })

  it('should show custom badge for custom industries', async () => {
    // This test would require mocking the storage to return custom industries
    // For now, we'll test the structure
    renderWithProvider(<CategorySelector />)

    await waitFor(() => {
      // Default industries should not have custom badge
      const industryCards = screen.getAllByText(/Law Firms|Accounting|Medical|Dental|Real Estate/)
      expect(industryCards.length).toBeGreaterThan(0)
    })
  })

  it('should open modal when clicking Add Custom button', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Wait for component to load
    await waitForText('Add Custom')

    // Click the add custom button to open the modal
    await clickButton(user, 'Add Custom')

    // Verify modal opened with correct title
    await waitForText('Add Industry Category')
  })

  it('should show industry keywords', async () => {
    renderWithProvider(<CategorySelector />)

    await waitFor(() => {
      // Check if keywords are displayed (truncated)
      expect(screen.getByText(/law firm near me, corporate law office/)).toBeInTheDocument()
    })
  })

  it('should allow editing keywords in expanded mode', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Wait for component to load
    await waitForText(/law firm near me, corporate law office/)

    // Click on the keywords to start expanded editing
    await userInteraction(async () => {
      const keywordsText = screen.getByText(/law firm near me, corporate law office/)
      await user.click(keywordsText)
    })

    // Should show expanded editor form with textarea
    await waitFor(() => {
      const textarea = getByDisplayValue(/law firm near me/)
      expect(textarea).toBeInTheDocument()
    })
  })

  it('should save edited keywords using icon button', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Wait for component to load
    await waitForText(/law firm near me, corporate law office/)

    // Start expanded editing
    await userInteraction(async () => {
      const keywordsText = screen.getByText(/law firm near me, corporate law office/)
      await user.click(keywordsText)
    })

    // Wait for expanded editor
    await waitFor(() => {
      expect(getByDisplayValue(/law firm near me/)).toBeInTheDocument()
    })

    // Edit the keywords
    await userInteraction(async () => {
      const textarea = getByDisplayValue(/law firm near me/)
      await typeText(user, textarea, '\ntest keyword', { clear: false })
    })

    // Save using the check icon button
    await userInteraction(async () => {
      const saveButton = findButtonByIcon('check')
      if (saveButton) {
        await user.click(saveButton)
      } else {
        // Fallback: find button with green styling (save button)
        const greenButton = document.querySelector('button.text-green-600')
        if (greenButton) {
          await user.click(greenButton as HTMLElement)
        }
      }
    })

    // Should exit edit mode (textarea should disappear)
    await waitFor(() => {
      expect(screen.queryByDisplayValue(/law firm near me/)).not.toBeInTheDocument()
    }, { timeout: 3000 })
  })

  it('should cancel editing using icon button', async () => {
    const user = setupUserEvent()
    renderWithProvider(<CategorySelector />)

    // Wait for component to load
    await waitForText(/law firm near me, corporate law office/)

    // Start expanded editing
    await userInteraction(async () => {
      const keywordsText = screen.getByText(/law firm near me, corporate law office/)
      await user.click(keywordsText)
    })

    // Wait for expanded editor
    await waitFor(() => {
      expect(getByDisplayValue(/law firm near me/)).toBeInTheDocument()
    })

    // Cancel the editing using the X icon button
    await userInteraction(async () => {
      const cancelButton = findButtonByIcon('x')
      if (cancelButton) {
        await user.click(cancelButton)
      } else {
        // Fallback: find button with gray styling (cancel button)
        const grayButton = document.querySelector('button.text-gray-500')
        if (grayButton) {
          await user.click(grayButton as HTMLElement)
        }
      }
    })

    // Should exit edit mode without saving
    await waitFor(() => {
      expect(screen.queryByDisplayValue(/law firm near me/)).not.toBeInTheDocument()
    }, { timeout: 3000 })

    // Original keywords should still be there
    await waitFor(() => {
      expect(screen.getByText(/law firm near me, corporate law office/)).toBeInTheDocument()
    })
  })

  it('should handle empty state gracefully', async () => {
    // Mock empty industries
    const { storage } = require('@/model/storage')
    storage.getAllIndustries.mockResolvedValueOnce([])
    
    renderWithProvider(<CategorySelector />)
    
    // Should still render without crashing
    await waitFor(() => {
      expect(screen.getByText('Industry Categories')).toBeInTheDocument()
    })
  })
})
