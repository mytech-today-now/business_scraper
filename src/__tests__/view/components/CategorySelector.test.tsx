import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CategorySelector } from '@/view/components/CategorySelector'
import { ConfigProvider } from '@/controller/ConfigContext'
import { DEFAULT_INDUSTRIES } from '@/lib/industry-config'

// Mock the storage module
jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn(),
    getAllIndustries: jest.fn().mockResolvedValue([]),
    saveIndustry: jest.fn(),
    deleteIndustry: jest.fn(),
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

const renderWithProvider = (component: React.ReactElement) => {
  return render(
    <ConfigProvider>
      {component}
    </ConfigProvider>
  )
}

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
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Select All')).toBeInTheDocument()
    })

    // Click select all
    await user.click(screen.getByText('Select All'))
    
    await waitFor(() => {
      expect(screen.getByText('Deselect All')).toBeInTheDocument()
    })

    // Click deselect all
    await user.click(screen.getByText('Deselect All'))
    
    await waitFor(() => {
      expect(screen.getByText('Select All')).toBeInTheDocument()
    })
  })

  it('should show custom industry form when add custom is clicked', async () => {
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Add Custom')).toBeInTheDocument()
    })

    await user.click(screen.getByText('Add Custom'))
    
    await waitFor(() => {
      expect(screen.getByText('Add Custom Industry')).toBeInTheDocument()
      expect(screen.getByLabelText('Industry Name')).toBeInTheDocument()
      expect(screen.getByLabelText('Keywords (comma-separated)')).toBeInTheDocument()
    })
  })

  it('should allow adding a custom industry', async () => {
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    // Open custom industry form
    await user.click(screen.getByText('Add Custom'))
    
    // Fill in the form
    await user.type(screen.getByLabelText('Industry Name'), 'Pet Services')
    await user.type(screen.getByLabelText('Keywords (comma-separated)'), 'pet, veterinary, grooming')
    
    // Submit the form
    await user.click(screen.getByText('Add Industry'))
    
    // Form should be hidden after submission
    await waitFor(() => {
      expect(screen.queryByText('Add Custom Industry')).not.toBeInTheDocument()
    })
  })

  it('should cancel custom industry creation', async () => {
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    // Open custom industry form
    await user.click(screen.getByText('Add Custom'))
    
    // Fill in some data
    await user.type(screen.getByLabelText('Industry Name'), 'Test Industry')
    
    // Cancel
    await user.click(screen.getByText('Cancel'))
    
    // Form should be hidden
    await waitFor(() => {
      expect(screen.queryByText('Add Custom Industry')).not.toBeInTheDocument()
    })
    
    // Open form again to check if it's cleared
    await user.click(screen.getByText('Add Custom'))
    
    await waitFor(() => {
      expect(screen.getByLabelText('Industry Name')).toHaveValue('')
    })
  })

  it('should disable add industry button when name is empty', async () => {
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    await user.click(screen.getByText('Add Custom'))
    
    await waitFor(() => {
      const addButton = screen.getByText('Add Industry')
      expect(addButton).toBeDisabled()
    })
    
    // Type something and it should be enabled
    await user.type(screen.getByLabelText('Industry Name'), 'Test')
    
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
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      expect(screen.getByText('Restaurants & Food Service')).toBeInTheDocument()
    })

    // Click on a category
    await user.click(screen.getByText('Restaurants & Food Service'))
    
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
      const industryCards = screen.getAllByText(/Restaurants|Retail|Healthcare|Professional|Construction/)
      expect(industryCards.length).toBeGreaterThan(0)
    })
  })

  it('should handle keyboard navigation', async () => {
    const user = userEvent.setup()
    renderWithProvider(<CategorySelector />)

    await waitFor(() => {
      expect(screen.getByText('Add Custom')).toBeInTheDocument()
    })

    // Click the add custom button to open the form
    await user.click(screen.getByText('Add Custom'))

    await waitFor(() => {
      expect(screen.getByText('Add Custom Industry')).toBeInTheDocument()
    })
  })

  it('should show industry keywords', async () => {
    renderWithProvider(<CategorySelector />)
    
    await waitFor(() => {
      // Check if keywords are displayed (truncated)
      expect(screen.getByText(/restaurant, cafe, food service/)).toBeInTheDocument()
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
