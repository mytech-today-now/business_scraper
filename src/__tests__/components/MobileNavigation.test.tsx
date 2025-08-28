/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'
import { MobileNavigation } from '@/view/components/MobileNavigation'

// Mock the useResponsive hook
jest.mock('@/hooks/useResponsive', () => ({
  useResponsive: jest.fn(),
}))

const mockUseResponsive = require('@/hooks/useResponsive').useResponsive

describe('MobileNavigation', () => {
  const defaultProps = {
    activeTab: 'config' as const,
    onTabChange: jest.fn(),
    onApiConfigOpen: jest.fn(),
    isDarkMode: false,
    onToggleDarkMode: jest.fn(),
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Desktop Navigation', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: false,
        isTouchDevice: false,
      })
    })

    it('should render desktop navigation when not mobile', () => {
      render(<MobileNavigation {...defaultProps} />)

      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.getByText('Scraping')).toBeInTheDocument()
      expect(screen.getByTitle('API Configuration')).toBeInTheDocument()
      expect(screen.getByTitle('Switch to dark mode')).toBeInTheDocument()
    })

    it('should highlight active tab in desktop mode', () => {
      render(<MobileNavigation {...defaultProps} activeTab="scraping" />)

      const scrapingButton = screen.getByText('Scraping')
      expect(scrapingButton).toHaveClass('bg-primary') // Active variant
    })

    it('should call onTabChange when desktop tab is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      await user.click(screen.getByText('Scraping'))

      expect(defaultProps.onTabChange).toHaveBeenCalledWith('scraping')
    })

    it('should call onApiConfigOpen when settings button is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      await user.click(screen.getByTitle('API Configuration'))

      expect(defaultProps.onApiConfigOpen).toHaveBeenCalled()
    })

    it('should call onToggleDarkMode when dark mode button is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      await user.click(screen.getByTitle('Switch to dark mode'))

      expect(defaultProps.onToggleDarkMode).toHaveBeenCalled()
    })

    it('should show correct dark mode icon', () => {
      render(<MobileNavigation {...defaultProps} isDarkMode={true} />)

      expect(screen.getByTitle('Switch to light mode')).toBeInTheDocument()
    })
  })

  describe('Mobile Navigation', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTouchDevice: true,
      })
    })

    it('should render mobile menu button when mobile', () => {
      render(<MobileNavigation {...defaultProps} />)

      expect(screen.getByLabelText('Open navigation menu')).toBeInTheDocument()
      expect(screen.queryByText('Configuration')).not.toBeInTheDocument()
    })

    it('should open drawer when menu button is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      await user.click(screen.getByLabelText('Open navigation menu'))

      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.getByText('Navigation')).toBeInTheDocument()
      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.getByText('Scraping')).toBeInTheDocument()
    })

    it('should close drawer when close button is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))
      expect(screen.getByRole('dialog')).toBeInTheDocument()

      // Close drawer
      await user.click(screen.getByLabelText('Close navigation menu'))

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      }, { timeout: 3000 })
    })

    it('should close drawer when overlay is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))

      // Click overlay (the backdrop)
      const overlay = document.querySelector('.fixed.inset-0.bg-black\\/50')
      expect(overlay).toBeInTheDocument()

      await user.click(overlay!)

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      }, { timeout: 3000 })
    })

    it('should close drawer when tab is selected', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))

      // Click on a tab
      await user.click(screen.getByText('Scraping'))

      expect(defaultProps.onTabChange).toHaveBeenCalledWith('scraping')

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      }, { timeout: 3000 })
    })

    it('should close drawer when action button is clicked', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))

      // Click API Configuration
      await user.click(screen.getByText('API Configuration'))

      expect(defaultProps.onApiConfigOpen).toHaveBeenCalled()

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      }, { timeout: 3000 })
    })

    it('should show correct dark mode text in drawer', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} isDarkMode={true} />)

      await user.click(screen.getByLabelText('Open navigation menu'))

      expect(screen.getByText('Light Mode')).toBeInTheDocument()
    })

    it('should handle dark mode toggle in drawer', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      await user.click(screen.getByLabelText('Open navigation menu'))
      await user.click(screen.getByText('Dark Mode'))

      expect(defaultProps.onToggleDarkMode).toHaveBeenCalled()

      // Note: The drawer may or may not close after clicking dark mode
      // This depends on the component implementation
      // Let's just verify the dark mode toggle was called
    })

    it('should highlight active tab in mobile drawer', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} activeTab="scraping" />)

      await user.click(screen.getByLabelText('Open navigation menu'))

      const scrapingButton = screen.getByText('Scraping')
      expect(scrapingButton).toHaveClass('bg-primary') // Active variant
    })

    it('should prevent body scroll when drawer is open', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      expect(document.body.style.overflow).toBe('')

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))

      expect(document.body.style.overflow).toBe('hidden')

      // Close drawer
      await user.click(screen.getByLabelText('Close navigation menu'))

      await waitFor(() => {
        expect(document.body.style.overflow).toBe('')
      })
    })

    it('should handle escape key to close drawer', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))
      expect(screen.getByRole('dialog')).toBeInTheDocument()

      // Press escape using userEvent for better simulation
      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      }, { timeout: 3000 })
    })

    it('should have proper ARIA attributes', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      const menuButton = screen.getByLabelText('Open navigation menu')
      expect(menuButton).toHaveAttribute('aria-expanded', 'false')

      await user.click(menuButton)

      expect(menuButton).toHaveAttribute('aria-expanded', 'true')

      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveAttribute('aria-modal', 'true')
      expect(dialog).toHaveAttribute('aria-label', 'Navigation menu')
    })

    it('should have touch-friendly button sizes', async () => {
      const user = userEvent.setup()
      render(<MobileNavigation {...defaultProps} />)

      const menuButton = screen.getByLabelText('Open navigation menu')
      expect(menuButton).toHaveClass('min-h-touch', 'min-w-touch')

      await user.click(menuButton)

      const configButton = screen.getByText('Configuration')
      expect(configButton).toHaveClass('min-h-touch')

      const closeButton = screen.getByLabelText('Close navigation menu')
      expect(closeButton).toHaveClass('min-h-touch', 'min-w-touch')
    })
  })

  describe('Responsive Behavior', () => {
    it('should close drawer when switching from mobile to desktop', async () => {
      const user = userEvent.setup()

      // Start in mobile mode
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTouchDevice: true,
      })

      const { rerender } = render(<MobileNavigation {...defaultProps} />)

      // Open drawer
      await user.click(screen.getByLabelText('Open navigation menu'))
      expect(screen.getByRole('dialog')).toBeInTheDocument()

      // Switch to desktop mode
      mockUseResponsive.mockReturnValue({
        isMobile: false,
        isTouchDevice: false,
      })

      rerender(<MobileNavigation {...defaultProps} />)

      // Drawer should be closed and desktop nav should be visible
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      expect(screen.getByText('Configuration')).toBeInTheDocument()
    })
  })
})
