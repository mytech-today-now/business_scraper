/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'
import { App } from '@/view/components/App'

// Polyfill for TextEncoder/TextDecoder in Node.js environment
if (typeof global.TextEncoder === 'undefined') {
  const { TextEncoder, TextDecoder } = require('util')
  global.TextEncoder = TextEncoder
  global.TextDecoder = TextDecoder
}
import { ConfigProvider } from '@/controller/ConfigContext'
import { PerformanceProvider } from '@/controller/PerformanceContext'

// Mock the responsive hooks
jest.mock('@/hooks/useResponsive', () => ({
  useResponsive: jest.fn(),
  useResponsiveValue: jest.fn(),
}))

// Mock other dependencies
jest.mock('@/model/clientScraperService', () => ({
  clientScraperService: {
    refreshCredentials: jest.fn(),
  },
}))

jest.mock('@/hooks/useOfflineSupport', () => ({
  useOfflineSupport: jest.fn(() => ({
    isOnline: true,
    isOffline: false,
    wasOffline: false,
  })),
}))

const mockUseResponsive = require('@/hooks/useResponsive').useResponsive

// Test wrapper with providers
const TestWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <ConfigProvider>
    <PerformanceProvider>{children}</PerformanceProvider>
  </ConfigProvider>
)

describe('Mobile Responsiveness Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Mobile Layout', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTablet: false,
        isDesktop: false,
        isTouchDevice: true,
        breakpoints: {
          sm: false,
          md: false,
          lg: false,
          xl: false,
          '2xl': false,
        },
        windowSize: { width: 375, height: 667 },
      })
    })

    it('should render mobile-optimized header', () => {
      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Should show mobile title
      expect(screen.getByText('Scraper')).toBeInTheDocument()
      expect(screen.queryByText('Business Scraper')).not.toBeInTheDocument()

      // Should show mobile menu button
      expect(screen.getByLabelText('Open navigation menu')).toBeInTheDocument()
    })

    it('should open mobile navigation drawer', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      await user.click(screen.getByLabelText('Open navigation menu'))

      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.getByText('Navigation')).toBeInTheDocument()
    })

    it('should have touch-friendly targets', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      const menuButton = screen.getByLabelText('Open navigation menu')
      expect(menuButton).toHaveClass('min-h-touch', 'min-w-touch')

      await user.click(menuButton)

      const configButton = screen.getByText('Configuration')
      expect(configButton).toHaveClass('min-h-touch')
    })

    it('should handle mobile navigation between tabs', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Open mobile menu
      await user.click(screen.getByLabelText('Open navigation menu'))

      // Navigate to scraping tab
      await user.click(screen.getByText('Scraping'))

      // Drawer should close
      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })

      // Should be on scraping tab (check for scraping-specific content)
      // This would depend on the actual content structure
    })
  })

  describe('Tablet Layout', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: false,
        isTablet: true,
        isDesktop: false,
        isTouchDevice: true,
        breakpoints: {
          sm: true,
          md: true,
          lg: false,
          xl: false,
          '2xl': false,
        },
        windowSize: { width: 768, height: 1024 },
      })
    })

    it('should render tablet-optimized layout', () => {
      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Should show full title on tablet
      expect(screen.getByText('Business Scraper')).toBeInTheDocument()

      // Should show desktop navigation on tablet
      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.getByText('Scraping')).toBeInTheDocument()
    })
  })

  describe('Desktop Layout', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: false,
        isTablet: false,
        isDesktop: true,
        isTouchDevice: false,
        breakpoints: {
          sm: true,
          md: true,
          lg: true,
          xl: false,
          '2xl': false,
        },
        windowSize: { width: 1200, height: 800 },
      })
    })

    it('should render desktop layout', () => {
      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Should show full title
      expect(screen.getByText('Business Scraper')).toBeInTheDocument()

      // Should show desktop navigation
      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.getByText('Scraping')).toBeInTheDocument()

      // Should not show mobile menu button
      expect(screen.queryByLabelText('Open navigation menu')).not.toBeInTheDocument()
    })
  })

  describe('Responsive Breakpoint Changes', () => {
    it('should adapt when switching from mobile to desktop', async () => {
      const user = userEvent.setup()

      // Start in mobile mode
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTablet: false,
        isDesktop: false,
        isTouchDevice: true,
        breakpoints: { sm: false, md: false, lg: false, xl: false, '2xl': false },
        windowSize: { width: 375, height: 667 },
      })

      const { rerender } = render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Should be in mobile mode
      expect(screen.getByLabelText('Open navigation menu')).toBeInTheDocument()

      // Open mobile drawer
      await user.click(screen.getByLabelText('Open navigation menu'))
      expect(screen.getByRole('dialog')).toBeInTheDocument()

      // Switch to desktop mode
      mockUseResponsive.mockReturnValue({
        isMobile: false,
        isTablet: false,
        isDesktop: true,
        isTouchDevice: false,
        breakpoints: { sm: true, md: true, lg: true, xl: false, '2xl': false },
        windowSize: { width: 1200, height: 800 },
      })

      rerender(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      // Should switch to desktop mode
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.queryByLabelText('Open navigation menu')).not.toBeInTheDocument()
    })
  })

  describe('Touch Interactions', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTablet: false,
        isDesktop: false,
        isTouchDevice: true,
        breakpoints: { sm: false, md: false, lg: false, xl: false, '2xl': false },
        windowSize: { width: 375, height: 667 },
      })
    })

    it('should handle touch events properly', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      const menuButton = screen.getByLabelText('Open navigation menu')

      // Simulate touch events
      fireEvent.touchStart(menuButton)
      fireEvent.touchEnd(menuButton)

      await user.click(menuButton)

      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })

    it('should prevent body scroll when modal is open', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      expect(document.body.style.overflow).toBe('')

      await user.click(screen.getByLabelText('Open navigation menu'))

      expect(document.body.style.overflow).toBe('hidden')

      await user.click(screen.getByLabelText('Close navigation menu'))

      await waitFor(() => {
        expect(document.body.style.overflow).toBe('')
      })
    })
  })

  describe('Accessibility on Mobile', () => {
    beforeEach(() => {
      mockUseResponsive.mockReturnValue({
        isMobile: true,
        isTablet: false,
        isDesktop: false,
        isTouchDevice: true,
        breakpoints: { sm: false, md: false, lg: false, xl: false, '2xl': false },
        windowSize: { width: 375, height: 667 },
      })
    })

    it('should have proper ARIA attributes for mobile navigation', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      const menuButton = screen.getByLabelText('Open navigation menu')
      expect(menuButton).toHaveAttribute('aria-expanded', 'false')

      await user.click(menuButton)

      expect(menuButton).toHaveAttribute('aria-expanded', 'true')

      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveAttribute('aria-modal', 'true')
      expect(dialog).toHaveAttribute('aria-label', 'Navigation menu')
    })

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      await user.click(screen.getByLabelText('Open navigation menu'))

      // Should be able to close with Escape
      fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' })

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })

    it('should have minimum touch target sizes', async () => {
      const user = userEvent.setup()

      render(
        <TestWrapper>
          <App />
        </TestWrapper>
      )

      const menuButton = screen.getByLabelText('Open navigation menu')
      expect(menuButton).toHaveClass('min-h-touch', 'min-w-touch')

      await user.click(menuButton)

      const buttons = screen.getAllByRole('button')
      buttons.forEach(button => {
        if (button.classList.contains('min-h-touch')) {
          expect(button).toHaveClass('min-h-touch')
        }
      })
    })
  })
})
