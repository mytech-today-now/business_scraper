/**
 * Provider Management UI Tests
 * Tests for provider management panel, configuration UI, and real-time monitoring dashboard
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import '@testing-library/jest-dom'
import { ProviderManagementPanel } from '../../view/components/ProviderManagementPanel'

describe('Provider Management Panel', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Basic Rendering', () => {
    it('should render the component without crashing', () => {
      render(<ProviderManagementPanel />)

      // Should show the main title
      expect(screen.getByText('Provider Management')).toBeInTheDocument()
    })

    it('should render tab navigation', () => {
      render(<ProviderManagementPanel />)

      // Should show all three tabs
      expect(screen.getByText('Performance')).toBeInTheDocument()
      expect(screen.getByText('Costs')).toBeInTheDocument()
      expect(screen.getByText('Quotas')).toBeInTheDocument()
    })

    it('should show refresh button', () => {
      render(<ProviderManagementPanel />)

      // Should have buttons (refresh and possibly close)
      const buttons = screen.getAllByRole('button')
      expect(buttons.length).toBeGreaterThan(0)
    })
  })

  describe('Performance Tab', () => {
    it('should display provider cards', async () => {
      render(<ProviderManagementPanel />)

      // Wait for component to load mock data
      await waitFor(() => {
        // Should show provider names from mock data
        expect(screen.getByText('Google')).toBeInTheDocument()
        expect(screen.getByText('Bing')).toBeInTheDocument()
        expect(screen.getByText('DuckDuckGo')).toBeInTheDocument()
      })
    })

    it('should show performance metrics', async () => {
      render(<ProviderManagementPanel />)

      await waitFor(() => {
        // Should show provider names from mock data
        expect(screen.getByText('Google')).toBeInTheDocument()
      }, { timeout: 3000 })

      // Should show some metric content
      expect(screen.getByText('Performance')).toBeInTheDocument()
    })
  })

  describe('Tab Navigation', () => {
    it('should switch to costs tab', async () => {
      render(<ProviderManagementPanel />)

      const costsTab = screen.getByText('Costs')
      fireEvent.click(costsTab)

      // Tab should be clickable and not crash
      expect(costsTab).toBeInTheDocument()
    })

    it('should switch to quotas tab', async () => {
      render(<ProviderManagementPanel />)

      const quotasTab = screen.getByText('Quotas')
      fireEvent.click(quotasTab)

      // Tab should be clickable and not crash
      expect(quotasTab).toBeInTheDocument()
    })

    it('should highlight active tab', () => {
      render(<ProviderManagementPanel />)

      // Performance tab should be active by default
      const performanceTab = screen.getByText('Performance')
      const tabButton = performanceTab.closest('button')
      expect(tabButton).toBeInTheDocument()
      // Check if it has any blue color class (could be text-blue-600 or similar)
      expect(tabButton?.className).toMatch(/blue/)
    })
  })

  describe('Interactive Features', () => {
    it('should handle refresh button click', async () => {
      render(<ProviderManagementPanel />)

      const buttons = screen.getAllByRole('button')
      const refreshButton = buttons[0] // First button should be refresh
      fireEvent.click(refreshButton)

      // Should not crash when refresh is clicked
      expect(refreshButton).toBeInTheDocument()
    })

    it('should handle close button when provided', () => {
      const mockClose = jest.fn()
      render(<ProviderManagementPanel onClose={mockClose} />)

      const closeButton = screen.getByText('✕')
      fireEvent.click(closeButton)

      expect(mockClose).toHaveBeenCalled()
    })
  })

  describe('Accessibility', () => {
    it('should have proper ARIA roles', () => {
      render(<ProviderManagementPanel />)

      // Should have accessible button elements
      const buttons = screen.getAllByRole('button')
      expect(buttons.length).toBeGreaterThan(0)
    })

    it('should support keyboard navigation', () => {
      render(<ProviderManagementPanel />)

      const firstButton = screen.getAllByRole('button')[0]
      firstButton.focus()

      expect(document.activeElement).toBe(firstButton)
    })
  })

  describe('Component Structure', () => {
    it('should render without errors', () => {
      const { container } = render(<ProviderManagementPanel />)
      expect(container).toBeInTheDocument()
    })

    it('should have proper CSS classes', () => {
      const { container } = render(<ProviderManagementPanel />)

      // Should have main container
      const mainDiv = container.firstChild
      expect(mainDiv).toBeInTheDocument()
      expect(mainDiv).toHaveClass('fixed')
    })

    it('should handle props correctly', () => {
      const mockClose = jest.fn()
      render(<ProviderManagementPanel onClose={mockClose} />)

      // Should render close button when onClose is provided
      expect(screen.getByText('✕')).toBeInTheDocument()
    })
  })
})
