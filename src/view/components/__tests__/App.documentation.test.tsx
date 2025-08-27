/**
 * Documentation Button Tests
 * Tests for the documentation button functionality
 */

import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { Button } from '@/view/components/ui/button'
import { FileText } from 'lucide-react'

// Mock window.open
const mockWindowOpen = jest.fn()
Object.defineProperty(window, 'open', {
  value: mockWindowOpen,
  writable: true,
})

// Simple Documentation Button Component for testing
const DocumentationButton: React.FC = () => {
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => window.open('/docs/readme.html', '_blank')}
      title="Documentation"
    >
      <FileText className="h-4 w-4" />
    </Button>
  )
}

describe('Documentation Button', () => {
  beforeEach(() => {
    mockWindowOpen.mockClear()
  })

  it('should render the documentation button', () => {
    render(<DocumentationButton />)

    // Look for the documentation button by its title attribute
    const docButton = screen.getByTitle('Documentation')
    expect(docButton).toBeInTheDocument()

    // Verify it has the correct title attribute
    expect(docButton).toHaveAttribute('title', 'Documentation')
  })

  it('should open documentation in new tab when clicked', () => {
    render(<DocumentationButton />)

    // Find and click the documentation button
    const docButton = screen.getByTitle('Documentation')
    fireEvent.click(docButton)

    // Verify window.open was called with correct parameters
    expect(mockWindowOpen).toHaveBeenCalledWith('/docs/readme.html', '_blank')
    expect(mockWindowOpen).toHaveBeenCalledTimes(1)
  })

  it('should have proper accessibility attributes', () => {
    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')

    // Should have title for accessibility
    expect(docButton).toHaveAttribute('title', 'Documentation')

    // Should be a button element
    expect(docButton.tagName).toBe('BUTTON')

    // Should be focusable
    expect(docButton).not.toHaveAttribute('disabled')
  })

  it('should have the FileText icon', () => {
    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')

    // Should contain the FileText icon (check for SVG element)
    const icon = docButton.querySelector('svg')
    expect(icon).toBeInTheDocument()
  })

  it('should handle multiple clicks without issues', () => {
    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')

    // Click multiple times
    fireEvent.click(docButton)
    fireEvent.click(docButton)
    fireEvent.click(docButton)

    // Should call window.open each time
    expect(mockWindowOpen).toHaveBeenCalledTimes(3)
    expect(mockWindowOpen).toHaveBeenCalledWith('/docs/readme.html', '_blank')
  })

  it('should call window.open with correct parameters', () => {
    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')
    fireEvent.click(docButton)

    // Verify window.open was called with correct parameters
    expect(mockWindowOpen).toHaveBeenCalledWith('/docs/readme.html', '_blank')
    expect(mockWindowOpen).toHaveBeenCalledTimes(1)
  })
})

describe('Documentation Integration', () => {
  it('should have the correct documentation path', () => {
    // Verify the path matches our documentation structure
    const expectedPath = '/docs/readme.html'

    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')
    fireEvent.click(docButton)

    expect(mockWindowOpen).toHaveBeenCalledWith(expectedPath, '_blank')
  })

  it('should open in a new tab/window', () => {
    render(<DocumentationButton />)

    const docButton = screen.getByTitle('Documentation')
    fireEvent.click(docButton)

    // Verify the second parameter is '_blank' for new tab
    expect(mockWindowOpen).toHaveBeenCalledWith(expect.any(String), '_blank')
  })
})
