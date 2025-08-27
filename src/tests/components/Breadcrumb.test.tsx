import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { renderHook } from '@testing-library/react'
import '@testing-library/jest-dom'
import { Home, Settings, Search } from 'lucide-react'
import { Breadcrumb, useBreadcrumbItems, BreadcrumbItem } from '@/view/components/ui/Breadcrumb'

// Mock toast to avoid issues in tests
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    error: jest.fn(),
    success: jest.fn(),
  },
}))

describe('Breadcrumb Component', () => {
  const mockOnItemClick = jest.fn()

  beforeEach(() => {
    mockOnItemClick.mockClear()
  })

  describe('Basic Rendering', () => {
    it('renders empty breadcrumb when no items provided', () => {
      render(<Breadcrumb items={[]} />)
      expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    })

    it('renders single breadcrumb item', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} />)

      expect(screen.getByRole('navigation')).toBeInTheDocument()
      expect(screen.getByText('Home')).toBeInTheDocument()
      // The aria-current is on the parent span, not the text span
      const homeElement = screen.getByText('Home').closest('[aria-current]')
      expect(homeElement).toHaveAttribute('aria-current', 'page')
    })

    it('renders multiple breadcrumb items with separators', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Configuration', path: 'config', clickable: true },
        { label: 'Settings', path: 'settings', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} />)

      expect(screen.getByText('Home')).toBeInTheDocument()
      expect(screen.getByText('Configuration')).toBeInTheDocument()
      expect(screen.getByText('Settings')).toBeInTheDocument()

      // Check for separators (ChevronRight icons) - they have aria-hidden so we need to use a different approach
      const separators = document.querySelectorAll('[role="presentation"]')
      expect(separators).toHaveLength(2) // Two separators for three items
    })

    it('renders breadcrumb items with icons', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', icon: Home, clickable: true },
        { label: 'Settings', path: 'settings', icon: Settings, clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} showHomeIcon={false} onItemClick={jest.fn()} />)

      expect(screen.getByText('Home')).toBeInTheDocument()
      expect(screen.getByText('Settings')).toBeInTheDocument()

      // Icons should be present (though we can't easily test the specific icon)
      const homeButton = screen.getByRole('button', { name: 'Home' })
      expect(homeButton).toBeInTheDocument()
    })

    it('shows home icon for first item when showHomeIcon is true', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Config', path: 'config', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} showHomeIcon={true} onItemClick={jest.fn()} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      expect(homeButton).toBeInTheDocument()
    })
  })

  describe('Navigation Functionality', () => {
    it('calls onItemClick when clickable item is clicked', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      fireEvent.click(homeButton)

      expect(mockOnItemClick).toHaveBeenCalledWith(items[0], 0)
    })

    it('does not call onItemClick for non-clickable items', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: false },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const homeSpan = screen.getByText('Home')
      fireEvent.click(homeSpan)

      expect(mockOnItemClick).not.toHaveBeenCalled()
    })

    it('does not call onItemClick for current/last item', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: true, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const currentSpan = screen.getByText('Current')
      fireEvent.click(currentSpan)

      expect(mockOnItemClick).not.toHaveBeenCalled()
    })

    it('handles keyboard navigation with Enter key', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      fireEvent.keyDown(homeButton, { key: 'Enter' })

      expect(mockOnItemClick).toHaveBeenCalledWith(items[0], 0)
    })

    it('handles keyboard navigation with Space key', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      fireEvent.keyDown(homeButton, { key: ' ' })

      expect(mockOnItemClick).toHaveBeenCalledWith(items[0], 0)
    })

    it('ignores other keyboard keys', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={mockOnItemClick} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      fireEvent.keyDown(homeButton, { key: 'Tab' })

      expect(mockOnItemClick).not.toHaveBeenCalled()
    })
  })

  describe('Accessibility', () => {
    it('has proper ARIA attributes', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Configuration', path: 'config', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} />)

      const nav = screen.getByRole('navigation')
      expect(nav).toHaveAttribute('aria-label', 'Breadcrumb navigation')

      const currentItem = screen.getByText('Current').closest('[aria-current]')
      expect(currentItem).toHaveAttribute('aria-current', 'page')
    })

    it('has proper semantic HTML structure', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} />)

      expect(screen.getByRole('navigation')).toBeInTheDocument()
      expect(screen.getByRole('list')).toBeInTheDocument()
      expect(screen.getAllByRole('listitem')).toHaveLength(2)
    })

    it('provides proper button titles for clickable items', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} onItemClick={jest.fn()} />)

      const homeButton = screen.getByRole('button', { name: 'Home' })
      expect(homeButton).toHaveAttribute('title', 'Navigate to Home')
    })
  })

  describe('Item Collapsing', () => {
    it('collapses items when exceeding maxItems', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Level1', path: 'level1', clickable: true },
        { label: 'Level2', path: 'level2', clickable: true },
        { label: 'Level3', path: 'level3', clickable: true },
        { label: 'Level4', path: 'level4', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} maxItems={4} />)

      expect(screen.getByText('Home')).toBeInTheDocument()
      expect(screen.getByText(/\.\.\. \(\d+ more\)/)).toBeInTheDocument()
      expect(screen.getByText('Level4')).toBeInTheDocument()
      expect(screen.getByText('Current')).toBeInTheDocument()

      // Middle items should be collapsed
      expect(screen.queryByText('Level1')).not.toBeInTheDocument()
      expect(screen.queryByText('Level2')).not.toBeInTheDocument()
      expect(screen.queryByText('Level3')).not.toBeInTheDocument()
    })

    it('does not collapse when items are within maxItems limit', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Config', path: 'config', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      render(<Breadcrumb items={items} maxItems={5} />)

      expect(screen.getByText('Home')).toBeInTheDocument()
      expect(screen.getByText('Config')).toBeInTheDocument()
      expect(screen.getByText('Current')).toBeInTheDocument()
      expect(screen.queryByText(/\.\.\./)).not.toBeInTheDocument()
    })
  })

  describe('Custom Separators', () => {
    it('renders custom separator', () => {
      const items: BreadcrumbItem[] = [
        { label: 'Home', path: 'home', clickable: true },
        { label: 'Current', path: 'current', clickable: false, isCurrent: true },
      ]

      const customSeparator = <span data-testid="custom-separator">→</span>

      render(<Breadcrumb items={items} separator={customSeparator} />)

      expect(screen.getByTestId('custom-separator')).toBeInTheDocument()
    })
  })
})

describe('useBreadcrumbItems Hook', () => {
  it('generates correct items for config tab', () => {
    const { result } = renderHook(() => useBreadcrumbItems('config', false))

    expect(result.current).toHaveLength(2)
    expect(result.current[0]).toMatchObject({
      label: 'Home',
      path: 'home',
      clickable: true,
    })
    expect(result.current[1]).toMatchObject({
      label: 'Configuration',
      path: 'config',
      clickable: false,
      isCurrent: true,
    })
  })

  it('generates correct items for scraping tab without results', () => {
    const { result } = renderHook(() => useBreadcrumbItems('scraping', false))

    expect(result.current).toHaveLength(3)
    expect(result.current[0]).toMatchObject({
      label: 'Home',
      path: 'home',
      clickable: true,
    })
    expect(result.current[1]).toMatchObject({
      label: 'Configuration',
      path: 'config',
      clickable: true,
    })
    expect(result.current[2]).toMatchObject({
      label: 'Scraping',
      path: 'scraping',
      clickable: true,
      isCurrent: true,
    })
  })

  it('generates correct items for scraping tab with results', () => {
    const { result } = renderHook(() => useBreadcrumbItems('scraping', true))

    expect(result.current).toHaveLength(4)
    expect(result.current[0]).toMatchObject({
      label: 'Home',
      path: 'home',
      clickable: true,
    })
    expect(result.current[1]).toMatchObject({
      label: 'Configuration',
      path: 'config',
      clickable: true,
    })
    expect(result.current[2]).toMatchObject({
      label: 'Scraping',
      path: 'scraping',
      clickable: false,
    })
    expect(result.current[3]).toMatchObject({
      label: 'Results',
      path: 'results',
      clickable: false,
      isCurrent: true,
    })
  })
})
