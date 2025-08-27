import React from 'react'
import { clsx } from 'clsx'
import { LucideIcon, ChevronRight, Home } from 'lucide-react'

/**
 * Breadcrumb item interface
 */
export interface BreadcrumbItem {
  /** Display label for the breadcrumb item */
  label: string
  /** Path or identifier for navigation */
  path?: string
  /** Optional icon to display */
  icon?: LucideIcon
  /** Whether this item is clickable */
  clickable?: boolean
  /** Whether this is the current/active item */
  isCurrent?: boolean
}

/**
 * Breadcrumb component props
 */
export interface BreadcrumbProps {
  /** Array of breadcrumb items */
  items: BreadcrumbItem[]
  /** Callback when a breadcrumb item is clicked */
  onItemClick?: (item: BreadcrumbItem, index: number) => void
  /** Custom separator between items */
  separator?: React.ReactNode
  /** Additional CSS classes */
  className?: string
  /** Show home icon for first item */
  showHomeIcon?: boolean
  /** Maximum items to show before collapsing */
  maxItems?: number
}

/**
 * Breadcrumb separator component
 */
const BreadcrumbSeparator: React.FC<{ children?: React.ReactNode }> = ({
  children = <ChevronRight className="h-4 w-4" />,
}) => (
  <span
    className="flex items-center text-muted-foreground mx-2"
    aria-hidden="true"
    role="presentation"
  >
    {children}
  </span>
)

/**
 * Breadcrumb item component
 */
const BreadcrumbItemComponent: React.FC<{
  item: BreadcrumbItem
  index: number
  isLast: boolean
  onItemClick?: (item: BreadcrumbItem, index: number) => void
  showHomeIcon?: boolean
}> = ({ item, index, isLast, onItemClick, showHomeIcon }) => {
  const isClickable = item.clickable !== false && !isLast && onItemClick
  const Icon = item.icon || (index === 0 && showHomeIcon ? Home : undefined)

  const handleClick = () => {
    if (isClickable && onItemClick) {
      onItemClick(item, index)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (isClickable && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault()
      handleClick()
    }
  }

  const itemClasses = clsx('flex items-center gap-1.5 text-sm font-medium transition-colors', {
    'text-muted-foreground hover:text-foreground cursor-pointer focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 rounded-sm px-1 py-0.5':
      isClickable,
    'text-foreground': isLast,
    'text-muted-foreground': !isLast && !isClickable,
  })

  const content = (
    <>
      {Icon && <Icon className="h-4 w-4 flex-shrink-0" />}
      <span className="truncate">{item.label}</span>
    </>
  )

  if (isClickable) {
    return (
      <button
        type="button"
        className={itemClasses}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        aria-current={isLast ? 'page' : undefined}
        title={`Navigate to ${item.label}`}
      >
        {content}
      </button>
    )
  }

  return (
    <span className={itemClasses} aria-current={isLast ? 'page' : undefined}>
      {content}
    </span>
  )
}

/**
 * Breadcrumb component with navigation support
 *
 * Provides accessible breadcrumb navigation with support for:
 * - Custom icons and separators
 * - Click handlers for navigation
 * - Responsive design with item collapsing
 * - Keyboard navigation support
 * - ARIA accessibility attributes
 */
export const Breadcrumb: React.FC<BreadcrumbProps> = ({
  items,
  onItemClick,
  separator,
  className,
  showHomeIcon = true,
  maxItems = 5,
}) => {
  // Handle item collapsing for long breadcrumb trails
  const displayItems = React.useMemo(() => {
    if (items.length <= maxItems) {
      return items
    }

    // Always show first and last items, collapse middle items
    const firstItem = items[0]
    const lastItems = items.slice(-2) // Last 2 items
    const collapsedCount = items.length - 3

    return [
      firstItem,
      {
        label: `... (${collapsedCount} more)`,
        clickable: false,
        isCurrent: false,
      },
      ...lastItems,
    ]
  }, [items, maxItems])

  if (!items.length) {
    return null
  }

  return (
    <nav
      aria-label="Breadcrumb navigation"
      className={clsx('flex items-center space-x-1', className)}
    >
      <ol className="flex items-center space-x-1">
        {displayItems.map((item, index) => {
          const isLast = index === displayItems.length - 1
          const originalIndex = item.label.includes('...')
            ? -1
            : items.findIndex(originalItem => originalItem.label === item.label)

          return (
            <li key={`${item.label}-${index}`} className="flex items-center">
              <BreadcrumbItemComponent
                item={item}
                index={originalIndex >= 0 ? originalIndex : index}
                isLast={isLast}
                onItemClick={onItemClick}
                showHomeIcon={showHomeIcon}
              />
              {!isLast && <BreadcrumbSeparator>{separator}</BreadcrumbSeparator>}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

/**
 * Hook to generate breadcrumb items for the Business Scraper app
 */
export const useBreadcrumbItems = (
  activeTab: 'config' | 'scraping',
  hasResults: boolean = false
): BreadcrumbItem[] => {
  return React.useMemo(() => {
    const items: BreadcrumbItem[] = [
      {
        label: 'Home',
        path: 'home',
        clickable: true,
        icon: Home,
      },
    ]

    if (activeTab === 'config') {
      items.push({
        label: 'Configuration',
        path: 'config',
        clickable: false,
        isCurrent: true,
      })
    } else if (activeTab === 'scraping') {
      items.push(
        {
          label: 'Configuration',
          path: 'config',
          clickable: true,
        },
        {
          label: 'Scraping',
          path: 'scraping',
          clickable: !hasResults,
          isCurrent: !hasResults,
        }
      )

      if (hasResults) {
        items.push({
          label: 'Results',
          path: 'results',
          clickable: false,
          isCurrent: true,
        })
      }
    }

    return items
  }, [activeTab, hasResults])
}

Breadcrumb.displayName = 'Breadcrumb'
