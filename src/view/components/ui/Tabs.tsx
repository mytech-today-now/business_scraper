import React, { createContext, useContext, useState } from 'react'
import { clsx } from 'clsx'

/**
 * Tabs context for managing active tab state
 */
interface TabsContextValue {
  value: string
  onValueChange: (value: string) => void
}

const TabsContext = createContext<TabsContextValue | undefined>(undefined)

/**
 * Hook to access tabs context
 */
const useTabsContext = () => {
  const context = useContext(TabsContext)
  if (!context) {
    throw new Error('Tabs components must be used within a Tabs provider')
  }
  return context
}

/**
 * Tabs root component props
 */
export interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string
  value?: string
  onValueChange?: (value: string) => void
  children: React.ReactNode
}

/**
 * Tabs root component
 */
export const Tabs = React.forwardRef<HTMLDivElement, TabsProps>(
  ({ className, defaultValue, value, onValueChange, children, ...props }, ref) => {
    const [internalValue, setInternalValue] = useState(defaultValue || '')

    const currentValue = value !== undefined ? value : internalValue
    const handleValueChange = onValueChange || setInternalValue

    return (
      <TabsContext.Provider value={{ value: currentValue, onValueChange: handleValueChange }}>
        <div ref={ref} className={clsx('w-full', className)} {...props}>
          {children}
        </div>
      </TabsContext.Provider>
    )
  }
)

Tabs.displayName = 'Tabs'

/**
 * Tabs list component props
 */
export interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

/**
 * Tabs list component
 */
export const TabsList = React.forwardRef<HTMLDivElement, TabsListProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={clsx(
        'inline-flex h-10 items-center justify-center rounded-md bg-muted p-1 text-muted-foreground',
        className
      )}
      role="tablist"
      {...props}
    >
      {children}
    </div>
  )
)

TabsList.displayName = 'TabsList'

/**
 * Tabs trigger component props
 */
export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string
  children: React.ReactNode
}

/**
 * Tabs trigger component
 */
export const TabsTrigger = React.forwardRef<HTMLButtonElement, TabsTriggerProps>(
  ({ className, value, children, disabled, ...props }, ref) => {
    const { value: selectedValue, onValueChange } = useTabsContext()
    const isSelected = selectedValue === value

    return (
      <button
        ref={ref}
        className={clsx(
          'inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1.5 text-sm font-medium',
          'ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2',
          'focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
          isSelected
            ? 'bg-background text-foreground shadow-sm'
            : 'hover:bg-background/50 hover:text-foreground',
          className
        )}
        role="tab"
        aria-selected={isSelected}
        aria-controls={`tabpanel-${value}`}
        tabIndex={isSelected ? 0 : -1}
        disabled={disabled}
        onClick={() => !disabled && onValueChange(value)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            if (!disabled) onValueChange(value)
          }
        }}
        {...props}
      >
        {children}
      </button>
    )
  }
)

TabsTrigger.displayName = 'TabsTrigger'

/**
 * Tabs content component props
 */
export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string
  children: React.ReactNode
  forceMount?: boolean
}

/**
 * Tabs content component
 */
export const TabsContent = React.forwardRef<HTMLDivElement, TabsContentProps>(
  ({ className, value, children, forceMount = false, ...props }, ref) => {
    const { value: selectedValue } = useTabsContext()
    const isSelected = selectedValue === value

    if (!isSelected && !forceMount) {
      return null
    }

    return (
      <div
        ref={ref}
        className={clsx(
          'mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2',
          'focus-visible:ring-ring focus-visible:ring-offset-2',
          !isSelected && 'hidden',
          className
        )}
        role="tabpanel"
        id={`tabpanel-${value}`}
        aria-labelledby={`tab-${value}`}
        tabIndex={0}
        {...props}
      >
        {children}
      </div>
    )
  }
)

TabsContent.displayName = 'TabsContent'

/**
 * Controlled tabs component for advanced use cases
 */
export interface ControlledTabsProps extends Omit<TabsProps, 'defaultValue'> {
  value: string
  onValueChange: (value: string) => void
}

export const ControlledTabs: React.FC<ControlledTabsProps> = props => {
  return <Tabs {...props} />
}

ControlledTabs.displayName = 'ControlledTabs'
