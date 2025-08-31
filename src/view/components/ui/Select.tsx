import React, { useState, useRef, useEffect } from 'react'
import { clsx } from 'clsx'
import { ChevronDown, Check } from 'lucide-react'

/**
 * Select option interface
 */
export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

/**
 * Select component props
 */
export interface SelectProps {
  value?: string
  onValueChange?: (value: string) => void
  options: SelectOption[]
  placeholder?: string
  disabled?: boolean
  className?: string
  'aria-label'?: string
}

/**
 * Select component with dropdown functionality
 */
export const Select: React.FC<SelectProps> = ({
  value,
  onValueChange,
  options,
  placeholder = 'Select an option...',
  disabled = false,
  className,
  'aria-label': ariaLabel,
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [focusedIndex, setFocusedIndex] = useState(-1)
  const selectRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  // Find the selected option
  const selectedOption = options.find(option => option.value === value)

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (selectRef.current && !selectRef.current.contains(event.target as Node)) {
        setIsOpen(false)
        setFocusedIndex(-1)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Handle keyboard navigation
  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (disabled) return

    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault()
        if (isOpen && focusedIndex >= 0) {
          const option = options[focusedIndex]
          if (!option.disabled) {
            onValueChange?.(option.value)
            setIsOpen(false)
            setFocusedIndex(-1)
          }
        } else {
          setIsOpen(true)
        }
        break
      case 'Escape':
        setIsOpen(false)
        setFocusedIndex(-1)
        break
      case 'ArrowDown':
        event.preventDefault()
        if (!isOpen) {
          setIsOpen(true)
        } else {
          const nextIndex = Math.min(focusedIndex + 1, options.length - 1)
          setFocusedIndex(nextIndex)
        }
        break
      case 'ArrowUp':
        event.preventDefault()
        if (isOpen) {
          const prevIndex = Math.max(focusedIndex - 1, 0)
          setFocusedIndex(prevIndex)
        }
        break
    }
  }

  // Handle option selection
  const handleOptionClick = (option: SelectOption) => {
    if (!option.disabled) {
      onValueChange?.(option.value)
      setIsOpen(false)
      setFocusedIndex(-1)
    }
  }

  // Toggle dropdown
  const toggleDropdown = () => {
    if (!disabled) {
      setIsOpen(!isOpen)
      if (!isOpen) {
        setFocusedIndex(-1)
      }
    }
  }

  return (
    <div ref={selectRef} className={clsx('relative', className)} onKeyDown={handleKeyDown}>
      {/* Select trigger */}
      <button
        type="button"
        className={clsx(
          'flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm',
          'ring-offset-background placeholder:text-muted-foreground',
          'focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
          'disabled:cursor-not-allowed disabled:opacity-50',
          isOpen && 'ring-2 ring-ring ring-offset-2'
        )}
        onClick={toggleDropdown}
        disabled={disabled}
        aria-label={ariaLabel}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
      >
        <span className={clsx(selectedOption ? 'text-foreground' : 'text-muted-foreground')}>
          {selectedOption ? selectedOption.label : placeholder}
        </span>
        <ChevronDown
          className={clsx('h-4 w-4 opacity-50 transition-transform', isOpen && 'rotate-180')}
        />
      </button>

      {/* Dropdown menu */}
      {isOpen && (
        <div className="absolute top-full z-50 mt-1 w-full rounded-md border bg-popover text-popover-foreground shadow-md">
          <ul
            ref={listRef}
            className="max-h-60 overflow-auto p-1"
            role="listbox"
            aria-label="Options"
          >
            {options.map((option, index) => (
              <li
                key={option.value}
                className={clsx(
                  'relative flex cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none',
                  'transition-colors',
                  option.disabled
                    ? 'pointer-events-none opacity-50'
                    : 'cursor-pointer hover:bg-accent hover:text-accent-foreground',
                  focusedIndex === index && 'bg-accent text-accent-foreground',
                  value === option.value && 'bg-accent text-accent-foreground'
                )}
                onClick={() => handleOptionClick(option)}
                role="option"
                aria-selected={value === option.value}
              >
                <span className="flex-1">{option.label}</span>
                {value === option.value && <Check className="h-4 w-4" />}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

Select.displayName = 'Select'
