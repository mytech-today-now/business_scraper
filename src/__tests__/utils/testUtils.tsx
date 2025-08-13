/**
 * Test Utilities for Business Scraper Application
 * Comprehensive utilities for React Testing Library with proper act() handling
 */

import React from 'react'
import { render, screen, waitFor, act, RenderResult } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfigProvider } from '@/controller/ConfigContext'

/**
 * Enhanced render function with ConfigProvider
 */
export const renderWithProvider = (component: React.ReactElement): RenderResult => {
  return render(
    <ConfigProvider>
      {component}
    </ConfigProvider>
  )
}

/**
 * Suppress React act() warnings for specific test scenarios
 * Use sparingly and only when act() warnings are expected/unavoidable
 */
export const suppressActWarnings = () => {
  const originalError = console.error
  beforeAll(() => {
    console.error = (...args: any[]) => {
      if (
        typeof args[0] === 'string' &&
        args[0].includes('Warning: An update to') &&
        args[0].includes('was not wrapped in act')
      ) {
        return
      }
      originalError.call(console, ...args)
    }
  })

  afterAll(() => {
    console.error = originalError
  })
}

/**
 * Enhanced user event setup with proper act() handling
 */
export const setupUserEvent = () => {
  return userEvent.setup()
}

/**
 * Wrapper for user interactions with proper act() and error handling
 */
export const userInteraction = async (fn: () => Promise<void>): Promise<void> => {
  try {
    await act(async () => {
      await fn()
    })
  } catch (error) {
    // If act() fails, try without it (for some edge cases)
    await fn()
  }
}

/**
 * Wait for element with timeout and proper error handling
 */
export const waitForElement = async (
  selector: () => HTMLElement | null,
  options: { timeout?: number; interval?: number } = {}
): Promise<HTMLElement> => {
  const { timeout = 5000, interval = 50 } = options
  
  return waitFor(
    () => {
      const element = selector()
      if (!element) {
        throw new Error('Element not found')
      }
      return element
    },
    { timeout, interval }
  )
}

/**
 * Find button by icon class or SVG content
 */
export const findButtonByIcon = (iconName: string): HTMLElement | null => {
  // Try to find by lucide icon class
  const iconElement = document.querySelector(`.lucide-${iconName}`)
  if (iconElement) {
    // Find the parent button
    let parent = iconElement.parentElement
    while (parent && parent.tagName !== 'BUTTON') {
      parent = parent.parentElement
    }
    return parent as HTMLElement
  }

  // Try to find by SVG content patterns
  const buttons = Array.from(document.querySelectorAll('button'))
  return buttons.find(button => {
    const svg = button.querySelector('svg')
    if (!svg) return false
    
    const svgContent = svg.innerHTML.toLowerCase()
    
    // Check for common icon patterns
    switch (iconName.toLowerCase()) {
      case 'check':
        return svgContent.includes('polyline') && svgContent.includes('points="20 6 9 17 4 12"')
      case 'x':
        return svgContent.includes('line') && svgContent.includes('x1="18"') && svgContent.includes('y1="6"')
      case 'plus':
        return svgContent.includes('path') && svgContent.includes('d="M5 12h14"')
      default:
        return false
    }
  }) || null
}

/**
 * Click button with proper act() wrapping and retry logic
 */
export const clickButton = async (
  user: ReturnType<typeof userEvent.setup>,
  selector: string | HTMLElement | (() => HTMLElement | null)
): Promise<void> => {
  await userInteraction(async () => {
    let element: HTMLElement | null = null
    
    if (typeof selector === 'string') {
      // Try different selection strategies
      element = screen.queryByRole('button', { name: selector }) ||
                screen.queryByText(selector) ||
                screen.queryByLabelText(selector) ||
                screen.queryByTitle(selector)
    } else if (typeof selector === 'function') {
      element = selector()
    } else {
      element = selector
    }
    
    if (!element) {
      throw new Error(`Button not found: ${selector}`)
    }
    
    await user.click(element)
  })
}

/**
 * Type text with proper act() wrapping
 */
export const typeText = async (
  user: ReturnType<typeof userEvent.setup>,
  element: HTMLElement,
  text: string,
  options: { clear?: boolean } = {}
): Promise<void> => {
  await userInteraction(async () => {
    if (options.clear) {
      await user.clear(element)
    }
    await user.type(element, text)
  })
}

/**
 * Wait for text to appear with proper error handling
 */
export const waitForText = async (
  text: string | RegExp,
  options: { timeout?: number } = {}
): Promise<HTMLElement> => {
  const { timeout = 5000 } = options
  
  return waitFor(
    () => {
      const element = typeof text === 'string' 
        ? screen.getByText(text)
        : screen.getByText(text)
      return element
    },
    { timeout }
  )
}

/**
 * Wait for text to disappear
 */
export const waitForTextToDisappear = async (
  text: string | RegExp,
  options: { timeout?: number } = {}
): Promise<void> => {
  const { timeout = 5000 } = options
  
  await waitFor(
    () => {
      const element = typeof text === 'string'
        ? screen.queryByText(text)
        : screen.queryByText(text)
      if (element) {
        throw new Error('Element still present')
      }
    },
    { timeout }
  )
}

/**
 * Get element by display value with fallback strategies
 */
export const getByDisplayValue = (value: string | RegExp): HTMLElement => {
  try {
    return screen.getByDisplayValue(value)
  } catch {
    // Fallback: find textarea/input with matching value
    const inputs = Array.from(document.querySelectorAll('input, textarea')) as HTMLInputElement[]
    const element = inputs.find(input => {
      if (typeof value === 'string') {
        return input.value.includes(value)
      } else {
        return value.test(input.value)
      }
    })
    
    if (!element) {
      throw new Error(`Element with display value not found: ${value}`)
    }
    
    return element
  }
}

/**
 * Debug helper to log current DOM state
 */
export const debugDOM = (message?: string) => {
  if (message) {
    console.log(`\n=== DEBUG: ${message} ===`)
  }
  
  // Log all buttons
  const buttons = Array.from(document.querySelectorAll('button'))
  console.log('Buttons found:', buttons.map(btn => ({
    text: btn.textContent?.trim(),
    title: btn.title,
    className: btn.className,
    hasIcon: !!btn.querySelector('svg')
  })))
  
  // Log all inputs/textareas
  const inputs = Array.from(document.querySelectorAll('input, textarea'))
  console.log('Inputs found:', inputs.map(input => ({
    type: input.tagName.toLowerCase(),
    value: (input as HTMLInputElement).value,
    placeholder: (input as HTMLInputElement).placeholder
  })))
}

/**
 * Mock common dependencies for tests
 */
export const mockDependencies = () => {
  // Mock storage
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

  // Mock logger
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
}

/**
 * Test wrapper component that suppresses act warnings
 */
export const TestWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <ConfigProvider>
      {children}
    </ConfigProvider>
  )
}
