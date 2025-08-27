'use client'

import { useState, useEffect } from 'react'

/**
 * Breakpoint definitions following Tailwind CSS conventions
 */
export const BREAKPOINTS = {
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
} as const

export type Breakpoint = keyof typeof BREAKPOINTS
export type BreakpointState = Record<Breakpoint, boolean>

/**
 * Custom hook for responsive breakpoint detection
 * Provides real-time breakpoint state and utility functions
 *
 * @returns Object containing breakpoint states and utility functions
 */
export function useResponsive() {
  const [breakpoints, setBreakpoints] = useState<BreakpointState>({
    sm: false,
    md: false,
    lg: false,
    xl: false,
    '2xl': false,
  })

  const [windowSize, setWindowSize] = useState({
    width: 0,
    height: 0,
  })

  useEffect(() => {
    // Initialize with current window size
    const updateSize = () => {
      const width = window.innerWidth
      const height = window.innerHeight

      setWindowSize({ width, height })
      setBreakpoints({
        sm: width >= BREAKPOINTS.sm,
        md: width >= BREAKPOINTS.md,
        lg: width >= BREAKPOINTS.lg,
        xl: width >= BREAKPOINTS.xl,
        '2xl': width >= BREAKPOINTS['2xl'],
      })
    }

    // Set initial size
    updateSize()

    // Add event listener
    window.addEventListener('resize', updateSize)

    // Cleanup
    return () => window.removeEventListener('resize', updateSize)
  }, [])

  /**
   * Check if current screen is at or above a specific breakpoint
   */
  const isAbove = (breakpoint: Breakpoint): boolean => {
    return breakpoints[breakpoint]
  }

  /**
   * Check if current screen is below a specific breakpoint
   */
  const isBelow = (breakpoint: Breakpoint): boolean => {
    return !breakpoints[breakpoint]
  }

  /**
   * Check if current screen is between two breakpoints
   */
  const isBetween = (min: Breakpoint, max: Breakpoint): boolean => {
    return breakpoints[min] && !breakpoints[max]
  }

  /**
   * Get the current active breakpoint (largest one that matches)
   */
  const getCurrentBreakpoint = (): Breakpoint | null => {
    if (breakpoints['2xl']) return '2xl'
    if (breakpoints.xl) return 'xl'
    if (breakpoints.lg) return 'lg'
    if (breakpoints.md) return 'md'
    if (breakpoints.sm) return 'sm'
    return null // No breakpoint active (below sm)
  }

  /**
   * Utility functions for common responsive patterns
   */
  const isMobile = isBelow('md')
  const isTablet = isBetween('md', 'lg')
  const isDesktop = isAbove('lg')
  const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0

  return {
    // Breakpoint states
    breakpoints,
    windowSize,

    // Utility functions
    isAbove,
    isBelow,
    isBetween,
    getCurrentBreakpoint,

    // Common patterns
    isMobile,
    isTablet,
    isDesktop,
    isTouchDevice,
  }
}

/**
 * Hook for getting responsive values based on current breakpoint
 *
 * @param values Object with breakpoint keys and corresponding values
 * @param defaultValue Fallback value if no breakpoint matches
 * @returns The value for the current breakpoint
 */
export function useResponsiveValue<T>(
  values: Partial<Record<Breakpoint | 'base', T>>,
  defaultValue: T
): T {
  const { getCurrentBreakpoint } = useResponsive()
  const currentBreakpoint = getCurrentBreakpoint()

  // If no breakpoint is active, check base first
  if (currentBreakpoint === null) {
    return values.base !== undefined ? (values.base as T) : defaultValue
  }

  // Check current breakpoint first, then fall back to smaller ones
  if (values[currentBreakpoint] !== undefined) {
    return values[currentBreakpoint] as T
  }

  // Fall back to smaller breakpoints
  const breakpointOrder: (Breakpoint | 'base')[] = ['2xl', 'xl', 'lg', 'md', 'sm', 'base']
  const currentIndex = breakpointOrder.indexOf(currentBreakpoint)

  // Check from current breakpoint down to base
  for (let i = currentIndex + 1; i < breakpointOrder.length; i++) {
    const bp = breakpointOrder[i]
    if (values[bp] !== undefined) {
      return values[bp] as T
    }
  }

  return defaultValue
}
