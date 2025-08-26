/**
 * @jest-environment jsdom
 */

import { renderHook, act } from '@testing-library/react'
import { useResponsive, useResponsiveValue, BREAKPOINTS } from '@/hooks/useResponsive'

// Mock window.innerWidth and window.innerHeight
const mockWindowSize = (width: number, height: number = 800) => {
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: width,
  })
  Object.defineProperty(window, 'innerHeight', {
    writable: true,
    configurable: true,
    value: height,
  })
}

// Mock touch support
const mockTouchSupport = (hasTouch: boolean) => {
  Object.defineProperty(window, 'ontouchstart', {
    writable: true,
    configurable: true,
    value: hasTouch ? {} : undefined,
  })
  
  Object.defineProperty(navigator, 'maxTouchPoints', {
    writable: true,
    configurable: true,
    value: hasTouch ? 5 : 0,
  })
}

describe('useResponsive', () => {
  beforeEach(() => {
    // Reset to default desktop size
    mockWindowSize(1024, 768)
    mockTouchSupport(false)
  })

  afterEach(() => {
    // Clean up event listeners
    window.removeEventListener('resize', jest.fn())
  })

  describe('breakpoint detection', () => {
    it('should detect mobile breakpoint correctly', () => {
      mockWindowSize(500) // Below sm (640px)
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.breakpoints.sm).toBe(false)
      expect(result.current.breakpoints.md).toBe(false)
      expect(result.current.breakpoints.lg).toBe(false)
      expect(result.current.isMobile).toBe(true)
      expect(result.current.isTablet).toBe(false)
      expect(result.current.isDesktop).toBe(false)
    })

    it('should detect tablet breakpoint correctly', () => {
      mockWindowSize(800) // Between md (768px) and lg (1024px)
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.breakpoints.sm).toBe(true)
      expect(result.current.breakpoints.md).toBe(true)
      expect(result.current.breakpoints.lg).toBe(false)
      expect(result.current.isMobile).toBe(false)
      expect(result.current.isTablet).toBe(true)
      expect(result.current.isDesktop).toBe(false)
    })

    it('should detect desktop breakpoint correctly', () => {
      mockWindowSize(1200) // Above lg (1024px)
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.breakpoints.sm).toBe(true)
      expect(result.current.breakpoints.md).toBe(true)
      expect(result.current.breakpoints.lg).toBe(true)
      expect(result.current.isMobile).toBe(false)
      expect(result.current.isTablet).toBe(false)
      expect(result.current.isDesktop).toBe(true)
    })

    it('should detect touch device correctly', () => {
      mockTouchSupport(true)
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.isTouchDevice).toBe(true)
    })
  })

  describe('utility functions', () => {
    it('should correctly identify breakpoint states', () => {
      mockWindowSize(800) // md breakpoint
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.isAbove('sm')).toBe(true)
      expect(result.current.isAbove('md')).toBe(true)
      expect(result.current.isAbove('lg')).toBe(false)
      
      expect(result.current.isBelow('sm')).toBe(false)
      expect(result.current.isBelow('md')).toBe(false)
      expect(result.current.isBelow('lg')).toBe(true)
      
      expect(result.current.isBetween('md', 'lg')).toBe(true)
      expect(result.current.isBetween('sm', 'md')).toBe(false)
    })

    it('should return correct current breakpoint', () => {
      mockWindowSize(800) // md breakpoint
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.getCurrentBreakpoint()).toBe('md')
    })
  })

  describe('resize handling', () => {
    it('should update breakpoints on window resize', () => {
      mockWindowSize(500) // Mobile
      
      const { result } = renderHook(() => useResponsive())
      
      expect(result.current.isMobile).toBe(true)
      
      // Simulate resize to desktop
      act(() => {
        mockWindowSize(1200)
        window.dispatchEvent(new Event('resize'))
      })
      
      expect(result.current.isMobile).toBe(false)
      expect(result.current.isDesktop).toBe(true)
    })

    it('should update window size on resize', () => {
      const { result } = renderHook(() => useResponsive())
      
      act(() => {
        mockWindowSize(1200, 900)
        window.dispatchEvent(new Event('resize'))
      })
      
      expect(result.current.windowSize.width).toBe(1200)
      expect(result.current.windowSize.height).toBe(900)
    })
  })
})

describe('useResponsiveValue', () => {
  beforeEach(() => {
    mockWindowSize(1024) // Default to lg breakpoint
  })

  it('should return correct value for current breakpoint', () => {
    const values = {
      base: 'base-value',
      sm: 'sm-value',
      md: 'md-value',
      lg: 'lg-value',
    }
    
    const { result } = renderHook(() => 
      useResponsiveValue(values, 'default-value')
    )
    
    expect(result.current).toBe('lg-value')
  })

  it('should fallback to smaller breakpoint if current not defined', () => {
    const values = {
      base: 'base-value',
      sm: 'sm-value',
      // md and lg not defined
    }

    const { result } = renderHook(() =>
      useResponsiveValue(values, 'default-value')
    )

    expect(result.current).toBe('sm-value') // Falls back to sm when lg is active but not defined
  })

  it('should return default value if no breakpoints match', () => {
    const values = {
      xl: 'xl-value', // Only xl defined, but we're at lg
    }
    
    const { result } = renderHook(() => 
      useResponsiveValue(values, 'default-value')
    )
    
    expect(result.current).toBe('default-value')
  })

  it('should update value when breakpoint changes', () => {
    const values = {
      sm: 'mobile-value',
      lg: 'desktop-value',
    }
    
    mockWindowSize(500) // Mobile
    
    const { result } = renderHook(() => 
      useResponsiveValue(values, 'default-value')
    )
    
    expect(result.current).toBe('default-value') // sm not active at 500px (below 640px threshold)
    
    act(() => {
      mockWindowSize(700) // sm active
      window.dispatchEvent(new Event('resize'))
    })
    
    expect(result.current).toBe('mobile-value')
    
    act(() => {
      mockWindowSize(1200) // lg active
      window.dispatchEvent(new Event('resize'))
    })
    
    expect(result.current).toBe('desktop-value')
  })
})

describe('BREAKPOINTS constant', () => {
  it('should have correct breakpoint values', () => {
    expect(BREAKPOINTS.sm).toBe(640)
    expect(BREAKPOINTS.md).toBe(768)
    expect(BREAKPOINTS.lg).toBe(1024)
    expect(BREAKPOINTS.xl).toBe(1280)
    expect(BREAKPOINTS['2xl']).toBe(1536)
  })
})
