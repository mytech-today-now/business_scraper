/**
 * @jest-environment jsdom
 */

import { renderHook, act } from '@testing-library/react'
import { useVirtualScroll, useInfiniteVirtualScroll } from '@/hooks/useVirtualScroll'

// Mock data for testing
const generateMockItems = (count: number) =>
  Array.from({ length: count }, (_, i) => ({ id: i, name: `Item ${i}` }))

// Mock scroll element
const createMockScrollElement = () => {
  const element = document.createElement('div')
  element.scrollTop = 0
  element.scrollTo = jest.fn((options: any) => {
    element.scrollTop = options.top || 0
  })
  return element
}

describe('useVirtualScroll', () => {
  const defaultOptions = {
    itemHeight: 50,
    containerHeight: 300,
    overscan: 2,
  }

  it('should calculate visible items correctly', () => {
    const items = generateMockItems(100)

    const { result } = renderHook(() => useVirtualScroll(items, defaultOptions))

    // With containerHeight 300 and itemHeight 50, we can see 6 items
    // Plus overscan of 2 on each side = 9 items total (0-8)
    expect(result.current.virtualItems).toHaveLength(9)
    expect(result.current.startIndex).toBe(0)
    expect(result.current.endIndex).toBe(8)
    expect(result.current.totalHeight).toBe(5000) // 100 items * 50px
  })

  it('should update visible items when scrolling', () => {
    const items = generateMockItems(100)

    const { result } = renderHook(() => useVirtualScroll(items, defaultOptions))

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    // Simulate scroll to middle
    act(() => {
      mockElement.scrollTop = 1000 // Scroll to item 20 (1000 / 50)
      mockElement.dispatchEvent(new Event('scroll'))
    })

    // Should show items around index 20
    expect(result.current.startIndex).toBe(18) // 20 - 2 (overscan)
    expect(result.current.endIndex).toBe(28) // 20 + 6 (visible) + 2 (overscan)
  })

  it('should provide scroll utilities', () => {
    const items = generateMockItems(100)

    const { result } = renderHook(() => useVirtualScroll(items, defaultOptions))

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    // Test scrollToIndex
    act(() => {
      result.current.scrollToIndex(25)
    })

    expect(mockElement.scrollTo).toHaveBeenCalledWith({
      top: 1250, // 25 * 50
      behavior: 'smooth',
    })

    // Test scrollToTop
    act(() => {
      result.current.scrollToTop()
    })

    expect(mockElement.scrollTo).toHaveBeenCalledWith({
      top: 0,
      behavior: 'smooth',
    })
  })

  it('should handle scrolling state', () => {
    const items = generateMockItems(100)

    const { result } = renderHook(() =>
      useVirtualScroll(items, { ...defaultOptions, scrollThreshold: 100 })
    )

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    expect(result.current.isScrolling).toBe(false)

    // Simulate scroll
    act(() => {
      mockElement.scrollTop = 500
      mockElement.dispatchEvent(new Event('scroll'))
    })

    expect(result.current.isScrolling).toBe(true)

    // Should become false after threshold
    act(() => {
      jest.advanceTimersByTime(150)
    })

    expect(result.current.isScrolling).toBe(false)
  })

  it('should handle empty items array', () => {
    const { result } = renderHook(() => useVirtualScroll([], defaultOptions))

    expect(result.current.virtualItems).toHaveLength(0)
    expect(result.current.totalHeight).toBe(0)
    expect(result.current.startIndex).toBe(0)
    expect(result.current.endIndex).toBe(-1)
  })

  it('should handle items array smaller than container', () => {
    const items = generateMockItems(3) // Only 3 items

    const { result } = renderHook(() => useVirtualScroll(items, defaultOptions))

    expect(result.current.virtualItems).toHaveLength(3)
    expect(result.current.startIndex).toBe(0)
    expect(result.current.endIndex).toBe(2)
  })
})

describe('useInfiniteVirtualScroll', () => {
  const mockLoadMore = jest.fn().mockResolvedValue(undefined)

  const defaultOptions = {
    itemHeight: 50,
    containerHeight: 300,
    loadMore: mockLoadMore,
    hasMore: true,
    isLoading: false,
    threshold: 5,
  }

  beforeEach(() => {
    mockLoadMore.mockClear()
  })

  it('should trigger loadMore when approaching end', () => {
    const items = generateMockItems(20)

    const { result } = renderHook(() => useInfiniteVirtualScroll(items, defaultOptions))

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    // Scroll near the end (within threshold)
    act(() => {
      mockElement.scrollTop = 600 // Near item 12, threshold is 5, so should trigger
      mockElement.dispatchEvent(new Event('scroll'))
    })

    expect(mockLoadMore).toHaveBeenCalled()
  })

  it('should not trigger loadMore when hasMore is false', () => {
    const items = generateMockItems(20)

    const { result } = renderHook(() =>
      useInfiniteVirtualScroll(items, { ...defaultOptions, hasMore: false })
    )

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    // Scroll to end
    act(() => {
      mockElement.scrollTop = 800
      mockElement.dispatchEvent(new Event('scroll'))
    })

    expect(mockLoadMore).not.toHaveBeenCalled()
  })

  it('should not trigger loadMore when already loading', () => {
    const items = generateMockItems(20)

    const { result } = renderHook(() =>
      useInfiniteVirtualScroll(items, { ...defaultOptions, isLoading: true })
    )

    const mockElement = createMockScrollElement()

    act(() => {
      result.current.setScrollElementRef(mockElement)
    })

    // Scroll near end
    act(() => {
      mockElement.scrollTop = 600
      mockElement.dispatchEvent(new Event('scroll'))
    })

    expect(mockLoadMore).not.toHaveBeenCalled()
  })

  it('should expose loading state', () => {
    const items = generateMockItems(20)

    const { result } = renderHook(() =>
      useInfiniteVirtualScroll(items, { ...defaultOptions, isLoading: true })
    )

    expect(result.current.isLoading).toBe(true)
    expect(result.current.hasMore).toBe(true)
  })
})

// Setup and teardown for timers
beforeEach(() => {
  jest.useFakeTimers()
})

afterEach(() => {
  jest.runOnlyPendingTimers()
  jest.useRealTimers()
})
