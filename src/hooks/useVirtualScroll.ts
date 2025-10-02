'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'

export interface VirtualScrollOptions {
  itemHeight: number
  containerHeight: number
  overscan?: number
  scrollThreshold?: number
}

export interface VirtualScrollResult<T> {
  virtualItems: Array<{
    index: number
    item: T
    offsetTop: number
  }>
  totalHeight: number
  scrollToIndex: (index: number) => void
  scrollToTop: () => void
  isScrolling: boolean
  startIndex: number
  endIndex: number
  setScrollElementRef: (element: HTMLElement | null) => void
}

/**
 * Custom hook for virtual scrolling large datasets efficiently
 * Renders only visible items plus overscan buffer for performance
 *
 * @param items Array of items to virtualize
 * @param options Configuration for virtual scrolling
 * @returns Virtual scroll utilities and visible items
 */
export function useVirtualScroll<T>(
  items: T[],
  options: VirtualScrollOptions
): VirtualScrollResult<T> {
  const { itemHeight, containerHeight, overscan = 5, scrollThreshold = 16 } = options

  const [scrollTop, setScrollTop] = useState(0)
  const [isScrolling, setIsScrolling] = useState(false)
  const [scrollElement, setScrollElement] = useState<HTMLElement | null>(null)

  // Calculate visible range
  const { startIndex, endIndex, totalHeight } = useMemo(() => {
    const totalHeight = items.length * itemHeight
    const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan)
    const endIndex = Math.min(
      items.length - 1,
      Math.ceil((scrollTop + containerHeight) / itemHeight) + overscan
    )

    return { startIndex, endIndex, totalHeight }
  }, [items.length, itemHeight, scrollTop, containerHeight, overscan])

  // Generate virtual items for rendering
  const virtualItems = useMemo(() => {
    const result = []
    for (let i = startIndex; i <= endIndex; i++) {
      if (items[i]) {
        result.push({
          index: i,
          item: items[i],
          offsetTop: i * itemHeight,
        })
      }
    }
    return result
  }, [items, startIndex, endIndex, itemHeight])

  // Scroll event handler with throttling
  const handleScroll = useCallback(
    (event: Event) => {
      const target = event.target as HTMLElement
      const newScrollTop = target.scrollTop

      setScrollTop(newScrollTop)
      setIsScrolling(true)

      // Debounce scrolling state
      const timeoutId = setTimeout(() => {
        setIsScrolling(false)
      }, scrollThreshold)

      return () => clearTimeout(timeoutId)
    },
    [scrollThreshold]
  )

  // Attach scroll listener
  useEffect(() => {
    if (!scrollElement) return

    scrollElement.addEventListener('scroll', handleScroll, { passive: true })

    return () => {
      scrollElement.removeEventListener('scroll', handleScroll)
    }
  }, [scrollElement, handleScroll])

  // Scroll to specific index
  const scrollToIndex = useCallback(
    (index: number) => {
      if (!scrollElement) return

      const targetScrollTop = Math.max(0, index * itemHeight)
      scrollElement.scrollTo({
        top: targetScrollTop,
        behavior: 'smooth',
      })
    },
    [scrollElement, itemHeight]
  )

  // Scroll to top
  const scrollToTop = useCallback(() => {
    if (!scrollElement) return

    scrollElement.scrollTo({
      top: 0,
      behavior: 'smooth',
    })
  }, [scrollElement])

  // Ref callback to set scroll element
  const setScrollElementRef = useCallback((element: HTMLElement | null) => {
    setScrollElement(element)
  }, [])

  return {
    virtualItems,
    totalHeight,
    scrollToIndex,
    scrollToTop,
    isScrolling,
    startIndex,
    endIndex,
    setScrollElementRef,
  }
}

/**
 * Hook for infinite scrolling with virtual scrolling
 * Automatically loads more data when approaching the end
 */
export function useInfiniteVirtualScroll<T>(
  items: T[],
  options: VirtualScrollOptions & {
    loadMore: () => Promise<void>
    hasMore: boolean
    isLoading: boolean
    threshold?: number
  }
) {
  const { loadMore, hasMore, isLoading, threshold = 10 } = options
  const virtualScroll = useVirtualScroll(items, options)

  // Check if we need to load more items
  useEffect(() => {
    const { endIndex } = virtualScroll
    const shouldLoadMore = hasMore && !isLoading && endIndex >= items.length - threshold

    if (shouldLoadMore) {
      loadMore()
    }
  }, [virtualScroll.endIndex, items.length, hasMore, isLoading, threshold, loadMore])

  return {
    ...virtualScroll,
    hasMore,
    isLoading,
  }
}

/**
 * Hook for virtual grid scrolling (2D virtualization)
 * Useful for large tables or grid layouts
 */
export function useVirtualGrid<T>(
  items: T[],
  options: {
    itemWidth: number
    itemHeight: number
    containerWidth: number
    containerHeight: number
    columnsCount: number
    overscan?: number
  }
) {
  const {
    itemWidth,
    itemHeight,
    containerWidth,
    containerHeight,
    columnsCount,
    overscan = 5,
  } = options

  const [scrollTop, setScrollTop] = useState(0)
  const [scrollLeft, setScrollLeft] = useState(0)

  const rowCount = Math.ceil(items.length / columnsCount)

  // Calculate visible range
  const { startRowIndex, endRowIndex, startColIndex, endColIndex } = useMemo(() => {
    const startRowIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan)
    const endRowIndex = Math.min(
      rowCount - 1,
      Math.ceil((scrollTop + containerHeight) / itemHeight) + overscan
    )

    const startColIndex = Math.max(0, Math.floor(scrollLeft / itemWidth) - overscan)
    const endColIndex = Math.min(
      columnsCount - 1,
      Math.ceil((scrollLeft + containerWidth) / itemWidth) + overscan
    )

    return { startRowIndex, endRowIndex, startColIndex, endColIndex }
  }, [
    scrollTop,
    scrollLeft,
    itemHeight,
    itemWidth,
    containerHeight,
    containerWidth,
    rowCount,
    columnsCount,
    overscan,
  ])

  // Generate virtual grid items
  const virtualGridItems = useMemo(() => {
    const result = []
    for (let rowIndex = startRowIndex; rowIndex <= endRowIndex; rowIndex++) {
      for (let colIndex = startColIndex; colIndex <= endColIndex; colIndex++) {
        const itemIndex = rowIndex * columnsCount + colIndex
        if (items[itemIndex]) {
          result.push({
            rowIndex,
            colIndex,
            itemIndex,
            item: items[itemIndex],
            offsetTop: rowIndex * itemHeight,
            offsetLeft: colIndex * itemWidth,
          })
        }
      }
    }
    return result
  }, [
    items,
    startRowIndex,
    endRowIndex,
    startColIndex,
    endColIndex,
    columnsCount,
    itemHeight,
    itemWidth,
  ])

  return {
    virtualGridItems,
    totalHeight: rowCount * itemHeight,
    totalWidth: columnsCount * itemWidth,
    setScrollTop,
    setScrollLeft,
  }
}
