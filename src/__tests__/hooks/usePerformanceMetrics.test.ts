import { renderHook, act } from '@testing-library/react'
import { usePerformanceMetrics } from '@/hooks/usePerformanceMetrics'

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock performance API
const mockPerformance = {
  now: jest.fn(() => Date.now()),
  memory: {
    usedJSHeapSize: 50 * 1024 * 1024, // 50MB
  },
}

Object.defineProperty(global, 'performance', {
  value: mockPerformance,
  writable: true,
})

describe('usePerformanceMetrics', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
    mockPerformance.now.mockReturnValue(1000)
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('initializes with default metrics', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    expect(result.current.metrics).toEqual({
      renderTime: 0,
      memoryUsage: 0,
      scrollEvents: 0,
      lastRenderTime: 0,
      averageRenderTime: 0,
      peakMemoryUsage: 0,
      totalScrollEvents: 0,
      frameRate: 0,
      isPerformanceGood: true,
    })
  })

  it('measures render time correctly', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    act(() => {
      result.current.startRenderMeasurement()
    })

    // Simulate time passing
    mockPerformance.now.mockReturnValue(1016) // 16ms later

    act(() => {
      result.current.endRenderMeasurement()
    })

    expect(result.current.metrics.renderTime).toBe(16)
    expect(result.current.metrics.lastRenderTime).toBe(16)
    expect(result.current.metrics.averageRenderTime).toBe(16)
  })

  it('calculates average render time correctly', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    // First render
    act(() => {
      result.current.startRenderMeasurement()
    })
    mockPerformance.now.mockReturnValue(1010)
    act(() => {
      result.current.endRenderMeasurement()
    })

    // Second render
    act(() => {
      result.current.startRenderMeasurement()
    })
    mockPerformance.now.mockReturnValue(1030)
    act(() => {
      result.current.endRenderMeasurement()
    })

    expect(result.current.metrics.averageRenderTime).toBe(15) // (10 + 20) / 2
  })

  it('tracks scroll events', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    act(() => {
      result.current.trackScrollEvent()
    })

    expect(result.current.metrics.scrollEvents).toBe(1)
    expect(result.current.metrics.totalScrollEvents).toBe(1)

    act(() => {
      result.current.trackScrollEvent()
    })

    expect(result.current.metrics.scrollEvents).toBe(2)
    expect(result.current.metrics.totalScrollEvents).toBe(2)
  })

  it('updates memory usage periodically', async () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    // Fast-forward time to trigger memory update
    act(() => {
      jest.advanceTimersByTime(1000)
    })

    expect(result.current.metrics.memoryUsage).toBe(50 * 1024 * 1024)
  })

  it('tracks peak memory usage', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    // Initial memory usage
    act(() => {
      jest.advanceTimersByTime(1000)
    })

    const initialMemory = result.current.metrics.memoryUsage

    // Increase memory usage
    mockPerformance.memory.usedJSHeapSize = 100 * 1024 * 1024 // 100MB

    act(() => {
      jest.advanceTimersByTime(1000)
    })

    expect(result.current.metrics.peakMemoryUsage).toBeGreaterThan(initialMemory)
  })

  it('warns when render time exceeds threshold', () => {
    const { logger } = require('@/utils/logger')
    const { result } = renderHook(() => 
      usePerformanceMetrics('TestComponent', { maxRenderTime: 10, maxMemoryUsage: 100 * 1024 * 1024, minFrameRate: 30 })
    )

    act(() => {
      result.current.startRenderMeasurement()
    })

    // Simulate slow render (20ms > 10ms threshold)
    mockPerformance.now.mockReturnValue(1020)

    act(() => {
      result.current.endRenderMeasurement()
    })

    expect(logger.warn).toHaveBeenCalledWith(
      'TestComponent render time exceeded threshold',
      expect.objectContaining({
        renderTime: 20,
        threshold: 10,
        componentName: 'TestComponent',
      })
    )
  })

  it('warns when memory usage exceeds threshold', () => {
    const { logger } = require('@/utils/logger')
    const lowMemoryThreshold = 10 * 1024 * 1024 // 10MB
    
    renderHook(() => 
      usePerformanceMetrics('TestComponent', { 
        maxRenderTime: 16, 
        maxMemoryUsage: lowMemoryThreshold, 
        minFrameRate: 30 
      })
    )

    act(() => {
      jest.advanceTimersByTime(1000)
    })

    expect(logger.warn).toHaveBeenCalledWith(
      'TestComponent memory usage exceeded threshold',
      expect.objectContaining({
        memoryUsage: 50 * 1024 * 1024,
        threshold: lowMemoryThreshold,
        componentName: 'TestComponent',
      })
    )
  })

  it('resets metrics correctly', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    // Add some metrics
    act(() => {
      result.current.trackScrollEvent()
      result.current.startRenderMeasurement()
    })
    mockPerformance.now.mockReturnValue(1016)
    act(() => {
      result.current.endRenderMeasurement()
    })

    // Reset metrics
    act(() => {
      result.current.resetMetrics()
    })

    expect(result.current.metrics).toEqual({
      renderTime: 0,
      memoryUsage: 0,
      scrollEvents: 0,
      lastRenderTime: 0,
      averageRenderTime: 0,
      peakMemoryUsage: 0,
      totalScrollEvents: 0,
      frameRate: 0,
      isPerformanceGood: true,
    })
  })

  it('provides performance summary', () => {
    const { result } = renderHook(() => usePerformanceMetrics('TestComponent'))

    const summary = result.current.getPerformanceSummary()

    expect(summary).toEqual({
      componentName: 'TestComponent',
      metrics: result.current.metrics,
      thresholds: result.current.thresholds,
      timestamp: expect.any(String),
    })
  })

  it('determines performance status correctly', () => {
    const { result } = renderHook(() => 
      usePerformanceMetrics('TestComponent', { 
        maxRenderTime: 16, 
        maxMemoryUsage: 100 * 1024 * 1024, 
        minFrameRate: 30 
      })
    )

    // Good performance
    act(() => {
      result.current.startRenderMeasurement()
    })
    mockPerformance.now.mockReturnValue(1010) // 10ms render time
    act(() => {
      result.current.endRenderMeasurement()
    })

    // Fast-forward to update frame rate and status
    act(() => {
      jest.advanceTimersByTime(500)
    })

    expect(result.current.metrics.isPerformanceGood).toBe(true)

    // Bad performance - slow render
    act(() => {
      result.current.startRenderMeasurement()
    })
    mockPerformance.now.mockReturnValue(1050) // 40ms render time (exceeds 16ms threshold)
    act(() => {
      result.current.endRenderMeasurement()
    })

    act(() => {
      jest.advanceTimersByTime(500)
    })

    expect(result.current.metrics.isPerformanceGood).toBe(false)
  })

  it('handles missing performance.memory gracefully', () => {
    const originalMemory = mockPerformance.memory
    delete (mockPerformance as any).memory

    const { result } = renderHook(() => usePerformanceMetrics())

    act(() => {
      jest.advanceTimersByTime(1000)
    })

    expect(result.current.metrics.memoryUsage).toBe(0)

    // Restore memory
    mockPerformance.memory = originalMemory
  })

  it('logs performance summary in development mode', () => {
    const originalEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'development'
    
    const { logger } = require('@/utils/logger')
    
    renderHook(() => usePerformanceMetrics('TestComponent'))

    act(() => {
      jest.advanceTimersByTime(10000) // 10 seconds
    })

    expect(logger.info).toHaveBeenCalledWith(
      'Performance metrics for TestComponent',
      expect.any(Object)
    )

    process.env.NODE_ENV = originalEnv
  })

  it('limits render time history to 100 entries', () => {
    const { result } = renderHook(() => usePerformanceMetrics())

    // Add 150 render measurements
    for (let i = 0; i < 150; i++) {
      act(() => {
        result.current.startRenderMeasurement()
      })
      mockPerformance.now.mockReturnValue(1000 + (i + 1) * 10)
      act(() => {
        result.current.endRenderMeasurement()
      })
    }

    // The average should be calculated from the last 100 measurements only
    // Last 100 measurements: 510ms to 1500ms, average = 1005ms
    expect(result.current.metrics.averageRenderTime).toBe(1005)
  })
})
