/**
 * Unit tests for Performance Monitoring Service
 * Tests performance tracking, metrics recording, and alert generation
 */

import {
  performanceMonitoringService,
  PerformanceMetrics,
  PerformanceAlert,
} from '@/lib/performanceMonitoringService'

// Mock performance API
const mockPerformance = {
  now: jest.fn(() => Date.now()),
  memory: {
    usedJSHeapSize: 50 * 1024 * 1024, // 50MB
  },
}

// Mock window.setInterval and clearInterval
const mockSetInterval = jest.fn()
const mockClearInterval = jest.fn()

// Setup mocks
beforeAll(() => {
  global.performance = mockPerformance as any
  global.setInterval = mockSetInterval
  global.clearInterval = mockClearInterval

  // Mock window object
  Object.defineProperty(window, 'setInterval', {
    value: mockSetInterval,
    writable: true,
  })

  Object.defineProperty(window, 'clearInterval', {
    value: mockClearInterval,
    writable: true,
  })
})

beforeEach(() => {
  // Clear all metrics and alerts before each test
  performanceMonitoringService.clear()
  jest.clearAllMocks()

  // Reset mock return values
  mockPerformance.now.mockReturnValue(Date.now())
})

describe('PerformanceMonitoringService', () => {
  describe('Basic Functionality', () => {
    test('should enable and disable monitoring', () => {
      performanceMonitoringService.setEnabled(true)
      expect(performanceMonitoringService['isEnabled']).toBe(true)

      performanceMonitoringService.setEnabled(false)
      expect(performanceMonitoringService['isEnabled']).toBe(false)
    })

    test('should record performance metrics', () => {
      performanceMonitoringService.setEnabled(true)

      const metric: PerformanceMetrics = {
        renderTime: 10.5,
        scrollPosition: 100,
        visibleItemsCount: 20,
        totalItemsCount: 1000,
        memoryUsage: 50 * 1024 * 1024,
        timestamp: Date.now(),
        componentName: 'TestComponent',
        operation: 'render',
      }

      performanceMonitoringService.recordMetric(metric)

      const metrics = performanceMonitoringService.getMetrics('TestComponent')
      expect(metrics).toHaveLength(1)
      expect(metrics[0]).toMatchObject(metric)
    })

    test('should not record metrics when disabled', () => {
      performanceMonitoringService.setEnabled(false)

      const metric: PerformanceMetrics = {
        renderTime: 10.5,
        scrollPosition: 100,
        visibleItemsCount: 20,
        totalItemsCount: 1000,
        timestamp: Date.now(),
      }

      performanceMonitoringService.recordMetric(metric)

      const metrics = performanceMonitoringService.getMetrics()
      expect(metrics).toHaveLength(0)
    })
  })

  describe('Frame Rate Monitoring', () => {
    test('should start and stop frame rate monitoring', () => {
      const componentName = 'TestComponent'

      performanceMonitoringService.startFrameRateMonitoring(componentName)
      expect(mockSetInterval).toHaveBeenCalledWith(expect.any(Function), 1000)

      performanceMonitoringService.stopFrameRateMonitoring(componentName)
      expect(mockClearInterval).toHaveBeenCalled()
    })

    test('should increment frame count', () => {
      const componentName = 'TestComponent'

      performanceMonitoringService.startFrameRateMonitoring(componentName)

      performanceMonitoringService.incrementFrameCount(componentName)
      performanceMonitoringService.incrementFrameCount(componentName)
      performanceMonitoringService.incrementFrameCount(componentName)

      const frameRate = performanceMonitoringService.getFrameRate(componentName)
      expect(frameRate).toBe(3)
    })

    test('should return 0 frame rate for non-existent component', () => {
      const frameRate = performanceMonitoringService.getFrameRate('NonExistentComponent')
      expect(frameRate).toBe(0)
    })
  })

  describe('Performance Alerts', () => {
    test('should create alert for slow render time', () => {
      performanceMonitoringService.setEnabled(true)

      const slowMetric: PerformanceMetrics = {
        renderTime: 20, // Above 16.67ms threshold
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        componentName: 'SlowComponent',
      }

      performanceMonitoringService.recordMetric(slowMetric)

      const alerts = performanceMonitoringService.getAlerts('SlowComponent')
      expect(alerts).toHaveLength(1)
      expect(alerts[0].type).toBe('critical')
      expect(alerts[0].metric).toBe('renderTime')
      expect(alerts[0].value).toBe(20)
    })

    test('should create alert for low frame rate', () => {
      performanceMonitoringService.setEnabled(true)

      const lowFrameRateMetric: PerformanceMetrics = {
        renderTime: 5,
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        frameRate: 25, // Below 30fps threshold
        componentName: 'LowFrameRateComponent',
      }

      performanceMonitoringService.recordMetric(lowFrameRateMetric)

      const alerts = performanceMonitoringService.getAlerts('LowFrameRateComponent')
      expect(alerts).toHaveLength(1)
      expect(alerts[0].type).toBe('critical')
      expect(alerts[0].metric).toBe('frameRate')
      expect(alerts[0].value).toBe(25)
    })

    test('should create alert for high memory usage', () => {
      performanceMonitoringService.setEnabled(true)

      const highMemoryMetric: PerformanceMetrics = {
        renderTime: 5,
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        memoryUsage: 250 * 1024 * 1024, // 250MB - above critical threshold
        componentName: 'HighMemoryComponent',
      }

      performanceMonitoringService.recordMetric(highMemoryMetric)

      const alerts = performanceMonitoringService.getAlerts('HighMemoryComponent')
      expect(alerts).toHaveLength(1)
      expect(alerts[0].type).toBe('critical')
      expect(alerts[0].metric).toBe('memoryUsage')
      expect(alerts[0].value).toBe(250 * 1024 * 1024)
    })
  })

  describe('Statistics and Performance Score', () => {
    test('should calculate correct statistics', () => {
      performanceMonitoringService.setEnabled(true)

      const metrics: PerformanceMetrics[] = [
        {
          renderTime: 5,
          scrollPosition: 0,
          visibleItemsCount: 10,
          totalItemsCount: 100,
          timestamp: Date.now(),
          frameRate: 60,
          componentName: 'TestComponent',
        },
        {
          renderTime: 10,
          scrollPosition: 100,
          visibleItemsCount: 10,
          totalItemsCount: 100,
          timestamp: Date.now(),
          frameRate: 55,
          componentName: 'TestComponent',
        },
        {
          renderTime: 15,
          scrollPosition: 200,
          visibleItemsCount: 10,
          totalItemsCount: 100,
          timestamp: Date.now(),
          frameRate: 50,
          componentName: 'TestComponent',
        },
      ]

      metrics.forEach(metric => performanceMonitoringService.recordMetric(metric))

      const stats = performanceMonitoringService.getStatistics('TestComponent')

      expect(stats.avgRenderTime).toBe(10) // (5 + 10 + 15) / 3
      expect(stats.maxRenderTime).toBe(15)
      expect(stats.minRenderTime).toBe(5)
      expect(stats.avgFrameRate).toBe(55) // (60 + 55 + 50) / 3
      expect(stats.metricsCount).toBe(3)
    })

    test('should calculate performance score correctly', () => {
      performanceMonitoringService.setEnabled(true)

      // Good performance metrics
      const goodMetric: PerformanceMetrics = {
        renderTime: 5, // Good
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        frameRate: 60, // Good
        memoryUsage: 50 * 1024 * 1024, // Good
        componentName: 'GoodComponent',
      }

      performanceMonitoringService.recordMetric(goodMetric)

      const score = performanceMonitoringService.getPerformanceScore('GoodComponent')
      expect(score).toBe(100) // Perfect score

      // Poor performance metrics
      const poorMetric: PerformanceMetrics = {
        renderTime: 25, // Poor
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        frameRate: 20, // Poor
        memoryUsage: 250 * 1024 * 1024, // Poor
        componentName: 'PoorComponent',
      }

      performanceMonitoringService.recordMetric(poorMetric)

      const poorScore = performanceMonitoringService.getPerformanceScore('PoorComponent')
      expect(poorScore).toBeLessThan(50) // Poor score
    })
  })

  describe('Data Management', () => {
    test('should limit metrics to 1000 entries', () => {
      performanceMonitoringService.setEnabled(true)

      // Add 1100 metrics
      for (let i = 0; i < 1100; i++) {
        const metric: PerformanceMetrics = {
          renderTime: 5,
          scrollPosition: i,
          visibleItemsCount: 10,
          totalItemsCount: 100,
          timestamp: Date.now() + i,
          componentName: 'TestComponent',
        }
        performanceMonitoringService.recordMetric(metric)
      }

      const metrics = performanceMonitoringService.getMetrics('TestComponent')
      expect(metrics).toHaveLength(1000) // Should be limited to 1000
    })

    test('should limit alerts to 100 entries', () => {
      performanceMonitoringService.setEnabled(true)

      // Add 110 slow metrics to generate alerts
      for (let i = 0; i < 110; i++) {
        const metric: PerformanceMetrics = {
          renderTime: 20, // Slow render time
          scrollPosition: i,
          visibleItemsCount: 10,
          totalItemsCount: 100,
          timestamp: Date.now() + i,
          componentName: 'TestComponent',
        }
        performanceMonitoringService.recordMetric(metric)
      }

      const alerts = performanceMonitoringService.getAlerts('TestComponent')
      expect(alerts).toHaveLength(100) // Should be limited to 100
    })

    test('should clear metrics and alerts', () => {
      performanceMonitoringService.setEnabled(true)

      const metric: PerformanceMetrics = {
        renderTime: 20,
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        componentName: 'TestComponent',
      }

      performanceMonitoringService.recordMetric(metric)

      expect(performanceMonitoringService.getMetrics()).toHaveLength(1)
      expect(performanceMonitoringService.getAlerts()).toHaveLength(1)

      performanceMonitoringService.clear()

      expect(performanceMonitoringService.getMetrics()).toHaveLength(0)
      expect(performanceMonitoringService.getAlerts()).toHaveLength(0)
    })

    test('should clear metrics for specific component', () => {
      performanceMonitoringService.setEnabled(true)

      const metric1: PerformanceMetrics = {
        renderTime: 5,
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        componentName: 'Component1',
      }

      const metric2: PerformanceMetrics = {
        renderTime: 5,
        scrollPosition: 0,
        visibleItemsCount: 10,
        totalItemsCount: 100,
        timestamp: Date.now(),
        componentName: 'Component2',
      }

      performanceMonitoringService.recordMetric(metric1)
      performanceMonitoringService.recordMetric(metric2)

      expect(performanceMonitoringService.getMetrics('Component1')).toHaveLength(1)
      expect(performanceMonitoringService.getMetrics('Component2')).toHaveLength(1)

      performanceMonitoringService.clearComponent('Component1')

      expect(performanceMonitoringService.getMetrics('Component1')).toHaveLength(0)
      expect(performanceMonitoringService.getMetrics('Component2')).toHaveLength(1)
    })
  })

  describe('Cleanup', () => {
    test('should cleanup all resources', () => {
      const componentName = 'TestComponent'

      performanceMonitoringService.startFrameRateMonitoring(componentName)
      performanceMonitoringService.cleanup()

      expect(mockClearInterval).toHaveBeenCalled()
    })
  })
})
