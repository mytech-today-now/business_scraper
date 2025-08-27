/**
 * Performance monitoring tests
 * Tests for Prometheus metrics collection and performance monitoring
 */

import { metrics } from '@/lib/metrics'
import { register } from 'prom-client'

describe('Performance Metrics', () => {
  beforeEach(async () => {
    // Clear metrics before each test
    register.clear()
    await metrics.initialize()
  })

  afterEach(() => {
    register.clear()
  })

  describe('Metrics Initialization', () => {
    it('should initialize metrics collector successfully', async () => {
      await metrics.initialize()
      expect(metrics).toBeDefined()
    })

    it('should register all required metrics', async () => {
      await metrics.initialize()
      const metricsString = await metrics.getMetrics()

      // Check for key metrics
      expect(metricsString).toContain('http_request_duration_seconds')
      expect(metricsString).toContain('http_requests_total')
      expect(metricsString).toContain('db_query_duration_seconds')
      expect(metricsString).toContain('scraping_duration_seconds')
      expect(metricsString).toContain('cache_hits_total')
      expect(metricsString).toContain('memory_usage_bytes')
    })
  })

  describe('HTTP Metrics', () => {
    it('should record HTTP request metrics', async () => {
      const labels = { method: 'GET', route: '/api/test', status_code: '200' }

      metrics.httpRequestTotal.inc(labels)
      metrics.httpRequestDuration.observe(labels, 0.5)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('http_requests_total')
      expect(metricsString).toContain('method="GET"')
      expect(metricsString).toContain('route="/api/test"')
    })

    it('should record HTTP error metrics', async () => {
      const labels = { method: 'POST', route: '/api/scrape', error_type: 'server_error' }

      metrics.httpRequestErrors.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('http_request_errors_total')
      expect(metricsString).toContain('error_type="server_error"')
    })
  })

  describe('Database Metrics', () => {
    it('should record database query metrics', async () => {
      const labels = { operation: 'SELECT', table: 'businesses', status: 'success' }

      metrics.dbQueryTotal.inc(labels)
      metrics.dbQueryDuration.observe(labels, 0.1)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('db_queries_total')
      expect(metricsString).toContain('operation="SELECT"')
      expect(metricsString).toContain('table="businesses"')
    })

    it('should record database connection metrics', async () => {
      metrics.dbConnectionsActive.set({ pool: 'main' }, 5)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('db_connections_active')
      expect(metricsString).toContain('pool="main"')
    })
  })

  describe('Scraping Metrics', () => {
    it('should record scraping operation metrics', async () => {
      const labels = { strategy: 'website', status: 'success' }

      metrics.scrapingTotal.inc(labels)
      metrics.scrapingDuration.observe({ ...labels, url: 'example.com' }, 5.0)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('scraping_operations_total')
      expect(metricsString).toContain('strategy="website"')
    })

    it('should record businesses found metrics', async () => {
      const labels = { strategy: 'website', industry: 'technology' }

      metrics.businessesFound.inc(labels, 10)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('businesses_found_total')
      expect(metricsString).toContain('industry="technology"')
    })
  })

  describe('Cache Metrics', () => {
    it('should record cache hit metrics', async () => {
      const labels = { cache_type: 'redis', key_prefix: 'business' }

      metrics.cacheHits.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('cache_hits_total')
      expect(metricsString).toContain('cache_type="redis"')
    })

    it('should record cache miss metrics', async () => {
      const labels = { cache_type: 'memory', key_prefix: 'search' }

      metrics.cacheMisses.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('cache_misses_total')
      expect(metricsString).toContain('cache_type="memory"')
    })

    it('should record cache operation duration', async () => {
      const labels = { operation: 'get', cache_type: 'redis' }

      metrics.cacheOperationDuration.observe(labels, 0.01)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('cache_operation_duration_seconds')
    })
  })

  describe('System Metrics', () => {
    it('should record memory usage metrics', async () => {
      metrics.memoryUsage.set({ type: 'heapUsed' }, 100000000)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('memory_usage_bytes')
      expect(metricsString).toContain('type="heapUsed"')
    })

    it('should record CPU usage metrics', async () => {
      metrics.cpuUsage.set({ core: 'user' }, 45.5)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('cpu_usage_percent')
      expect(metricsString).toContain('core="user"')
    })
  })

  describe('Business Logic Metrics', () => {
    it('should record search operation metrics', async () => {
      const labels = { provider: 'google', status: 'success' }

      metrics.searchOperations.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('search_operations_total')
      expect(metricsString).toContain('provider="google"')
    })

    it('should record export operation metrics', async () => {
      const labels = { format: 'csv', status: 'success' }

      metrics.exportOperations.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('export_operations_total')
      expect(metricsString).toContain('format="csv"')
    })

    it('should record validation error metrics', async () => {
      const labels = { field: 'email', error_type: 'invalid_format' }

      metrics.validationErrors.inc(labels)

      const metricsString = await metrics.getMetrics()
      expect(metricsString).toContain('validation_errors_total')
      expect(metricsString).toContain('field="email"')
    })
  })

  describe('Metrics Export', () => {
    it('should export metrics in Prometheus format', async () => {
      // Add some test metrics
      metrics.httpRequestTotal.inc({ method: 'GET', route: '/test', status_code: '200' })
      metrics.dbQueryTotal.inc({ operation: 'SELECT', table: 'test', status: 'success' })

      const metricsString = await metrics.getMetrics()

      // Check Prometheus format
      expect(metricsString).toContain('# HELP')
      expect(metricsString).toContain('# TYPE')
      expect(metricsString).toMatch(/\w+\{.*\}\s+\d+/)
    })

    it('should handle metrics clearing', () => {
      metrics.clear()
      expect(() => metrics.getMetrics()).not.toThrow()
    })
  })
})
