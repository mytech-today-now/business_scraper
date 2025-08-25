'use strict'

import { register, collectDefaultMetrics, Counter, Histogram, Gauge, Summary } from 'prom-client'
import { logger } from '@/utils/logger'

/**
 * Prometheus metrics collection for performance monitoring
 */
export class MetricsCollector {
  private static instance: MetricsCollector
  private initialized = false

  // API Metrics
  public readonly httpRequestDuration: Histogram<string>
  public readonly httpRequestTotal: Counter<string>
  public readonly httpRequestErrors: Counter<string>

  // Database Metrics
  public readonly dbQueryDuration: Histogram<string>
  public readonly dbConnectionsActive: Gauge<string>
  public readonly dbQueryTotal: Counter<string>
  public readonly dbQueryErrors: Counter<string>

  // Scraping Metrics
  public readonly scrapingDuration: Histogram<string>
  public readonly scrapingTotal: Counter<string>
  public readonly scrapingErrors: Counter<string>
  public readonly businessesFound: Counter<string>
  public readonly pagesScraped: Counter<string>

  // Cache Metrics
  public readonly cacheHits: Counter<string>
  public readonly cacheMisses: Counter<string>
  public readonly cacheOperationDuration: Histogram<string>

  // Memory and System Metrics
  public readonly memoryUsage: Gauge<string>
  public readonly cpuUsage: Gauge<string>
  public readonly activeConnections: Gauge<string>

  // Business Logic Metrics
  public readonly searchOperations: Counter<string>
  public readonly exportOperations: Counter<string>
  public readonly validationErrors: Counter<string>

  private constructor() {
    // HTTP Request Metrics
    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30]
    })

    this.httpRequestTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code']
    })

    this.httpRequestErrors = new Counter({
      name: 'http_request_errors_total',
      help: 'Total number of HTTP request errors',
      labelNames: ['method', 'route', 'error_type']
    })

    // Database Metrics
    this.dbQueryDuration = new Histogram({
      name: 'db_query_duration_seconds',
      help: 'Duration of database queries in seconds',
      labelNames: ['operation', 'table', 'status'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
    })

    this.dbConnectionsActive = new Gauge({
      name: 'db_connections_active',
      help: 'Number of active database connections',
      labelNames: ['pool']
    })

    this.dbQueryTotal = new Counter({
      name: 'db_queries_total',
      help: 'Total number of database queries',
      labelNames: ['operation', 'table', 'status']
    })

    this.dbQueryErrors = new Counter({
      name: 'db_query_errors_total',
      help: 'Total number of database query errors',
      labelNames: ['operation', 'table', 'error_type']
    })

    // Scraping Metrics
    this.scrapingDuration = new Histogram({
      name: 'scraping_duration_seconds',
      help: 'Duration of scraping operations in seconds',
      labelNames: ['url', 'strategy', 'status'],
      buckets: [1, 5, 10, 30, 60, 120, 300]
    })

    this.scrapingTotal = new Counter({
      name: 'scraping_operations_total',
      help: 'Total number of scraping operations',
      labelNames: ['strategy', 'status']
    })

    this.scrapingErrors = new Counter({
      name: 'scraping_errors_total',
      help: 'Total number of scraping errors',
      labelNames: ['strategy', 'error_type']
    })

    this.businessesFound = new Counter({
      name: 'businesses_found_total',
      help: 'Total number of businesses found during scraping',
      labelNames: ['strategy', 'industry']
    })

    this.pagesScraped = new Counter({
      name: 'pages_scraped_total',
      help: 'Total number of pages scraped',
      labelNames: ['strategy', 'domain']
    })

    // Cache Metrics
    this.cacheHits = new Counter({
      name: 'cache_hits_total',
      help: 'Total number of cache hits',
      labelNames: ['cache_type', 'key_prefix']
    })

    this.cacheMisses = new Counter({
      name: 'cache_misses_total',
      help: 'Total number of cache misses',
      labelNames: ['cache_type', 'key_prefix']
    })

    this.cacheOperationDuration = new Histogram({
      name: 'cache_operation_duration_seconds',
      help: 'Duration of cache operations in seconds',
      labelNames: ['operation', 'cache_type'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
    })

    // System Metrics
    this.memoryUsage = new Gauge({
      name: 'memory_usage_bytes',
      help: 'Memory usage in bytes',
      labelNames: ['type']
    })

    this.cpuUsage = new Gauge({
      name: 'cpu_usage_percent',
      help: 'CPU usage percentage',
      labelNames: ['core']
    })

    this.activeConnections = new Gauge({
      name: 'active_connections',
      help: 'Number of active connections',
      labelNames: ['type']
    })

    // Business Logic Metrics
    this.searchOperations = new Counter({
      name: 'search_operations_total',
      help: 'Total number of search operations',
      labelNames: ['provider', 'status']
    })

    this.exportOperations = new Counter({
      name: 'export_operations_total',
      help: 'Total number of export operations',
      labelNames: ['format', 'status']
    })

    this.validationErrors = new Counter({
      name: 'validation_errors_total',
      help: 'Total number of validation errors',
      labelNames: ['field', 'error_type']
    })
  }

  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector()
    }
    return MetricsCollector.instance
  }

  /**
   * Initialize metrics collection
   */
  public async initialize(): Promise<void> {
    if (this.initialized) {
      return
    }

    try {
      // Register all metrics
      register.registerMetric(this.httpRequestDuration)
      register.registerMetric(this.httpRequestTotal)
      register.registerMetric(this.httpRequestErrors)
      register.registerMetric(this.dbQueryDuration)
      register.registerMetric(this.dbConnectionsActive)
      register.registerMetric(this.dbQueryTotal)
      register.registerMetric(this.dbQueryErrors)
      register.registerMetric(this.scrapingDuration)
      register.registerMetric(this.scrapingTotal)
      register.registerMetric(this.scrapingErrors)
      register.registerMetric(this.businessesFound)
      register.registerMetric(this.pagesScraped)
      register.registerMetric(this.cacheHits)
      register.registerMetric(this.cacheMisses)
      register.registerMetric(this.cacheOperationDuration)
      register.registerMetric(this.memoryUsage)
      register.registerMetric(this.cpuUsage)
      register.registerMetric(this.activeConnections)
      register.registerMetric(this.searchOperations)
      register.registerMetric(this.exportOperations)
      register.registerMetric(this.validationErrors)

      // Collect default metrics (CPU, memory, etc.)
      collectDefaultMetrics({ register })

      // Start system metrics collection
      this.startSystemMetricsCollection()

      this.initialized = true
      logger.info('Metrics', 'Prometheus metrics collector initialized successfully')
    } catch (error) {
      logger.error('Metrics', 'Failed to initialize metrics collector', error)
      throw error
    }
  }

  /**
   * Get metrics in Prometheus format
   */
  public async getMetrics(): Promise<string> {
    return register.metrics()
  }

  /**
   * Clear all metrics
   */
  public clear(): void {
    register.clear()
    this.initialized = false
  }

  /**
   * Start collecting system metrics
   */
  private startSystemMetricsCollection(): void {
    // Collect memory usage every 30 seconds
    setInterval(() => {
      if (typeof process !== 'undefined' && process.memoryUsage) {
        const memUsage = process.memoryUsage()
        this.memoryUsage.set({ type: 'rss' }, memUsage.rss)
        this.memoryUsage.set({ type: 'heapUsed' }, memUsage.heapUsed)
        this.memoryUsage.set({ type: 'heapTotal' }, memUsage.heapTotal)
        this.memoryUsage.set({ type: 'external' }, memUsage.external)
      }
    }, 30000)

    // Collect CPU usage every 60 seconds
    setInterval(() => {
      if (typeof process !== 'undefined' && process.cpuUsage) {
        const cpuUsage = process.cpuUsage()
        this.cpuUsage.set({ core: 'user' }, cpuUsage.user / 1000000) // Convert to seconds
        this.cpuUsage.set({ core: 'system' }, cpuUsage.system / 1000000)
      }
    }, 60000)
  }
}

// Export singleton instance
export const metrics = MetricsCollector.getInstance()

/**
 * Decorator for measuring function execution time
 */
export function measureExecutionTime(
  histogram: Histogram<string>,
  labels: Record<string, string>
) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value

    descriptor.value = async function (...args: any[]) {
      const end = histogram.startTimer(labels)
      try {
        const result = await method.apply(this, args)
        end({ status: 'success' })
        return result
      } catch (error) {
        end({ status: 'error' })
        throw error
      }
    }

    return descriptor
  }
}

/**
 * Middleware for measuring HTTP request metrics
 */
export function createHttpMetricsMiddleware() {
  return (req: any, res: any, next: any) => {
    const start = Date.now()
    
    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000
      const labels = {
        method: req.method,
        route: req.route?.path || req.path || 'unknown',
        status_code: res.statusCode.toString()
      }

      metrics.httpRequestDuration.observe(labels, duration)
      metrics.httpRequestTotal.inc(labels)

      if (res.statusCode >= 400) {
        metrics.httpRequestErrors.inc({
          method: req.method,
          route: labels.route,
          error_type: res.statusCode >= 500 ? 'server_error' : 'client_error'
        })
      }
    })

    next()
  }
}
