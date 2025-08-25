# Performance Monitoring & Optimization Setup Guide

This guide provides comprehensive instructions for setting up and using the performance monitoring and optimization system for the Business Scraper application.

## Overview

The Business Scraper application includes a complete performance monitoring stack with:

- **Prometheus** - Metrics collection and storage
- **Grafana** - Visualization and dashboards
- **Alertmanager** - Alert handling and notifications
- **Database Optimization** - Indexes and query optimization
- **Caching Strategy** - Multi-layer caching with monitoring
- **Performance Testing** - Automated validation

## Quick Start

### 1. Prerequisites

Ensure you have the following installed:
- Docker and Docker Compose
- Node.js 18+ and npm
- PostgreSQL 13+ (if using database features)
- Redis 6+ (for caching)

### 2. Install Dependencies

```bash
npm install
```

The performance monitoring dependencies are already included in package.json:
- `prom-client` - Prometheus metrics client
- `express-prometheus-middleware` - HTTP metrics middleware
- `response-time` - Response time measurement

### 3. Start Monitoring Stack

```bash
cd monitoring
docker-compose up -d
```

This starts:
- Prometheus on http://localhost:9090
- Grafana on http://localhost:3001 (admin/admin123)
- Alertmanager on http://localhost:9093
- Node Exporter on http://localhost:9100
- PostgreSQL Exporter on http://localhost:9187
- Redis Exporter on http://localhost:9121

### 4. Start Application

```bash
npm run dev
```

The application will automatically:
- Initialize Prometheus metrics collection
- Start collecting performance data
- Expose metrics at http://localhost:3000/api/metrics

## Metrics Collection

### Available Metrics

#### HTTP Metrics
- `http_request_duration_seconds` - Request response times
- `http_requests_total` - Total HTTP requests
- `http_request_errors_total` - HTTP errors by type

#### Database Metrics
- `db_query_duration_seconds` - Database query times
- `db_connections_active` - Active database connections
- `db_queries_total` - Total database queries
- `db_query_errors_total` - Database errors

#### Scraping Metrics
- `scraping_duration_seconds` - Scraping operation times
- `scraping_operations_total` - Total scraping operations
- `businesses_found_total` - Businesses discovered
- `pages_scraped_total` - Pages processed

#### Cache Metrics
- `cache_hits_total` - Cache hits by type
- `cache_misses_total` - Cache misses by type
- `cache_operation_duration_seconds` - Cache operation times

#### System Metrics
- `memory_usage_bytes` - Memory usage by type
- `cpu_usage_percent` - CPU usage by core
- `active_connections` - Active network connections

### Custom Metrics

Add custom metrics in your code:

```typescript
import { metrics } from '@/lib/metrics'

// Record a custom operation
metrics.searchOperations.inc({ provider: 'google', status: 'success' })

// Record timing
const end = metrics.scrapingDuration.startTimer({ strategy: 'website' })
// ... perform operation
end({ status: 'success' })
```

## Database Optimization

### Applied Optimizations

The system includes comprehensive database optimizations:

#### Indexes Added
- **Campaigns**: status, industry, location, created_at, zip_code
- **Businesses**: campaign_id, name, scraped_at, confidence_score, website
- **Sessions**: campaign_id, status, created_at, updated_at
- **Search Results**: session_id, provider, created_at

#### Composite Indexes
- `campaigns(status, industry)` - Common filtering pattern
- `businesses(campaign_id, scraped_at)` - Campaign timeline queries
- `sessions(campaign_id, status)` - Session management queries

#### Specialized Indexes
- GIN indexes for JSONB fields (address data)
- GIN indexes for array fields (email arrays)
- Trigram indexes for text search (business names)

### Performance Views

Access optimized views for common queries:

```sql
-- Campaign performance overview
SELECT * FROM campaign_performance;

-- Business search with denormalized data
SELECT * FROM business_search WHERE industry = 'technology';
```

### Performance Functions

Use built-in functions for statistics:

```sql
-- Get campaign statistics
SELECT * FROM get_campaign_stats('campaign-uuid');

-- Search businesses by text similarity
SELECT * FROM search_businesses_by_text('restaurant', 50);
```

## Caching Strategy

### Cache Types

The application uses multiple cache layers:

#### Static Assets
- **Max Age**: 1 year
- **Policy**: Public, immutable
- **Files**: Images, fonts, icons

#### JavaScript/CSS
- **Max Age**: 1 day
- **Stale While Revalidate**: 1 hour
- **Policy**: Public

#### API Responses
- **Business Data**: 5 minutes (private)
- **Search Results**: 10 minutes (private)
- **Industry Data**: 1 hour (public)
- **Config Data**: 30 minutes (private)

#### Cache Headers

Automatic cache headers are applied based on request patterns:

```typescript
import { withCacheHeaders } from '@/lib/cache-headers'

export const GET = withCacheHeaders(async (request) => {
  // Your handler logic
  return NextResponse.json(data)
})
```

### Cache Monitoring

Monitor cache performance through metrics:
- Hit/miss rates by cache type
- Operation duration by cache type
- Key prefix categorization

## Grafana Dashboards

### Available Dashboards

#### 1. Application Overview
- HTTP request rates and response times
- Error rates and system health
- Memory and CPU usage
- Active connections

#### 2. Database Performance
- Query rates and response times
- Connection pool usage
- Error rates by operation
- Slow query detection

### Accessing Dashboards

1. Open Grafana at http://localhost:3001
2. Login with admin/admin123
3. Navigate to Dashboards > Browse
4. Select "Business Scraper" folder

### Custom Dashboards

Create custom dashboards using available metrics:

1. Add new dashboard in Grafana
2. Use Prometheus as data source
3. Query metrics like `rate(http_requests_total[5m])`
4. Configure visualization and alerts

## Alerting

### Alert Rules

The system includes comprehensive alerting:

#### Critical Alerts
- Service down (immediate)
- Critical error rate >15% (1 minute)
- Critical memory usage >95% (2 minutes)

#### Warning Alerts
- High error rate >5% (2 minutes)
- High response time >5s (3 minutes)
- High memory usage >85% (5 minutes)
- Database connection pool high (2 minutes)
- Low cache hit rate <70% (10 minutes)

### Alert Configuration

Alerts are configured in `monitoring/prometheus/alert_rules.yml`.

To add custom alerts:

1. Edit alert_rules.yml
2. Add new rule to appropriate group
3. Restart Prometheus: `docker-compose restart prometheus`

### Notification Channels

Configure notification channels in Alertmanager:

1. Edit `monitoring/alertmanager/alertmanager.yml`
2. Add email, Slack, or webhook receivers
3. Restart Alertmanager: `docker-compose restart alertmanager`

## Performance Testing

### Running Tests

```bash
# Run performance tests
npm run test:performance

# Run all tests including performance
npm run test:all
```

### Test Coverage

Performance tests validate:
- Metrics collection accuracy
- Database query performance
- Cache operation efficiency
- HTTP request monitoring
- System resource tracking

### Load Testing

For load testing, use tools like:

```bash
# Install artillery for load testing
npm install -g artillery

# Run load test
artillery quick --count 100 --num 10 http://localhost:3000/api/search
```

## Production Deployment

### Environment Variables

Set these environment variables for production:

```bash
# Monitoring
ENABLE_METRICS=true
PROMETHEUS_ENDPOINT=/api/metrics

# Database optimization
DB_POOL_MIN=5
DB_POOL_MAX=20
DB_POOL_IDLE_TIMEOUT=30000

# Caching
REDIS_URL=redis://localhost:6379
CACHE_TTL_DEFAULT=300
ENABLE_CACHE_HEADERS=true
```

### Security Considerations

1. **Metrics Endpoint**: Restrict access to `/api/metrics`
2. **Grafana**: Change default admin password
3. **Prometheus**: Configure authentication if exposed
4. **Database**: Use connection pooling and read replicas

### Scaling Considerations

1. **Horizontal Scaling**: Use load balancer with session affinity
2. **Database**: Consider read replicas for heavy read workloads
3. **Cache**: Use Redis cluster for high availability
4. **Monitoring**: Use remote storage for long-term metrics

## Troubleshooting

### Common Issues

#### Metrics Not Appearing
1. Check if metrics endpoint is accessible: `curl http://localhost:3000/api/metrics`
2. Verify Prometheus configuration in `prometheus.yml`
3. Check Prometheus targets: http://localhost:9090/targets

#### High Memory Usage
1. Check memory metrics in Grafana
2. Review cache size limits
3. Monitor database connection pool
4. Check for memory leaks in application code

#### Slow Database Queries
1. Review slow query logs
2. Check if indexes are being used: `EXPLAIN ANALYZE`
3. Monitor connection pool usage
4. Consider query optimization

#### Cache Issues
1. Check Redis connectivity
2. Monitor cache hit/miss rates
3. Verify cache TTL settings
4. Review cache key patterns

### Getting Help

1. Check application logs for errors
2. Review Grafana dashboards for anomalies
3. Use Prometheus query interface for custom metrics
4. Monitor alert notifications for system issues

## Best Practices

1. **Regular Monitoring**: Check dashboards daily
2. **Alert Tuning**: Adjust thresholds based on usage patterns
3. **Performance Testing**: Run load tests before deployments
4. **Capacity Planning**: Monitor trends for resource planning
5. **Documentation**: Keep monitoring setup documented and updated
