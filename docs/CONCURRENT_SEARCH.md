# Concurrent Search Implementation

## Overview

The SearchOrchestrator now supports concurrent search execution, allowing multiple search providers to run simultaneously instead of sequentially. This provides significant performance improvements while maintaining full compatibility with existing rate limiting and error handling.

## Performance Benefits

- **3-5x Faster Searches**: Total search time reduced from sum of all providers to maximum time of slowest provider
- **Better Resource Utilization**: Leverages existing browser pool and concurrent capabilities
- **Maintained Rate Limiting**: Respects individual provider rate limits and concurrent request limits

## Configuration

### Default Configuration

```typescript
const defaultConfig = {
  enableConcurrentSearches: true,
  maxConcurrentProviders: 6,
  searchTimeout: 120000 // 2 minutes
}
```

### Updating Configuration

```typescript
import { searchOrchestrator } from '@/lib/searchProviderAbstraction'

// Enable high-performance mode
searchOrchestrator.updateConfig({
  enableConcurrentSearches: true,
  maxConcurrentProviders: 8,
  searchTimeout: 60000
})

// Enable debug mode (sequential)
searchOrchestrator.updateConfig({
  enableConcurrentSearches: false,
  searchTimeout: 180000
})
```

## Usage Examples

### Basic Concurrent Search

```typescript
import { searchOrchestrator } from '@/lib/searchProviderAbstraction'

const searchOptions = {
  query: 'restaurants',
  location: 'New York, NY',
  maxResults: 50
}

// Concurrent search (default)
const results = await searchOrchestrator.searchBusinesses(searchOptions)
```

### Performance Comparison

```typescript
// Measure concurrent performance
const concurrentStart = Date.now()
const concurrentResults = await searchOrchestrator.searchBusinesses(searchOptions)
const concurrentTime = Date.now() - concurrentStart

// Switch to sequential for comparison
searchOrchestrator.updateConfig({ enableConcurrentSearches: false })
const sequentialStart = Date.now()
const sequentialResults = await searchOrchestrator.searchBusinesses(searchOptions)
const sequentialTime = Date.now() - sequentialStart

console.log(`Concurrent: ${concurrentTime}ms, Sequential: ${sequentialTime}ms`)
console.log(`Performance improvement: ${(sequentialTime / concurrentTime).toFixed(1)}x faster`)
```

## Rate Limiting Compliance

The concurrent implementation respects existing rate limiting rules:

- **DuckDuckGo**: 1 concurrent request, 45s min delay
- **Google**: 2 concurrent requests, 12s min delay  
- **Bing**: 3 concurrent requests, 6s min delay
- **BBB**: 1 concurrent request, 20s min delay
- **Yelp**: 2 concurrent requests, 12s min delay

## Error Handling

### Graceful Degradation

```typescript
// Individual provider failures don't affect other providers
const results = await searchOrchestrator.searchBusinesses(searchOptions)
// Results will include data from successful providers only
```

### Timeout Protection

```typescript
// Configure shorter timeout for faster failure detection
searchOrchestrator.updateConfig({
  searchTimeout: 30000 // 30 seconds
})

// Providers that exceed timeout return empty results
const results = await searchOrchestrator.searchBusinesses(searchOptions)
```

## Implementation Details

### Concurrent Execution Flow

1. **SERP Providers**: Google, Bing, DuckDuckGo execute simultaneously
2. **Business Providers**: BBB, Yelp execute simultaneously  
3. **Parallel Groups**: Both groups run concurrently with each other
4. **Result Aggregation**: All results combined and deduplicated
5. **Error Handling**: Failed providers return empty arrays

### Sequential Fallback

```typescript
// For debugging or compatibility
searchOrchestrator.updateConfig({ enableConcurrentSearches: false })

// Providers execute one after another
// Useful for:
// - Debugging individual provider issues
// - Environments with resource constraints
// - Development and testing
```

## Monitoring and Logging

### Performance Metrics

```typescript
// Logs include timing information
// "MockGoogle SERP search completed in 150ms with 5 results"
// "Concurrent search completed: 15 total → 12 unique → 12 final results"
```

### Error Tracking

```typescript
// Failed providers are logged with details
// "MockProvider SERP search failed: Error message"
// "MockProvider search timed out after 30000ms"
```

## Best Practices

### Production Configuration

```typescript
// Recommended production settings
searchOrchestrator.updateConfig({
  enableConcurrentSearches: true,
  maxConcurrentProviders: 6,
  searchTimeout: 120000
})
```

### Development Configuration

```typescript
// Recommended development settings
searchOrchestrator.updateConfig({
  enableConcurrentSearches: false, // Sequential for easier debugging
  maxConcurrentProviders: 3,
  searchTimeout: 180000
})
```

### High-Volume Configuration

```typescript
// For high-volume applications
searchOrchestrator.updateConfig({
  enableConcurrentSearches: true,
  maxConcurrentProviders: 8,
  searchTimeout: 60000
})
```

## Migration Guide

### Existing Code Compatibility

No changes required for existing code. The concurrent implementation is:

- **Backward Compatible**: Existing code works without modification
- **Drop-in Replacement**: Same API, better performance
- **Configurable**: Can be disabled if needed

### Testing Considerations

```typescript
// Test both modes in your test suite
describe('Search functionality', () => {
  it('should work in concurrent mode', async () => {
    searchOrchestrator.updateConfig({ enableConcurrentSearches: true })
    // Test concurrent behavior
  })
  
  it('should work in sequential mode', async () => {
    searchOrchestrator.updateConfig({ enableConcurrentSearches: false })
    // Test sequential behavior
  })
})
```

## Troubleshooting

### Common Issues

1. **Timeouts**: Increase `searchTimeout` if providers are timing out
2. **Rate Limits**: Concurrent execution may hit rate limits faster
3. **Resource Usage**: Monitor browser pool usage with high concurrency

### Debug Mode

```typescript
// Enable sequential mode for debugging
searchOrchestrator.updateConfig({
  enableConcurrentSearches: false,
  searchTimeout: 300000 // 5 minutes for debugging
})
```

## Future Enhancements

- Dynamic concurrency adjustment based on provider performance
- Provider-specific timeout configuration
- Advanced load balancing and circuit breaker patterns
- Real-time performance monitoring and alerting
