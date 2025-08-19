# Performance Monitoring & Optimization Guide

## Overview

With the unlimited results refactor, the application can now handle 1000+ business records. This guide provides monitoring strategies and optimization recommendations to ensure optimal performance.

## 🔍 Performance Monitoring Areas

### 1. Browser Performance

#### Memory Usage Monitoring
```javascript
// Add to browser console for real-time monitoring
setInterval(() => {
  if (performance.memory) {
    console.log('Memory Usage:', {
      used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024) + ' MB',
      total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024) + ' MB',
      limit: Math.round(performance.memory.jsHeapSizeLimit / 1024 / 1024) + ' MB'
    });
  }
}, 5000);
```

#### DOM Performance
- Monitor table rendering time with large datasets
- Check scroll performance with 1000+ rows
- Measure filter/sort operation response times

### 2. Server Performance

#### Key Metrics to Monitor
- **Search Duration**: Time to complete full industry searches
- **Memory Usage**: Server RAM consumption during large scrapes
- **CPU Usage**: Processing load during concurrent operations
- **Response Times**: API endpoint response times

#### Monitoring Commands
```bash
# Monitor server resources
top -p $(pgrep -f "next start")

# Monitor memory usage
ps aux | grep "next start"

# Check port usage
netstat -tulpn | grep :3000
```

### 3. Database Performance (if applicable)

#### Storage Monitoring
- IndexedDB storage size growth
- Query performance with large datasets
- Storage cleanup efficiency

## 📊 Performance Benchmarks

### Expected Performance Targets

#### Search Operations
- **Single Industry Search**: 2-5 minutes for 6 pages
- **Multiple Industries**: 10-20 minutes for 3-4 industries
- **Result Processing**: <1 second per 100 businesses

#### UI Performance
- **Table Rendering**: <2 seconds for 1000 rows
- **Filtering**: <500ms response time
- **Sorting**: <1 second for large datasets
- **Export**: <30 seconds for 1000+ records

#### Memory Usage
- **Browser**: <500MB for 1000 businesses
- **Server**: <1GB RAM during active scraping
- **Storage**: ~1MB per 100 business records

## ⚡ Optimization Strategies

### 1. UI Optimizations

#### Virtual Scrolling Implementation
```typescript
// Consider implementing virtual scrolling for large tables
// Libraries: react-window, react-virtualized
import { FixedSizeList as List } from 'react-window';

const VirtualizedTable = ({ items }) => (
  <List
    height={600}
    itemCount={items.length}
    itemSize={50}
    itemData={items}
  >
    {Row}
  </List>
);
```

#### Lazy Loading Components
```typescript
// Implement lazy loading for heavy components
const ResultsTable = lazy(() => import('./ResultsTable'));
const AdvancedDashboard = lazy(() => import('./AdvancedDashboard'));
```

#### Debounced Filtering
```typescript
// Implement debounced search/filter
const debouncedFilter = useMemo(
  () => debounce((searchTerm) => {
    setFilteredResults(filterResults(allResults, searchTerm));
  }, 300),
  [allResults]
);
```

### 2. Data Management Optimizations

#### Pagination Controls
```typescript
// Add smart pagination for performance mode
const PaginationControls = () => {
  const [performanceMode, setPerformanceMode] = useState(false);
  
  useEffect(() => {
    // Auto-enable pagination for large datasets
    if (results.length > 1000) {
      setPerformanceMode(true);
    }
  }, [results.length]);
  
  return performanceMode ? <PaginatedView /> : <FullView />;
};
```

#### Result Streaming
```typescript
// Stream results as they're found instead of waiting for completion
const useStreamingResults = () => {
  const [results, setResults] = useState([]);
  
  const addResult = useCallback((newResult) => {
    setResults(prev => [...prev, newResult]);
  }, []);
  
  return { results, addResult };
};
```

### 3. Search Optimizations

#### Batch Processing
```typescript
// Process searches in smaller batches
const batchSize = 5; // URLs per batch
const processBatch = async (urls) => {
  const promises = urls.map(url => scrapeWebsite(url));
  return Promise.allSettled(promises);
};
```

#### Caching Strategy
```typescript
// Implement intelligent caching
const searchCache = new Map();
const getCachedResults = (query, location) => {
  const key = `${query}-${location}`;
  return searchCache.get(key);
};
```

## 🚨 Performance Warning System

### Automatic Performance Detection
```typescript
// Add performance monitoring to the application
const PerformanceMonitor = () => {
  const [performanceWarning, setPerformanceWarning] = useState(false);
  
  useEffect(() => {
    const checkPerformance = () => {
      if (performance.memory?.usedJSHeapSize > 500 * 1024 * 1024) {
        setPerformanceWarning(true);
      }
    };
    
    const interval = setInterval(checkPerformance, 10000);
    return () => clearInterval(interval);
  }, []);
  
  if (performanceWarning) {
    return (
      <Alert variant="warning">
        High memory usage detected. Consider enabling pagination mode.
      </Alert>
    );
  }
  
  return null;
};
```

### User Controls
```typescript
// Add performance mode toggle
const PerformanceControls = () => (
  <div className="performance-controls">
    <label>
      <input 
        type="checkbox" 
        onChange={(e) => setPerformanceMode(e.target.checked)}
      />
      Enable Performance Mode (pagination for large datasets)
    </label>
  </div>
);
```

## 📈 Monitoring Dashboard

### Key Performance Indicators (KPIs)

#### Real-time Metrics
- Current memory usage
- Active search operations
- Results processed per minute
- UI response times

#### Historical Metrics
- Average search completion times
- Peak memory usage patterns
- User interaction response times
- Error rates and timeouts

### Implementation Example
```typescript
const PerformanceDashboard = () => {
  const [metrics, setMetrics] = useState({
    memoryUsage: 0,
    searchDuration: 0,
    resultsCount: 0,
    uiResponseTime: 0
  });
  
  useEffect(() => {
    const updateMetrics = () => {
      setMetrics({
        memoryUsage: performance.memory?.usedJSHeapSize || 0,
        searchDuration: getLastSearchDuration(),
        resultsCount: getCurrentResultsCount(),
        uiResponseTime: getAverageResponseTime()
      });
    };
    
    const interval = setInterval(updateMetrics, 5000);
    return () => clearInterval(interval);
  }, []);
  
  return (
    <div className="performance-dashboard">
      <MetricCard title="Memory Usage" value={formatBytes(metrics.memoryUsage)} />
      <MetricCard title="Search Duration" value={formatTime(metrics.searchDuration)} />
      <MetricCard title="Results Count" value={metrics.resultsCount} />
      <MetricCard title="UI Response" value={`${metrics.uiResponseTime}ms`} />
    </div>
  );
};
```

## 🔧 Optimization Implementation Plan

### Phase 1: Immediate Optimizations
1. **Add performance warnings** for large datasets
2. **Implement smart pagination** (auto-enable for 1000+ results)
3. **Add memory monitoring** to detect issues early

### Phase 2: Advanced Optimizations
1. **Virtual scrolling** for large tables
2. **Result streaming** for real-time updates
3. **Intelligent caching** for repeated searches

### Phase 3: Enterprise Optimizations
1. **Worker threads** for heavy processing
2. **Database optimization** for large datasets
3. **CDN integration** for static assets

## 📝 Performance Testing Checklist

### Before Large Searches
- [ ] Monitor baseline memory usage
- [ ] Check available system resources
- [ ] Verify network connectivity

### During Searches
- [ ] Monitor memory growth patterns
- [ ] Check UI responsiveness
- [ ] Verify search progress indicators

### After Searches
- [ ] Measure total completion time
- [ ] Check final memory usage
- [ ] Test UI performance with results
- [ ] Verify export functionality

### Performance Regression Testing
- [ ] Compare with previous performance benchmarks
- [ ] Test with various dataset sizes
- [ ] Verify optimization effectiveness
- [ ] Document any performance degradation

This comprehensive performance monitoring setup ensures that the unlimited results capability maintains excellent user experience while providing tools to optimize performance as needed.
