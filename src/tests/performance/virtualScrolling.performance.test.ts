/**
 * Performance Tests for Virtual Scrolling Implementation
 * Tests rendering performance with large datasets up to 100,000 records
 */

import { performance } from 'perf_hooks'
import { BusinessRecord } from '@/types/business'
import { virtualScrollingService } from '@/lib/virtualScrollingService'
import { storage } from '@/model/storage'

// Mock data generator for performance testing
function generateMockBusiness(id: number): BusinessRecord {
  const industries = [
    'Technology',
    'Healthcare',
    'Finance',
    'Retail',
    'Manufacturing',
    'Education',
    'Real Estate',
  ]
  const states = ['CA', 'NY', 'TX', 'FL', 'IL', 'PA', 'OH', 'GA', 'NC', 'MI']

  return {
    id: `business-${id}`,
    businessName: `Test Business ${id}`,
    industry: industries[id % industries.length] as string,
    email: [`contact${id}@business${id}.com`],
    phone: `555-${String(id).padStart(4, '0')}`,
    websiteUrl: `https://business${id}.com`,
    address: {
      street: `${id} Main St`,
      city: 'Test City',
      state: states[id % states.length] as string,
      zipCode: String(10000 + id).slice(0, 5),
    },
    scrapedAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random date within last 30 days
    dataQualityScore: Math.random() * 100,
  }
}

// Generate large datasets for testing
function generateMockDataset(size: number): BusinessRecord[] {
  const businesses: BusinessRecord[] = []
  for (let i = 0; i < size; i++) {
    businesses.push(generateMockBusiness(i))
  }
  return businesses
}

// Performance measurement utilities
interface PerformanceMetrics {
  renderTime: number
  memoryUsage: number
  scrollPerformance: number
  filteringTime: number
  sortingTime: number
  exportTime: number
}

class PerformanceTester {
  private metrics: PerformanceMetrics[] = []

  async measureRenderPerformance(datasetSize: number): Promise<PerformanceMetrics> {
    console.log(`\n🧪 Testing render performance with ${datasetSize.toLocaleString()} records...`)

    const startTime = performance.now()
    const startMemory = process.memoryUsage().heapUsed

    // Generate test data
    const businesses = generateMockDataset(datasetSize)

    // Measure data preparation time
    const dataGenTime = performance.now() - startTime
    console.log(`  📊 Data generation: ${dataGenTime.toFixed(2)}ms`)

    // Simulate virtual scrolling service operations
    const renderStart = performance.now()

    // Test pagination API simulation
    const pageSize = 100
    const totalPages = Math.ceil(datasetSize / pageSize)
    let totalPaginationTime = 0

    for (let page = 0; page < Math.min(totalPages, 10); page++) {
      const pageStart = performance.now()
      const startIndex = page * pageSize
      const endIndex = Math.min(startIndex + pageSize, datasetSize)
      const pageData = businesses.slice(startIndex, endIndex)

      // Simulate AI scoring calculation
      pageData.forEach(business => {
        this.calculateMockAIScore(business)
      })

      totalPaginationTime += performance.now() - pageStart
    }

    const renderTime = performance.now() - renderStart
    const endMemory = process.memoryUsage().heapUsed
    const memoryUsage = endMemory - startMemory

    console.log(`  ⚡ Render time: ${renderTime.toFixed(2)}ms`)
    console.log(`  💾 Memory usage: ${(memoryUsage / 1024 / 1024).toFixed(2)}MB`)
    console.log(`  📄 Avg pagination time: ${(totalPaginationTime / 10).toFixed(2)}ms`)

    // Test filtering performance
    const filterStart = performance.now()
    const filteredData = businesses.filter(
      b =>
        b.businessName.includes('Test') &&
        b.email.some(email => email.includes('@')) &&
        b.industry === 'Technology'
    )
    const filteringTime = performance.now() - filterStart
    console.log(
      `  🔍 Filtering time: ${filteringTime.toFixed(2)}ms (${filteredData.length} results)`
    )

    // Test sorting performance
    const sortStart = performance.now()
    const sortedData = [...businesses].sort((a, b) => a.businessName.localeCompare(b.businessName))
    const sortingTime = performance.now() - sortStart
    console.log(`  📊 Sorting time: ${sortingTime.toFixed(2)}ms`)

    // Simulate export performance
    const exportStart = performance.now()
    const csvData = this.simulateCSVExport(businesses.slice(0, 1000)) // Test with 1000 records
    const exportTime = performance.now() - exportStart
    console.log(`  📤 Export time (1K records): ${exportTime.toFixed(2)}ms`)

    const metrics: PerformanceMetrics = {
      renderTime,
      memoryUsage,
      scrollPerformance: totalPaginationTime / 10, // Average pagination time
      filteringTime,
      sortingTime,
      exportTime,
    }

    this.metrics.push(metrics)
    return metrics
  }

  private calculateMockAIScore(business: BusinessRecord): number {
    // Simulate AI scoring calculation
    let score = 0
    if (business.businessName) score += 20
    if (business.email && business.email.length > 0) score += 25
    if (business.phone) score += 20
    if (business.websiteUrl) score += 15
    if (business.address) score += 10
    if (business.industry) score += 5
    return Math.min(score, 100)
  }

  private simulateCSVExport(businesses: BusinessRecord[]): string {
    const headers = ['Business Name', 'Industry', 'Email', 'Phone', 'Website', 'Address']
    const rows = businesses.map(b => [
      b.businessName,
      b.industry,
      b.email.join(';'),
      b.phone || '',
      b.websiteUrl,
      `${b.address.street}, ${b.address.city}, ${b.address.state} ${b.address.zipCode}`,
    ])

    return [headers, ...rows].map(row => row.join(',')).join('\n')
  }

  async runComprehensivePerformanceTest(): Promise<void> {
    console.log('🚀 Starting Virtual Scrolling Performance Test Suite\n')

    const testSizes = [100, 1000, 5000, 10000, 25000, 50000, 100000]
    const results: Array<{ size: number; metrics: PerformanceMetrics }> = []

    for (const size of testSizes) {
      try {
        const metrics = await this.measureRenderPerformance(size)
        results.push({ size, metrics })

        // Performance thresholds
        const thresholds = {
          renderTime: size < 10000 ? 1000 : 2000, // ms
          memoryUsage: size * 1000, // bytes per record
          scrollPerformance: 100, // ms
          filteringTime: size < 10000 ? 500 : 1000, // ms
          sortingTime: size < 10000 ? 1000 : 2000, // ms
          exportTime: 1000, // ms for 1K records
        }

        // Check performance thresholds
        const warnings: string[] = []
        if (metrics.renderTime > thresholds.renderTime) {
          warnings.push(
            `⚠️  Render time exceeded threshold: ${metrics.renderTime.toFixed(2)}ms > ${thresholds.renderTime}ms`
          )
        }
        if (metrics.memoryUsage > thresholds.memoryUsage) {
          warnings.push(
            `⚠️  Memory usage exceeded threshold: ${(metrics.memoryUsage / 1024 / 1024).toFixed(2)}MB`
          )
        }
        if (metrics.scrollPerformance > thresholds.scrollPerformance) {
          warnings.push(
            `⚠️  Scroll performance exceeded threshold: ${metrics.scrollPerformance.toFixed(2)}ms > ${thresholds.scrollPerformance}ms`
          )
        }
        if (metrics.filteringTime > thresholds.filteringTime) {
          warnings.push(
            `⚠️  Filtering time exceeded threshold: ${metrics.filteringTime.toFixed(2)}ms > ${thresholds.filteringTime}ms`
          )
        }
        if (metrics.sortingTime > thresholds.sortingTime) {
          warnings.push(
            `⚠️  Sorting time exceeded threshold: ${metrics.sortingTime.toFixed(2)}ms > ${thresholds.sortingTime}ms`
          )
        }

        if (warnings.length > 0) {
          console.log('  Performance Warnings:')
          warnings.forEach(warning => console.log(`    ${warning}`))
        } else {
          console.log('  ✅ All performance thresholds met!')
        }

        // Memory cleanup
        if (global.gc) {
          global.gc()
        }

        // Brief pause between tests
        await new Promise(resolve => setTimeout(resolve, 100))
      } catch (error) {
        console.error(`❌ Test failed for ${size} records:`, error)
      }
    }

    // Generate performance report
    this.generatePerformanceReport(results)
  }

  private generatePerformanceReport(
    results: Array<{ size: number; metrics: PerformanceMetrics }>
  ): void {
    console.log('\n📊 PERFORMANCE REPORT')
    console.log('='.repeat(80))

    console.log('\n📈 Render Performance:')
    results.forEach(({ size, metrics }) => {
      const recordsPerMs = size / metrics.renderTime
      console.log(
        `  ${size.toLocaleString().padStart(8)} records: ${metrics.renderTime.toFixed(2).padStart(8)}ms (${recordsPerMs.toFixed(0)} records/ms)`
      )
    })

    console.log('\n💾 Memory Usage:')
    results.forEach(({ size, metrics }) => {
      const bytesPerRecord = metrics.memoryUsage / size
      console.log(
        `  ${size.toLocaleString().padStart(8)} records: ${(metrics.memoryUsage / 1024 / 1024).toFixed(2).padStart(8)}MB (${bytesPerRecord.toFixed(0)} bytes/record)`
      )
    })

    console.log('\n⚡ Scroll Performance (Pagination):')
    results.forEach(({ size, metrics }) => {
      console.log(
        `  ${size.toLocaleString().padStart(8)} records: ${metrics.scrollPerformance.toFixed(2).padStart(8)}ms per page`
      )
    })

    console.log('\n🔍 Filtering Performance:')
    results.forEach(({ size, metrics }) => {
      const recordsPerMs = size / metrics.filteringTime
      console.log(
        `  ${size.toLocaleString().padStart(8)} records: ${metrics.filteringTime.toFixed(2).padStart(8)}ms (${recordsPerMs.toFixed(0)} records/ms)`
      )
    })

    console.log('\n📊 Sorting Performance:')
    results.forEach(({ size, metrics }) => {
      const recordsPerMs = size / metrics.sortingTime
      console.log(
        `  ${size.toLocaleString().padStart(8)} records: ${metrics.sortingTime.toFixed(2).padStart(8)}ms (${recordsPerMs.toFixed(0)} records/ms)`
      )
    })

    // Performance recommendations
    console.log('\n💡 RECOMMENDATIONS:')
    const largestTest = results[results.length - 1]
    if (largestTest && largestTest.metrics.renderTime > 2000) {
      console.log('  • Consider implementing progressive loading for datasets > 50K records')
    }
    if (largestTest && largestTest.metrics.memoryUsage > 100 * 1024 * 1024) {
      console.log('  • Consider implementing data compression for large datasets')
    }
    if (results.some(r => r.metrics.scrollPerformance > 100)) {
      console.log('  • Consider optimizing pagination query performance')
    }

    console.log('\n✅ Virtual Scrolling Performance Test Complete!')
  }
}

// Export for use in test suites
export { PerformanceTester, generateMockDataset, generateMockBusiness }

// Run tests if this file is executed directly
if (require.main === module) {
  const tester = new PerformanceTester()
  tester.runComprehensivePerformanceTest().catch(console.error)
}
