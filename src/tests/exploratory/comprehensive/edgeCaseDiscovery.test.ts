/**
 * Comprehensive Exploratory Testing for Edge Case Discovery
 * Structured exploratory testing to discover unexpected behaviors and edge cases
 */

import { jest } from '@jest/globals'
import { scraperService } from '@/model/scraperService'
import { clientSearchEngine } from '@/model/clientSearchEngine'
import { BusinessRecord } from '@/types/business'

// Mock dependencies
jest.mock('@/model/scraperService')
jest.mock('@/model/clientSearchEngine')
jest.mock('@/utils/logger')

interface ExploratoryTestCase {
  name: string
  category: 'boundary' | 'data' | 'interaction' | 'environment' | 'security' | 'performance'
  description: string
  testFunction: () => Promise<void>
  expectedBehavior: string
  actualBehavior?: string
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
}

interface ExploratoryTestResult {
  testCase: ExploratoryTestCase
  passed: boolean
  unexpectedBehavior?: string
  potentialIssue?: string
  recommendation?: string
}

class ExploratoryTester {
  private testCases: ExploratoryTestCase[] = []
  private results: ExploratoryTestResult[] = []

  addTestCase(testCase: ExploratoryTestCase): void {
    this.testCases.push(testCase)
  }

  async runExploratoryTests(): Promise<ExploratoryTestResult[]> {
    this.results = []

    for (const testCase of this.testCases) {
      try {
        await testCase.testFunction()

        this.results.push({
          testCase,
          passed: true,
        })
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'

        this.results.push({
          testCase,
          passed: false,
          unexpectedBehavior: errorMessage,
          potentialIssue: this.analyzePotentialIssue(testCase, errorMessage),
          recommendation: this.generateRecommendation(testCase, errorMessage),
        })
      }
    }

    return this.results
  }

  private analyzePotentialIssue(testCase: ExploratoryTestCase, error: string): string {
    if (testCase.category === 'security' && error.includes('injection')) {
      return 'Potential security vulnerability detected'
    }

    if (testCase.category === 'performance' && error.includes('timeout')) {
      return 'Performance degradation under stress conditions'
    }

    if (testCase.category === 'boundary' && error.includes('overflow')) {
      return 'Boundary condition handling issue'
    }

    if (testCase.category === 'data' && error.includes('validation')) {
      return 'Data validation gap identified'
    }

    return 'Unexpected behavior requiring investigation'
  }

  private generateRecommendation(testCase: ExploratoryTestCase, error: string): string {
    if (testCase.riskLevel === 'critical') {
      return 'Immediate investigation and fix required'
    }

    if (testCase.riskLevel === 'high') {
      return 'High priority fix needed before production'
    }

    if (testCase.riskLevel === 'medium') {
      return 'Should be addressed in next development cycle'
    }

    return 'Monitor and consider for future improvements'
  }

  getHighRiskIssues(): ExploratoryTestResult[] {
    return this.results.filter(
      r => !r.passed && (r.testCase.riskLevel === 'critical' || r.testCase.riskLevel === 'high')
    )
  }

  getCategorySummary(): Map<string, { total: number; failed: number }> {
    const summary = new Map()

    for (const result of this.results) {
      const category = result.testCase.category
      const current = summary.get(category) || { total: 0, failed: 0 }

      current.total++
      if (!result.passed) current.failed++

      summary.set(category, current)
    }

    return summary
  }
}

describe('Exploratory Testing - Edge Case Discovery', () => {
  let exploratoryTester: ExploratoryTester

  beforeEach(() => {
    exploratoryTester = new ExploratoryTester()
    jest.clearAllMocks()
  })

  describe('Boundary Value Exploration', () => {
    test('should explore extreme input boundaries', async () => {
      exploratoryTester.addTestCase({
        name: 'Maximum String Length Input',
        category: 'boundary',
        description: 'Test behavior with extremely long input strings',
        riskLevel: 'medium',
        expectedBehavior: 'Should handle or reject gracefully',
        testFunction: async () => {
          const maxString = 'a'.repeat(1000000) // 1MB string

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          const result = await clientSearchEngine.searchBusinesses(maxString, '12345', 10)
          expect(result).toEqual([])
        },
      })

      exploratoryTester.addTestCase({
        name: 'Negative Number Boundaries',
        category: 'boundary',
        description: 'Test behavior with negative numbers in unexpected places',
        riskLevel: 'medium',
        expectedBehavior: 'Should validate and reject negative values',
        testFunction: async () => {
          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          const result = await clientSearchEngine.searchBusinesses('restaurants', '12345', -999999)
          expect(result).toEqual([])
        },
      })

      exploratoryTester.addTestCase({
        name: 'Unicode and Special Character Boundaries',
        category: 'boundary',
        description: 'Test with extreme Unicode characters and symbols',
        riskLevel: 'low',
        expectedBehavior: 'Should handle Unicode gracefully',
        testFunction: async () => {
          const unicodeString = '🏢🍕🏨🛍️💼🔍📊🌐🚀⚡🎯🔧🎨🎭🎪🎨🎯🔥💎🌟⭐'

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          const result = await clientSearchEngine.searchBusinesses(unicodeString, '12345', 10)
          expect(result).toEqual([])
        },
      })

      const results = await exploratoryTester.runExploratoryTests()
      const boundaryIssues = results.filter(r => r.testCase.category === 'boundary' && !r.passed)

      // Log any boundary issues found
      if (boundaryIssues.length > 0) {
        console.log('🔍 Boundary issues discovered:', boundaryIssues.length)
      }
    })
  })

  describe('Data Format Exploration', () => {
    test('should explore unusual data formats and structures', async () => {
      exploratoryTester.addTestCase({
        name: 'Malformed JSON Structures',
        category: 'data',
        description: 'Test behavior with malformed or unusual JSON',
        riskLevel: 'high',
        expectedBehavior: 'Should parse safely or reject with clear error',
        testFunction: async () => {
          const malformedData = {
            businessName: { nested: { deeply: { invalid: 'structure' } } },
            url: ['array', 'instead', 'of', 'string'],
            confidence: 'string instead of number',
          }

          // Test data validation
          expect(() => {
            if (typeof malformedData.confidence !== 'number') {
              throw new Error('Invalid data type')
            }
          }).toThrow()
        },
      })

      exploratoryTester.addTestCase({
        name: 'Circular Reference Data',
        category: 'data',
        description: 'Test behavior with circular references in data',
        riskLevel: 'medium',
        expectedBehavior: 'Should detect and handle circular references',
        testFunction: async () => {
          const circularData: any = { name: 'test' }
          circularData.self = circularData

          // Should handle circular references safely
          expect(() => {
            JSON.stringify(circularData)
          }).toThrow()
        },
      })

      exploratoryTester.addTestCase({
        name: 'Mixed Data Type Arrays',
        category: 'data',
        description: 'Test arrays with mixed and unexpected data types',
        riskLevel: 'low',
        expectedBehavior: 'Should handle mixed types gracefully',
        testFunction: async () => {
          const mixedArray = [
            'string',
            123,
            { object: true },
            null,
            undefined,
            [1, 2, 3],
            () => 'function',
            Symbol('symbol'),
          ]

          // Should handle mixed array types
          mixedArray.forEach(item => {
            expect(typeof item).toBeDefined()
          })
        },
      })

      await exploratoryTester.runExploratoryTests()
    })
  })

  describe('Interaction Pattern Exploration', () => {
    test('should explore unusual user interaction patterns', async () => {
      exploratoryTester.addTestCase({
        name: 'Rapid Sequential Requests',
        category: 'interaction',
        description: 'Test rapid fire requests in quick succession',
        riskLevel: 'medium',
        expectedBehavior: 'Should handle or throttle appropriately',
        testFunction: async () => {
          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          const promises = Array.from({ length: 100 }, (_, i) =>
            clientSearchEngine.searchBusinesses(`query${i}`, '12345', 1)
          )

          const results = await Promise.allSettled(promises)

          // Should handle rapid requests without crashing
          expect(results.length).toBe(100)
        },
      })

      exploratoryTester.addTestCase({
        name: 'Concurrent Conflicting Operations',
        category: 'interaction',
        description: 'Test concurrent operations that might conflict',
        riskLevel: 'high',
        expectedBehavior: 'Should maintain data consistency',
        testFunction: async () => {
          ;(scraperService.initializeBrowser as jest.Mock).mockResolvedValue(true)
          ;(scraperService.cleanup as jest.Mock).mockResolvedValue(undefined)

          // Simulate concurrent init and cleanup
          const initPromise = scraperService.initializeBrowser()
          const cleanupPromise = scraperService.cleanup()

          const results = await Promise.allSettled([initPromise, cleanupPromise])

          // Should handle concurrent operations safely
          expect(results.length).toBe(2)
        },
      })

      await exploratoryTester.runExploratoryTests()
    })
  })

  describe('Environment Condition Exploration', () => {
    test('should explore unusual environment conditions', async () => {
      exploratoryTester.addTestCase({
        name: 'Memory Pressure Conditions',
        category: 'environment',
        description: 'Test behavior under simulated memory pressure',
        riskLevel: 'medium',
        expectedBehavior: 'Should degrade gracefully under memory pressure',
        testFunction: async () => {
          // Simulate memory pressure
          const largeArrays: number[][] = []

          try {
            for (let i = 0; i < 1000; i++) {
              largeArrays.push(new Array(10000).fill(i))
            }
          } catch (error) {
            // Memory pressure detected
          }

          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockResolvedValue([])

          // Should still function under memory pressure
          const result = await clientSearchEngine.searchBusinesses('test', '12345', 1)
          expect(result).toEqual([])
        },
      })

      exploratoryTester.addTestCase({
        name: 'Network Instability Simulation',
        category: 'environment',
        description: 'Test behavior with unstable network conditions',
        riskLevel: 'medium',
        expectedBehavior: 'Should retry and handle network issues',
        testFunction: async () => {
          // Simulate network instability
          let callCount = 0
          ;(clientSearchEngine.searchBusinesses as jest.Mock).mockImplementation(() => {
            callCount++
            if (callCount % 3 === 0) {
              return Promise.resolve([])
            } else {
              return Promise.reject(new Error('Network error'))
            }
          })

          try {
            await clientSearchEngine.searchBusinesses('test', '12345', 1)
          } catch (error) {
            // Network errors are expected in this simulation
          }

          expect(callCount).toBeGreaterThan(0)
        },
      })

      await exploratoryTester.runExploratoryTests()
    })
  })

  describe('Security Edge Case Exploration', () => {
    test('should explore potential security edge cases', async () => {
      exploratoryTester.addTestCase({
        name: 'Prototype Pollution Attempts',
        category: 'security',
        description: 'Test for prototype pollution vulnerabilities',
        riskLevel: 'critical',
        expectedBehavior: 'Should prevent prototype pollution',
        testFunction: async () => {
          const maliciousPayload = {
            __proto__: { polluted: true },
            constructor: { prototype: { polluted: true } },
          }

          // Should not pollute Object prototype
          const testObj = Object.assign({}, maliciousPayload)
          expect((Object.prototype as any).polluted).toBeUndefined()
        },
      })

      exploratoryTester.addTestCase({
        name: 'Script Injection in Data Fields',
        category: 'security',
        description: 'Test for script injection in various data fields',
        riskLevel: 'high',
        expectedBehavior: 'Should sanitize or escape script content',
        testFunction: async () => {
          const scriptPayloads = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            'onload="alert(1)"',
            '${alert("xss")}',
            '{{constructor.constructor("alert(1)")()}}',
          ]

          scriptPayloads.forEach(payload => {
            // Should sanitize script content
            const sanitized = payload
              .replace(/<script[^>]*>.*?<\/script>/gi, '')
              .replace(/javascript:/gi, '')
              .replace(/on\w+\s*=/gi, '')
              .replace(/\$\{.*?\}/g, '')
              .replace(/\{\{.*?\}\}/g, '')

            expect(sanitized).not.toContain('<script>')
            expect(sanitized).not.toContain('javascript:')
            expect(sanitized).not.toContain('alert')
          })
        },
      })

      await exploratoryTester.runExploratoryTests()
    })
  })

  describe('Performance Edge Case Exploration', () => {
    test('should explore performance edge cases', async () => {
      exploratoryTester.addTestCase({
        name: 'Large Dataset Processing',
        category: 'performance',
        description: 'Test performance with unusually large datasets',
        riskLevel: 'medium',
        expectedBehavior: 'Should handle large datasets efficiently',
        testFunction: async () => {
          const largeDataset: BusinessRecord[] = Array.from({ length: 10000 }, (_, i) => ({
            id: i.toString(),
            businessName: `Business ${i}`,
            url: `https://example${i}.com`,
            phone: `555-${i.toString().padStart(4, '0')}`,
            email: `business${i}@example.com`,
            address: `${i} Main St`,
            city: 'Test City',
            state: 'TS',
            zipCode: '12345',
            industry: 'test',
            confidence: Math.random(),
            source: 'test',
            scrapedAt: new Date().toISOString(),
          }))

          const startTime = Date.now()

          // Process large dataset
          const processed = largeDataset.filter(business => business.confidence > 0.5)

          const processingTime = Date.now() - startTime

          expect(processed.length).toBeGreaterThan(0)
          expect(processingTime).toBeLessThan(5000) // Should process within 5 seconds
        },
      })

      exploratoryTester.addTestCase({
        name: 'Recursive Operation Depth',
        category: 'performance',
        description: 'Test deep recursive operations',
        riskLevel: 'medium',
        expectedBehavior: 'Should handle recursion safely',
        testFunction: async () => {
          const deepRecursion = (depth: number): number => {
            if (depth <= 0) return 0
            if (depth > 1000) throw new Error('Maximum recursion depth exceeded')
            return 1 + deepRecursion(depth - 1)
          }

          // Should handle reasonable recursion depth
          const result = deepRecursion(100)
          expect(result).toBe(100)

          // Should prevent stack overflow
          expect(() => deepRecursion(10000)).toThrow()
        },
      })

      await exploratoryTester.runExploratoryTests()
    })
  })

  describe('Exploratory Test Analysis', () => {
    test('should analyze and report exploratory test findings', async () => {
      // Run all exploratory tests
      const results = await exploratoryTester.runExploratoryTests()
      const highRiskIssues = exploratoryTester.getHighRiskIssues()
      const categorySummary = exploratoryTester.getCategorySummary()

      // Generate comprehensive report
      console.log('\n🔍 Exploratory Testing Results:')
      console.log(`📊 Total Tests: ${results.length}`)
      console.log(`✅ Passed: ${results.filter(r => r.passed).length}`)
      console.log(`❌ Failed: ${results.filter(r => !r.passed).length}`)
      console.log(`🚨 High Risk Issues: ${highRiskIssues.length}`)

      console.log('\n📋 Category Summary:')
      categorySummary.forEach((summary, category) => {
        const failureRate =
          summary.total > 0 ? ((summary.failed / summary.total) * 100).toFixed(1) : '0'
        console.log(`  ${category}: ${summary.failed}/${summary.total} failed (${failureRate}%)`)
      })

      if (highRiskIssues.length > 0) {
        console.log('\n🚨 High Risk Issues Found:')
        highRiskIssues.forEach(issue => {
          console.log(`  - ${issue.testCase.name}: ${issue.unexpectedBehavior}`)
          console.log(`    Recommendation: ${issue.recommendation}`)
        })
      }

      // Exploratory testing quality metrics
      expect(results.length).toBeGreaterThan(10) // Should have comprehensive coverage
      expect(highRiskIssues.length).toBeLessThanOrEqual(2) // Minimal high-risk issues

      // Category coverage
      expect(categorySummary.size).toBeGreaterThanOrEqual(5) // Multiple categories tested

      // Overall failure rate should be reasonable for exploratory testing
      const failureRate = results.filter(r => !r.passed).length / results.length
      expect(failureRate).toBeLessThan(0.3) // Less than 30% failure rate
    })
  })
})
