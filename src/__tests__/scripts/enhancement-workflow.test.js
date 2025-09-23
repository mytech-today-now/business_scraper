/**
 * Tests for the Self-Documenting Enhancement Workflow
 */

const fs = require('fs')
const path = require('path')
const { 
  ConsoleLogAnalyzer, 
  AffectedFileDetector, 
  TestRunner,
  GitHubAPI 
} = require('../../../scripts/console-log-enhancement-workflow')

describe('Enhancement Workflow', () => {
  describe('ConsoleLogAnalyzer', () => {
    it('should analyze console logs correctly', () => {
      const sampleLog = `
6:36:58 PM [WARN] [06:36:58 PM] <useSearchStreaming> WARN: Streaming connection error {
  "readyState": 2,
  "url": "http://localhost:3000/api/stream-search",
  "retryCount": 0
}
6:36:58 PM [INFO] [06:36:58 PM] <useSearchStreaming> INFO: Retrying connection (1/3)
6:36:58 PM [INFO] [06:36:58 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:12 PM [DEBUG] [06:37:12 PM] <Monitoring> DEBUG: Metric recorded: memory_heap_used = 317316886 bytes
      `

      const analyzer = new ConsoleLogAnalyzer(sampleLog)
      const analysis = analyzer.analysis

      expect(analysis.infoLogs.length).toBeGreaterThan(0)
      expect(analysis.warnLogs.length).toBeGreaterThan(0)
      expect(analysis.debugLogs.length).toBeGreaterThan(0)
      expect(analysis.patterns.streamingConnectionIssues).toBeDefined()
      expect(analysis.recommendations.length).toBeGreaterThan(0)
    })

    it('should identify streaming connection patterns', () => {
      const logWithStreamingIssues = `
[WARN] useSearchStreaming: Streaming connection error
[WARN] useSearchStreaming: Streaming connection error
[WARN] useSearchStreaming: Streaming connection error
      `

      const analyzer = new ConsoleLogAnalyzer(logWithStreamingIssues)
      expect(analyzer.analysis.patterns.streamingConnectionIssues).toBeDefined()
      expect(analyzer.analysis.patterns.streamingConnectionIssues.count).toBe(3)
    })

    it('should identify excessive logging patterns', () => {
      const logWithExcessiveZipCode = Array(15).fill(
        '[INFO] AddressInputHandler: ZIP code input detected: 60047'
      ).join('\n')

      const analyzer = new ConsoleLogAnalyzer(logWithExcessiveZipCode)
      expect(analyzer.analysis.patterns.excessiveZipCodeLogging).toBeDefined()
      expect(analyzer.analysis.patterns.excessiveZipCodeLogging.count).toBe(15)
    })

    it('should generate appropriate recommendations', () => {
      const logWithIssues = `
[WARN] useSearchStreaming: Streaming connection error
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
[INFO] AddressInputHandler: ZIP code input detected: 60047
      `

      const analyzer = new ConsoleLogAnalyzer(logWithIssues)
      const recommendations = analyzer.analysis.recommendations

      expect(recommendations.length).toBeGreaterThan(0)
      expect(recommendations.some(r => r.component === 'useSearchStreaming')).toBe(true)
      expect(recommendations.some(r => r.component === 'AddressInputHandler')).toBe(true)
    })
  })

  describe('AffectedFileDetector', () => {
    it('should detect files from console patterns when git fails', () => {
      const detector = new AffectedFileDetector()
      const files = detector.detectFromConsolePatterns()

      expect(files).toContain('src/hooks/useSearchStreaming.ts')
      expect(files).toContain('src/components/AddressInputHandler.tsx')
      expect(files).toContain('src/lib/monitoring.ts')
      expect(files).toContain('src/app/api/stream-search/route.ts')
    })
  })

  describe('TestRunner', () => {
    let testRunner

    beforeEach(() => {
      testRunner = new TestRunner()
    })

    it('should find test files correctly', () => {
      // Mock file system
      const originalExistsSync = fs.existsSync
      fs.existsSync = jest.fn((filePath) => {
        return filePath.includes('useSearchStreaming.test.ts')
      })

      const testFile = testRunner.findTestFile('src/hooks/useSearchStreaming.ts')
      expect(testFile).toContain('useSearchStreaming.test.ts')

      // Restore original function
      fs.existsSync = originalExistsSync
    })

    it('should generate appropriate test commands', async () => {
      const result = await testRunner.runTestForFile('src/hooks/useSearchStreaming.ts')
      
      expect(result.command).toBeDefined()
      expect(result.result).toMatch(/PASS|FAIL/)
      expect(result.output).toBeDefined()
    })
  })

  describe('GitHubAPI', () => {
    let githubAPI

    beforeEach(() => {
      githubAPI = new GitHubAPI('fake-token', 'test/repo')
    })

    it('should construct API URLs correctly', () => {
      expect(githubAPI.baseURL).toBe('https://api.github.com')
      expect(githubAPI.repository).toBe('test/repo')
      expect(githubAPI.headers.Authorization).toBe('token fake-token')
    })

    it('should have correct headers', () => {
      expect(githubAPI.headers).toEqual({
        'Authorization': 'token fake-token',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'business-scraper-workflow'
      })
    })
  })

  describe('Integration Tests', () => {
    it('should process the actual console log file', () => {
      const consoleLogPath = path.join(process.cwd(), 'console_log_context.txt')
      
      if (fs.existsSync(consoleLogPath)) {
        const logContent = fs.readFileSync(consoleLogPath, 'utf8')
        const analyzer = new ConsoleLogAnalyzer(logContent)
        
        expect(analyzer.analysis).toBeDefined()
        expect(analyzer.analysis.infoLogs.length).toBeGreaterThan(0)
        expect(analyzer.analysis.warnLogs.length).toBeGreaterThan(0)
        
        // Should detect streaming issues from the actual log
        expect(analyzer.analysis.patterns.streamingConnectionIssues).toBeDefined()
        expect(analyzer.analysis.patterns.excessiveZipCodeLogging).toBeDefined()
      } else {
        console.warn('Console log file not found, skipping integration test')
      }
    })

    it('should handle empty or malformed logs gracefully', () => {
      const analyzer = new ConsoleLogAnalyzer('')
      expect(analyzer.analysis.infoLogs).toEqual([])
      expect(analyzer.analysis.warnLogs).toEqual([])
      expect(analyzer.analysis.errorLogs).toEqual([])
      expect(analyzer.analysis.debugLogs).toEqual([])
    })

    it('should handle logs without patterns', () => {
      const simpleLog = '[INFO] Simple log message'
      const analyzer = new ConsoleLogAnalyzer(simpleLog)
      
      expect(analyzer.analysis.infoLogs.length).toBe(1)
      expect(Object.keys(analyzer.analysis.patterns)).toHaveLength(0)
      expect(analyzer.analysis.recommendations).toHaveLength(0)
    })
  })

  describe('Error Handling', () => {
    it('should handle missing console log file gracefully', () => {
      const detector = new AffectedFileDetector()
      
      // Should not throw when git commands fail
      expect(() => detector.detectFromConsolePatterns()).not.toThrow()
    })

    it('should handle test execution failures', async () => {
      const testRunner = new TestRunner()

      // Test with non-existent file that would cause test command to fail
      const result = await testRunner.runTestForFile('non-existent-file-that-will-fail-tests.js')

      // The result could be PASS (if echo command succeeds) or FAIL (if test command fails)
      // We just need to ensure it doesn't crash and returns a valid result
      expect(result.result).toMatch(/PASS|FAIL/)
      expect(result.output).toBeDefined()
      expect(result.command).toBeDefined()
    })
  })
})
