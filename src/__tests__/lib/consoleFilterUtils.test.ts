/**
 * Tests for Console Filter Utils
 */

import { COMMON_CONSOLE_FILTERS, RESOURCE_BLOCKING_PATTERNS } from '@/lib/consoleFilterUtils'

describe('Console Filter Utils', () => {
  describe('COMMON_CONSOLE_FILTERS', () => {
    it('should contain DuckDuckGo specific filters', () => {
      expect(COMMON_CONSOLE_FILTERS.DUCKDUCKGO_SPECIFIC).toContain(
        'useTranslation: DISMISS is not available'
      )
      expect(COMMON_CONSOLE_FILTERS.DUCKDUCKGO_SPECIFIC).toContain('expanded-maps-vertical')
      expect(COMMON_CONSOLE_FILTERS.DUCKDUCKGO_SPECIFIC).toContain('duckassist-ia')
    })

    it('should contain permissions policy filters', () => {
      expect(COMMON_CONSOLE_FILTERS.PERMISSIONS_POLICY).toContain(
        'Permissions-Policy header: Unrecognized feature'
      )
      expect(COMMON_CONSOLE_FILTERS.PERMISSIONS_POLICY).toContain('interest-cohort')
    })

    it('should contain resource error filters', () => {
      expect(COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS).toContain('Failed to load resource')
      expect(COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS).toContain('net::ERR_FAILED')
      expect(COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS).toContain('favicon')
      expect(COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS).toContain('mapkit')
    })

    it('should contain preload warning filters', () => {
      expect(COMMON_CONSOLE_FILTERS.PRELOAD_WARNINGS).toContain(
        'was preloaded using link preload but not used'
      )
      expect(COMMON_CONSOLE_FILTERS.PRELOAD_WARNINGS).toContain('preload')
    })
  })

  describe('RESOURCE_BLOCKING_PATTERNS', () => {
    it('should contain console error sources', () => {
      expect(RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES).toContain('mapkit')
      expect(RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES).toContain('favicon')
      expect(RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES).toContain('expanded-maps-vertical')
      expect(RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES).toContain('duckassist-ia')
    })

    it('should contain performance blocks', () => {
      expect(RESOURCE_BLOCKING_PATTERNS.PERFORMANCE_BLOCKS).toContain('image')
      expect(RESOURCE_BLOCKING_PATTERNS.PERFORMANCE_BLOCKS).toContain('stylesheet')
      expect(RESOURCE_BLOCKING_PATTERNS.PERFORMANCE_BLOCKS).toContain('font')
      expect(RESOURCE_BLOCKING_PATTERNS.PERFORMANCE_BLOCKS).toContain('media')
    })

    it('should contain tracking blocks', () => {
      expect(RESOURCE_BLOCKING_PATTERNS.TRACKING_BLOCKS).toContain('google-analytics')
      expect(RESOURCE_BLOCKING_PATTERNS.TRACKING_BLOCKS).toContain('facebook.com')
      expect(RESOURCE_BLOCKING_PATTERNS.TRACKING_BLOCKS).toContain('doubleclick')
    })
  })

  describe('Filter patterns validation', () => {
    it('should filter DuckDuckGo specific console errors', () => {
      const testMessages = [
        "Error with Permissions-Policy header: Unrecognized feature: 'interest-cohort'.",
        'useTranslation: DISMISS is not available',
        'Failed to load resource: net::ERR_FAILED',
        'The resource was preloaded using link preload but not used within a few seconds',
        'Failed to load resource: the server responded with a status of 404 ()',
      ]

      testMessages.forEach(message => {
        const shouldBeFiltered = Object.values(COMMON_CONSOLE_FILTERS)
          .flat()
          .some(filter => message.includes(filter))

        expect(shouldBeFiltered).toBe(true)
      })
    })

    it('should not filter critical application errors', () => {
      const criticalMessages = [
        'TypeError: Cannot read property of undefined',
        'ReferenceError: variable is not defined',
        'SyntaxError: Unexpected token',
        'Network request failed with status 500',
      ]

      criticalMessages.forEach(message => {
        const shouldBeFiltered = Object.values(COMMON_CONSOLE_FILTERS)
          .flat()
          .some(filter => message.includes(filter))

        expect(shouldBeFiltered).toBe(false)
      })
    })
  })

  describe('Resource blocking validation', () => {
    it('should block problematic DuckDuckGo resources', () => {
      const problematicUrls = [
        'https://cdn.apple-mapkit.com/md/v1/shield?text=181&id=84000240',
        'https://www.isbe.net.ico',
        'https://duckduckgo.com/dist/wpm.expanded-maps-vertical.css',
        'https://duckduckgo.com/dist/wpm.duckassist-ia.js',
      ]

      problematicUrls.forEach(url => {
        const shouldBeBlocked = RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES.some(pattern =>
          url.includes(pattern)
        )

        expect(shouldBeBlocked).toBe(true)
      })
    })

    it('should allow essential resources', () => {
      const essentialUrls = [
        'https://duckduckgo.com/',
        'https://duckduckgo.com/js/spice/dictionary/definition',
        'https://api.duckduckgo.com/search',
      ]

      essentialUrls.forEach(url => {
        const shouldBeBlocked = RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES.some(pattern =>
          url.includes(pattern)
        )

        expect(shouldBeBlocked).toBe(false)
      })
    })
  })
})
