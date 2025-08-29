/**
 * Unit Tests for Business Intelligence Service
 * Comprehensive test suite for business enrichment features
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { BusinessIntelligenceService } from '@/lib/businessIntelligenceService'
import { BusinessIntelligence, TechnologyPlatform } from '@/types/business'

// Mock Puppeteer Page
const mockPage = {
  content: jest.fn(),
  evaluate: jest.fn(),
  url: jest.fn(),
}

describe('BusinessIntelligenceService', () => {
  let businessIntelligenceService: BusinessIntelligenceService

  beforeEach(() => {
    businessIntelligenceService = BusinessIntelligenceService.getInstance()
    businessIntelligenceService.clearCache()
    jest.clearAllMocks()
  })

  afterEach(() => {
    businessIntelligenceService.clearCache()
  })

  describe('Company Size Estimation', () => {
    it('should estimate company size from explicit employee count', async () => {
      mockPage.content.mockResolvedValue(
        '<html><body>We have 25 employees working hard</body></html>'
      )
      mockPage.evaluate.mockResolvedValue('We have 25 employees working hard')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company',
        mockPage as any
      )

      expect(result.companySize).toBeDefined()
      expect(result.companySize?.employeeCount).toBe(25)
      expect(result.companySize?.employeeRange).toBe('11-50')
      expect(result.companySize?.confidence).toBeGreaterThan(80)
    })

    it('should estimate company size from content indicators', async () => {
      mockPage.content.mockResolvedValue('<html><body>We are a small startup company</body></html>')
      mockPage.evaluate
        .mockResolvedValueOnce('We are a small startup company')
        .mockResolvedValueOnce(15) // complexity score

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Startup',
        mockPage as any
      )

      expect(result.companySize).toBeDefined()
      expect(result.companySize?.employeeRange).toBeDefined()
      expect(result.companySize?.confidence).toBeGreaterThan(0)
    })

    it('should analyze business name for size indicators', async () => {
      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Corporation Inc.'
      )

      expect(result.companySize).toBeDefined()
      expect(result.companySize?.confidence).toBeGreaterThan(0)
    })
  })

  describe('Revenue Estimation', () => {
    it('should estimate revenue from explicit mentions', async () => {
      mockPage.content.mockResolvedValue('<html><body>Annual revenue of $5 million</body></html>')
      mockPage.evaluate.mockResolvedValue('Annual revenue of $5 million')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company',
        mockPage as any
      )

      expect(result.revenue).toBeDefined()
      expect(result.revenue?.estimatedRevenue).toBe(5000000)
      expect(result.revenue?.revenueRange).toBe('$1M-$10M')
      expect(result.revenue?.confidence).toBeGreaterThan(70)
    })

    it('should estimate revenue from company size', async () => {
      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company'
      )

      expect(result.revenue).toBeDefined()
      expect(result.revenue?.revenueRange).toBeDefined()
      expect(result.revenue?.confidence).toBeGreaterThan(0)
    })

    it('should handle billion dollar mentions', async () => {
      mockPage.content.mockResolvedValue('<html><body>Revenue of $2.5 billion</body></html>')
      mockPage.evaluate.mockResolvedValue('Revenue of $2.5 billion')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Large Corp',
        mockPage as any
      )

      expect(result.revenue?.estimatedRevenue).toBe(2500000000)
      expect(result.revenue?.revenueRange).toBe('$1B+')
    })
  })

  describe('Business Maturity Assessment', () => {
    it('should detect founding year', async () => {
      mockPage.content.mockResolvedValue('<html><body>Founded in 1995</body></html>')
      mockPage.evaluate.mockResolvedValue('Founded in 1995')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Established Company',
        mockPage as any
      )

      expect(result.businessMaturity).toBeDefined()
      expect(result.businessMaturity?.yearsInBusiness).toBeGreaterThan(25)
      expect(result.businessMaturity?.maturityStage).toBe('enterprise')
      expect(result.businessMaturity?.confidence).toBeGreaterThan(60)
    })

    it('should classify maturity stages correctly', async () => {
      const testCases = [
        { year: 2022, expectedStage: 'startup' },
        { year: 2015, expectedStage: 'growth' },
        { year: 2000, expectedStage: 'mature' },
        { year: 1980, expectedStage: 'enterprise' },
      ]

      for (const testCase of testCases) {
        mockPage.content.mockResolvedValue(`<html><body>Founded in ${testCase.year}</body></html>`)
        mockPage.evaluate.mockResolvedValue(`Founded in ${testCase.year}`)

        const result = await businessIntelligenceService.enrichBusinessData(
          'https://example.com',
          'Test Company',
          mockPage as any
        )

        expect(result.businessMaturity?.maturityStage).toBe(testCase.expectedStage)
      }
    })

    it('should detect maturity keywords', async () => {
      mockPage.content.mockResolvedValue(
        '<html><body>We are an established industry leader</body></html>'
      )
      mockPage.evaluate.mockResolvedValue('We are an established industry leader')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Leader Corp',
        mockPage as any
      )

      expect(result.businessMaturity?.indicators).toContain('Contains "established"')
      expect(result.businessMaturity?.indicators).toContain('Contains "industry leader"')
    })
  })

  describe('Technology Stack Detection', () => {
    it('should detect WordPress', async () => {
      mockPage.content.mockResolvedValue(
        '<html><head><link rel="stylesheet" href="/wp-content/themes/style.css"></head></html>'
      )
      mockPage.evaluate
        .mockResolvedValueOnce(['/wp-content/themes/script.js']) // scripts
        .mockResolvedValueOnce(['/wp-content/themes/style.css']) // stylesheets
        .mockResolvedValueOnce([]) // headers

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'WP Site',
        mockPage as any
      )

      expect(result.technologyStack).toBeDefined()
      const wpPlatform = result.technologyStack?.platforms?.find(p => p.name === 'WordPress')
      expect(wpPlatform).toBeDefined()
      expect(wpPlatform?.category).toBe('cms')
    })

    it('should detect Shopify', async () => {
      mockPage.content.mockResolvedValue('<html><body class="shopify-section"></body></html>')
      mockPage.evaluate
        .mockResolvedValueOnce(['https://cdn.shopify.com/script.js'])
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([])

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Shop Site',
        mockPage as any
      )

      const shopifyPlatform = result.technologyStack?.platforms?.find(p => p.name === 'Shopify')
      expect(shopifyPlatform).toBeDefined()
      expect(shopifyPlatform?.category).toBe('ecommerce')
    })

    it('should detect multiple technologies', async () => {
      mockPage.content.mockResolvedValue(
        '<html><head><script src="https://www.google-analytics.com/analytics.js"></script></head></html>'
      )
      mockPage.evaluate
        .mockResolvedValueOnce(['https://www.google-analytics.com/analytics.js'])
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([
          { name: 'React', category: 'other', confidence: 80, indicators: ['React detected'] },
        ])

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Tech Site',
        mockPage as any
      )

      expect(result.technologyStack?.platforms?.length).toBeGreaterThan(1)
    })
  })

  describe('Social Media Presence Analysis', () => {
    it('should detect social media links', async () => {
      mockPage.evaluate.mockResolvedValue([
        { href: 'https://facebook.com/testcompany', text: 'Facebook', title: '' },
        { href: 'https://twitter.com/testcompany', text: 'Twitter', title: '' },
        { href: 'https://linkedin.com/company/testcompany', text: 'LinkedIn', title: '' },
      ])

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Social Company',
        mockPage as any
      )

      expect(result.socialMediaPresence).toBeDefined()
      expect(result.socialMediaPresence?.profiles.length).toBeGreaterThan(0)
      expect(result.socialMediaPresence?.overallPresence).toBeGreaterThan(0)

      const platforms = result.socialMediaPresence?.profiles.map(p => p.platform)
      expect(platforms).toContain('Facebook')
      expect(platforms).toContain('Twitter')
      expect(platforms).toContain('LinkedIn')
    })

    it('should extract social media handles', async () => {
      mockPage.evaluate.mockResolvedValue([
        { href: 'https://twitter.com/testcompany', text: 'Twitter', title: '' },
      ])

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company',
        mockPage as any
      )

      const twitterProfile = result.socialMediaPresence?.profiles.find(
        p => p.platform === 'Twitter'
      )
      expect(twitterProfile?.handle).toBe('@testcompany')
    })

    it('should detect social media widgets', async () => {
      mockPage.evaluate
        .mockResolvedValueOnce([]) // social links
        .mockResolvedValueOnce([{ platform: 'Facebook', url: '', confidence: 60 }]) // widgets

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Widget Company',
        mockPage as any
      )

      expect(result.socialMediaPresence?.profiles.length).toBeGreaterThan(0)
    })

    it('should deduplicate social media profiles', async () => {
      mockPage.evaluate
        .mockResolvedValueOnce([
          { href: 'https://facebook.com/testcompany', text: 'Facebook', title: '' },
          { href: 'https://facebook.com/testcompany', text: 'Facebook Page', title: '' },
        ])
        .mockResolvedValueOnce([])

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company',
        mockPage as any
      )

      const facebookProfiles = result.socialMediaPresence?.profiles.filter(
        p => p.platform === 'Facebook'
      )
      expect(facebookProfiles?.length).toBe(1)
    })
  })

  describe('Caching', () => {
    it('should cache enrichment results', async () => {
      const url = 'https://example.com'
      const businessName = 'Test Company'

      // First call
      const result1 = await businessIntelligenceService.enrichBusinessData(url, businessName)

      // Second call should use cache
      const result2 = await businessIntelligenceService.enrichBusinessData(url, businessName)

      expect(result1).toEqual(result2)
    })

    it('should provide cache statistics', () => {
      const stats = businessIntelligenceService.getCacheStats()

      expect(stats).toHaveProperty('enrichmentCacheSize')
      expect(stats).toHaveProperty('technologyCacheSize')
      expect(stats).toHaveProperty('socialMediaCacheSize')
    })

    it('should clear all caches', () => {
      businessIntelligenceService.clearCache()

      const stats = businessIntelligenceService.getCacheStats()
      expect(stats.enrichmentCacheSize).toBe(0)
      expect(stats.technologyCacheSize).toBe(0)
      expect(stats.socialMediaCacheSize).toBe(0)
    })
  })

  describe('Error Handling', () => {
    it('should handle page evaluation errors gracefully', async () => {
      mockPage.content.mockRejectedValue(new Error('Page load failed'))

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Company',
        mockPage as any
      )

      expect(result).toBeDefined()
      expect(result.companySize?.confidence).toBe(0)
      expect(result.revenue?.confidence).toBe(0)
    })

    it('should provide fallback data when page is not available', async () => {
      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Test Corporation Inc.'
      )

      expect(result).toBeDefined()
      expect(result.companySize).toBeDefined()
      expect(result.revenue).toBeDefined()
      expect(result.businessMaturity).toBeDefined()
    })
  })

  describe('Confidence Scoring', () => {
    it('should provide higher confidence for explicit data', async () => {
      mockPage.content.mockResolvedValue(
        '<html><body>We have 50 employees and $10M revenue</body></html>'
      )
      mockPage.evaluate.mockResolvedValue('We have 50 employees and $10M revenue')

      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Data Rich Company',
        mockPage as any
      )

      expect(result.companySize?.confidence).toBeGreaterThan(80)
      expect(result.revenue?.confidence).toBeGreaterThan(70)
    })

    it('should provide lower confidence for inferred data', async () => {
      const result = await businessIntelligenceService.enrichBusinessData(
        'https://example.com',
        'Unknown Company'
      )

      expect(result.companySize?.confidence).toBeLessThan(50)
      expect(result.revenue?.confidence).toBeLessThan(50)
    })
  })
})
