/**
 * Comprehensive Business Rule Tests for Business Maturity Analyzer
 * Tests business maturity analysis algorithms and scoring logic
 */

import { BusinessMaturityAnalyzer } from '@/lib/businessMaturityAnalyzer'
import { BusinessRecord, BusinessMaturityIndicators } from '@/types/business'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('puppeteer', () => ({
  launch: jest.fn(() => ({
    newPage: jest.fn(() => ({
      goto: jest.fn(),
      content: jest.fn(),
      close: jest.fn(),
    })),
    close: jest.fn(),
  })),
}))

describe('Business Maturity Analyzer - Business Logic Rules', () => {
  let analyzer: BusinessMaturityAnalyzer

  const mockBusinessRecord: BusinessRecord = {
    id: 'business-1',
    businessName: 'Acme Corporation',
    email: ['contact@acme.com'],
    phone: '+1-555-123-4567',
    websiteUrl: 'https://acme.com',
    address: {
      street: '123 Main Street',
      city: 'San Francisco',
      state: 'CA',
      zipCode: '94105',
    },
    industry: 'Technology',
    description: 'Leading technology solutions provider with over 50 employees',
    scrapedAt: new Date(),
  }

  beforeEach(() => {
    analyzer = new BusinessMaturityAnalyzer()
    jest.clearAllMocks()
  })

  describe('Overall Maturity Analysis', () => {
    test('should analyze business maturity with all indicators', async () => {
      const result = await analyzer.analyzeBusinessMaturity(mockBusinessRecord)

      expect(result).toHaveProperty('maturityScore')
      expect(result).toHaveProperty('growthSignals')
      expect(result).toHaveProperty('sizeIndicators')
      expect(result).toHaveProperty('digitalPresence')
      expect(result).toHaveProperty('analyzedAt')

      expect(result.maturityScore).toBeGreaterThanOrEqual(0)
      expect(result.maturityScore).toBeLessThanOrEqual(100)
      expect(result.analyzedAt).toBeInstanceOf(Date)
    })

    test('should handle businesses without websites', async () => {
      const businessWithoutWebsite = {
        ...mockBusinessRecord,
        websiteUrl: undefined,
      }

      const result = await analyzer.analyzeBusinessMaturity(businessWithoutWebsite)

      expect(result.maturityScore).toBe(40) // Base score for basic business info
      expect(result.growthSignals).toBeDefined()
      expect(result.sizeIndicators).toBeDefined()
      expect(result.digitalPresence).toBeDefined()
    })

    test('should provide fallback analysis on errors', async () => {
      // Mock error in website analysis
      jest.spyOn(analyzer as any, 'analyzeGrowthSignals').mockRejectedValue(
        new Error('Website analysis failed')
      )

      const result = await analyzer.analyzeBusinessMaturity(mockBusinessRecord)

      expect(result).toBeDefined()
      expect(result.maturityScore).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Growth Signals Analysis', () => {
    test('should detect careers page existence', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <a href="/careers">Join Our Team</a>
              <div>We are hiring software engineers</div>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const growthSignals = await (analyzer as any).analyzeGrowthSignals('https://acme.com', mockPage)

      expect(growthSignals.careersPageExists).toBe(true)
      expect(growthSignals.jobPostingsFound).toBeGreaterThan(0)
    })

    test('should detect funding mentions', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div>We recently raised $10M in Series A funding</div>
              <p>Our investors include top venture capital firms</p>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const growthSignals = await (analyzer as any).analyzeGrowthSignals('https://acme.com', mockPage)

      expect(growthSignals.fundingMentions).toContain('$10M')
      expect(growthSignals.fundingMentions.length).toBeGreaterThan(0)
    })

    test('should assess about page quality', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div class="about">
                <h1>About Us</h1>
                <p>Founded in 2010, Acme Corporation has been a leader in technology solutions.</p>
                <p>Our mission is to provide innovative software that transforms businesses.</p>
                <p>We serve clients across multiple industries and have offices worldwide.</p>
                <p>Our team consists of experienced professionals dedicated to excellence.</p>
              </div>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const growthSignals = await (analyzer as any).analyzeGrowthSignals('https://acme.com', mockPage)

      expect(growthSignals.aboutPageQuality).toBeGreaterThan(50) // Good quality content
      expect(growthSignals.teamPageExists).toBe(false) // No team page in this example
    })

    test('should handle missing growth indicators', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <h1>Simple Business Website</h1>
              <p>Contact us for services</p>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const growthSignals = await (analyzer as any).analyzeGrowthSignals('https://acme.com', mockPage)

      expect(growthSignals.careersPageExists).toBe(false)
      expect(growthSignals.jobPostingsFound).toBe(0)
      expect(growthSignals.fundingMentions).toHaveLength(0)
      expect(growthSignals.aboutPageQuality).toBeLessThan(30)
    })
  })

  describe('Size Indicators Analysis', () => {
    test('should estimate employee count from description', async () => {
      const businessWithEmployeeInfo = {
        ...mockBusinessRecord,
        description: 'We are a growing company with over 100 employees across 3 offices',
      }

      const sizeIndicators = await (analyzer as any).analyzeSizeIndicators(businessWithEmployeeInfo)

      expect(sizeIndicators.estimatedEmployeeCount).toBeGreaterThan(50)
      expect(sizeIndicators.officeLocations).toBeDefined()
    })

    test('should extract service areas from description', async () => {
      const businessWithServiceAreas = {
        ...mockBusinessRecord,
        description: 'Serving clients in California, Nevada, and Arizona with premium services',
      }

      const sizeIndicators = await (analyzer as any).analyzeSizeIndicators(businessWithServiceAreas)

      expect(sizeIndicators.serviceAreas).toContain('California')
      expect(sizeIndicators.serviceAreas).toContain('Nevada')
      expect(sizeIndicators.serviceAreas).toContain('Arizona')
    })

    test('should detect client testimonials and case studies', async () => {
      const businessWithTestimonials = {
        ...mockBusinessRecord,
        description: 'Client testimonials show our success. Case studies demonstrate our expertise.',
      }

      const sizeIndicators = await (analyzer as any).analyzeSizeIndicators(businessWithTestimonials)

      expect(sizeIndicators.clientTestimonials).toBeGreaterThan(0)
      expect(sizeIndicators.caseStudies).toBeGreaterThan(0)
    })

    test('should handle minimal business information', async () => {
      const minimalBusiness = {
        ...mockBusinessRecord,
        description: 'Small business',
      }

      const sizeIndicators = await (analyzer as any).analyzeSizeIndicators(minimalBusiness)

      expect(sizeIndicators.estimatedEmployeeCount).toBeLessThan(10)
      expect(sizeIndicators.serviceAreas).toHaveLength(0)
      expect(sizeIndicators.clientTestimonials).toBe(0)
      expect(sizeIndicators.caseStudies).toBe(0)
    })
  })

  describe('Digital Presence Analysis', () => {
    test('should detect social media accounts', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <a href="https://facebook.com/acmecorp">Facebook</a>
              <a href="https://twitter.com/acmecorp">Twitter</a>
              <a href="https://linkedin.com/company/acmecorp">LinkedIn</a>
              <a href="https://instagram.com/acmecorp">Instagram</a>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence.socialMediaAccounts).toContain('facebook')
      expect(digitalPresence.socialMediaAccounts).toContain('twitter')
      expect(digitalPresence.socialMediaAccounts).toContain('linkedin')
      expect(digitalPresence.socialMediaAccounts).toContain('instagram')
      expect(digitalPresence.socialMediaAccounts).toHaveLength(4)
    })

    test('should detect blog activity', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div class="blog">
                <h2>Latest Blog Posts</h2>
                <article>Recent industry insights</article>
                <article>Company updates and news</article>
              </div>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence.blogActivity).toBe(true)
      expect(digitalPresence.lastBlogPost).toBeInstanceOf(Date)
    })

    test('should detect email marketing signup', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <form class="newsletter">
                <input type="email" placeholder="Subscribe to our newsletter">
                <button>Sign Up</button>
              </form>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence.emailMarketingSignup).toBe(true)
    })

    test('should detect live chat availability', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div class="chat-widget">
                <p>Chat with us live for instant support</p>
                <button>Start Live Chat</button>
              </div>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence.liveChatAvailable).toBe(true)
    })

    test('should handle minimal digital presence', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <h1>Basic Business Website</h1>
              <p>Contact us by phone</p>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence.socialMediaAccounts).toHaveLength(0)
      expect(digitalPresence.blogActivity).toBe(false)
      expect(digitalPresence.emailMarketingSignup).toBe(false)
      expect(digitalPresence.liveChatAvailable).toBe(false)
    })
  })

  describe('Maturity Score Calculation', () => {
    test('should calculate high maturity score for mature business', async () => {
      const matureGrowthSignals = {
        careersPageExists: true,
        jobPostingsFound: 5,
        fundingMentions: ['$10M Series A'],
        teamPageExists: true,
        aboutPageQuality: 90,
      }

      const matureSizeIndicators = {
        estimatedEmployeeCount: 100,
        officeLocations: ['San Francisco', 'New York'],
        serviceAreas: ['California', 'New York', 'Texas'],
        clientTestimonials: 10,
        caseStudies: 5,
      }

      const matureDigitalPresence = {
        socialMediaAccounts: ['facebook', 'twitter', 'linkedin', 'instagram'],
        blogActivity: true,
        lastBlogPost: new Date(),
        emailMarketingSignup: true,
        liveChatAvailable: true,
      }

      const score = (analyzer as any).calculateMaturityScore(
        matureGrowthSignals,
        matureSizeIndicators,
        matureDigitalPresence
      )

      expect(score).toBeGreaterThan(80) // High maturity score
      expect(score).toBeLessThanOrEqual(100)
    })

    test('should calculate low maturity score for basic business', async () => {
      const basicGrowthSignals = {
        careersPageExists: false,
        jobPostingsFound: 0,
        fundingMentions: [],
        teamPageExists: false,
        aboutPageQuality: 20,
      }

      const basicSizeIndicators = {
        estimatedEmployeeCount: 2,
        officeLocations: [],
        serviceAreas: [],
        clientTestimonials: 0,
        caseStudies: 0,
      }

      const basicDigitalPresence = {
        socialMediaAccounts: [],
        blogActivity: false,
        lastBlogPost: null,
        emailMarketingSignup: false,
        liveChatAvailable: false,
      }

      const score = (analyzer as any).calculateMaturityScore(
        basicGrowthSignals,
        basicSizeIndicators,
        basicDigitalPresence
      )

      expect(score).toBeLessThan(50) // Low maturity score
      expect(score).toBeGreaterThanOrEqual(30) // Base score
    })

    test('should cap maturity score at 100', async () => {
      const exceptionalGrowthSignals = {
        careersPageExists: true,
        jobPostingsFound: 20,
        fundingMentions: ['$50M Series B', '$100M Series C'],
        teamPageExists: true,
        aboutPageQuality: 100,
      }

      const exceptionalSizeIndicators = {
        estimatedEmployeeCount: 1000,
        officeLocations: ['San Francisco', 'New York', 'London', 'Tokyo'],
        serviceAreas: ['Global'],
        clientTestimonials: 50,
        caseStudies: 25,
      }

      const exceptionalDigitalPresence = {
        socialMediaAccounts: ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube'],
        blogActivity: true,
        lastBlogPost: new Date(),
        emailMarketingSignup: true,
        liveChatAvailable: true,
      }

      const score = (analyzer as any).calculateMaturityScore(
        exceptionalGrowthSignals,
        exceptionalSizeIndicators,
        exceptionalDigitalPresence
      )

      expect(score).toBe(100) // Should be capped at 100
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle website analysis failures', async () => {
      // Mock page.goto to fail
      const mockPage = {
        goto: jest.fn().mockRejectedValue(new Error('Website unreachable')),
        content: jest.fn(),
        close: jest.fn(),
      }

      const result = await analyzer.analyzeBusinessMaturity(mockBusinessRecord)

      expect(result).toBeDefined()
      expect(result.maturityScore).toBeGreaterThanOrEqual(0)
    })

    test('should handle invalid website URLs', async () => {
      const businessWithInvalidUrl = {
        ...mockBusinessRecord,
        websiteUrl: 'invalid-url',
      }

      const result = await analyzer.analyzeBusinessMaturity(businessWithInvalidUrl)

      expect(result).toBeDefined()
      expect(result.maturityScore).toBeGreaterThanOrEqual(0)
    })

    test('should handle empty business descriptions', async () => {
      const businessWithoutDescription = {
        ...mockBusinessRecord,
        description: '',
      }

      const result = await analyzer.analyzeBusinessMaturity(businessWithoutDescription)

      expect(result).toBeDefined()
      expect(result.sizeIndicators.estimatedEmployeeCount).toBeLessThan(10)
    })

    test('should handle malformed HTML content', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue('<html><body><div>Incomplete HTML'),
        close: jest.fn(),
      }

      const digitalPresence = await (analyzer as any).analyzeDigitalPresence('https://acme.com', mockPage)

      expect(digitalPresence).toBeDefined()
      expect(digitalPresence.socialMediaAccounts).toBeDefined()
    })
  })

  describe('Performance and Efficiency', () => {
    test('should complete analysis within reasonable time', async () => {
      const startTime = Date.now()
      
      await analyzer.analyzeBusinessMaturity(mockBusinessRecord)
      
      const endTime = Date.now()
      const analysisTime = endTime - startTime
      
      expect(analysisTime).toBeLessThan(10000) // Should complete within 10 seconds
    })

    test('should handle concurrent analysis requests', async () => {
      const businesses = Array(5).fill(0).map((_, i) => ({
        ...mockBusinessRecord,
        id: `business-${i}`,
        businessName: `Business ${i}`,
        websiteUrl: `https://business${i}.com`,
      }))

      const startTime = Date.now()
      
      const promises = businesses.map(business => 
        analyzer.analyzeBusinessMaturity(business)
      )
      
      const results = await Promise.all(promises)
      
      const endTime = Date.now()
      const totalTime = endTime - startTime
      
      expect(results).toHaveLength(5)
      expect(totalTime).toBeLessThan(15000) // Should complete within 15 seconds
      
      results.forEach(result => {
        expect(result.maturityScore).toBeGreaterThanOrEqual(0)
        expect(result.maturityScore).toBeLessThanOrEqual(100)
      })
    })
  })
})
