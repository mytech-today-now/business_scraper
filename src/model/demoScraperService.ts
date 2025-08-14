'use client'

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

/**
 * Demo scraper service for development and testing
 * Generates realistic sample data without actual web scraping
 */
export class DemoScraperService {
  private isInitialized = false

  /**
   * Sample business data for demonstration
   */
  private sampleBusinesses: Partial<BusinessRecord>[] = [
    {
      businessName: 'Bella Vista Restaurant',
      email: ['info@bellavista.com', 'reservations@bellavista.com'],
      phone: '(555) 123-4567',
      websiteUrl: 'https://bellavista.com',
      address: {
        street: '123 Main Street',
        city: 'Downtown',
        state: 'CA',
        zipCode: '90210',
      },
      contactPerson: 'Maria Rodriguez',
      industry: 'Restaurants & Food Service',
    },
    {
      businessName: 'TechFlow Solutions',
      email: ['contact@techflow.com'],
      phone: '(555) 987-6543',
      websiteUrl: 'https://techflow.com',
      address: {
        street: '456 Innovation Drive',
        suite: 'Suite 200',
        city: 'Tech Valley',
        state: 'CA',
        zipCode: '90211',
      },
      contactPerson: 'John Smith',
      industry: 'Professional Services',
    },
    {
      businessName: 'Green Valley Medical Center',
      email: ['appointments@greenvalley.com', 'info@greenvalley.com'],
      phone: '(555) 456-7890',
      websiteUrl: 'https://greenvalleymedical.com',
      address: {
        street: '789 Health Boulevard',
        city: 'Wellness City',
        state: 'CA',
        zipCode: '90212',
      },
      contactPerson: 'Dr. Sarah Johnson',
      industry: 'Healthcare & Medical',
    },
    {
      businessName: 'Elite Fitness Gym',
      email: ['membership@elitefitness.com'],
      phone: '(555) 321-0987',
      websiteUrl: 'https://elitefitness.com',
      address: {
        street: '321 Fitness Avenue',
        city: 'Active Town',
        state: 'CA',
        zipCode: '90213',
      },
      industry: 'Health & Fitness',
    },
    {
      businessName: 'Artisan Coffee Roasters',
      email: ['hello@artisancoffee.com'],
      phone: '(555) 654-3210',
      websiteUrl: 'https://artisancoffee.com',
      address: {
        street: '654 Bean Street',
        city: 'Coffee District',
        state: 'CA',
        zipCode: '90214',
      },
      contactPerson: 'Mike Chen',
      industry: 'Restaurants & Food Service',
    },
  ]

  /**
   * Initialize the demo scraper
   */
  async initialize(): Promise<void> {
    // Simulate initialization delay
    await new Promise(resolve => setTimeout(resolve, 1000))
    this.isInitialized = true
    logger.info('DemoScraper', 'Demo scraper initialized')
  }

  /**
   * Search for demo websites
   */
  async searchForWebsites(
    query: string,
    zipCode: string,
    maxResults: number = 50
  ): Promise<string[]> {
    // Simulate search delay
    await new Promise(resolve => setTimeout(resolve, 2000))

    const demoUrls = [
      'https://bellavista.com',
      'https://techflow.com',
      'https://greenvalleymedical.com',
      'https://elitefitness.com',
      'https://artisancoffee.com',
      'https://example-business1.com',
      'https://example-business2.com',
      'https://example-business3.com',
    ]

    const filteredUrls = demoUrls.slice(0, Math.min(maxResults, demoUrls.length))
    logger.info('DemoScraper', `Found ${filteredUrls.length} demo URLs for query: ${query}`)
    
    return filteredUrls
  }

  /**
   * Scrape demo business data
   */
  async scrapeWebsite(url: string, depth: number = 2, maxPages: number = 5): Promise<BusinessRecord[]> {
    // Simulate scraping delay
    await new Promise(resolve => setTimeout(resolve, 3000))

    // Find matching sample business or create a random one
    const matchingBusiness = this.sampleBusinesses.find(
      business => business.websiteUrl === url
    )

    if (matchingBusiness) {
      const business: BusinessRecord = {
        id: `demo-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        businessName: matchingBusiness.businessName || 'Demo Business',
        email: matchingBusiness.email || ['demo@example.com'],
        phone: matchingBusiness.phone,
        websiteUrl: matchingBusiness.websiteUrl || url,
        address: matchingBusiness.address || {
          street: '123 Demo Street',
          city: 'Demo City',
          state: 'CA',
          zipCode: '90210',
          country: 'USA'
        },
        contactPerson: matchingBusiness.contactPerson,
        coordinates: {
          lat: 34.0522 + (Math.random() - 0.5) * 0.1,
          lng: -118.2437 + (Math.random() - 0.5) * 0.1,
        },
        industry: matchingBusiness.industry || 'General Business',
        scrapedAt: new Date(),
      }

      logger.info('DemoScraper', `Scraped demo business from: ${url} (depth: ${depth}, maxPages: ${maxPages})`)
      return [business]
    }

    // Generate random business data
    const randomBusiness: BusinessRecord = {
      id: `demo-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      businessName: this.generateRandomBusinessName(),
      email: [this.generateRandomEmail()],
      phone: this.generateRandomPhone(),
      websiteUrl: url,
      address: this.generateRandomAddress(),
      industry: 'General Business',
      scrapedAt: new Date(),
    }

    logger.info('DemoScraper', `Generated random business data for: ${url} (depth: ${depth}, maxPages: ${maxPages})`)
    return [randomBusiness]
  }

  /**
   * Cleanup demo scraper
   */
  async cleanup(): Promise<void> {
    // Simulate cleanup delay
    await new Promise(resolve => setTimeout(resolve, 500))
    this.isInitialized = false
    logger.info('DemoScraper', 'Demo scraper cleaned up')
  }

  /**
   * Get demo statistics
   */
  getStats() {
    return {
      totalSites: 5,
      successfulScrapes: 5,
      failedScrapes: 0,
      totalBusinesses: 5,
      startTime: new Date(Date.now() - 60000), // 1 minute ago
      endTime: new Date(),
      duration: 60000,
    }
  }

  /**
   * Reset demo statistics
   */
  resetStats(): void {
    logger.info('DemoScraper', 'Demo stats reset')
  }

  /**
   * Generate random business name
   */
  private generateRandomBusinessName(): string {
    const prefixes = ['Elite', 'Premium', 'Quality', 'Professional', 'Expert', 'Modern', 'Classic']
    const types = ['Solutions', 'Services', 'Group', 'Company', 'Associates', 'Partners', 'Enterprises']
    
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)]
    const type = types[Math.floor(Math.random() * types.length)]
    
    return `${prefix} ${type}`
  }

  /**
   * Generate random email
   */
  private generateRandomEmail(): string {
    const domains = ['business.com', 'company.org', 'services.net', 'solutions.com']
    const domain = domains[Math.floor(Math.random() * domains.length)]
    
    return `info@${domain}`
  }

  /**
   * Generate random phone number
   */
  private generateRandomPhone(): string {
    const areaCode = Math.floor(Math.random() * 900) + 100
    const exchange = Math.floor(Math.random() * 900) + 100
    const number = Math.floor(Math.random() * 9000) + 1000
    
    return `(${areaCode}) ${exchange}-${number}`
  }

  /**
   * Generate random address
   */
  private generateRandomAddress() {
    const streets = ['Main St', 'Oak Ave', 'Pine Rd', 'Elm Dr', 'Maple Ln', 'Cedar Blvd']
    const cities = ['Springfield', 'Riverside', 'Franklin', 'Georgetown', 'Madison', 'Clinton']
    const states = ['CA', 'NY', 'TX', 'FL', 'IL', 'PA']
    
    const streetNumber = Math.floor(Math.random() * 9000) + 1000
    const street = streets[Math.floor(Math.random() * streets.length)]
    const city = cities[Math.floor(Math.random() * cities.length)]
    const state = states[Math.floor(Math.random() * states.length)]
    const zipCode = Math.floor(Math.random() * 90000) + 10000
    
    return {
      street: `${streetNumber} ${street}`,
      city: city || 'Springfield',
      state: state || 'CA',
      zipCode: zipCode.toString(),
    }
  }
}

/**
 * Default demo scraper instance
 */
export const demoScraperService = new DemoScraperService()
