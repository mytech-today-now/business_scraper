/**
 * Advanced Contact Information Extraction
 * Sophisticated algorithms for extracting business contact information
 */

import { Page } from 'puppeteer'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface ExtractedContact {
  emails: string[]
  phones: string[]
  addresses: string[]
  businessName: string
  socialMedia: SocialMediaProfile[]
  businessHours: BusinessHours[]
  contactForms: ContactForm[]
  structuredData: StructuredData[]
  confidence: ContactConfidence
}

export interface SocialMediaProfile {
  platform: string
  url: string
  handle?: string
}

export interface BusinessHours {
  day: string
  hours: string
  isOpen: boolean
}

export interface ContactForm {
  action: string
  method: string
  fields: string[]
}

export interface StructuredData {
  type: string
  data: any
}

export interface ContactConfidence {
  email: number
  phone: number
  address: number
  businessName: number
  overall: number
}

/**
 * Advanced Contact Information Extractor
 */
export class ContactExtractor {
  private emailPatterns = [
    // Standard email pattern
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    // Email with display name
    /\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    // Obfuscated emails (dot, at)
    /\b[A-Za-z0-9._%+-]+\s*(?:at|AT)\s*[A-Za-z0-9.-]+\s*(?:dot|DOT)\s*[A-Z|a-z]{2,}\b/g,
  ]

  private phonePatterns = [
    // US phone numbers
    /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
    // International format
    /\b\+?[1-9]\d{1,14}\b/g,
    // Formatted phone numbers
    /\b\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    // Phone with extension
    /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})(?:\s*(?:ext|extension|x)\.?\s*(\d+))?\b/g,
  ]

  private addressPatterns = [
    // Street address with number
    /\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b/gi,
    // PO Box
    /\bP\.?O\.?\s*Box\s+\d+\b/gi,
    // Suite/Unit numbers
    /\b(?:Suite|Ste|Unit|Apt|Apartment)\s*#?\s*[A-Za-z0-9]+\b/gi,
  ]

  private businessNameSelectors = [
    'h1',
    '[itemProp="name"]',
    '.business-name',
    '.company-name',
    '.site-title',
    'title',
    '[data-testid*="name"]',
    '[class*="business"]',
    '[class*="company"]',
  ]

  private socialMediaPatterns = {
    facebook: /(?:https?:\/\/)?(?:www\.)?facebook\.com\/[A-Za-z0-9._-]+/gi,
    twitter: /(?:https?:\/\/)?(?:www\.)?twitter\.com\/[A-Za-z0-9._-]+/gi,
    instagram: /(?:https?:\/\/)?(?:www\.)?instagram\.com\/[A-Za-z0-9._-]+/gi,
    linkedin: /(?:https?:\/\/)?(?:www\.)?linkedin\.com\/(?:company|in)\/[A-Za-z0-9._-]+/gi,
    youtube: /(?:https?:\/\/)?(?:www\.)?youtube\.com\/(?:channel|user|c)\/[A-Za-z0-9._-]+/gi,
  }

  /**
   * Extract comprehensive contact information from a page
   */
  async extractContactInfo(page: Page, url: string): Promise<ExtractedContact> {
    logger.debug('ContactExtractor', `Extracting contact info from: ${url}`)

    try {
      // Get page content
      const content = await page.content()
      const textContent = await page.evaluate(() => document.body.innerText || '')

      // Extract different types of information
      const emails = this.extractEmails(content, textContent)
      const phones = this.extractPhones(content, textContent)
      const addresses = this.extractAddresses(content, textContent)
      const businessName = await this.extractBusinessName(page, content)
      const socialMedia = this.extractSocialMedia(content)
      const businessHours = await this.extractBusinessHours(page)
      const contactForms = await this.extractContactForms(page)
      const structuredData = await this.extractStructuredData(page)

      // Calculate confidence scores
      const confidence = this.calculateConfidence({
        emails,
        phones,
        addresses,
        businessName,
        socialMedia,
        businessHours,
        contactForms,
        structuredData,
      })

      return {
        emails,
        phones,
        addresses,
        businessName,
        socialMedia,
        businessHours,
        contactForms,
        structuredData,
        confidence,
      }
    } catch (error) {
      logger.error('ContactExtractor', `Failed to extract contact info from ${url}`, error)
      return this.getEmptyContact()
    }
  }

  /**
   * Extract email addresses
   */
  private extractEmails(content: string, textContent: string): string[] {
    const emails = new Set<string>()

    // Apply all email patterns
    for (const pattern of this.emailPatterns) {
      const matches = content.match(pattern) || []
      matches.forEach(email => {
        // Clean and validate email
        const cleanEmail = this.cleanEmail(email)
        if (this.isValidEmail(cleanEmail)) {
          emails.add(cleanEmail.toLowerCase())
        }
      })
    }

    // Extract from text content as well
    for (const pattern of this.emailPatterns) {
      const matches = textContent.match(pattern) || []
      matches.forEach(email => {
        const cleanEmail = this.cleanEmail(email)
        if (this.isValidEmail(cleanEmail)) {
          emails.add(cleanEmail.toLowerCase())
        }
      })
    }

    const filteredEmails = Array.from(emails).filter(email => !this.isCommonInvalidEmail(email))
    return this.prioritizeEmails(filteredEmails)
  }

  /**
   * Extract phone numbers
   */
  private extractPhones(content: string, textContent: string): string[] {
    const phones = new Set<string>()

    // Apply all phone patterns
    for (const pattern of this.phonePatterns) {
      const matches = content.match(pattern) || []
      matches.forEach(phone => {
        const cleanPhone = this.cleanPhone(phone)
        if (this.isValidPhone(cleanPhone)) {
          phones.add(cleanPhone)
        }
      })
    }

    // Extract from text content
    for (const pattern of this.phonePatterns) {
      const matches = textContent.match(pattern) || []
      matches.forEach(phone => {
        const cleanPhone = this.cleanPhone(phone)
        if (this.isValidPhone(cleanPhone)) {
          phones.add(cleanPhone)
        }
      })
    }

    return Array.from(phones).map(phone => this.formatPhoneNumber(phone))
  }

  /**
   * Extract addresses
   */
  private extractAddresses(content: string, textContent: string): string[] {
    const addresses = new Set<string>()

    // Apply address patterns
    for (const pattern of this.addressPatterns) {
      const matches = textContent.match(pattern) || []
      matches.forEach(address => {
        const cleanAddress = address.trim()
        if (cleanAddress.length > 10) {
          addresses.add(cleanAddress)
        }
      })
    }

    return Array.from(addresses)
  }

  /**
   * Extract business name
   */
  private async extractBusinessName(page: Page, content: string): Promise<string> {
    try {
      // Try structured selectors first
      for (const selector of this.businessNameSelectors) {
        try {
          const element = await page.$(selector)
          if (element) {
            const text = await element.evaluate(el => el.textContent?.trim())
            if (text && text.length > 2 && text.length < 100) {
              return text
            }
          }
        } catch (error) {
          // Continue to next selector
        }
      }

      // Fallback to page title
      const title = await page.title()
      if (title && title.length > 2) {
        const titleParts = title.split('|')[0]?.split('-')[0]
        return titleParts ? titleParts.trim() : ''
      }

      return ''
    } catch (error) {
      logger.warn('ContactExtractor', 'Failed to extract business name', error)
      return ''
    }
  }

  /**
   * Extract social media profiles
   */
  private extractSocialMedia(content: string): SocialMediaProfile[] {
    const profiles: SocialMediaProfile[] = []

    for (const [platform, pattern] of Object.entries(this.socialMediaPatterns)) {
      const matches = content.match(pattern) || []
      matches.forEach(url => {
        const cleanUrl = url.replace(/^(?:https?:\/\/)?(?:www\.)?/, 'https://www.')
        profiles.push({
          platform,
          url: cleanUrl,
          handle: this.extractSocialHandle(cleanUrl, platform),
        })
      })
    }

    return profiles
  }

  /**
   * Extract business hours
   */
  private async extractBusinessHours(page: Page): Promise<BusinessHours[]> {
    try {
      const hours = await page.evaluate(() => {
        const hourElements = document.querySelectorAll('[class*="hours"], [class*="time"], [itemProp*="hours"]')
        const results: BusinessHours[] = []

        hourElements.forEach(element => {
          const text = element.textContent?.trim()
          if (text) {
            // Parse business hours (simplified)
            const dayMatch = text.match(/(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)/i)
            const timeMatch = text.match(/(\d{1,2}:\d{2}\s*(?:AM|PM)?)/gi)
            
            if (dayMatch && dayMatch[1] && timeMatch) {
              results.push({
                day: dayMatch[1],
                hours: timeMatch.join(' - '),
                isOpen: !text.toLowerCase().includes('closed'),
              })
            }
          }
        })

        return results
      })

      return hours
    } catch (error) {
      logger.warn('ContactExtractor', 'Failed to extract business hours', error)
      return []
    }
  }

  /**
   * Extract contact forms
   */
  private async extractContactForms(page: Page): Promise<ContactForm[]> {
    try {
      const forms = await page.evaluate(() => {
        const formElements = document.querySelectorAll('form')
        const results: ContactForm[] = []

        formElements.forEach(form => {
          const action = form.getAttribute('action') || ''
          const method = form.getAttribute('method') || 'GET'
          const inputs = Array.from(form.querySelectorAll('input, textarea, select'))
          const fields = inputs.map(input => 
            input.getAttribute('name') || input.getAttribute('id') || ''
          ).filter(Boolean)

          if (fields.length > 0) {
            results.push({ action, method, fields })
          }
        })

        return results
      })

      return forms
    } catch (error) {
      logger.warn('ContactExtractor', 'Failed to extract contact forms', error)
      return []
    }
  }

  /**
   * Extract structured data (Schema.org)
   */
  private async extractStructuredData(page: Page): Promise<StructuredData[]> {
    try {
      const structuredData = await page.evaluate(() => {
        const scripts = document.querySelectorAll('script[type="application/ld+json"]')
        const results: StructuredData[] = []

        scripts.forEach(script => {
          try {
            const data = JSON.parse(script.textContent || '')
            if (data['@type']) {
              results.push({
                type: data['@type'],
                data: data,
              })
            }
          } catch (error) {
            // Invalid JSON, skip
          }
        })

        return results
      })

      return structuredData
    } catch (error) {
      logger.warn('ContactExtractor', 'Failed to extract structured data', error)
      return []
    }
  }

  /**
   * Calculate confidence scores
   */
  private calculateConfidence(contact: Partial<ExtractedContact>): ContactConfidence {
    const emailConfidence = Math.min((contact.emails?.length || 0) * 0.3, 1.0)
    const phoneConfidence = Math.min((contact.phones?.length || 0) * 0.4, 1.0)
    const addressConfidence = Math.min((contact.addresses?.length || 0) * 0.5, 1.0)
    const businessNameConfidence = contact.businessName ? 0.8 : 0.0

    const overall = (emailConfidence + phoneConfidence + addressConfidence + businessNameConfidence) / 4

    return {
      email: emailConfidence,
      phone: phoneConfidence,
      address: addressConfidence,
      businessName: businessNameConfidence,
      overall,
    }
  }

  /**
   * Clean email address
   */
  private cleanEmail(email: string): string {
    return email
      .replace(/\s+/g, '')
      .replace(/\(at\)/gi, '@')
      .replace(/\(dot\)/gi, '.')
      .replace(/\[at\]/gi, '@')
      .replace(/\[dot\]/gi, '.')
      .toLowerCase()
  }

  /**
   * Validate email address
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email) && email.length < 100
  }

  /**
   * Check if email is commonly invalid
   */
  private isCommonInvalidEmail(email: string): boolean {
    const invalidPatterns = [
      'example.com',
      'test.com',
      'placeholder',
      'noreply',
      'no-reply',
      'donotreply',
    ]
    return invalidPatterns.some(pattern => email.includes(pattern))
  }

  /**
   * Clean phone number
   */
  private cleanPhone(phone: string): string {
    return phone.replace(/[^\d+]/g, '')
  }

  /**
   * Validate phone number
   */
  private isValidPhone(phone: string): boolean {
    const cleanPhone = phone.replace(/[^\d]/g, '')
    return cleanPhone.length >= 10 && cleanPhone.length <= 15
  }

  /**
   * Enhanced email validation and prioritization
   */
  private prioritizeEmails(emails: string[]): string[] {
    const emailPriority = {
      // High priority - business emails
      business: /^(info|contact|sales|support|admin|office|hello|inquiries)@/i,
      // Medium priority - general emails
      general: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      // Low priority - personal or generic
      personal: /^(noreply|no-reply|donotreply|test|example)@/i
    }

    return emails
      .filter(email => this.isValidEmail(email))
      .sort((a, b) => {
        // Prioritize business emails
        if (emailPriority.business.test(a) && !emailPriority.business.test(b)) return -1
        if (!emailPriority.business.test(a) && emailPriority.business.test(b)) return 1

        // Deprioritize personal/generic emails
        if (emailPriority.personal.test(a) && !emailPriority.personal.test(b)) return 1
        if (!emailPriority.personal.test(a) && emailPriority.personal.test(b)) return -1

        return 0
      })
  }

  /**
   * Format and validate phone numbers
   */
  private formatPhoneNumber(phone: string): string {
    // Remove all non-digit characters except +
    const digits = phone.replace(/[^\d+]/g, '')

    // Handle US phone numbers
    const cleanDigits = digits.replace(/^\+?1?/, '') // Remove country code
    if (cleanDigits.length === 10) {
      return `(${cleanDigits.slice(0, 3)}) ${cleanDigits.slice(3, 6)}-${cleanDigits.slice(6)}`
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
    }

    // Return original if can't format
    return phone
  }

  /**
   * Extract social media handle
   */
  private extractSocialHandle(url: string, platform: string): string {
    const match = url.match(/\/([^\/\?]+)(?:\?|$)/)
    return match && match[1] ? match[1] : ''
  }

  /**
   * Get empty contact structure
   */
  private getEmptyContact(): ExtractedContact {
    return {
      emails: [],
      phones: [],
      addresses: [],
      businessName: '',
      socialMedia: [],
      businessHours: [],
      contactForms: [],
      structuredData: [],
      confidence: {
        email: 0,
        phone: 0,
        address: 0,
        businessName: 0,
        overall: 0,
      },
    }
  }
}

/**
 * Default contact extractor instance
 */
export const contactExtractor = new ContactExtractor()
