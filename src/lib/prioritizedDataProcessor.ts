/**
 * Prioritized Data Processing System
 *
 * Processes scraped business data with priority-based deduplication
 * Priority order: Email (1st), Phone (2nd), Street Address (3rd), City (4th), ZIP (5th)
 */

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { addressParser, ParsedAddress } from '@/utils/addressParser'
import { phoneFormatter } from '@/utils/phoneFormatter'

export interface PrioritizedBusinessRecord {
  id: string
  email: string // Primary email (highest priority)
  phone: string // Primary phone number (standardized format)
  streetNumber: string // Street number (e.g., "123")
  streetName: string // Street name (e.g., "Main St")
  suite?: string // Suite/unit information
  city: string // City name
  state: string // State abbreviation
  zipCode: string // ZIP or ZIP+4
  businessName: string
  contactName: string
  website: string
  coordinates: string
  additionalEmails: string[] // Secondary emails
  additionalPhones: string[] // Secondary phones (standardized)
  confidence: number
  sources: string[] // URLs where this business was found
}

export interface DeduplicationKey {
  email: string
  phone: string
  streetNumber: string
  streetName: string
  city: string
  zipCode: string
}

export interface ProcessingStats {
  totalRecords: number
  duplicatesRemoved: number
  recordsWithEmail: number
  recordsWithPhone: number
  recordsWithAddress: number
  finalRecords: number
}

/**
 * Prioritized Data Processor for high-quality business contact extraction
 */
export class PrioritizedDataProcessor {
  private emailPriorityPatterns = [
    /^info@/i, // Priority 0 (highest)
    /^contact@/i, // Priority 1
    /^sales@/i, // Priority 2
    /^admin@/i, // Priority 3
    /^office@/i, // Priority 4
    /^hello@/i, // Priority 5
    /^support@/i, // Priority 6
    /^business@/i, // Priority 7
    /^mail@/i, // Priority 8
    /^general@/i, // Priority 9
  ]

  private phonePriorityPatterns = [
    /^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$/, // US format
    /^\([0-9]{3}\)\s[0-9]{3}-[0-9]{4}$/, // (555) 123-4567
    /^[0-9]{3}-[0-9]{3}-[0-9]{4}$/, // 555-123-4567
    /^[0-9]{10}$/, // 5551234567
  ]

  /**
   * Process and deduplicate business records with priority-based logic
   */
  async processBusinessRecords(records: BusinessRecord[]): Promise<{
    processedRecords: PrioritizedBusinessRecord[]
    stats: ProcessingStats
  }> {
    logger.info('PrioritizedDataProcessor', `Processing ${records.length} business records`)

    const stats: ProcessingStats = {
      totalRecords: records.length,
      duplicatesRemoved: 0,
      recordsWithEmail: 0,
      recordsWithPhone: 0,
      recordsWithAddress: 0,
      finalRecords: 0,
    }

    // Step 1: Convert to prioritized format
    const prioritizedRecords = records.map(record => this.convertToPrioritized(record))

    // Step 2: Filter records with valuable contact information
    const valuableRecords = prioritizedRecords.filter(record => {
      const hasEmail = record.email.length > 0
      const hasPhone = record.phone.length > 0
      const hasAddress = record.streetName.length > 0 || record.streetNumber.length > 0

      if (hasEmail) stats.recordsWithEmail++
      if (hasPhone) stats.recordsWithPhone++
      if (hasAddress) stats.recordsWithAddress++

      // Keep records that have at least email OR phone OR complete address
      return hasEmail || hasPhone || (hasAddress && record.city && record.zipCode)
    })

    logger.info(
      'PrioritizedDataProcessor',
      `Filtered to ${valuableRecords.length} valuable records`
    )

    // Step 3: Deduplicate based on priority fields
    const deduplicatedRecords = this.deduplicateByPriorityFields(valuableRecords)
    stats.duplicatesRemoved = valuableRecords.length - deduplicatedRecords.length
    stats.finalRecords = deduplicatedRecords.length

    logger.info(
      'PrioritizedDataProcessor',
      `Removed ${stats.duplicatesRemoved} duplicates, final count: ${stats.finalRecords}`
    )

    return {
      processedRecords: deduplicatedRecords,
      stats,
    }
  }

  /**
   * Convert BusinessRecord to PrioritizedBusinessRecord
   */
  private convertToPrioritized(record: BusinessRecord): PrioritizedBusinessRecord {
    // Prioritize emails
    const emails = this.prioritizeEmails(record.email || [])
    const primaryEmail = emails[0] || ''
    const additionalEmails = emails.slice(1)

    // Prioritize and format phones
    const phones = this.prioritizePhones([record.phone].filter(Boolean))
    const primaryPhone = this.formatPhoneNumber(phones[0] || '')
    const additionalPhones = phones
      .slice(1)
      .map(phone => this.formatPhoneNumber(phone))
      .filter(Boolean)

    // Parse address components using enhanced parser
    const address = record.address || {}
    const rawAddress = this.buildRawAddressString(address)
    const parsedAddress = addressParser.parseAddress(rawAddress, {
      allowPartialMatches: true,
      logErrors: false,
    })

    // Format coordinates
    const coordinates = record.coordinates
      ? `${record.coordinates.lat.toFixed(6)}, ${record.coordinates.lng.toFixed(6)}`
      : ''

    return {
      id: record.id,
      email: primaryEmail,
      phone: primaryPhone,
      streetNumber: parsedAddress.streetNumber || '',
      streetName: parsedAddress.streetName || this.cleanStreetAddress(address.street || ''),
      suite: parsedAddress.suite,
      city: parsedAddress.city || this.cleanCityName(address.city || ''),
      state: parsedAddress.state || this.cleanStateName(address.state || ''),
      zipCode: parsedAddress.zipCode || this.cleanZipCode(address.zipCode || ''),
      businessName: this.cleanBusinessName(record.businessName || ''),
      contactName: record.contactPerson || '',
      website: record.websiteUrl || '',
      coordinates,
      additionalEmails,
      additionalPhones,
      confidence: this.calculateRecordConfidence(record),
      sources: [record.websiteUrl].filter(Boolean),
    }
  }

  /**
   * Prioritize emails based on business value
   */
  private prioritizeEmails(emails: string[]): string[] {
    // Clean emails first, then validate
    const cleanedEmails = emails
      .map(email => email.toLowerCase().trim())
      .filter(email => this.isValidEmail(email))

    // Remove duplicates
    const uniqueEmails = Array.from(new Set(cleanedEmails))

    // Sort by priority patterns
    const sorted = uniqueEmails.sort((a, b) => {
      const aPriority = this.getEmailPriority(a)
      const bPriority = this.getEmailPriority(b)
      return aPriority - bPriority
    })

    return sorted
  }

  /**
   * Get email priority score (lower is better)
   */
  private getEmailPriority(email: string): number {
    for (let i = 0; i < this.emailPriorityPatterns.length; i++) {
      if (this.emailPriorityPatterns[i].test(email)) {
        return i
      }
    }
    return 999 // Lowest priority for unmatched patterns
  }

  /**
   * Prioritize phone numbers based on format quality
   */
  private prioritizePhones(phones: string[]): string[] {
    const validPhones = phones
      .filter(phone => phone && phone.trim().length > 0)
      .map(phone => this.cleanPhoneNumber(phone))
      .filter(phone => phone.length >= 10)

    // Remove duplicates
    const uniquePhones = Array.from(new Set(validPhones))

    // Sort by format quality
    return uniquePhones.sort((a, b) => {
      const aScore = this.getPhoneFormatScore(a)
      const bScore = this.getPhoneFormatScore(b)
      return bScore - aScore // Higher score is better
    })
  }

  /**
   * Format phone number using enhanced formatter
   */
  private formatPhoneNumber(phone: string): string {
    if (!phone) return ''

    const result = phoneFormatter.formatPhone(phone, {
      format: 'programmatic',
      removeCountryCode: true,
      strictValidation: false,
    })

    return result.formatted || ''
  }

  /**
   * Build raw address string from address components
   */
  private buildRawAddressString(address: BusinessRecord['address']): string {
    if (!address) return ''

    const parts = [address.street, address.city, address.state, address.zipCode].filter(Boolean)

    return parts.join(', ')
  }

  /**
   * Get phone format quality score
   */
  private getPhoneFormatScore(phone: string): number {
    for (let i = 0; i < this.phonePriorityPatterns.length; i++) {
      if (this.phonePriorityPatterns[i].test(phone)) {
        return this.phonePriorityPatterns.length - i
      }
    }
    return 0
  }

  /**
   * Deduplicate records based on priority fields
   */
  private deduplicateByPriorityFields(
    records: PrioritizedBusinessRecord[]
  ): PrioritizedBusinessRecord[] {
    const seenKeys = new Map<string, PrioritizedBusinessRecord>()
    const result: PrioritizedBusinessRecord[] = []

    for (const record of records) {
      const key = this.generateDeduplicationKey(record)
      const existing = seenKeys.get(key)

      if (!existing) {
        // New record
        seenKeys.set(key, record)
        result.push(record)
      } else {
        // Merge with existing record
        const merged = this.mergeRecords(existing, record)
        seenKeys.set(key, merged)

        // Replace in result array
        const index = result.findIndex(r => r.id === existing.id)
        if (index >= 0) {
          result[index] = merged
        }
      }
    }

    return result
  }

  /**
   * Generate deduplication key based on priority fields
   */
  private generateDeduplicationKey(record: PrioritizedBusinessRecord): string {
    const parts = [
      record.email.toLowerCase(),
      this.normalizePhone(record.phone),
      this.normalizeAddress(`${record.streetNumber} ${record.streetName}`),
      record.city.toLowerCase(),
      record.zipCode,
    ].filter(Boolean)

    return parts.join('|')
  }

  /**
   * Merge two records, keeping the best information
   */
  private mergeRecords(
    existing: PrioritizedBusinessRecord,
    incoming: PrioritizedBusinessRecord
  ): PrioritizedBusinessRecord {
    return {
      ...existing,
      // Keep the best email
      email: existing.email || incoming.email,
      // Keep the best phone
      phone: existing.phone || incoming.phone,
      // Merge additional emails
      additionalEmails: Array.from(
        new Set([
          ...existing.additionalEmails,
          ...incoming.additionalEmails,
          ...(incoming.email ? [incoming.email] : []),
        ])
      ).filter(email => email !== existing.email),
      // Merge additional phones
      additionalPhones: Array.from(
        new Set([
          ...existing.additionalPhones,
          ...incoming.additionalPhones,
          ...(incoming.phone ? [incoming.phone] : []),
        ])
      ).filter(phone => phone !== existing.phone),
      // Merge sources
      sources: Array.from(new Set([...existing.sources, ...incoming.sources])),
      // Use higher confidence
      confidence: Math.max(existing.confidence, incoming.confidence),
      // Keep the better business name (longer is usually better)
      businessName:
        existing.businessName.length > incoming.businessName.length
          ? existing.businessName
          : incoming.businessName,
      // Keep the better contact name
      contactName: existing.contactName || incoming.contactName,
    }
  }

  /**
   * Calculate confidence score for a record
   */
  private calculateRecordConfidence(record: BusinessRecord): number {
    let score = 0

    // Email presence and quality
    if (record.email && record.email.length > 0) {
      score += 0.4
      if (record.email.some(email => this.isBusinessEmail(email))) {
        score += 0.1
      }
    }

    // Phone presence
    if (record.phone) {
      score += 0.3
    }

    // Address completeness
    if (record.address) {
      if (record.address.street) score += 0.1
      if (record.address.city) score += 0.05
      if (record.address.state) score += 0.05
      if (record.address.zipCode) score += 0.05
    }

    // Contact person
    if (record.contactPerson) {
      score += 0.05
    }

    return Math.min(score, 1.0)
  }

  // Utility methods
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  private isBusinessEmail(email: string): boolean {
    const businessPatterns = /^(info|contact|sales|admin|office|hello|support|business)@/i
    return businessPatterns.test(email)
  }

  private cleanPhoneNumber(phone: string): string {
    return phone.replace(/[^\d]/g, '')
  }

  private normalizePhone(phone: string): string {
    return this.cleanPhoneNumber(phone)
  }

  private normalizeAddress(address: string): string {
    return address
      .toLowerCase()
      .replace(/[^\w\s]/g, '')
      .trim()
  }

  private cleanStreetAddress(address: string): string {
    return address.trim().replace(/\s+/g, ' ')
  }

  private cleanCityName(city: string): string {
    return city.trim().replace(/\s+/g, ' ')
  }

  private cleanStateName(state: string): string {
    return state.trim().toUpperCase()
  }

  private cleanZipCode(zip: string): string {
    return zip.replace(/[^\d-]/g, '').trim()
  }

  private cleanBusinessName(name: string): string {
    return name.trim().replace(/\s+/g, ' ')
  }

  private getPhoneFormatScore(phone: string): number {
    // Implementation for phone format scoring
    if (/^\([0-9]{3}\)\s[0-9]{3}-[0-9]{4}$/.test(phone)) return 4
    if (/^[0-9]{3}-[0-9]{3}-[0-9]{4}$/.test(phone)) return 3
    if (/^[0-9]{10}$/.test(phone)) return 2
    return 1
  }
}

/**
 * Default prioritized data processor instance
 */
export const prioritizedDataProcessor = new PrioritizedDataProcessor()
