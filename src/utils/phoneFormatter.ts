/**
 * Enhanced Phone Number Formatter
 *
 * Provides comprehensive phone number standardization for programmatic access.
 * Assumes all numbers are in the +1 zone (US/Canada) and formats them consistently.
 */

import { logger } from './logger'

export interface FormattedPhone {
  formatted: string
  digits: string
  areaCode: string
  exchange: string
  number: string
  isValid: boolean
  confidence: number
}

export interface PhoneFormattingOptions {
  format?: 'standard' | 'programmatic' | 'display'
  removeCountryCode?: boolean
  strictValidation?: boolean
  logErrors?: boolean
}

/**
 * Enhanced Phone Number Formatter Class
 */
export class PhoneFormatter {
  // Valid US/Canada area codes (partial list of most common ones)
  private readonly validAreaCodes = new Set([
    '201',
    '202',
    '203',
    '205',
    '206',
    '207',
    '208',
    '209',
    '210',
    '212',
    '213',
    '214',
    '215',
    '216',
    '217',
    '218',
    '219',
    '224',
    '225',
    '228',
    '229',
    '231',
    '234',
    '239',
    '240',
    '248',
    '251',
    '252',
    '253',
    '254',
    '256',
    '260',
    '262',
    '267',
    '269',
    '270',
    '276',
    '281',
    '301',
    '302',
    '303',
    '304',
    '305',
    '307',
    '308',
    '309',
    '310',
    '312',
    '313',
    '314',
    '315',
    '316',
    '317',
    '318',
    '319',
    '320',
    '321',
    '323',
    '325',
    '330',
    '331',
    '334',
    '336',
    '337',
    '339',
    '347',
    '351',
    '352',
    '360',
    '361',
    '386',
    '401',
    '402',
    '404',
    '405',
    '406',
    '407',
    '408',
    '409',
    '410',
    '412',
    '413',
    '414',
    '415',
    '417',
    '419',
    '423',
    '424',
    '425',
    '430',
    '432',
    '434',
    '435',
    '440',
    '442',
    '443',
    '458',
    '469',
    '470',
    '475',
    '478',
    '479',
    '480',
    '484',
    '501',
    '502',
    '503',
    '504',
    '505',
    '507',
    '508',
    '509',
    '510',
    '512',
    '513',
    '515',
    '516',
    '517',
    '518',
    '520',
    '530',
    '540',
    '541',
    '551',
    '559',
    '561',
    '562',
    '563',
    '564',
    '567',
    '570',
    '571',
    '573',
    '574',
    '575',
    '580',
    '585',
    '586',
    '601',
    '602',
    '603',
    '605',
    '606',
    '607',
    '608',
    '609',
    '610',
    '612',
    '614',
    '615',
    '616',
    '617',
    '618',
    '619',
    '620',
    '623',
    '626',
    '628',
    '629',
    '630',
    '631',
    '636',
    '641',
    '646',
    '650',
    '651',
    '657',
    '660',
    '661',
    '662',
    '667',
    '669',
    '678',
    '681',
    '682',
    '701',
    '702',
    '703',
    '704',
    '706',
    '707',
    '708',
    '712',
    '713',
    '714',
    '715',
    '716',
    '717',
    '718',
    '719',
    '720',
    '724',
    '725',
    '727',
    '731',
    '732',
    '734',
    '737',
    '740',
    '743',
    '747',
    '754',
    '757',
    '760',
    '762',
    '763',
    '765',
    '770',
    '772',
    '773',
    '774',
    '775',
    '781',
    '785',
    '786',
    '787',
    '801',
    '802',
    '803',
    '804',
    '805',
    '806',
    '808',
    '810',
    '812',
    '813',
    '814',
    '815',
    '816',
    '817',
    '818',
    '828',
    '830',
    '831',
    '832',
    '843',
    '845',
    '847',
    '848',
    '850',
    '856',
    '857',
    '858',
    '859',
    '860',
    '862',
    '863',
    '864',
    '865',
    '870',
    '872',
    '878',
    '901',
    '903',
    '904',
    '906',
    '907',
    '908',
    '909',
    '910',
    '912',
    '913',
    '914',
    '915',
    '916',
    '917',
    '918',
    '919',
    '920',
    '925',
    '928',
    '929',
    '931',
    '934',
    '936',
    '937',
    '940',
    '941',
    '947',
    '949',
    '951',
    '952',
    '954',
    '956',
    '959',
    '970',
    '971',
    '972',
    '973',
    '978',
    '979',
    '980',
    '984',
    '985',
    '989',
  ])

  /**
   * Format a phone number for programmatic access
   */
  formatPhone(rawPhone: string, options: PhoneFormattingOptions = {}): FormattedPhone {
    const {
      format = 'programmatic',
      removeCountryCode = true,
      strictValidation = false,
      logErrors = false,
    } = options

    if (!rawPhone || typeof rawPhone !== 'string') {
      return this.createEmptyPhone()
    }

    try {
      // Clean the phone number
      const cleaned = this.cleanPhoneNumber(rawPhone)

      // Extract digits
      const digits = this.extractDigits(cleaned)

      // Validate and parse
      const parsed = this.parsePhoneDigits(digits, removeCountryCode, strictValidation)

      if (!parsed.isValid) {
        if (logErrors) {
          logger.warn('PhoneFormatter', `Invalid phone number: ${rawPhone}`, { digits, parsed })
        }
        return this.createEmptyPhone()
      }

      // Format according to requested format
      const formatted = this.formatByType(parsed, format)

      return {
        formatted,
        digits: parsed.digits,
        areaCode: parsed.areaCode,
        exchange: parsed.exchange,
        number: parsed.number,
        isValid: parsed.isValid,
        confidence: parsed.confidence,
      }
    } catch (error) {
      if (logErrors) {
        logger.error('PhoneFormatter', `Failed to format phone: ${rawPhone}`, error)
      }
      return this.createEmptyPhone()
    }
  }

  /**
   * Clean phone number string
   */
  private cleanPhoneNumber(phone: string): string {
    return phone
      .trim()
      .replace(/\s*(ext|extension|x)\s*\d+.*$/i, '') // Remove extensions first
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/[^\d\s\-\(\)\+\.]/g, '') // Remove invalid characters
  }

  /**
   * Extract only digits from phone string
   */
  private extractDigits(phone: string): string {
    return phone.replace(/\D/g, '')
  }

  /**
   * Parse phone digits into components
   */
  private parsePhoneDigits(
    digits: string,
    removeCountryCode: boolean,
    strictValidation: boolean
  ): {
    digits: string
    areaCode: string
    exchange: string
    number: string
    isValid: boolean
    confidence: number
  } {
    let workingDigits = digits
    let confidence = 0.5 // Start with base confidence

    // Handle country code removal
    if (removeCountryCode && workingDigits.length === 11 && workingDigits.startsWith('1')) {
      workingDigits = workingDigits.substring(1)
      confidence += 0.1
    }

    // For non-removal case, allow 11 digits if starts with 1
    const expectedLength = removeCountryCode ? 10 : workingDigits.startsWith('1') ? 11 : 10

    // Must be exactly 10 digits for US/Canada (or 11 with country code)
    if (workingDigits.length !== expectedLength) {
      return {
        digits: workingDigits,
        areaCode: '',
        exchange: '',
        number: '',
        isValid: false,
        confidence: 0,
      }
    }

    // Extract components (skip country code if present)
    const startIndex = workingDigits.length === 11 ? 1 : 0
    const areaCode = workingDigits.substring(startIndex, startIndex + 3)
    const exchange = workingDigits.substring(startIndex + 3, startIndex + 6)
    const number = workingDigits.substring(startIndex + 6, startIndex + 10)

    // Validate area code
    if (strictValidation && !this.validAreaCodes.has(areaCode)) {
      confidence -= 0.3
    } else if (this.validAreaCodes.has(areaCode)) {
      confidence += 0.2
    }

    // Validate exchange (first digit cannot be 0 or 1)
    if (exchange[0] === '0' || exchange[0] === '1') {
      if (strictValidation) {
        return {
          digits: workingDigits,
          areaCode,
          exchange,
          number,
          isValid: false,
          confidence: 0,
        }
      }
      confidence -= 0.1
    } else {
      confidence += 0.1
    }

    // Validate number part (first digit cannot be 0 or 1)
    if (number[0] === '0' || number[0] === '1') {
      if (strictValidation) {
        return {
          digits: workingDigits,
          areaCode,
          exchange,
          number,
          isValid: false,
          confidence: 0,
        }
      }
      confidence -= 0.1
    } else {
      confidence += 0.1
    }

    // Check for obviously invalid patterns
    if (this.isInvalidPattern(workingDigits)) {
      if (strictValidation) {
        return {
          digits: workingDigits,
          areaCode,
          exchange,
          number,
          isValid: false,
          confidence: 0,
        }
      }
      confidence -= 0.3
    }

    // Ensure minimum confidence for valid format
    confidence = Math.max(confidence, 0.1)

    return {
      digits: workingDigits,
      areaCode,
      exchange,
      number,
      isValid: true, // If we got here, it's a valid 10-digit format
      confidence: Math.min(confidence, 1.0),
    }
  }

  /**
   * Check for invalid phone number patterns
   */
  private isInvalidPattern(digits: string): boolean {
    // All same digit
    if (/^(\d)\1{9}$/.test(digits)) return true

    // Sequential digits
    if (digits === '1234567890' || digits === '0123456789') return true

    // Common fake numbers
    const fakeNumbers = ['5555555555', '1111111111', '0000000000', '1234567890', '9876543210']

    return fakeNumbers.includes(digits)
  }

  /**
   * Format phone number by type
   */
  private formatByType(
    parsed: { digits: string; areaCode: string; exchange: string; number: string },
    format: string
  ): string {
    const { areaCode, exchange, number } = parsed

    switch (format) {
      case 'standard':
        return `(${areaCode}) ${exchange}-${number}`

      case 'programmatic':
        return `${areaCode}${exchange}${number}`

      case 'display':
        return `${areaCode}-${exchange}-${number}`

      default:
        return `${areaCode}${exchange}${number}`
    }
  }

  /**
   * Create empty phone structure
   */
  private createEmptyPhone(): FormattedPhone {
    return {
      formatted: '',
      digits: '',
      areaCode: '',
      exchange: '',
      number: '',
      isValid: false,
      confidence: 0,
    }
  }

  /**
   * Batch format multiple phone numbers
   */
  formatMultiplePhones(phones: string[], options: PhoneFormattingOptions = {}): FormattedPhone[] {
    return phones.map(phone => this.formatPhone(phone, options))
  }

  /**
   * Validate if a phone number is likely valid
   */
  isValidPhone(phone: string, strictValidation = false): boolean {
    const result = this.formatPhone(phone, { strictValidation })
    return result.isValid && result.confidence > 0.1
  }

  /**
   * Get the best phone number from a list
   */
  getBestPhone(phones: string[], options: PhoneFormattingOptions = {}): FormattedPhone {
    const formatted = this.formatMultiplePhones(phones, options)
    const valid = formatted.filter(phone => phone.isValid)

    if (valid.length === 0) {
      return this.createEmptyPhone()
    }

    // Return the one with highest confidence
    return valid.reduce((best, current) => (current.confidence > best.confidence ? current : best))
  }
}

/**
 * Default phone formatter instance
 */
export const phoneFormatter = new PhoneFormatter()

/**
 * Quick format function for common use cases
 */
export function formatPhoneNumber(
  phone: string,
  format: 'standard' | 'programmatic' | 'display' = 'programmatic'
): string {
  const result = phoneFormatter.formatPhone(phone, { format, removeCountryCode: true })
  return result.formatted
}

/**
 * Quick validation function
 */
export function isValidPhoneNumber(phone: string): boolean {
  return phoneFormatter.isValidPhone(phone, false)
}
