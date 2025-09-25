/**
 * Address Input Handler Utility
 *
 * Handles various address input formats and extracts ZIP codes gracefully
 * with proper error handling and fallbacks.
 */

import { logger } from '@/utils/logger'

export interface AddressParseResult {
  zipCode: string | null
  originalInput: string
  wasExtracted: boolean
  extractedFrom: 'zip-only' | 'full-address' | 'partial-address' | 'city-state-zip' | 'unknown'
  confidence: 'high' | 'medium' | 'low'
  warning?: string
  error?: string
}

export interface AddressComponents {
  street?: string
  city?: string
  state?: string
  zipCode?: string
  suite?: string
}

/**
 * Address Input Handler Class
 */
export class AddressInputHandler {
  private static readonly ZIP_REGEX = /\b(\d{5})(?:-\d{4})?\b/g
  private static readonly ZIP_ONLY_REGEX = /^\s*(\d{5})(?:-\d{4})?\s*$/
  private static readonly FULL_ADDRESS_REGEX =
    /^(.+?),?\s*([A-Za-z\s]+),?\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)\s*$/
  private static readonly CITY_STATE_ZIP_REGEX =
    /^([A-Za-z\s]+),?\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)\s*$/

  // Enhanced debouncing for logging to prevent spam
  private static lastLoggedZip: string | null = null
  private static lastLogTime: number = 0
  private static logCount: number = 0
  private static readonly LOG_DEBOUNCE_MS = 10000 // 10 seconds (increased from 5)
  private static readonly MAX_LOGS_PER_SESSION = 5 // Limit logs per session
  private static readonly STATE_ABBREVIATIONS = new Set([
    'AL',
    'AK',
    'AZ',
    'AR',
    'CA',
    'CO',
    'CT',
    'DE',
    'FL',
    'GA',
    'HI',
    'ID',
    'IL',
    'IN',
    'IA',
    'KS',
    'KY',
    'LA',
    'ME',
    'MD',
    'MA',
    'MI',
    'MN',
    'MS',
    'MO',
    'MT',
    'NE',
    'NV',
    'NH',
    'NJ',
    'NM',
    'NY',
    'NC',
    'ND',
    'OH',
    'OK',
    'OR',
    'PA',
    'RI',
    'SC',
    'SD',
    'TN',
    'TX',
    'UT',
    'VT',
    'VA',
    'WA',
    'WV',
    'WI',
    'WY',
    'DC',
  ])

  /**
   * Enhanced helper method to log ZIP code detection with intelligent debouncing
   * Fixed to prevent duplicate logging and ANSI color codes
   */
  private static logZipCodeDetection(zipCode: string, context: string): void {
    const now = Date.now()

    // Check if we've exceeded the session log limit
    if (this.logCount >= this.MAX_LOGS_PER_SESSION) {
      return // Silently skip logging to prevent spam
    }

    // Enhanced deduplication: check both ZIP code and context to prevent identical logs
    const logKey = `${zipCode}-${context}`
    const shouldLog = this.lastLoggedZip !== logKey || now - this.lastLogTime > this.LOG_DEBOUNCE_MS

    if (shouldLog) {
      // Use debug level to reduce console noise and prevent INFO level spam
      // Only log in development to reduce production noise
      if (process.env.NODE_ENV === 'development') {
        logger.debug('AddressInputHandler', `ZIP code input detected: ${zipCode} (${context})`)
      }

      this.lastLoggedZip = logKey
      this.lastLogTime = now
      this.logCount++

      // Log a summary message when approaching the limit
      if (this.logCount === this.MAX_LOGS_PER_SESSION - 1) {
        logger.debug('AddressInputHandler', 'Approaching log limit, further ZIP code detections will be silent')
      }
    }
  }

  /**
   * Parse address input and extract ZIP code with comprehensive error handling
   */
  static parseAddressInput(input: string): AddressParseResult {
    const result: AddressParseResult = {
      zipCode: null,
      originalInput: input.trim(),
      wasExtracted: false,
      extractedFrom: 'unknown',
      confidence: 'low',
    }

    try {
      // Handle empty input
      if (!input || input.trim().length === 0) {
        result.error = 'Input is empty'
        return result
      }

      const trimmedInput = input.trim()

      // Early return for incomplete input (less than 5 characters)
      // This prevents premature validation warnings while user is typing
      if (trimmedInput.length < 5) {
        result.error = 'Incomplete input - continue typing'
        return result
      }

      // Strategy 1: Check if input is already just a ZIP code
      const zipOnlyMatch = trimmedInput.match(this.ZIP_ONLY_REGEX)
      if (zipOnlyMatch) {
        result.zipCode = zipOnlyMatch[1]
        result.wasExtracted = false
        result.extractedFrom = 'zip-only'
        result.confidence = 'high'
        this.logZipCodeDetection(result.zipCode, 'zip-only')
        return result
      }

      // Strategy 2: Try to parse as full address (street, city, state, zip)
      const fullAddressMatch = trimmedInput.match(this.FULL_ADDRESS_REGEX)
      if (fullAddressMatch) {
        const [, street, city, state, zip] = fullAddressMatch
        if (this.STATE_ABBREVIATIONS.has(state.toUpperCase())) {
          result.zipCode = zip
          result.wasExtracted = true
          result.extractedFrom = 'full-address'
          result.confidence = 'high'
          result.warning = `Extracted ZIP code "${zip}" from full address`
          this.logZipCodeDetection(zip, `full-address: ${street}, ${city}, ${state}`)
          return result
        }
      }

      // Strategy 3: Try to parse as city, state, zip
      const cityStateZipMatch = trimmedInput.match(this.CITY_STATE_ZIP_REGEX)
      if (cityStateZipMatch) {
        const [, city, state, zip] = cityStateZipMatch
        if (this.STATE_ABBREVIATIONS.has(state.toUpperCase())) {
          result.zipCode = zip
          result.wasExtracted = true
          result.extractedFrom = 'city-state-zip'
          result.confidence = 'high'
          result.warning = `Extracted ZIP code "${zip}" from city, state, ZIP format`
          this.logZipCodeDetection(zip, `city-state-zip: ${city}, ${state}`)
          return result
        }
      }

      // Strategy 4: Extract any ZIP code found in the input (fallback)
      const zipMatches = Array.from(trimmedInput.matchAll(this.ZIP_REGEX))
      if (zipMatches.length > 0) {
        // Take the last ZIP code found (most likely to be the actual ZIP)
        const lastZipMatch = zipMatches[zipMatches.length - 1]
        result.zipCode = lastZipMatch[1]
        result.wasExtracted = true
        result.extractedFrom = 'partial-address'
        result.confidence = zipMatches.length === 1 ? 'medium' : 'low'
        result.warning =
          zipMatches.length > 1
            ? `Multiple ZIP codes found, using "${result.zipCode}"`
            : `Extracted ZIP code "${result.zipCode}" from address text`
        this.logZipCodeDetection(result.zipCode, `partial-address (${zipMatches.length} matches)`)
        return result
      }

      // Strategy 5: No ZIP code found
      result.error = 'No valid ZIP code found in input'
      result.confidence = 'low'
      logger.warn('AddressInputHandler', `No ZIP code found in input: "${trimmedInput}"`)
      return result
    } catch (error) {
      result.error = `Error parsing address: ${error instanceof Error ? error.message : 'Unknown error'}`
      result.confidence = 'low'
      logger.error('AddressInputHandler', 'Error parsing address input', error)
      return result
    }
  }

  /**
   * Parse address into components (for future use)
   */
  static parseAddressComponents(input: string): AddressComponents {
    const components: AddressComponents = {}

    try {
      const trimmedInput = input.trim()

      // Try full address format
      const fullAddressMatch = trimmedInput.match(this.FULL_ADDRESS_REGEX)
      if (fullAddressMatch) {
        const [, street, city, state, zip] = fullAddressMatch
        components.street = street.trim()
        components.city = city.trim()
        components.state = state.toUpperCase()
        components.zipCode = zip
        return components
      }

      // Try city, state, zip format
      const cityStateZipMatch = trimmedInput.match(this.CITY_STATE_ZIP_REGEX)
      if (cityStateZipMatch) {
        const [, city, state, zip] = cityStateZipMatch
        components.city = city.trim()
        components.state = state.toUpperCase()
        components.zipCode = zip
        return components
      }

      // Extract ZIP code if present
      const zipMatch = trimmedInput.match(this.ZIP_REGEX)
      if (zipMatch) {
        components.zipCode = zipMatch[1]
      }

      return components
    } catch (error) {
      logger.error('AddressInputHandler', 'Error parsing address components', error)
      return components
    }
  }

  /**
   * Validate ZIP code format
   */
  static isValidZipCode(zipCode: string): boolean {
    return /^\d{5}(-\d{4})?$/.test(zipCode.trim())
  }

  /**
   * Clean and normalize ZIP code
   */
  static normalizeZipCode(zipCode: string): string {
    return zipCode.trim().replace(/[^\d-]/g, '')
  }

  /**
   * Get user-friendly message for address parsing result
   */
  static getParseResultMessage(result: AddressParseResult): string {
    if (result.error) {
      return result.error
    }

    if (result.warning) {
      return result.warning
    }

    if (result.zipCode && !result.wasExtracted) {
      return `ZIP code "${result.zipCode}" is valid`
    }

    if (result.zipCode && result.wasExtracted) {
      return `ZIP code "${result.zipCode}" extracted successfully`
    }

    return 'Unable to extract ZIP code from input'
  }

  /**
   * Get confidence level description
   */
  static getConfidenceDescription(confidence: 'high' | 'medium' | 'low'): string {
    switch (confidence) {
      case 'high':
        return 'High confidence - ZIP code clearly identified'
      case 'medium':
        return 'Medium confidence - ZIP code extracted with some uncertainty'
      case 'low':
        return 'Low confidence - ZIP code extraction may be inaccurate'
      default:
        return 'Unknown confidence level'
    }
  }

  /**
   * Reset logging state (useful for testing or session resets)
   */
  static resetLoggingState(): void {
    this.lastLoggedZip = null
    this.lastLogTime = 0
    this.logCount = 0
    logger.debug('AddressInputHandler', 'Logging state reset')
  }
}

/**
 * Convenience function for quick ZIP code extraction
 */
export function extractZipCodeFromInput(input: string): string | null {
  const result = AddressInputHandler.parseAddressInput(input)
  return result.zipCode
}

/**
 * Convenience function to check if input contains a valid ZIP code
 */
export function hasValidZipCode(input: string): boolean {
  const result = AddressInputHandler.parseAddressInput(input)
  return result.zipCode !== null && AddressInputHandler.isValidZipCode(result.zipCode)
}
